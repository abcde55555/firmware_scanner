"""Unit tests for Cryptographic Bill of Materials (CBOM) and AI Bill of Materials (AIBOM)."""

from firmware_scanner.extraction.aibom import (
    AIBOMScanner,
)
from firmware_scanner.extraction.cbom import (
    ALGO_CATALOG,
    BROKEN,
    PQC,
    SYMMETRIC,
    VULNERABLE,
    CBOMScanner,
    cyclonedx_primitive,
)


def test_cbom_algorithm_catalog():
    """Verify algorithm catalog covers essential primitives and quantum classifications."""
    keys = {a.key for a in ALGO_CATALOG}
    assert "aes" in keys
    assert "rsa" in keys
    assert "ecdsa" in keys
    assert "ecdh" in keys
    assert "sm4" in keys
    assert "sm3" in keys
    assert "sm2" in keys
    assert "ml-kem" in keys
    assert "ml-dsa" in keys
    assert "des" in keys
    assert "rc4" in keys


def test_internal_primitives_map_to_cyclonedx_enum_values():
    assert cyclonedx_primitive("public-key") == "pke"
    assert cyclonedx_primitive("key-agreement") == "key-agree"
    assert cyclonedx_primitive("hash") == "hash"


def test_cbom_scanner_detection():
    """Test detection and PQC categorization of cryptographic algorithms."""
    scanner = CBOMScanner()

    # Synthetic binary buffers containing typical crypto API calls
    data_aes = b"\x00\x11\x22AES_set_encrypt_key\x00mbedtls_aes_crypt_ecb\x00"
    data_rsa = b"\x55\x89RSA_public_encrypt\x00wc_InitRsaKey\x00"
    data_pqc = b"\x00pqcrystals_kyber768_ref_keypair\x00DILITHIUM_MODE\x00"
    data_sm = b"\x00sm4_crypt_cbc\x00sm3_starts\x00sm2_sign_ctx\x00"
    data_broken = b"\x00DES_ecb_encrypt\x00RC4_set_key\x00MD5_Init\x00"

    # Test AES
    assets_aes = scanner.scan_binary("libtest_aes.so", data_aes)
    names = {a.algorithm_name for a in assets_aes}
    assert "AES" in names
    aes_asset = next(a for a in assets_aes if a.algorithm_name == "AES")
    assert aes_asset.quantum_status == SYMMETRIC
    assert aes_asset.hit_count >= 2

    # Test RSA
    assets_rsa = scanner.scan_binary("libtest_rsa.so", data_rsa)
    rsa_asset = next(a for a in assets_rsa if a.algorithm_name == "RSA")
    assert rsa_asset.quantum_status == VULNERABLE
    assert "ML-KEM" in rsa_asset.pqc_recommendation

    # Test PQC
    assets_pqc = scanner.scan_binary("libtest_pqc.so", data_pqc)
    pqc_names = {a.algorithm_name for a in assets_pqc}
    assert "ML-KEM (Kyber)" in pqc_names
    assert "ML-DSA (Dilithium)" in pqc_names
    kyber = next(a for a in assets_pqc if a.algorithm_name == "ML-KEM (Kyber)")
    assert kyber.quantum_status == PQC

    # Test ShangMi (SM2/SM3/SM4)
    assets_sm = scanner.scan_binary("libtest_sm.so", data_sm)
    sm_names = {a.algorithm_name for a in assets_sm}
    assert "SM4" in sm_names
    assert "SM3" in sm_names
    assert "SM2" in sm_names
    sm2 = next(a for a in assets_sm if a.algorithm_name == "SM2")
    assert sm2.quantum_status == VULNERABLE

    # Test Broken (DES, RC4, MD5)
    assets_broken = scanner.scan_binary("libtest_legacy.so", data_broken)
    broken_statuses = {a.quantum_status for a in assets_broken}
    assert broken_statuses == {BROKEN}


def test_cbom_scanner_uses_one_regex_pass_per_binary():
    scanner = CBOMScanner()

    assets = scanner.scan_binary(
        "libtest.so",
        b"\x00AES_set_encrypt_key\x00RSA_public_encrypt\x00pqcrystals_kyber768_ref\x00",
    )

    assert len(assets) == 3
    assert scanner.last_prefilter_passes == 1
    assert scanner.last_detail_passes == 3


def test_binary_asset_scanners_use_a_two_mib_prefix_window():
    data = b"AES_set_encrypt_key\0" + b"\0" * (3 * 1024 * 1024)
    cbom = CBOMScanner()
    aibom = AIBOMScanner()

    assert cbom.scan_binary("libcrypto.so", data)
    assert aibom.scan_binary_for_runtimes("libai.so", data) == []
    assert cbom.last_scan_bytes == 2 * 1024 * 1024
    assert aibom.last_scan_bytes == 2 * 1024 * 1024


def test_cbom_to_components_and_cyclonedx():
    """Test converting CBOM assets to native components and CycloneDX format."""
    scanner = CBOMScanner()
    data = b"\x00mbedtls_aes_init\x00RSA_public_encrypt\x00pqcrystals_kyber512_ref\x00"
    assets = scanner.scan_binary("libcrypto_test.so", data)
    assert len(assets) >= 3

    comps = scanner.to_components(assets)
    assert len(comps) == len(assets)
    for c in comps:
        assert c.component_type == "cryptographic-asset"
        assert c.crypto_properties["assetType"] == "algorithm"
        assert any(p["name"] == "gangmu:quantumStatus" for p in c.properties)

    cdx = scanner.to_cyclonedx_components(assets)
    assert len(cdx) == len(assets)
    for item in cdx:
        assert item["type"] == "cryptographic-asset"
        assert "cryptoProperties" in item
        assert "primitive" in item["cryptoProperties"]["algorithmProperties"]


def test_aibom_model_formats():
    """Test identifying machine learning model file headers and magics."""
    scanner = AIBOMScanner()

    # GGUF magic at offset 0
    gguf_header = b"GGUF\x03\x00\x00\x00" + b"\x00" * 32
    m_gguf = scanner.scan_file_header("qwen2.5-0.5b.gguf", gguf_header, len(gguf_header))
    assert m_gguf is not None
    assert m_gguf.format_key == "gguf"
    assert m_gguf.format_name == "GGUF"

    # TFLite magic at offset 4
    tflite_header = b"\x00\x00\x00\x00TFL3" + b"\x00" * 32
    m_tflite = scanner.scan_file_header("person_detect.tflite", tflite_header, len(tflite_header))
    assert m_tflite is not None
    assert m_tflite.format_key == "tflite"

    # ExecuTorch magic at offset 4
    pte_header = b"\x00\x00\x00\x00ET12" + b"\x00" * 32
    m_pte = scanner.scan_file_header("mobilenet.pte", pte_header, len(pte_header))
    assert m_pte is not None
    assert m_pte.format_key == "executorch"

    # Embedded TFLite C array
    c_array_data = (
        b"const unsigned char model_data[] = { 0x1c, 0x00, 0x54, 0x46, 0x4c, 0x33, 0x00 };"
    )
    m_arr = scanner.scan_file_header("model_data.c", c_array_data, len(c_array_data))
    assert m_arr is not None
    assert "Embedded Array" in m_arr.format_name


def test_aibom_runtimes_and_components():
    """Test detecting embedded AI inference runtimes and CycloneDX conversion."""
    scanner = AIBOMScanner()

    runtime_data = (
        b"\x00tflite::MicroInterpreter::AllocateTensors\x00"
        b"OrtCreateSession\x00"
        b"llama_model_load_from_file\x00"
        b"arm_convolve_s8\x00"
    )
    runtimes = scanner.scan_binary_for_runtimes("libai_engine.so", runtime_data)
    keys = {r.runtime_key for r in runtimes}
    assert "tflite-micro" in keys
    assert "onnxruntime" in keys
    assert "llama-cpp" in keys
    assert "cmsis-nn" in keys
    assert scanner.last_prefilter_passes == 1
    assert scanner.last_detail_passes == 5

    # Convert to components
    models = [
        scanner.scan_file_header("model.tflite", b"\x00\x00\x00\x00TFL3" + b"\x00" * 32, 1024)
    ]
    comps = scanner.to_components(models, runtimes)
    assert len(comps) == 1 + len(runtimes)

    model_comp = next(c for c in comps if c.component_type == "machine-learning-model")
    assert model_comp.name == "model.tflite"
    assert "modelParameters" in model_comp.model_card

    cdx = scanner.to_cyclonedx_components(models, runtimes)
    assert any(c["type"] == "machine-learning-model" for c in cdx)
    assert any(c["type"] == "library" for c in cdx)
