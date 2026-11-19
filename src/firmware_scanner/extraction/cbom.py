"""Cryptographic Bill of Materials (CBOM) scanner and Post-Quantum Cryptography (PQC) readiness evaluator.

Discovers cryptographic algorithms, primitives, and implementations in embedded firmware binaries,
classifying each algorithm by its quantum vulnerability status (vulnerable, symmetric, pqc, broken, neutral).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


VULNERABLE = "quantum-vulnerable"  # Broken by Shor's algorithm (RSA, ECC, SM2, DH)
SYMMETRIC = "symmetric"            # Grover halves security; 256-bit keys recommended (AES, SM4, ChaCha)
PQC = "post-quantum"              # NIST standardized post-quantum schemes (ML-KEM, ML-DSA)
BROKEN = "legacy/broken"           # Broken by classical cryptanalysis (MD5, SHA-1, DES, RC4)
NEUTRAL = "neutral"                # Key derivation, DRBG, hash without quantum impact (SM3, SHA-256)

_B = r"(?<![A-Za-z0-9_])"
_CDX_PRIMITIVES = {
    "public-key": "pke",
    "key-agreement": "key-agree",
}


def cyclonedx_primitive(value: str) -> str:
    """Map internal labels to CycloneDX 1.6's algorithm primitive enum."""
    return _CDX_PRIMITIVES.get(value, value)


@dataclass(frozen=True)
class AlgoDef:
    key: str
    name: str
    primitive: str
    quantum_status: str
    patterns: tuple[str, ...]
    note: str = ""
    pqc_recommendation: str = ""


# Comprehensive embedded cryptographic algorithm signatures (inspired by Gangmu CBOM)
ALGO_CATALOG: tuple[AlgoDef, ...] = (
    AlgoDef(
        "aes", "AES", "block-cipher", SYMMETRIC,
        (
            _B + r"(?:mbedtls_aes_|esp_aes_|wc_Aes|tc_aes_|HAL_CRYP|AES_(?:set_)?(?:en|de)crypt_key|"
            r"AES_(?:encrypt|decrypt|ecb_encrypt|cbc_encrypt|ctr128_encrypt)\b|MBEDTLS_AES_C\b|"
            r"CONFIG_MBEDTLS_AES\w*|CONFIG_CRYPTO_AES\w*|PSA_KEY_TYPE_AES\b|"
            r"br_aes_\w+|tc_aes\d+_\w+|rijndael_(?:setup|ecb_encrypt|ecb_decrypt)\b|EVP_aes_\d+_(?:cbc|ecb|ctr|cfb\w*|ofb)\b|"
            r"aes_expandkey\b|crypto_aes_set_key\b|aes(?:128|192|256)-(?:ctr|cbc)\b|TPM2?_ALG_AES\b)",
        ),
        note="128-bit key offers ~64-bit quantum security; 256-bit recommended for quantum resistance.",
    ),
    AlgoDef(
        "rsa", "RSA", "public-key", VULNERABLE,
        (
            _B + r"(?:mbedtls_rsa_|RSA_(?:public|private)_(?:encrypt|decrypt)|RSA_sign|RSA_verify|"
            r"wc_InitRsaKey|wc_Rsa\w*|MBEDTLS_RSA_C\b|br_rsa_\w+|EVP_PKEY_RSA\b|"
            r"PSA_KEY_TYPE_RSA\w*|TPM2?_ALG_RSA\b|RSA_generate_key\w*)",
        ),
        note="Vulnerable to Shor's algorithm on quantum computers.",
        pqc_recommendation="Migrate to ML-KEM (FIPS 203 / Kyber) for key encapsulation, ML-DSA (FIPS 204 / Dilithium) for signatures.",
    ),
    AlgoDef(
        "ecdsa", "ECDSA", "signature", VULNERABLE,
        (
            _B + r"(?:mbedtls_ecdsa_|ECDSA_sign|ECDSA_verify|wc_ecc_sign_hash|MBEDTLS_ECDSA_C\b|"
            r"br_ecdsa_\w+|PSA_KEY_TYPE_ECC_KEY_PAIR\b|TPM2?_ALG_ECDSA\b)",
        ),
        note="Elliptic curve signatures broken by Shor's algorithm.",
        pqc_recommendation="Migrate to ML-DSA (Dilithium) or SLH-DSA (SPHINCS+).",
    ),
    AlgoDef(
        "ecdh", "ECDH", "key-agreement", VULNERABLE,
        (
            _B + r"(?:mbedtls_ecdh_|ECDH_compute_key|wc_ecc_shared_secret|MBEDTLS_ECDH_C\b|"
            r"br_ecdh_\w+|TPM2?_ALG_ECDH\b)",
        ),
        note="Elliptic curve Diffie-Hellman broken by Shor's algorithm.",
        pqc_recommendation="Migrate to ML-KEM (Kyber).",
    ),
    AlgoDef(
        "chacha20-poly1305", "ChaCha20-Poly1305", "ae", SYMMETRIC,
        (
            _B + r"(?:mbedtls_chacha20\w*|mbedtls_poly1305\w*|wc_Chacha\w*|wc_Poly1305\w*|"
            r"EVP_chacha20\w*|MBEDTLS_CHACHA20_C\b|MBEDTLS_CHACHAPOLY_C\b|crypto_aead_chacha20poly1305\w*|"
            r"crypto_chacha20\w*|br_chacha20_\w+|chacha20-poly1305@openssh\.com)",
        ),
        note="256-bit key offers ~128-bit quantum security.",
    ),
    AlgoDef(
        "sm4", "SM4", "block-cipher", SYMMETRIC,
        (
            _B + r"(?:sm4_(?:setkey|crypt|encrypt|decrypt|set_key)\w*|SM4_(?:set_key|encrypt|decrypt|CTX)\w*|"
            r"mbedtls_sm4_\w+|EVP_sm4_\w+|TPM2?_ALG_SM4\b)",
        ),
        note="Chinese national standard (GB/T 32907-2016) 128-bit block cipher.",
    ),
    AlgoDef(
        "sm3", "SM3", "hash", NEUTRAL,
        (
            _B + r"(?:sm3_(?:init|update|finish|starts|process)\w*|SM3_(?:Init|Update|Final|CTX)\w*|"
            r"mbedtls_sm3_\w+|EVP_sm3\b|TPM2?_ALG_SM3\b)",
        ),
        note="Chinese national standard (GB/T 32905-2016) cryptographic hash.",
    ),
    AlgoDef(
        "sm2", "SM2", "public-key", VULNERABLE,
        (
            _B + r"(?:sm2_(?:sign|verify|encrypt|decrypt)\w*|SM2_(?:sign|verify|encrypt|decrypt)\w*|"
            r"EVP_PKEY_SM2\b|TPM2?_ALG_SM2\b)",
        ),
        note="Chinese national standard (GB/T 32918-2016) ECC public key system; quantum-vulnerable.",
        pqc_recommendation="Transition to PQC hybrid key exchange / post-quantum signature schemes.",
    ),
    AlgoDef(
        "des", "DES/3DES", "block-cipher", BROKEN,
        (
            _B + r"(?:mbedtls_des3?_|DES_(?:ecb|cbc|ede3|set_key)\w*|wc_Des3?_\w+|MBEDTLS_DES_C\b|"
            r"br_des_\w+|des3?_(?:setup|ecb_encrypt|ecb_decrypt)\b|EVP_des_\w+|3des-cbc\b)",
        ),
        note="DES is practically broken; deprecated in all modern standards.",
        pqc_recommendation="Immediately upgrade to AES-256 or ChaCha20-Poly1305.",
    ),
    AlgoDef(
        "rc4", "RC4", "stream-cipher", BROKEN,
        (
            _B + r"(?:mbedtls_arc4_|RC4_set_key|RC4\(|wc_Arc4\w*|MBEDTLS_ARC4_C\b|"
            r"arc4_(?:setkey|crypt)\b)",
        ),
        note="Severe known statistical biases; prohibited in TLS (RFC 7465).",
        pqc_recommendation="Immediately remove and replace with ChaCha20-Poly1305 or AES-GCM.",
    ),
    AlgoDef(
        "md5", "MD5", "hash", BROKEN,
        (
            _B + r"(?:mbedtls_md5_|MD5_(?:Init|Update|Final)|wc_Md5\w*|MBEDTLS_MD5_C\b|"
            r"EVP_md5\b)",
        ),
        note="Collision resistance broken; forbidden for digital signatures.",
        pqc_recommendation="Replace with SHA-256, SHA-3, or SM3.",
    ),
    AlgoDef(
        "sha1", "SHA-1", "hash", BROKEN,
        (
            _B + r"(?:mbedtls_sha1_|SHA1_(?:Init|Update|Final)|wc_Sha1\w*|MBEDTLS_SHA1_C\b|"
            r"EVP_sha1\b)",
        ),
        note="Practical collision attacks (SHAttered); deprecated by NIST.",
        pqc_recommendation="Replace with SHA-256 or SHA-3.",
    ),
    AlgoDef(
        "sha256", "SHA-256", "hash", NEUTRAL,
        (
            _B + r"(?:mbedtls_sha256_|SHA256_(?:Init|Update|Final)|wc_Sha256\w*|MBEDTLS_SHA256_C\b|"
            r"EVP_sha256\b)",
        ),
        note="Standard cryptographic hash function; secure.",
    ),
    AlgoDef(
        "ml-kem", "ML-KEM (Kyber)", "kem", PQC,
        (
            _B + r"(?:pqcrystals_kyber\w*|KYBER_\w+|crypto_kem_kyber\w*|ml_kem_\w+|"
            r"OQS_KEM_alg_kyber_\w+|FIPS203\w*)",
        ),
        note="NIST FIPS 203 Standard Post-Quantum Key Encapsulation Mechanism.",
    ),
    AlgoDef(
        "ml-dsa", "ML-DSA (Dilithium)", "signature", PQC,
        (
            _B + r"(?:pqcrystals_dilithium\w*|DILITHIUM_\w+|crypto_sign_dilithium\w*|ml_dsa_\w+|"
            r"OQS_SIG_alg_dilithium_\w+|FIPS204\w*)",
        ),
        note="NIST FIPS 204 Standard Post-Quantum Digital Signature Algorithm.",
    ),
)


@dataclass
class DiscoveredCryptoAsset:
    algorithm_key: str
    algorithm_name: str
    primitive: str
    quantum_status: str
    hit_count: int = 0
    matched_locations: list[str] = field(default_factory=list)
    note: str = ""
    pqc_recommendation: str = ""


class CBOMScanner:
    """Scans binary data, libraries, and firmware images for cryptographic assets."""

    def __init__(self):
        self._compiled_algos = []
        for algo in ALGO_CATALOG:
            regexes = [re.compile(p.encode("ascii", errors="ignore")) for p in algo.patterns]
            self._compiled_algos.append((algo, regexes))

    def scan_binary(self, filename: str, data: bytes) -> list[DiscoveredCryptoAsset]:
        """Scan a binary buffer for cryptographic algorithms and API signatures."""
        results: list[DiscoveredCryptoAsset] = []
        # Look in the first 8MB (covers .text, .rodata, symbol tables)
        chunk = data[:8 * 1024 * 1024]

        for algo, regexes in self._compiled_algos:
            total_hits = 0
            for r in regexes:
                matches = r.findall(chunk)
                total_hits += len(matches)

            if total_hits > 0:
                results.append(
                    DiscoveredCryptoAsset(
                        algorithm_key=algo.key,
                        algorithm_name=algo.name,
                        primitive=algo.primitive,
                        quantum_status=algo.quantum_status,
                        hit_count=total_hits,
                        matched_locations=[filename],
                        note=algo.note,
                        pqc_recommendation=algo.pqc_recommendation,
                    )
                )

        return results

    def to_components(self, assets: list[DiscoveredCryptoAsset]) -> list[Any]:
        """Convert discovered cryptographic assets to native Component objects."""
        from .models import Component, VersionConfidence, ExtractionMethod
        comps: list[Component] = []
        for asset in assets:
            props = [
                {"name": "gangmu:quantumStatus", "value": asset.quantum_status},
                {"name": "cbom:primitive", "value": asset.primitive},
                {"name": "cbom:detectionHits", "value": str(asset.hit_count)},
            ]
            if asset.pqc_recommendation:
                props.append({"name": "cbom:pqcRecommendation", "value": asset.pqc_recommendation})
            if asset.note:
                props.append({"name": "cbom:note", "value": asset.note})

            c = Component(
                name=asset.algorithm_name,
                component_type="cryptographic-asset",
                resolved_version="",
                description=f"Cryptographic algorithm {asset.algorithm_name} ({asset.primitive}) | Quantum status: {asset.quantum_status}",
                crypto_properties={
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": cyclonedx_primitive(asset.primitive),
                    },
                },
                properties=props,
                versions=[VersionConfidence(
                    version="detected",
                    confidence=0.90,
                    method=ExtractionMethod.BINARY_SIGNATURE,
                    evidence=f"Detected in {', '.join(asset.matched_locations[:3])}",
                )],
            )
            comps.append(c)
        return comps

    def to_cyclonedx_components(self, assets: list[DiscoveredCryptoAsset]) -> list[dict[str, Any]]:
        """Convert discovered cryptographic assets to CycloneDX 1.6 cryptographic-asset components."""
        cdx_components: list[dict[str, Any]] = []

        for asset in assets:
            props = [
                {"name": "gangmu:quantumStatus", "value": asset.quantum_status},
                {"name": "cbom:primitive", "value": asset.primitive},
                {"name": "cbom:detectionHits", "value": str(asset.hit_count)},
            ]
            if asset.pqc_recommendation:
                props.append({"name": "cbom:pqcRecommendation", "value": asset.pqc_recommendation})
            if asset.note:
                props.append({"name": "cbom:note", "value": asset.note})

            comp: dict[str, Any] = {
                "type": "cryptographic-asset",
                "name": asset.algorithm_name,
                "description": f"Cryptographic algorithm {asset.algorithm_name} ({asset.primitive})",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": cyclonedx_primitive(asset.primitive),
                    },
                },
                "properties": props,
            }
            cdx_components.append(comp)

        return cdx_components
