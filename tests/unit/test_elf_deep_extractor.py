"""Unit tests for the five-layer ELF deep version extractor."""

import pytest
from firmware_scanner.extraction.elf_deep_extractor import (
    ELFDeepExtractor,
    AES_SBOX_PREFIX,
    CHACHA20_MAGIC,
    SHA256_IV,
)
from firmware_scanner.extraction.models import ExtractionMethod


@pytest.fixture
def extractor():
    return ELFDeepExtractor()


def test_hal_hidl_interface(extractor):
    """Test Layer 3: Android HIDL interface version extraction."""
    dummy_elf = b"\x7fELF" + b"\x00" * 60
    res = extractor.extract("android.hardware.camera.device@3.7.so", dummy_elf)
    assert res is not None
    assert res.version == "3.7"
    assert res.method == ExtractionMethod.MANIFEST_BINARY
    assert "HIDL" in res.evidence


def test_hal_aidl_interface(extractor):
    """Test Layer 3: Android AIDL interface version extraction."""
    dummy_elf = b"\x7fELF" + b"\x00" * 60
    res = extractor.extract("netd_aidl_interface-V17-cpp.so", dummy_elf)
    assert res is not None
    assert res.version == "V17"
    assert res.method == ExtractionMethod.MANIFEST_BINARY
    assert "AIDL" in res.evidence

    res_ndk = extractor.extract("android.hardware.audio.common-V4-ndk.so", dummy_elf)
    assert res_ndk is not None
    assert res_ndk.version == "V4"


def test_rodata_signatures(extractor):
    """Test Layer 2: .rodata banner signatures for well-known libraries."""
    # SQLite
    sqlite_data = b"\x7fELF" + b"\x00" * 20 + b"SQLite version 3.44.5" + b"\x00" * 20
    res = extractor.extract("libsqlite.so", sqlite_data)
    assert res is not None
    assert res.version == "3.44.5"

    # libpng
    png_data = b"\x7fELF" + b"\x00" * 20 + b"libpng version 1.6.44" + b"\x00" * 20
    res = extractor.extract("libpng.so", png_data)
    assert res is not None
    assert res.version == "1.6.44"

    # HarfBuzz
    hb_data = b"\x7fELF" + b"\x00" * 20 + b"\x0010.2.0\x00end table" + b"\x00" * 20
    res = extractor.extract("libharfbuzz_ng.so", hb_data)
    assert res is not None
    assert res.version == "10.2.0"

    # libpcap
    pcap_data = b"\x7fELF" + b"\x00" * 20 + b"libpcap version 1.10.5 (with TPACKET_V3)" + b"\x00" * 20
    res = extractor.extract("libpcap.so", pcap_data)
    assert res is not None
    assert res.version == "1.10.5"

    # libevent
    event_data = b"\x7fELF" + b"\x00" * 20 + b"2.1.8-stable\x00" + b"\x00" * 20
    res = extractor.extract("libevent.so", event_data)
    assert res is not None
    assert res.version == "2.1.8"

    # zlib
    zlib_data = b"\x7fELF" + b"\x00" * 20 + b"deflate 1.3.0.1" + b"\x00" * 20
    res = extractor.extract("libz.so", zlib_data)
    assert res is not None
    assert res.version == "1.3.0.1"


def test_rodata_binaries(extractor):
    """Test Layer 2: .rodata banner signatures for executables."""
    # curl
    curl_data = b"\x7fELF" + b"\x00" * 20 + b"libcurl/8.12.0" + b"\x00" * 20
    res = extractor.extract("curl", curl_data)
    assert res is not None
    assert res.version == "8.12.0"

    # toybox
    toybox_data = b"\x7fELF" + b"\x00" * 20 + b"0.8.12-android\x00" + b"\x00" * 20
    res = extractor.extract("toybox", toybox_data)
    assert res is not None
    assert res.version == "0.8.12"

    # iptables
    iptables_data = b"\x7fELF" + b"\x00" * 20 + b"1.8.11 (legacy)\x00" + b"\x00" * 20
    res = extractor.extract("iptables", iptables_data)
    assert res is not None
    assert res.version == "1.8.11"

    # bzip2
    bzip2_data = b"\x7fELF" + b"\x00" * 20 + b"1.0.8, 13-Jul-2019\x00" + b"\x00" * 20
    res = extractor.extract("bzip2", bzip2_data)
    assert res is not None
    assert res.version == "1.0.8"

    # MirBSD Korn Shell
    mksh_data = b"\x7fELF" + b"\x00" * 20 + b"KSH_VERSION=@(#)MIRBSD KSH R59 20" + b"\x00" * 20
    res = extractor.extract("sh", mksh_data)
    assert res is not None
    assert res.version == "R59"


def test_landmark_symbol_fingerprinting(extractor):
    """Test Layer 3: Exported Landmark API milestone fingerprinting."""
    data = b"\x7fELF" + b"\x00" * 20 + b"TLS_method\x00" + b"\x00" * 20
    res = extractor.extract("libssl.so", data)
    assert res is not None
    assert res.version == "1.1+"
    assert res.method == ExtractionMethod.SYMBOL_TABLE


def test_crypto_magic_constants(extractor):
    """Test Layer 4: Cryptographic magic constants detection."""
    data = b"\x7fELF" + b"\x00" * 20 + AES_SBOX_PREFIX + b"\x00" * 20
    res = extractor._extract_crypto_constants(data, extractor.extract("libsec.so", b"\x7fELF" + b"\x00" * 60) or extractor.__class__())
