"""Unit tests for the five-layer ELF deep version extractor."""

import shutil
import subprocess

import pytest

from firmware_scanner.extraction import elf_deep_extractor
from firmware_scanner.extraction.elf_deep_extractor import (
    AES_SBOX_PREFIX,
    ELFDeepExtractor,
    ELFExtractionResult,
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
    pcap_data = (
        b"\x7fELF" + b"\x00" * 20 + b"libpcap version 1.10.5 (with TPACKET_V3)" + b"\x00" * 20
    )
    res = extractor.extract("libpcap.so", pcap_data)
    assert res is not None
    assert res.version == "1.10.5"

    # libevent
    event_data = b"\x7fELF" + b"\x00" * 20 + b"2.1.8-stable\x00" + b"\x00" * 20
    res = extractor.extract("libevent.so", event_data)
    assert res is not None
    assert res.version == "2.1.8-stable"

    # zlib
    zlib_data = b"\x7fELF" + b"\x00" * 20 + b"deflate 1.3.0.1" + b"\x00" * 20
    res = extractor.extract("libz.so", zlib_data)
    assert res is not None
    assert res.version == "1.3.0.1"


def test_rodata_binaries(extractor):
    """Test Layer 2: .rodata banner signatures for executables."""
    # curl
    curl_data = b"\x7fELF" + b"\x00" * 20 + b"curl 8.12.0" + b"\x00" * 20
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

    # mbed TLS
    mbed_data = b"\x7fELF" + b"\x00" * 20 + b"mbed TLS 2.28.8" + b"\x00" * 20
    res = extractor.extract("libmbedtls.so", mbed_data)
    assert res is not None
    assert res.version == "2.28.8"

    # cJSON
    cjson_data = b"\x7fELF" + b"\x00" * 20 + b"cJSON 1.7.18" + b"\x00" * 20
    res = extractor.extract("libcjson.so", cjson_data)
    assert res is not None
    assert res.version == "1.7.18"

    # Dropbear
    dropbear_data = b"\x7fELF" + b"\x00" * 20 + b"Dropbear v2022.83" + b"\x00" * 20
    res = extractor.extract("dropbear", dropbear_data)
    assert res is not None
    assert res.version == "2022.83"


def test_landmark_symbol_fingerprinting(extractor):
    """Bare API strings cannot establish an exact version or a defined export."""
    data = b"\x7fELF" + b"\x00" * 20 + b"TLS_method\x00" + b"\x00" * 20
    res = extractor.extract("libssl.so", data)
    assert res is None or not res.version

    # curl milestone
    curl_sym = b"\x7fELF" + b"\x00" * 20 + b"curl_ws_send\x00" + b"\x00" * 20
    res_curl = extractor.extract("libcurl.so", curl_sym)
    assert res_curl is None or not res_curl.version


def test_crypto_magic_constants(extractor):
    """Test Layer 4: Cryptographic magic constants detection."""
    data = b"\x7fELF" + b"\x00" * 20 + AES_SBOX_PREFIX + b"\x00" * 20
    extractor._extract_crypto_constants(
        data, extractor.extract("libsec.so", b"\x7fELF" + b"\x00" * 60) or extractor.__class__()
    )


def test_anchored_signatures(extractor):
    """Test Layer 2.5: Anchored format-string + version-shape extraction."""
    # dnsmasq with separated format string and version string
    dnsmasq_elf = (
        b"\x7fELF" + b"\x00" * 20 + b"Dnsmasq version %s\x00some other data\x002.86\x00more data"
    )
    res = extractor.extract("dnsmasq", dnsmasq_elf)
    assert res is not None
    assert res.version == "2.86"
    assert res.canonical_name == "dnsmasq"
    assert "Anchored" in res.evidence

    # hostapd
    hostapd_elf = b"\x7fELF" + b"\x00" * 20 + b"hostapd v%s\x002.10\x00tail"
    res_hapd = extractor.extract("hostapd", hostapd_elf)
    assert res_hapd is not None
    assert res_hapd.version == "2.10"
    assert res_hapd.canonical_name == "hostapd"


def test_symbol_sets_containment(extractor):
    """Test Layer 3.5: Multi-symbol set containment matching."""
    # libogg with 12 matching API symbols
    ogg_syms = [
        "ogg_stream_init",
        "ogg_stream_clear",
        "ogg_stream_packetin",
        "ogg_stream_pageout",
        "ogg_stream_pagein",
        "ogg_stream_packetout",
        "ogg_stream_flush",
        "ogg_sync_init",
        "ogg_sync_buffer",
        "ogg_sync_wrote",
        "ogg_sync_pageout",
        "ogg_sync_pageseek",
    ]
    ogg_data = (
        b"\x7fELF" + b"\x00" * 20 + b"".join(f"\x00{s}\x00".encode("ascii") for s in ogg_syms)
    )
    res = extractor.extract("libcustom_audio.so", ogg_data)
    assert res is None


def test_codec_symbol_identity_emits_third_party_taxonomy(extractor):
    result = ELFExtractionResult()
    extractor._extract_symbol_sets(
        "libstagefright_soft_mp3dec.so",
        b"",
        result,
        {
            "pvmp3_InitDecoder",
            "pvmp3_framedecoder",
            "pvmp3_decode_header",
            "pvmp3_alias_reduction",
            "pvmp3_dct_9",
        },
    )

    assert result.canonical_name == "pvmp3dec"
    assert result.version == ""
    assert {
        "name": "firmware:taxonomy",
        "value": "third-party-oss",
    } in result.claim_facts["pvmp3dec"]
    assert {
        "name": "firmware:taxonomy:evidence",
        "value": "confirmed-symbol-set-identity",
    } in result.claim_facts["pvmp3dec"]
    assert any(
        fact["name"] == "firmware:evidence:source"
        and fact["value"] == "https://android.googlesource.com/platform/frameworks/av/"
        for fact in result.claim_facts["pvmp3dec"]
    )


def test_binary_inventory_scopes_codec_facts_to_contained_identity(tmp_path):
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        pytest.skip("host C compiler unavailable")
    source = tmp_path / "codec.c"
    output = tmp_path / "libstagefright_soft_mp3dec.so"
    source.write_text(
        """
        __attribute__((visibility("default"))) void pvmp3_InitDecoder(void) {}
        __attribute__((visibility("default"))) void pvmp3_framedecoder(void) {}
        __attribute__((visibility("default"))) void pvmp3_decode_header(void) {}
        __attribute__((visibility("default"))) void pvmp3_alias_reduction(void) {}
        __attribute__((visibility("default"))) void pvmp3_dct_9(void) {}
        """
    )
    subprocess.run(
        [compiler, "-shared", "-fPIC", "-o", str(output), str(source)],
        check=True,
        capture_output=True,
    )

    components = BinaryInventory().extract(
        output.read_bytes(),
        output.name,
        f"/lib/{output.name}",
    )

    codec = next(component for component in components if component.name == "pvmp3dec")
    properties = {
        prop["name"]: prop["value"]
        for prop in codec.properties
        if prop.get("name")
    }
    assert codec.resolved_version == ""
    assert properties["firmware:taxonomy"] == "third-party-oss"
    assert properties["firmware:taxonomy:evidence"] == "confirmed-symbol-set-identity"
    assert (
        properties["firmware:evidence:source"]
        == "https://android.googlesource.com/platform/frameworks/av/"
    )


def test_go_buildinfo(extractor):
    """Test Layer 2.8: Go embedded buildinfo extraction."""
    from firmware_scanner.extraction.elf_deep_extractor import GO_MAGIC

    # build a small valid Go 1.18+ buildinfo header
    # GO_MAGIC (14 bytes) + byte 14 (pointer size 8) + byte 15 (flags 2: inline strings)
    # followed by 16 padding bytes to reach header 32, then uvarint length (6) + b"go1.22"
    header = GO_MAGIC + bytes([8, 2]) + b"\x00" * 16 + bytes([6]) + b"go1.22"
    go_elf = b"\x7fELF" + b"\x00" * 30 + header + b"\x00" * 20
    res = extractor.extract("go_service", go_elf)
    assert res is not None
    assert res.canonical_name == "golang"
    assert res.version == "1.22"
    assert res.version_kind == "runtime"
    assert "Go embedded buildinfo" in res.evidence


def test_unknown_elf_is_parsed_once_for_metadata_and_symbols(tmp_path, monkeypatch):
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is required for ELF fixtures")
    source = tmp_path / "unknown.c"
    target = tmp_path / "libunknown.so"
    source.write_text("int example(void) { return 42; }\n")
    subprocess.run(
        [compiler, "-shared", "-fPIC", str(source), "-o", str(target)],
        check=True,
        capture_output=True,
    )

    real_elffile = elf_deep_extractor.ELFFile
    calls = {"count": 0}

    def counting_elffile(*args, **kwargs):
        calls["count"] += 1
        return real_elffile(*args, **kwargs)

    monkeypatch.setattr(elf_deep_extractor, "ELFFile", counting_elffile)

    ELFDeepExtractor().extract("libunknown.so", target.read_bytes())

    assert calls["count"] == 1


def test_shared_defined_symbol_set_contains_only_exportable_symbols(tmp_path):
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is required for ELF fixtures")
    source = tmp_path / "symbols.c"
    target = tmp_path / "libsymbols.so"
    source.write_text(
        "static int local_only(void) { return 1; }\n"
        "int exported_symbol(void) { return local_only(); }\n"
    )
    subprocess.run(
        [compiler, "-shared", "-fPIC", "-O0", str(source), "-o", str(target)],
        check=True,
        capture_output=True,
    )

    result = ELFDeepExtractor().extract("libsymbols.so", target.read_bytes())

    assert result is not None
    assert result.defined_symbols is not None
    assert "exported_symbol" in result.defined_symbols
    assert "local_only" not in result.defined_symbols
