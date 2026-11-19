import json
import shutil
import subprocess
from pathlib import Path

import pytest

from firmware_scanner.extraction.binary_reference import BinaryReferenceMatcher


ROOT = Path(__file__).resolve().parents[2]
DATA_PATH = ROOT / "src" / "firmware_scanner" / "data" / "binary_reference.json"


def test_reference_catalog_has_provenance_and_versioned_rules():
    catalog = json.loads(DATA_PATH.read_text())
    assert catalog["schema_version"] == 1
    assert len(catalog["references"]) >= 100
    for rule in catalog["references"]:
        assert rule["name"]
        assert rule["source"].startswith("https://")
        assert rule["version_policy"] in {"banner", "identity_only"}


def test_binary_banners_preserve_full_development_versions():
    matcher = BinaryReferenceMatcher()
    cases = [
        (b"libxml2 21400-GITv2.13.0-1904-g4d38e2fe\x00", "libxml2", "21400-GITv2.13.0-1904-g4d38e2fe"),
        (b"curl 8.12.0-DEV\x00", "curl", "8.12.0-DEV"),
        (b"Zstandard v1.5.6\x00", "zstd", "1.5.6"),
        (b"BoringSSL\x00", "BoringSSL", ""),
    ]
    for payload, expected_name, expected_version in cases:
        matches = matcher.match(payload)
        match = next(item for item in matches if item.name == expected_name)
        assert match.version == expected_version
        assert 0.0 < match.confidence <= 1.0
        assert match.evidence
        assert match.source.startswith("https://")
        assert match.identity_only is (expected_version == "")


def test_filename_only_is_not_a_match_and_raw_bytes_need_a_real_signature():
    matcher = BinaryReferenceMatcher()
    assert matcher.match(b"ordinary unrelated payload", "libcurl.so") == []
    assert matcher.match(b"JFIF 1.02\x00", "libjpeg.so") == []
    assert matcher.match(b"libbpf\x00zstd 1.5.6\x00", "libbpf.so") == []
    assert matcher.match(b"\x7fELF\x00not a recognized binary") == []


def test_defined_elf_symbols_can_identify_a_library_but_imports_cannot(tmp_path):
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not compiler:
        pytest.skip("a C compiler is required for ELF symbol fixtures")

    library_source = tmp_path / "libfixture.c"
    library_source.write_text(
        "int avcodec_send_packet(void) { return 0; }\n"
        "int avcodec_receive_frame(void) { return 0; }\n"
    )
    library = tmp_path / "libfixture.so"
    subprocess.run([compiler, "-shared", "-fPIC", str(library_source), "-o", str(library)], check=True)

    importer_source = tmp_path / "importer.c"
    importer_source.write_text(
        "extern int avcodec_send_packet(void);\n"
        "int main(void) { return avcodec_send_packet(); }\n"
    )
    importer = tmp_path / "importer"
    subprocess.run([compiler, "-shared", "-fPIC", str(importer_source), "-o", str(importer)], check=True)

    matcher = BinaryReferenceMatcher()
    defined_matches = matcher.match(library.read_bytes(), "libfixture.so")
    imported_matches = matcher.match(importer.read_bytes(), "ffmpeg-client")
    assert any(item.name == "FFmpeg" for item in defined_matches)
    assert not any(item.name == "FFmpeg" for item in imported_matches)


def test_filename_can_narrow_candidates_but_not_invent_version():
    matcher = BinaryReferenceMatcher()
    result = matcher.match(b"curl 8.12.0-DEV\x00", "libcurl.so")
    curl = next(item for item in result if item.name == "curl")
    assert curl.version == "8.12.0-DEV"
    assert curl.confidence >= 0.9


def test_one_rule_returns_distinct_versions_and_caps_candidates(tmp_path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "references": [
                    {
                        "name": "DemoLib",
                        "source": "https://example.org/demolib",
                        "version_policy": "banner",
                        "banner_regex": r"DemoLib ([0-9]+\.[0-9]+)",
                    }
                ],
            }
        )
    )
    matcher = BinaryReferenceMatcher(catalog)

    matches = matcher.match(b"DemoLib 1.2 DemoLib 2.3 DemoLib 1.2")
    assert [item.version for item in matches] == ["1.2", "2.3"]

    payload = b" ".join(f"DemoLib {index}.0".encode() for index in range(40))
    assert len(matcher.match(payload)) == 32


def test_identity_evidence_survives_when_version_banner_is_absent(tmp_path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "references": [
                    {
                        "name": "DemoLib",
                        "source": "https://example.org/demolib",
                        "version_policy": "banner",
                        "banner_regex": r"DemoLib version ([0-9]+\.[0-9]+)",
                        "identity_banner": "DemoLib upstream library",
                    }
                ],
            }
        )
    )

    matches = BinaryReferenceMatcher(catalog).match(b"DemoLib upstream library")
    assert len(matches) == 1
    assert matches[0].version == ""
    assert matches[0].identity_only is True


def test_catalog_identifies_additional_native_libraries_from_defined_symbols(tmp_path):
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not compiler:
        pytest.skip("a C compiler is required for ELF symbol fixtures")

    symbols = [
        ("exif_data_new_from_file", "exif_data_save_data"),
        ("ntfs_attr_open", "ntfs_attr_pread"),
        ("FPDF_InitLibrary", "FPDF_LoadPage"),
        ("drmIoctl", "drmGetVersion"),
        ("fuse_new", "fuse_main_real"),
        ("minijail_new", "minijail_run"),
        ("capng_get_caps_process", "capng_apply"),
        ("dav1d_open", "dav1d_send_data"),
        ("I420ToNV12", "NV12ToI420"),
        ("opj_create_decompress", "opj_create_compress"),
        ("heif_context_alloc", "heif_context_read_from_file"),
        ("avifDecoderCreate", "avifDecoderNextImage"),
        ("snappy_compress", "snappy_uncompress"),
        ("JxlDecoderCreate", "JxlDecoderProcessInput"),
        ("zip_open", "zip_fopen"),
        ("libraw_init", "libraw_open_file"),
        ("TIFFOpen", "TIFFReadDirectory"),
    ]
    source = tmp_path / "catalog-fixture.c"
    source.write_text("\n".join(
        f"int {name}(void) {{ return 0; }}"
        for pair in symbols
        for name in pair
    ))
    library = tmp_path / "libcatalog-fixture.so"
    subprocess.run(
        [compiler, "-shared", "-fPIC", str(source), "-o", str(library)],
        check=True,
        capture_output=True,
    )
    matched = {
        item.name
        for item in BinaryReferenceMatcher().match(
            library.read_bytes(),
            "libcatalog-fixture.so",
        )
    }
    assert {
        "libexif",
        "NTFS-3G",
        "PDFium",
        "libdrm",
        "libfuse",
        "minijail",
        "libcap-ng",
        "dav1d",
        "libyuv",
        "OpenJPEG",
        "libheif",
        "libavif",
        "Snappy",
        "libjxl",
        "libzip",
        "LibRaw",
        "libtiff",
    }.issubset(matched)
