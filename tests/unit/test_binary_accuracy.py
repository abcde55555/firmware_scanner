"""Regressions for version evidence being attributed to the wrong component."""

import shutil
import subprocess

import pytest

from firmware_scanner.android.build_prop import AndroidBuildInfo
from firmware_scanner.android.system_scanner import AndroidScanResult, AndroidSystemScanner
from firmware_scanner.extraction.elf_deep_extractor import ELFDeepExtractor
from firmware_scanner.extraction.models import Component, VersionConfidence


class Files:
    def __init__(self, files):
        self.files = files

    def read_file(self, path, max_size=16 * 1024 * 1024):
        return self.files.get(path, b"")[:max_size] or None

    def exists(self, path):
        return path in self.files or any(k.startswith(path.rstrip("/") + "/") for k in self.files)

    def list_directory(self, path):
        from types import SimpleNamespace

        prefix = path.rstrip("/") + "/"
        names = {k[len(prefix) :].split("/")[0] for k in self.files if k.startswith(prefix)}
        return [
            SimpleNamespace(
                name=n, is_file=prefix + n in self.files, is_dir=prefix + n not in self.files
            )
            for n in sorted(names)
        ]

    def file_size(self, path):
        return len(self.files.get(path, b""))


def test_platform_baseline_is_not_a_library_release():
    comp = Component(
        name="libbinder.so", description="AOSP native library at /system/lib64/libbinder.so"
    )
    result = AndroidScanResult(build_info=AndroidBuildInfo(android_version="16"), components=[comp])
    AndroidSystemScanner(Files({}))._apply_os_version_fallback(result)
    assert comp.resolved_version == ""
    assert any(
        p["name"] == "firmware:android:release" and p["value"] == "16" for p in comp.properties
    )


@pytest.mark.parametrize(
    "filename,payload",
    [
        ("libjpeg.so", b"1.02\x00JFIF"),
        ("libbpf.so", b"\x001.5.7\x00Operation made no progress"),
        ("libssl.so", b"\x00TLS_method\x00"),
        ("libwebrtc_audio_preprocessing.so", b"VerifyVersion\x00TLS_method\x00"),
    ],
)
def test_protocol_dependency_and_random_integer_are_not_host_versions(filename, payload):
    result = ELFDeepExtractor().extract(filename, b"\x7fELF" + b"\x00" * 60 + payload)
    assert result is None or not result.version


@pytest.mark.parametrize(
    "filename,banner,want",
    [
        ("curl", b"curl 8.12.0-DEV (aarch64-linux-android)", "8.12.0-DEV"),
        ("libxml2.so", b"21400-GITv2.13.0-1904-g4d38e2fe\x00", "21400-GITv2.13.0-1904-g4d38e2fe"),
        ("hostapd", b"hostapd v%s\x002.11-devel\x00", "2.11-devel"),
    ],
)
def test_development_versions_retain_observed_suffix(filename, banner, want):
    result = ELFDeepExtractor().extract(filename, b"\x7fELF" + b"\x00" * 60 + banner)
    assert result is not None
    assert result.version == want


def test_banner_beats_soname_abi(tmp_path):
    cc = shutil.which("cc")
    if not cc:
        pytest.skip("C compiler needed for real ELF fixture")
    src = tmp_path / "png.c"
    src.write_text('const char *png_banner = "libpng version 1.6.44";')
    target = tmp_path / "libpng.so"
    subprocess.run(
        [cc, "-shared", "-fPIC", "-Wl,-soname,libpng.so.1", "-o", str(target), str(src)], check=True
    )
    result = ELFDeepExtractor().extract("libpng.so", target.read_bytes())
    assert result.version == "1.6.44"


def test_soname_alone_does_not_supply_release(tmp_path):
    cc = shutil.which("cc")
    if not cc:
        pytest.skip("C compiler needed for real ELF fixture")
    src = tmp_path / "unknown.c"
    src.write_text("int example(void) { return 42; }")
    target = tmp_path / "libunknown.so"
    subprocess.run(
        [cc, "-shared", "-fPIC", "-Wl,-soname,libunknown.so.7", "-o", str(target), str(src)],
        check=True,
    )
    result = ELFDeepExtractor().extract("libunknown.so", target.read_bytes())
    assert result is None or not result.version


def test_imports_do_not_assign_openssl_version_to_client():
    data = b"\x7fELF" + b"\x00" * 60 + b"\x00TLS_method\x00"
    scanner = AndroidSystemScanner(Files({"/system/bin/client": data}))
    comps = scanner._scan_executables({"client": "3.0.0"})
    assert len(comps) == 1
    assert comps[0].name == "client"
    assert comps[0].resolved_version == ""


def test_native_host_keeps_dependency_as_separate_component():
    data = b"\x7fELF" + b"\x00" * 60 + b"libpng version 1.6.44\x00"
    scanner = AndroidSystemScanner(Files({"/system/lib64/libvendor.so": data}))
    comps = scanner._scan_native_libs()
    host = next(c for c in comps if c.name == "libvendor.so")
    dependency = next(c for c in comps if c.name.lower() in ("libpng", "png"))
    assert host.resolved_version == ""
    assert dependency.resolved_version == "1.6.44"
    assert any(
        p["name"] == "firmware:evidence:location" and p["value"] == "/system/lib64/libvendor.so"
        for p in dependency.properties
    )


def test_native_abi_paths_keep_both_versions():
    files = {
        "/system/lib64/libpng.so": b"\x7fELF" + b"\0" * 60 + b"libpng version 1.6.44\0",
        "/system/lib/arm/libpng.so": b"\x7fELF" + b"\0" * 60 + b"libpng version 1.2.46\0",
    }
    comps = AndroidSystemScanner(Files(files))._scan_native_libs()
    assert {c.resolved_version for c in comps if c.name == "libpng.so"} == {"1.6.44", "1.2.46"}


def test_identical_binary_contents_reuse_cbom_and_aibom_scans(monkeypatch):
    payload = b"\x7fELF" + b"\0" * 60 + b"libpng version 1.6.44\0"
    scanner = AndroidSystemScanner(
        Files(
            {
                "/system/lib64/liba.so": payload,
                "/system/lib/libb.so": payload,
            }
        )
    )
    calls = {"cbom": 0, "aibom": 0}

    def scan_cbom(_path, _data):
        calls["cbom"] += 1
        return []

    def scan_aibom(_path, _data):
        calls["aibom"] += 1
        return []

    monkeypatch.setattr(scanner._cbom_scanner, "scan_binary", scan_cbom)
    monkeypatch.setattr(scanner._aibom_scanner, "scan_binary_for_runtimes", scan_aibom)

    scanner._scan_native_libs()

    assert calls == {"cbom": 1, "aibom": 1}


def test_cli_dedup_preserves_distinct_versions_and_merges_locations():
    from firmware_scanner.cli.app import _deduplicate_components

    comps = [
        Component(
            name="libpng.so",
            resolved_version=v,
            versions=[VersionConfidence(version=v, confidence=0.9)],
            properties=[{"name": "firmware:evidence:location", "value": path}],
        )
        for v, path in [
            ("1.6.44", "/system/lib64/libpng.so"),
            ("1.2.46", "/system/lib/arm/libpng.so"),
            ("1.6.44", "/vendor/lib64/libpng.so"),
        ]
    ]
    result = _deduplicate_components(comps)
    assert {c.resolved_version for c in result} == {"1.6.44", "1.2.46"}
    latest = next(c for c in result if c.resolved_version == "1.6.44")
    assert {p["value"] for p in latest.properties} == {
        "/system/lib64/libpng.so",
        "/vendor/lib64/libpng.so",
    }


def test_cli_dedup_merges_unknown_identity_with_build_version():
    from firmware_scanner.cli.app import _deduplicate_components

    comps = [
        Component(
            name="ESP-IDF",
            vendor="Espressif",
            component_type="framework",
            resolved_version="detected (version unknown)",
            versions=[VersionConfidence(version="detected", confidence=0.9)],
        ),
        Component(
            name="ESP-IDF",
            vendor="Espressif",
            component_type="framework",
            resolved_version="v5.4",
            versions=[VersionConfidence(version="v5.4", confidence=0.99)],
        ),
    ]

    result = _deduplicate_components(comps)

    assert len(result) == 1
    assert result[0].resolved_version == "v5.4"
    assert {claim.version for claim in result[0].versions} == {"detected", "v5.4"}


def test_cli_dedup_merges_license_evidence_for_duplicate_components():
    from firmware_scanner.cli.app import _deduplicate_components

    comps = [
        Component(
            name="libdemo.so",
            resolved_version="1.0",
            versions=[VersionConfidence(version="1.0", confidence=0.9)],
            licenses=["Apache-2.0"],
            properties=[
                {
                    "name": "firmware:evidence:location",
                    "value": "/system/lib/libdemo.so",
                }
            ],
        ),
        Component(
            name="libdemo.so",
            resolved_version="1.0",
            versions=[VersionConfidence(version="1.0", confidence=0.9)],
            licenses=["BSD-3-Clause"],
            properties=[
                {
                    "name": "firmware:evidence:location",
                    "value": "/vendor/lib/libdemo.so",
                }
            ],
        ),
    ]

    result = _deduplicate_components(comps)

    assert len(result) == 1
    assert result[0].licenses == ["Apache-2.0", "BSD-3-Clause"]


def test_apk_embedded_native_library_is_scanned():
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            "lib/arm64-v8a/libpng.so", b"\x7fELF" + b"\0" * 60 + b"libpng version 1.6.44\0"
        )
    result = AndroidSystemScanner(Files({}))._analyze_apk_data(
        buffer.getvalue(), "/system/app/App/App.apk"
    )
    lib = next(c for c in result if c.name == "libpng.so")
    assert lib.resolved_version == "1.6.44"
    assert {
        "name": "firmware:evidence:location",
        "value": "/system/app/App/App.apk!/lib/arm64-v8a/libpng.so",
    } in lib.properties


def test_general_elf_path_uses_same_dependency_attribution():
    from firmware_scanner.extraction.smart_analyzer import SmartSectionAnalyzer

    data = b"\x7fELF" + b"\0" * 60 + b"libpng version 1.6.44\0"
    comps = SmartSectionAnalyzer()._analyze_elf("/usr/lib/libvendor.so", data)
    assert any(c.name == "libvendor.so" and not c.resolved_version for c in comps)
    assert any(
        c.name.lower() in ("png", "libpng") and c.resolved_version == "1.6.44" for c in comps
    )


def test_four_part_jpeg_version_does_not_conflict_with_truncated_rule():
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    result = BinaryInventory().extract(
        b"\x7fELF" + b"\0" * 60 + b"libjpeg-turbo version 2.1.5.1\0",
        "libjpeg.so",
        "/system/lib64/libjpeg.so",
    )
    assert result[0].resolved_version == "2.1.5.1"


def test_libcurl_banner_does_not_version_curl_executable():
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    result = BinaryInventory().extract(
        b"\x7fELF" + b"\0" * 60 + b"libcurl/8.12.0-DEV\0", "curl", "/system/bin/curl", "application"
    )
    assert result[0].resolved_version == ""
    assert any(c.name == "libcurl" and c.resolved_version == "8.12.0-DEV" for c in result)


def test_android_coverage_warning_reaches_cli_context():
    from pathlib import Path

    from firmware_scanner.cli.app import _store_android_build_info
    from firmware_scanner.core.context import AnalysisContext

    context = AnalysisContext(firmware_path=Path("system.img"))
    result = AndroidScanResult(warnings=["ELF exceeds 32 MiB scan limit: /system/lib64/large.so"])
    _store_android_build_info(context, result)
    assert result.warnings[0] in context.warnings


def test_android_analysis_cache_stats_reach_cli_context():
    from pathlib import Path

    from firmware_scanner.cli.app import _store_android_build_info
    from firmware_scanner.core.context import AnalysisContext

    context = AnalysisContext(firmware_path=Path("system.img"))
    result = AndroidScanResult(
        analysis_stats={
            "content_cache_hits": 12,
            "content_cache_entries": 40,
        }
    )
    _store_android_build_info(context, result)
    assert context.metadata["android_build_info"]["analysis_stats"] == {
        "content_cache_hits": 12,
        "content_cache_entries": 40,
    }
    assert context.metadata["analysis_stats"] == {
        "content_cache_hits": 12,
        "content_cache_entries": 40,
    }


def test_unique_low_confidence_string_is_not_labelled_exact(monkeypatch):
    from firmware_scanner.extraction.binary_inventory import BinaryInventory
    from firmware_scanner.extraction.models import ExtractionMethod

    inventory = BinaryInventory()
    monkeypatch.setattr(inventory._deep, "extract", lambda _filename, _data: None)
    monkeypatch.setattr(
        inventory._reference,
        "match",
        lambda _data, _filename, **_kwargs: [],
    )
    monkeypatch.setattr(
        inventory._samples,
        "match",
        lambda _data: [
            type(
                "Hit",
                (),
                {
                    "name": "libdemo",
                    "version": "1.2.3",
                    "confidence": 0.6,
                    "method": ExtractionMethod.STRING_PATTERN,
                    "evidence": "weak string evidence",
                },
            )()
        ],
    )
    components = inventory.extract(
        b"\x7fELF" + b"\0" * 60,
        "libdemo.so",
        "/lib/libdemo.so",
    )
    state = next(
        prop["value"]
        for prop in components[0].properties
        if prop["name"] == "firmware:version:resolution-state"
    )
    assert state == "estimated"


@pytest.mark.parametrize(
    "payload,forbidden",
    [
        (b"This is not GNU sed version 4.0\x00", "sed"),
        (b"glibc 2.11.1\x00", "bc"),
    ],
)
def test_legacy_rule_does_not_turn_negation_or_substring_into_component(payload, forbidden):
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    result = BinaryInventory().extract(
        b"\x7fELF" + b"\0" * 60 + payload, "vendor", "/bin/vendor", "application"
    )
    assert not any(c.name.lower() == forbidden and c.resolved_version for c in result)


def test_libcurl_space_banner_is_not_curl_tool_version():
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    result = BinaryInventory().extract(
        b"\x7fELF" + b"\0" * 60 + b"CLIENT libcurl 7.24.0\0", "curl", "/bin/curl", "application"
    )
    assert result[0].resolved_version == ""


def test_product_inventory_uses_integer_version_api_without_versioning_host(tmp_path):
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    cc = shutil.which("cc")
    if not cc:
        pytest.skip("C compiler needed")
    source = tmp_path / "api.c"
    source.write_text("unsigned XXH_versionNumber(void) { return 605; }")
    output = tmp_path / "host.so"
    subprocess.run([cc, "-shared", "-fPIC", "-O2", "-o", str(output), str(source)], check=True)
    result = BinaryInventory().extract(output.read_bytes(), "libhost.so", "/lib/libhost.so")
    assert result[0].resolved_version == ""
    assert any(c.name == "xxHash" and c.resolved_version == "0.6.5" for c in result)


def test_product_inventory_uses_source_backed_whole_file_index(tmp_path):
    import hashlib
    import json

    from firmware_scanner.extraction.binary_inventory import BinaryInventory
    from firmware_scanner.extraction.binary_samples import BinarySampleMatcher

    cc = shutil.which("cc")
    if not cc:
        pytest.skip("C compiler needed")
    source = tmp_path / "opaque.c"
    source.write_text("unsigned opaque_value(void) { return 17; }")
    output = tmp_path / "libopaque.so"
    subprocess.run([cc, "-shared", "-fPIC", "-O2", "-o", str(output), str(source)], check=True)
    data = output.read_bytes()
    row = {
        "name": "libopaque.so",
        "version": "7.8.9",
        "sha256": hashlib.sha256(data).hexdigest(),
        "source": "https://repo.maven.apache.org/maven2/",
        "upstream_source": "https://www.kernel.org/",
        "artifact_path": "jni/x86_64/libopaque.so",
        "architecture": "x86_64",
        "version_kind": "release",
    }
    index = tmp_path / "samples.json"
    index.write_text(json.dumps({"schema_version": 1, "samples": [row]}))
    inventory = BinaryInventory()
    inventory._samples = BinarySampleMatcher(index)
    result = inventory.extract(data, output.name, "/lib/libopaque.so")
    assert len(result) == 1
    assert result[0].resolved_version == "7.8.9"
    assert any("whole_file_sha256" in v.evidence for v in result[0].versions)


def test_boringssl_compatibility_string_is_not_an_openssl_release():
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    raw = (
        b"\x7fELF" + bytes(60) + b"android.openssl.version=OpenSSL 1.1.1 (compatible; BoringSSL)\0"
    )
    components = BinaryInventory().extract(raw, "libopenjdk.so", "/apex/lib/libopenjdk.so")
    assert any(c.name == "BoringSSL" and not c.resolved_version for c in components)
    assert not any(c.name.lower() == "openssl" for c in components)


def test_real_openssl_release_survives_boringssl_compatibility_text():
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    raw = (
        b"\x7fELF"
        + bytes(60)
        + b"OpenSSL 1.1.1 (compatible; BoringSSL)\0"
        + b"OpenSSL 1.1.1w  11 Sep 2023\0"
    )
    components = BinaryInventory().extract(raw, "libvendor.so", "/lib/libvendor.so")
    assert any(c.name == "OpenSSL" and c.resolved_version == "1.1.1w" for c in components)
    assert not any(c.name == "OpenSSL" and c.resolved_version == "1.1.1" for c in components)
