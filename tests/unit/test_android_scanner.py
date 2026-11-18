"""Unit tests for Android system scanner enhancements."""

import io
import zipfile
from pathlib import Path
from firmware_scanner.extraction.models import Component
from firmware_scanner.android.system_scanner import AndroidSystemScanner, AndroidScanResult
from firmware_scanner.android.build_prop import AndroidBuildInfo
from firmware_scanner.sbom.cyclonedx import CycloneDXGenerator
from firmware_scanner.sbom.spdx3 import SPDX3Generator


class MockFilesystem:
    def __init__(self, files: dict[str, bytes]):
        self._files = files

    def is_valid(self) -> bool:
        return True

    def exists(self, path: str) -> bool:
        return path in self._files or any(k.startswith(path.rstrip('/') + '/') for k in self._files)

    def read_file(self, path: str, max_size: int = 16 * 1024 * 1024) -> bytes | None:
        data = self._files.get(path)
        if data is not None:
            return data[:max_size]
        return None

    def list_directory(self, path: str):
        class Entry:
            def __init__(self, name: str, is_file: bool = True, is_dir: bool = False):
                self.name = name
                self.is_file = is_file
                self.is_dir = is_dir

        prefix = path.rstrip('/') + '/'
        sub_items = set()
        for k in self._files.keys():
            if k.startswith(prefix):
                rest = k[len(prefix):]
                parts = rest.split('/')
                if len(parts) == 1:
                    sub_items.add((parts[0], True, False))
                else:
                    sub_items.add((parts[0], False, True))
        return [Entry(name, is_f, is_d) for name, is_f, is_d in sorted(sub_items)]


def _create_mock_apk_with_maven() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x00" * 20)  # Dummy
        pom_content = "groupId=com.google.guava\nartifactId=listenablefuture\nversion=1.0\n"
        zf.writestr("META-INF/maven/com.google.guava/listenablefuture/pom.properties", pom_content)
    return buf.getvalue()


def test_embedded_maven_extraction():
    """Verify that embedded pom.properties in APKs are extracted as independent libraries."""
    apk_data = _create_mock_apk_with_maven()
    fs = MockFilesystem({
        "/system/app/TestApp/TestApp.apk": apk_data,
    })
    scanner = AndroidSystemScanner(fs)
    comps = scanner._scan_apks()

    # Should contain the app component AND the embedded maven library
    maven_comps = [c for c in comps if c.name == "com.google.guava:listenablefuture"]
    assert len(maven_comps) == 1
    assert maven_comps[0].resolved_version == "1.0"
    assert maven_comps[0].purl == "pkg:maven/com.google.guava/listenablefuture@1.0"


def test_known_bin_patterns():
    """Verify regex extraction of toybox, curl, e2fsck versions."""
    scanner = AndroidSystemScanner(MockFilesystem({}))

    toybox_data = b"taskset\x00ulimit\x00which\x000.8.12-android\x00bad -l"
    ver_info = scanner._extract_known_bin_version("toybox", toybox_data)
    assert ver_info is not None
    assert ver_info[0] == "0.8.12"

    curl_data = b"prefix curl 8.12.0 (x86_64-pc-linux-gnu)"
    ver_info2 = scanner._extract_known_bin_version("curl", curl_data)
    assert ver_info2 is not None
    assert ver_info2[0] == "8.12.0"

    e2fsck_data = b"version of e2fsck!\x001.46.6\x00%12u non-contiguous"
    ver_info3 = scanner._extract_known_bin_version("e2fsck", e2fsck_data)
    assert ver_info3 is not None
    assert ver_info3[0] == "1.46.6"


def test_no_fake_16_fallback():
    """Android context must never invent a component's release version."""
    scanner = AndroidSystemScanner(MockFilesystem({}))
    result = AndroidScanResult(
        build_info=AndroidBuildInfo(android_version="16", security_patch="2025-08-05", build_id="BP2A.250805.005"),
        components=[
            Component(name="Android", component_type="operating-system", resolved_version=""),
            Component(name="libcrypto.so", component_type="library", resolved_version=""),
            Component(name="libbinder.so", component_type="library", resolved_version="", description="AOSP native library in /system at /system/lib64/libbinder.so"),
            Component(name="curl", component_type="application", resolved_version="8.12.0"),
        ]
    )
    scanner._apply_os_version_fallback(result)

    # OS component gets 16
    assert result.components[0].resolved_version == "16"

    # libcrypto.so (third-party blacklist) should remain unversioned (empty string), NOT "16"
    assert result.components[1].resolved_version == ""
    assert {"name": "firmware:android:release", "value": "16"} in result.components[1].properties

    assert result.components[2].resolved_version == ""
    assert {"name": "firmware:android:security_patch", "value": "2025-08-05"} in result.components[2].properties

    # curl keeps its real version
    assert result.components[3].resolved_version == "8.12.0"


def test_sbom_includes_unversioned_components():
    """Verify CycloneDX 1.6 and SPDX 3.0.1 include unversioned components."""
    comps = [
        Component(name="curl", resolved_version="8.12.0", component_type="application"),
        Component(name="libbinder.so", resolved_version="", component_type="library", description="AOSP platform lib"),
    ]

    # CycloneDX 1.6
    cdx_gen = CycloneDXGenerator()
    cdx = cdx_gen.generate(comps, firmware_path="fw.img", firmware_hash_sha256="abc")
    assert len(cdx["components"]) == 2
    assert cdx["components"][0]["name"] == "curl"
    assert cdx["components"][0]["version"] == "8.12.0"
    assert cdx["components"][1]["name"] == "libbinder.so"
    assert "version" not in cdx["components"][1]  # unversioned

    # SPDX 3.0.1
    spdx_gen = SPDX3Generator()
    spdx = spdx_gen.generate(comps, firmware_path="fw.img", firmware_hash_sha256="abc")
    graph = spdx["@graph"]
    packages = [e for e in graph if e.get("type") == "software_Package"]
    # 1 root firmware + 2 components = 3
    assert len(packages) == 3
    binder_pkg = next(p for p in packages if p.get("name") == "libbinder.so")
    assert "software_packageVersion" not in binder_pkg
