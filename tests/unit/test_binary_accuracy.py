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
        return self.files.get(path, b'')[:max_size] or None

    def exists(self, path):
        return path in self.files or any(k.startswith(path.rstrip('/') + '/') for k in self.files)

    def list_directory(self, path):
        from types import SimpleNamespace
        prefix = path.rstrip('/') + '/'
        names = {k[len(prefix):].split('/')[0] for k in self.files if k.startswith(prefix)}
        return [SimpleNamespace(name=n, is_file=prefix+n in self.files,
                                is_dir=prefix+n not in self.files) for n in sorted(names)]

    def file_size(self, path):
        return len(self.files.get(path, b''))


def test_platform_baseline_is_not_a_library_release():
    comp = Component(name='libbinder.so', description='AOSP native library at /system/lib64/libbinder.so')
    result = AndroidScanResult(build_info=AndroidBuildInfo(android_version='16'), components=[comp])
    AndroidSystemScanner(Files({}))._apply_os_version_fallback(result)
    assert comp.resolved_version == ''
    assert any(p['name'] == 'firmware:android:release' and p['value'] == '16' for p in comp.properties)


@pytest.mark.parametrize('filename,payload', [
    ('libjpeg.so', b'1.02\x00JFIF'),
    ('libbpf.so', b'\x001.5.7\x00Operation made no progress'),
    ('libssl.so', b'\x00TLS_method\x00'),
    ('libwebrtc_audio_preprocessing.so', b'VerifyVersion\x00TLS_method\x00'),
])
def test_protocol_dependency_and_random_integer_are_not_host_versions(filename, payload):
    result = ELFDeepExtractor().extract(filename, b'\x7fELF' + b'\x00' * 60 + payload)
    assert result is None or not result.version


@pytest.mark.parametrize('filename,banner,want', [
    ('curl', b'curl 8.12.0-DEV (aarch64-linux-android)', '8.12.0-DEV'),
    ('libxml2.so', b'21400-GITv2.13.0-1904-g4d38e2fe\x00', '21400-GITv2.13.0-1904-g4d38e2fe'),
    ('hostapd', b'hostapd v%s\x002.11-devel\x00', '2.11-devel'),
])
def test_development_versions_retain_observed_suffix(filename, banner, want):
    result = ELFDeepExtractor().extract(filename, b'\x7fELF' + b'\x00' * 60 + banner)
    assert result is not None
    assert result.version == want


def test_banner_beats_soname_abi(tmp_path):
    cc = shutil.which('cc')
    if not cc:
        pytest.skip('C compiler needed for real ELF fixture')
    src = tmp_path / 'png.c'
    src.write_text('const char *png_banner = "libpng version 1.6.44";')
    target = tmp_path / 'libpng.so'
    subprocess.run([cc, '-shared', '-fPIC', '-Wl,-soname,libpng.so.1', '-o', str(target), str(src)], check=True)
    result = ELFDeepExtractor().extract('libpng.so', target.read_bytes())
    assert result.version == '1.6.44'


def test_soname_alone_does_not_supply_release(tmp_path):
    cc = shutil.which('cc')
    if not cc:
        pytest.skip('C compiler needed for real ELF fixture')
    src = tmp_path / 'unknown.c'
    src.write_text('int example(void) { return 42; }')
    target = tmp_path / 'libunknown.so'
    subprocess.run([cc, '-shared', '-fPIC', '-Wl,-soname,libunknown.so.7', '-o', str(target), str(src)], check=True)
    result = ELFDeepExtractor().extract('libunknown.so', target.read_bytes())
    assert result is None or not result.version


def test_imports_do_not_assign_openssl_version_to_client():
    data = b'\x7fELF' + b'\x00' * 60 + b'\x00TLS_method\x00'
    scanner = AndroidSystemScanner(Files({'/system/bin/client': data}))
    comps = scanner._scan_executables({'client': '3.0.0'})
    assert len(comps) == 1
    assert comps[0].name == 'client'
    assert comps[0].resolved_version == ''


def test_native_host_keeps_dependency_as_separate_component():
    data = b'\x7fELF' + b'\x00' * 60 + b'libpng version 1.6.44\x00'
    scanner = AndroidSystemScanner(Files({'/system/lib64/libvendor.so': data}))
    comps = scanner._scan_native_libs()
    host = next(c for c in comps if c.name == 'libvendor.so')
    dependency = next(c for c in comps if c.name.lower() in ('libpng', 'png'))
    assert host.resolved_version == ''
    assert dependency.resolved_version == '1.6.44'
    assert any(p['name'] == 'firmware:evidence:location' and p['value'] == '/system/lib64/libvendor.so' for p in dependency.properties)


def test_native_abi_paths_keep_both_versions():
    files = {'/system/lib64/libpng.so': b'\x7fELF'+b'\0'*60+b'libpng version 1.6.44\0',
             '/system/lib/arm/libpng.so': b'\x7fELF'+b'\0'*60+b'libpng version 1.2.46\0'}
    comps = AndroidSystemScanner(Files(files))._scan_native_libs()
    assert {c.resolved_version for c in comps if c.name == 'libpng.so'} == {'1.6.44', '1.2.46'}


def test_cli_dedup_preserves_distinct_versions_and_merges_locations():
    from firmware_scanner.cli.app import _deduplicate_components
    comps = [Component(name='libpng.so', resolved_version=v, versions=[
        VersionConfidence(version=v, confidence=.9)], properties=[{'name': 'firmware:evidence:location', 'value': path}])
             for v, path in [('1.6.44', '/system/lib64/libpng.so'),
                             ('1.2.46', '/system/lib/arm/libpng.so'),
                             ('1.6.44', '/vendor/lib64/libpng.so')]]
    result = _deduplicate_components(comps)
    assert {c.resolved_version for c in result} == {'1.6.44', '1.2.46'}
    latest = next(c for c in result if c.resolved_version == '1.6.44')
    assert {p['value'] for p in latest.properties} == {'/system/lib64/libpng.so', '/vendor/lib64/libpng.so'}


def test_apk_embedded_native_library_is_scanned():
    import io
    import zipfile
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('lib/arm64-v8a/libpng.so', b'\x7fELF'+b'\0'*60+b'libpng version 1.6.44\0')
    result = AndroidSystemScanner(Files({}))._analyze_apk_data(buffer.getvalue(), '/system/app/App/App.apk')
    lib = next(c for c in result if c.name == 'libpng.so')
    assert lib.resolved_version == '1.6.44'
    assert {'name': 'firmware:evidence:location', 'value': '/system/app/App/App.apk!/lib/arm64-v8a/libpng.so'} in lib.properties


def test_general_elf_path_uses_same_dependency_attribution():
    from firmware_scanner.extraction.smart_analyzer import SmartSectionAnalyzer
    data = b'\x7fELF'+b'\0'*60+b'libpng version 1.6.44\0'
    comps = SmartSectionAnalyzer()._analyze_elf('/usr/lib/libvendor.so', data)
    assert any(c.name == 'libvendor.so' and not c.resolved_version for c in comps)
    assert any(c.name.lower() in ('png', 'libpng') and c.resolved_version == '1.6.44' for c in comps)


def test_four_part_jpeg_version_does_not_conflict_with_truncated_rule():
    from firmware_scanner.extraction.binary_inventory import BinaryInventory
    result = BinaryInventory().extract(b'\x7fELF'+b'\0'*60+b'libjpeg-turbo version 2.1.5.1\0', 'libjpeg.so', '/system/lib64/libjpeg.so')
    assert result[0].resolved_version == '2.1.5.1'


def test_libcurl_banner_does_not_version_curl_executable():
    from firmware_scanner.extraction.binary_inventory import BinaryInventory
    result = BinaryInventory().extract(b'\x7fELF'+b'\0'*60+b'libcurl/8.12.0-DEV\0', 'curl', '/system/bin/curl', 'application')
    assert result[0].resolved_version == ''
    assert any(c.name == 'libcurl' and c.resolved_version == '8.12.0-DEV' for c in result)


def test_android_coverage_warning_reaches_cli_context():
    from pathlib import Path
    from firmware_scanner.cli.app import _store_android_build_info
    from firmware_scanner.core.context import AnalysisContext
    context = AnalysisContext(firmware_path=Path('system.img'))
    result = AndroidScanResult(warnings=['ELF exceeds 32 MiB scan limit: /system/lib64/large.so'])
    _store_android_build_info(context, result)
    assert result.warnings[0] in context.warnings


@pytest.mark.parametrize('payload,forbidden', [
    (b'This is not GNU sed version 4.0\x00', 'sed'),
    (b'glibc 2.11.1\x00', 'bc'),
])
def test_legacy_rule_does_not_turn_negation_or_substring_into_component(payload, forbidden):
    from firmware_scanner.extraction.binary_inventory import BinaryInventory
    result = BinaryInventory().extract(b'\x7fELF'+b'\0'*60+payload, 'vendor', '/bin/vendor', 'application')
    assert not any(c.name.lower() == forbidden and c.resolved_version for c in result)


def test_libcurl_space_banner_is_not_curl_tool_version():
    from firmware_scanner.extraction.binary_inventory import BinaryInventory
    result = BinaryInventory().extract(b'\x7fELF'+b'\0'*60+b'CLIENT libcurl 7.24.0\0', 'curl', '/bin/curl', 'application')
    assert result[0].resolved_version == ''
