import shutil
import subprocess

import pytest


def compile_elf(tmp_path, body):
    cc = shutil.which('cc')
    if not cc:
        pytest.skip('C compiler required')
    source = tmp_path / 'vendor.c'
    target = tmp_path / 'vendor.so'
    source.write_text(body)
    subprocess.run([cc, '-shared', '-fPIC', '-O2', str(source), '-o', str(target)], check=True)
    return target.read_bytes()


def test_powervr_driver_build_is_separate_from_egl_api(tmp_path):
    from firmware_scanner.extraction.vendor_version import extract_vendor_versions
    data = compile_elf(tmp_path, '''
      const char *vendor = "Imagination Technologies";
      const char *IMGeglQueryString(void) { return "1.4 build 1.12@3052601"; }
      void IMGeglGetProcAddress(void) {}
    ''')
    matches = extract_vendor_versions(data, 'libIMGegl.so')
    assert [(m.name, m.version) for m in matches] == [('libIMGegl.so', '1.12@3052601')]


@pytest.mark.parametrize('filename,body', [
    ('libIMGegl.so', 'const char *v="Imagination Technologies 1.4 build 1.12@3052601";'),
    ('libother.so', 'const char *v="Imagination Technologies 1.4 build 1.12@3052601";'),
    ('libIMGegl.so', 'const char *v="Imagination Technologies 1.4"; void IMGeglQueryString(void){} void IMGeglGetProcAddress(void){}'),
])
def test_vendor_identity_filename_and_build_are_all_required(tmp_path, filename, body):
    from firmware_scanner.extraction.vendor_version import extract_vendor_versions
    assert extract_vendor_versions(compile_elf(tmp_path, body), filename) == []


def test_widevine_requires_two_agreeing_returned_values(tmp_path):
    from firmware_scanner.extraction.vendor_version import extract_vendor_versions
    data = compile_elf(tmp_path, '''
      const char *WVGetVersion(void) { return "Version 4.5.0.10113 AES 601_AndroidOS_K  "; }
      const char *WVGetBuild(void) { return "4.5.0.10113"; }
    ''')
    matches = extract_vendor_versions(data, 'libWVStreamControlAPI_L3.so')
    assert [(m.name, m.version) for m in matches] == [('libWVStreamControlAPI_L3.so', '4.5.0.10113')]
    assert 'AES 601_AndroidOS_K' in matches[0].evidence


@pytest.mark.parametrize('build_body', [
    'return "4.5.0.10114";',
    'extern const char *external_build; return external_build;',
    'extern int choose; return choose ? "4.5.0.10113" : "4.5.0.10114";',
])
def test_widevine_conflicting_or_dynamic_build_is_refused(tmp_path, build_body):
    from firmware_scanner.extraction.vendor_version import extract_vendor_versions
    data = compile_elf(tmp_path, '''
      const char *WVGetVersion(void) { return "Version 4.5.0.10113 AES 601_AndroidOS_K"; }
      const char *WVGetBuild(void) { ''' + build_body + ' }')
    assert extract_vendor_versions(data, 'libWVStreamControlAPI_L3.so') == []
