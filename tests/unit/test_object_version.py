"""Defined release objects need identity, bounded storage and valid own values."""

import shutil
import subprocess

import pytest


def _elf(tmp_path, source):
    cc = shutil.which("cc")
    if not cc:
        pytest.skip("C compiler needed for static object controls")
    src, out = tmp_path / "objects.c", tmp_path / "objects.so"
    src.write_text(source)
    subprocess.run(
        [cc, "-shared", "-fPIC", "-O2", str(src), "-o", str(out)], capture_output=True, check=True
    )
    return out.read_bytes()


_IDENTITY = "int atcab_version(char *out) { return 0; } int atcab_init(void) { return 0; }"


def test_cryptoauth_declared_release_date_is_its_own_version(tmp_path):
    from firmware_scanner.extraction.object_version import extract_object_versions

    data = _elf(tmp_path, _IDENTITY + 'char atca_version[] = "20160108";')
    hits = extract_object_versions(data)
    assert [(hit.name, hit.version) for hit in hits] == [("CryptoAuthLib", "20160108")]


@pytest.mark.parametrize("version", ["20160230", "20160108 trailing", "1.2.3", "20160108%"])
def test_unrecognized_or_invalid_cryptoauth_release_objects_are_refused(tmp_path, version):
    from firmware_scanner.extraction.object_version import extract_object_versions

    assert (
        extract_object_versions(_elf(tmp_path, _IDENTITY + f'char atca_version[] = "{version}";'))
        == []
    )


@pytest.mark.parametrize(
    "source",
    [
        "extern char atca_version[]; char *version_pointer = atca_version;",
        'char atca_version[] = "20160108";',
        _IDENTITY + 'char *atca_version = "20160108";',
        _IDENTITY + 'char atca_version[8] = "20160108";',
    ],
)
def test_imports_unrelated_symbols_pointers_and_nonterminated_arrays_are_refused(tmp_path, source):
    from firmware_scanner.extraction.object_version import extract_object_versions

    assert extract_object_versions(_elf(tmp_path, source)) == []


def test_cryptoauth_version_does_not_version_its_containing_vendor_library(tmp_path):
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    data = _elf(tmp_path, _IDENTITY + 'char atca_version[] = "20160108";')
    components = BinaryInventory().extract(data, "libatsha204.so", "/lib/libatsha204.so")
    assert components[0].resolved_version == ""
    assert [(c.name, c.resolved_version) for c in components[1:]] == [("CryptoAuthLib", "20160108")]


def test_defined_cryptoauth_api_identity_survives_without_a_release_object(tmp_path):
    from firmware_scanner.extraction.binary_reference import BinaryReferenceMatcher

    data = _elf(tmp_path, _IDENTITY + "int atcab_release(void) { return 0; }")
    hits = BinaryReferenceMatcher().match(data, "libvendor.so")
    assert [(hit.name, hit.version) for hit in hits] == [("CryptoAuthLib", "")]
    imports = _elf(
        tmp_path,
        "extern int atcab_init(void); extern int atcab_version(char *); "
        "extern int atcab_release(void); "
        "int call(void) {return atcab_init()+atcab_version(0)+atcab_release();}",
    )
    assert BinaryReferenceMatcher().match(imports, "libatsha204.so") == []
