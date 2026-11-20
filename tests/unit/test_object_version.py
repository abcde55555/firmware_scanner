"""Defined release objects need identity, bounded storage and valid own values."""

import shutil
import subprocess

import pytest


def _elf(tmp_path, source, flags=()):
    cc = shutil.which("cc")
    if not cc:
        pytest.skip("C compiler needed for static object controls")
    src, out = tmp_path / "objects.c", tmp_path / "objects.so"
    src.write_text(source)
    subprocess.run(
        [cc, "-shared", "-fPIC", "-O2", *flags, str(src), "-o", str(out)],
        capture_output=True,
        check=True,
    )
    return out.read_bytes()


_IDENTITY = "int atcab_version(char *out) { return 0; } int atcab_init(void) { return 0; }"

_SQLITE_IDENTITY = """
extern const char sqlite3_version[];
const char *sqlite3_libversion(void) { return sqlite3_version; }
int sqlite3_libversion_number(void) { return 3044005; }
const char *sqlite3_sourceid(void) { return "source-identifier"; }
"""


@pytest.mark.parametrize("flags", [(), ("-m32", "-nostdlib")], ids=["elf64", "elf32"])
def test_sqlite_defined_readonly_object_declares_library_version(tmp_path, flags):
    import json

    from firmware_scanner.extraction.object_version import extract_object_versions

    data = _elf(tmp_path, _SQLITE_IDENTITY + 'const char sqlite3_version[] = "3.44.5";', flags)
    hits = extract_object_versions(data)
    assert [(hit.name, hit.version) for hit in hits] == [("SQLite", "3.44.5")]
    evidence = json.loads(hits[0].evidence)
    assert evidence["symbol"] == "sqlite3_version"
    assert evidence["source"] == "https://www.sqlite.org/c3ref/libversion.html"
    assert data[evidence["file_offset"] : evidence["file_offset"] + evidence["size"]] == b"3.44.5\0"


@pytest.mark.parametrize("version", ["3.44.5-vendor1", "3.8.11.1"])
def test_sqlite_object_preserves_complete_declared_identifier(tmp_path, version):
    from firmware_scanner.extraction.object_version import extract_object_versions

    data = _elf(tmp_path, _SQLITE_IDENTITY + f'const char sqlite3_version[] = "{version}";')
    assert [hit.version for hit in extract_object_versions(data)] == [version]


@pytest.mark.parametrize(
    "source",
    [
        "extern const char sqlite3_version[]; const char *use(void) { return sqlite3_version; }",
        'const char sqlite3_version[] = "3.44.5";',
        _SQLITE_IDENTITY.replace("int sqlite3_libversion_number(void) { return 3044005; }", "")
        + 'const char sqlite3_version[] = "3.44.5";',
        _SQLITE_IDENTITY.replace(
            "extern const char sqlite3_version[];", "extern char sqlite3_version[];"
        )
        + 'char sqlite3_version[] = "3.44.5";',
        _SQLITE_IDENTITY + 'const char sqlite3_version[6] = "3.44.5";',
        _SQLITE_IDENTITY + 'const char sqlite3_version[16] = "3.44.5";',
        _SQLITE_IDENTITY + 'const char sqlite3_version[] = "SQLite 3.44.5";',
        _SQLITE_IDENTITY + 'const char sqlite3_version[] = "3.44";',
        (
            'const char *sqlite3_version = "3.44.5"; '
            "const char *sqlite3_libversion(void) { return sqlite3_version; } "
            "int sqlite3_libversion_number(void) { return 3044005; } "
            'const char *sqlite3_sourceid(void) { return "source"; }'
        ),
    ],
)
def test_sqlite_imports_mutable_objects_and_incomplete_identity_are_refused(tmp_path, source):
    from firmware_scanner.extraction.object_version import extract_object_versions

    assert extract_object_versions(_elf(tmp_path, source)) == []


def test_sqlite_object_is_attributed_to_its_library_not_vendor_container(tmp_path):
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    data = _elf(tmp_path, _SQLITE_IDENTITY + 'const char sqlite3_version[] = "3.44.5";')
    inventory = BinaryInventory()
    vendor = inventory.extract(data, "libvendor.so", "/lib/libvendor.so")
    assert vendor[0].resolved_version == ""
    assert [(c.name, c.resolved_version) for c in vendor[1:]] == [("SQLite", "3.44.5")]
    own = inventory.extract(data, "libsqlite.so", "/lib/libsqlite.so")
    assert len(own) == 1
    assert own[0].resolved_version == "3.44.5"


@pytest.mark.parametrize("flags", [(), ("-m32", "-nostdlib")], ids=["elf64", "elf32"])
def test_gmp_pointer_release_object_uses_the_documented_symbol(tmp_path, flags):
    import json

    from firmware_scanner.extraction.object_version import extract_object_versions

    data = _elf(tmp_path, 'const char *__gmp_version = "6.3.0";', flags)
    hits = extract_object_versions(data)
    assert [(hit.name, hit.version) for hit in hits] == [("GMP", "6.3.0")]
    evidence = json.loads(hits[0].evidence)
    assert evidence["symbol"] == "__gmp_version"
    assert evidence["value"] == "6.3.0"


def test_flac_release_objects_cross_check_the_documented_version(tmp_path):
    import json

    from firmware_scanner.extraction.object_version import extract_object_versions

    data = _elf(
        tmp_path,
        'const char * const FLAC__VERSION_STRING = "1.2.1";'
        'const char * const FLAC__VENDOR_STRING = "reference libFLAC 1.2.1 20070917";',
    )
    hits = extract_object_versions(data)

    assert [(hit.name, hit.version) for hit in hits] == [("libFLAC", "1.2.1")]
    evidence = json.loads(hits[0].evidence)
    assert evidence["symbol"] == "FLAC__VERSION_STRING"
    assert evidence["vendor_symbol"] == "FLAC__VENDOR_STRING"
    assert evidence["value"] == "1.2.1"


def test_flac_mutable_version_pointer_is_not_release_proof(tmp_path):
    from firmware_scanner.extraction.object_version import extract_object_versions

    data = _elf(
        tmp_path,
        'char *FLAC__VERSION_STRING = "1.2.1";'
        'const char *FLAC__VENDOR_STRING = "reference libFLAC 1.2.1 20070917";',
    )

    assert extract_object_versions(data) == []


def test_openssl_md5_version_object_identifies_the_embedded_release(tmp_path):
    import json

    from firmware_scanner.extraction.object_version import extract_object_versions

    data = _elf(
        tmp_path,
        'const char MD5_version[] = "MD5 part of OpenSSL 0.9.8k 25 Mar 2009";',
    )
    hits = extract_object_versions(data)

    assert [(hit.name, hit.version) for hit in hits] == [("OpenSSL", "0.9.8k")]
    evidence = json.loads(hits[0].evidence)
    assert evidence["symbol"] == "MD5_version"
    assert evidence["value"] == "MD5 part of OpenSSL 0.9.8k 25 Mar 2009"


def test_openssl_mutable_md5_version_array_is_not_release_proof(tmp_path):
    from firmware_scanner.extraction.object_version import extract_object_versions

    data = _elf(
        tmp_path,
        'char MD5_version[] = "MD5 part of OpenSSL 0.9.8k 25 Mar 2009";',
    )

    assert extract_object_versions(data) == []


@pytest.mark.parametrize("value", ["GMP 6.3.0", "6.3.0 trailing", "dev"])
def test_gmp_release_requires_a_bare_numeric_release(tmp_path, value):
    from firmware_scanner.extraction.object_version import extract_object_versions

    assert extract_object_versions(_elf(tmp_path, f'const char *__gmp_version = "{value}";')) == []


def test_libunistring_packed_version_object_is_decoded(tmp_path):
    from firmware_scanner.extraction.object_version import extract_object_versions

    data = _elf(
        tmp_path,
        "const unsigned int _libunistring_version = 0x010402u;",
    )
    assert [(hit.name, hit.version) for hit in extract_object_versions(data)] == [
        ("libunistring", "1.4.2")
    ]


def test_gdk_pixbuf_documented_integer_triplet_is_combined(tmp_path):
    from firmware_scanner.extraction.object_version import extract_object_versions

    data = _elf(
        tmp_path,
        "const unsigned int gdk_pixbuf_major_version = 2;"
        "const unsigned int gdk_pixbuf_minor_version = 44;"
        "const unsigned int gdk_pixbuf_micro_version = 5;",
    )
    assert [(hit.name, hit.version) for hit in extract_object_versions(data)] == [
        ("GdkPixbuf", "2.44.5")
    ]


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


def test_glib_exported_integer_version_triplet(tmp_path):
    from firmware_scanner.extraction.object_version import extract_object_versions

    data = _elf(
        tmp_path,
        "const unsigned int glib_major_version = 2;\n"
        "const unsigned int glib_minor_version = 88;\n"
        "const unsigned int glib_micro_version = 3;\n",
    )

    assert [(hit.name, hit.version) for hit in extract_object_versions(data)] == [
        ("GLib", "2.88.3")
    ]


def test_fribidi_version_info_pointer_and_unicode_object_agree(tmp_path):
    from firmware_scanner.extraction.object_version import extract_object_versions

    data = _elf(
        tmp_path,
        'const char *fribidi_version_info = "(GNU FriBidi) 1.0.16\\n'
        'interface version 4,\\nUnicode Character Database version 16.0.0\\n";\n'
        'const char *fribidi_unicode_version = "16.0.0";\n',
    )

    assert [(hit.name, hit.version) for hit in extract_object_versions(data)] == [
        ("FriBidi", "1.0.16")
    ]


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
