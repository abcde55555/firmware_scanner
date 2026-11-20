"""Public version APIs require their documented symbols and release structure."""

import shutil
import subprocess

import pytest

from firmware_scanner.extraction.binary_inventory import BinaryInventory
from firmware_scanner.extraction.public_version import (
    _libevent_adjacent_version,
    extract_public_versions,
)


def _compile(
    tmp_path,
    source: str,
    name: str = "fixture.so",
    flags: tuple[str, ...] = (),
) -> bytes:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is required for public-version fixtures")
    c_path = tmp_path / "fixture.c"
    output = tmp_path / name
    c_path.write_text(source)
    subprocess.run(
        [compiler, "-shared", "-fPIC", "-O2", *flags, str(c_path), "-o", str(output)],
        check=True,
        capture_output=True,
    )
    return output.read_bytes()


@pytest.mark.parametrize(
    ("symbols", "banner", "expected_name", "expected_version"),
    [
        (
            ("assuan_check_version", "assuan_pipe_connect"),
            "This is Libassuan 3.0.2 - The GnuPG IPC Library",
            "libassuan",
            "3.0.2",
        ),
        (
            ("gpgme_check_version_internal", "gpgme_new"),
            "This is GPGME 2.1.2 - The GnuPG Made Easy library",
            "GPGME",
            "2.1.2",
        ),
        (
            ("ksba_check_version", "ksba_reader_new"),
            "This is Libksba 1.6.7 - An X.509 and CMS Library",
            "libksba",
            "1.6.7",
        ),
        (
            ("npth_get_version", "npth_init"),
            "This is nPth 1.8 - The New GNU Portable Threads Library",
            "nPth",
            "1.8",
        ),
        (
            ("cap_get_proc", "cap_to_text"),
            "shared library version: libcap-2.75",
            "libcap",
            "2.75",
        ),
        (
            ("dm_get_library_version", "dm_task_create"),
            "1.02.205 (2025-02-27)",
            "libdevmapper",
            "1.02.205",
        ),
    ],
)
def test_documented_banner_requires_its_library_apis(
    tmp_path,
    symbols,
    banner,
    expected_name,
    expected_version,
):
    definitions = "\n".join(f"void {symbol}(void) {{}}" for symbol in symbols)
    data = _compile(
        tmp_path,
        definitions + f'\nconst char *get_banner(void) {{ return "{banner}"; }}\n',
    )

    assert [(hit.name, hit.version) for hit in extract_public_versions(data)] == [
        (expected_name, expected_version)
    ]


def test_banner_without_all_required_apis_is_not_a_match(tmp_path):
    data = _compile(
        tmp_path,
        "void assuan_check_version(void) {}\n"
        "const char *get_banner(void) {\n"
        '  return "This is Libassuan 3.0.2 - The GnuPG IPC Library";\n'
        "}\n",
    )
    assert extract_public_versions(data) == []


def test_required_apis_without_release_banner_are_not_a_match(tmp_path):
    data = _compile(
        tmp_path,
        "void assuan_check_version(void) {}\nvoid assuan_pipe_connect(void) {}\n",
    )
    assert extract_public_versions(data) == []


def test_libevent_adjacent_banner_requires_identity_api_and_unique_release():
    data = (
        b"libevent using: %s\n\0"
        b"1.4.13-stable\0"
        b"event_base_new\0"
    )

    match = _libevent_adjacent_version(data)

    assert match is not None
    assert (match.name, match.version) == ("libevent", "1.4.13-stable")
    assert "event_base_new" in match.evidence
    assert _libevent_adjacent_version(
        b"libevent using: %s\n\0" b"1.4.13-stable\0"
    ) is None


def test_lua_numeric_api_and_official_banner_must_agree(tmp_path):
    data = _compile(
        tmp_path,
        'const char lua_banner[] = "$LuaVersion: Lua 5.4.8  Copyright";\n'
        "double lua_version(void *state) { (void)state; return 504.0; }\n"
        "void luaL_checkversion_(void) {}\n",
    )

    assert [(hit.name, hit.version) for hit in extract_public_versions(data)] == [
        ("Lua", "5.4.8")
    ]

    incompatible = _compile(
        tmp_path,
        'const char lua_banner[] = "$LuaVersion: Lua 5.4.8  Copyright";\n'
        "double lua_version(void *state) { (void)state; return 503.0; }\n"
        "void luaL_checkversion_(void) {}\n",
        "lua-incompatible.so",
    )
    assert extract_public_versions(incompatible) == []


def test_conflicting_release_banners_are_not_a_match(tmp_path):
    data = _compile(
        tmp_path,
        "void assuan_check_version(void) {}\n"
        "void assuan_pipe_connect(void) {}\n"
        "const char *first(void) {\n"
        '  return "This is Libassuan 3.0.2 - The GnuPG IPC Library";\n'
        "}\n"
        "const char *second(void) {\n"
        '  return "This is Libassuan 3.0.1 - The GnuPG IPC Library";\n'
        "}\n",
    )
    assert extract_public_versions(data) == []


def test_magic_integer_getter_is_estimated_from_the_api_encoding(tmp_path):
    data = _compile(
        tmp_path,
        "int magic_version(void) { return 0x222; }\nvoid magic_open(void) {}\n",
    )

    hits = extract_public_versions(data)

    assert [(hit.name, hit.version, hit.confidence) for hit in hits] == [("libmagic", "5.46", 0.88)]


def test_magic_interface_version_kind_survives_component_merge(tmp_path):
    data = _compile(
        tmp_path,
        "int magic_version(void) { return 0x222; }\nvoid magic_open(void) {}\n",
        "libmagic.so.1",
    )

    component = BinaryInventory().extract(
        data,
        "libmagic.so.1",
        "/usr/lib/libmagic.so.1",
    )[0]

    assert component.resolved_version == "5.46"
    assert {
        "name": "firmware:version:resolution-state",
        "value": "estimated",
    } in component.properties
    assert {
        "name": "firmware:version:kind",
        "value": "interface",
    } in component.properties


def test_lcms_integer_getter_preserves_the_release_triplet(tmp_path):
    data = _compile(
        tmp_path,
        "int cmsGetEncodedCMMversion(void) { return 0x87a; }\nvoid cmsCreateTransform(void) {}\n",
    )

    assert [(hit.name, hit.version) for hit in extract_public_versions(data)] == [("lcms2", "2.17")]
    patched = _compile(
        tmp_path,
        "int cmsGetEncodedCMMversion(void) { return 0x881; }\nvoid cmsCreateTransform(void) {}\n",
        "lcms-patched.so",
    )
    assert [(hit.name, hit.version) for hit in extract_public_versions(patched)] == [
        ("lcms2", "2.17.7")
    ]


def test_libidn_check_version_uses_the_defined_function_literal(tmp_path):
    data = _compile(
        tmp_path,
        "const char *stringprep_check_version(const char *required) {\n"
        '  (void)required; return "1.43";\n'
        "}\n"
        "void stringprep_4i(void) {}\n",
    )

    assert [(hit.name, hit.version) for hit in extract_public_versions(data)] == [
        ("libidn", "1.43")
    ]


def test_libidn_numeric_comparison_that_is_not_returned_gets_no_version(tmp_path):
    data = _compile(
        tmp_path,
        "int stringprep_check_version(const char *required) {\n"
        '  return required && __builtin_strcmp(required, "9.99") == 0;\n'
        "}\n"
        "void stringprep_4i(void) {}\n",
    )

    assert extract_public_versions(data) == []


def test_readline_pointer_and_packed_version_must_agree(tmp_path):
    data = _compile(
        tmp_path,
        'const char *rl_library_version = "8.3";\n'
        "const int rl_readline_version = 0x803;\n"
        "void readline(void) {}\n",
    )

    assert [(hit.name, hit.version) for hit in extract_public_versions(data)] == [
        ("Readline", "8.3")
    ]


def test_readline_editline_wrapper_is_not_a_numeric_release(tmp_path):
    data = _compile(
        tmp_path,
        'const char *rl_library_version = "EditLine wrapper";\n'
        "const int rl_readline_version = 0x204;\n"
        "void readline(void) {}\n",
    )

    assert extract_public_versions(data) == []


def test_readline_supports_a_32_bit_version_pointer(tmp_path):
    data = _compile(
        tmp_path,
        'const char *rl_library_version = "8.3";\n'
        "const int rl_readline_version = 0x803;\n"
        "void readline(void) {}\n",
        "readline32.so",
        ("-m32", "-nostdlib"),
    )

    assert [(hit.name, hit.version) for hit in extract_public_versions(data)] == [
        ("Readline", "8.3")
    ]


def test_gdbm_version_object_requires_library_functions(tmp_path):
    data = _compile(
        tmp_path,
        "const unsigned int gdbm_version_number[3] = {1, 26, 0};\n"
        "void gdbm_open(void) {}\n"
        "void gdbm_fetch(void) {}\n",
    )

    assert [(hit.name, hit.version) for hit in extract_public_versions(data)] == [("GDBM", "1.26")]


def test_gdbm_truncated_version_object_is_rejected(tmp_path):
    data = _compile(
        tmp_path,
        "const unsigned int gdbm_version_number = 1;\n"
        "void gdbm_open(void) {}\n"
        "void gdbm_fetch(void) {}\n",
    )

    assert extract_public_versions(data) == []


def test_public_version_claim_reaches_the_host_component(tmp_path):
    data = _compile(
        tmp_path,
        "void assuan_check_version(void) {}\n"
        "void assuan_pipe_connect(void) {}\n"
        "const char *get_banner(void) {\n"
        '  return "This is Libassuan 3.0.2 - The GnuPG IPC Library";\n'
        "}\n",
        "libassuan.so",
    )

    component = BinaryInventory().extract(
        data,
        "libassuan.so",
        "/usr/lib/libassuan.so",
    )[0]

    assert component.resolved_version == "3.0.2"
    assert {
        "name": "firmware:version:resolution-state",
        "value": "exact",
    } in component.properties
