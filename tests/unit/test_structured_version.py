"""Documented version-info structures require identity, age and agreement."""

import shutil
import subprocess

import pytest


def _elf(tmp_path, name, version, version_number, age=1):
    cc = shutil.which("cc")
    if cc is None:
        pytest.skip("C compiler needed for structured version controls")
    source = f"""
    typedef struct {{ int age; int version_num; const char *version_str; }} info;
    static const info published = {{{age}, {version_number}, "{version}"}};
    const info *{name}(int least_version) {{
        return least_version <= published.version_num ? &published : 0;
    }}
    """
    src, output = tmp_path / f"{name}.c", tmp_path / f"{name}.so"
    src.write_text(source)
    subprocess.run(
        [cc, "-shared", "-fPIC", "-O2", str(src), "-o", str(output)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["strip", "--strip-all", str(output)],
        check=True,
        capture_output=True,
    )
    return output.read_bytes()


@pytest.mark.parametrize(
    "name,component,version,number",
    [
        ("nghttp2_version", "nghttp2", "1.70.0", 0x014600),
        ("nghttp3_version", "nghttp3", "1.17.0", 0x011100),
        ("ngtcp2_version", "ngtcp2", "1.24.0", 0x011800),
    ],
)
def test_owned_structured_getter_recovers_three_part_release(
    tmp_path, name, component, version, number
):
    from firmware_scanner.extraction.structured_version import extract_structured_versions

    data = _elf(tmp_path, name, version, number)
    hits = extract_structured_versions(data)
    assert [(hit.name, hit.version, hit.confidence) for hit in hits] == [
        (component, version, 0.96)
    ]


@pytest.mark.parametrize(
    "version,number,age",
    [
        ("1.70.0", 0x014601, 1),
        ("1.70", 0x014600, 1),
        ("1.70.0", 0x014600, 2),
    ],
)
def test_structured_version_rejects_disagreement_or_unknown_age(
    tmp_path, version, number, age
):
    from firmware_scanner.extraction.structured_version import extract_structured_versions

    assert extract_structured_versions(
        _elf(tmp_path, "nghttp2_version", version, number, age)
    ) == []


def test_imported_structured_getter_is_not_version_proof(tmp_path):
    from firmware_scanner.extraction.structured_version import extract_structured_versions

    cc = shutil.which("cc")
    if cc is None:
        pytest.skip("C compiler needed for structured version controls")
    source = (
        "typedef struct { int age; int version_num; const char *version_str; } info;"
        "extern const info *nghttp2_version(int);"
        "const info *(*getter)(int) = nghttp2_version;"
    )
    src, output = tmp_path / "imports.c", tmp_path / "imports.so"
    src.write_text(source)
    subprocess.run(
        [cc, "-shared", "-fPIC", "-O2", str(src), "-o", str(output)],
        check=True,
        capture_output=True,
    )
    assert extract_structured_versions(output.read_bytes()) == []


def test_documented_integer_version_struct_recovers_seccomp_release(tmp_path):
    from firmware_scanner.extraction.structured_version import extract_structured_versions

    cc = shutil.which("cc")
    if cc is None:
        pytest.skip("C compiler needed for structured version controls")
    source = """
    typedef struct { unsigned int major; unsigned int minor; unsigned int micro; } info;
    static const info published = {2, 6, 0};
    const info *seccomp_version(void) { return &published; }
    """
    src, output = tmp_path / "seccomp.c", tmp_path / "seccomp.so"
    src.write_text(source)
    subprocess.run(
        [cc, "-shared", "-fPIC", "-O2", str(src), "-o", str(output)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["strip", "--strip-all", str(output)],
        check=True,
        capture_output=True,
    )
    assert [
        (hit.name, hit.version)
        for hit in extract_structured_versions(output.read_bytes())
    ] == [("seccomp", "2.6.0")]
