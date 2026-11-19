"""Static function-semantic version controls; compiled ELFs are never executed."""

import hashlib
import json
import mmap
import os
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def cc():
    compiler = shutil.which("gcc") or shutil.which("cc")
    if not compiler:
        pytest.skip("a C compiler is required for real ELF getter fixtures")
    return compiler


def _compile_shared(tmp_path, cc, name, source, *, language="c", flags=()):
    suffix = {"c++": ".cpp", "asm": ".S"}.get(language, ".c")
    src = tmp_path / f"{name}{suffix}"
    output = tmp_path / f"{name}.so"
    src.write_text(source, encoding="utf-8")
    subprocess.run(
        [cc, "-shared", "-fPIC", "-Wl,--build-id=none", *flags, str(src), "-o", str(output)],
        check=True,
        capture_output=True,
    )
    return output.read_bytes()


def test_c_compiled_constant_getters_return_static_version_matches(tmp_path, cc):
    from firmware_scanner.extraction.semantic_version import SemanticVersionExtractor

    data = _compile_shared(
        tmp_path,
        cc,
        "constant_getters",
        """
        int LZ4_versionNumber(void) { return 10902; }
        int sqlite3_libversion_number(void) { return 3044003; }
        int WebPGetDecoderVersion(void) { return 0x020c03; }
        """,
        flags=("-O2",),
    )

    matches = SemanticVersionExtractor().extract(data)

    assert {(match.name, match.version) for match in matches} == {
        ("LZ4", "1.9.2"),
        ("SQLite", "3.44.3"),
        ("libwebp", "2.12.3"),
    }
    assert all(match.confidence == 0.94 for match in matches)
    assert all(json.loads(match.evidence)["prototype"] == "function-version-semantics-v1" for match in matches)


def test_import_only_undefined_getter_is_not_treated_as_a_definition(tmp_path, cc):
    from firmware_scanner.extraction.semantic_version import SemanticVersionExtractor

    data = _compile_shared(
        tmp_path,
        cc,
        "undefined_getter",
        "extern int LZ4_versionNumber(void);\n"
        "int (*version_getter)(void) = LZ4_versionNumber;\n",
    )

    assert SemanticVersionExtractor().extract(data) == []


@pytest.mark.parametrize(
    "source",
    [
        "volatile int runtime_value; int LZ4_versionNumber(void) { return runtime_value; }\n",
        ("volatile int choose_version; int LZ4_versionNumber(void) { "
         "if (choose_version) return 10902; return 10903; }\n"),
    ],
    ids=("runtime-dependent", "conditional-return"),
)
def test_nonconstant_and_conditional_getter_paths_are_refused(tmp_path, cc, source):
    from firmware_scanner.extraction.semantic_version import SemanticVersionExtractor

    data = _compile_shared(tmp_path, cc, "unsafe_getter", source, flags=("-O2",))

    assert SemanticVersionExtractor().extract(data) == []


def _real_version_api_file(path_in_image, expected_sha256):
    from firmware_scanner.android.ext4_reader import Ext4Reader

    image = os.environ.get("FIRMWARE_SYSTEM_IMAGE") or os.environ.get("FREETYPE_SYSTEM_IMAGE")
    if image:
        with Path(image).open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            reader = Ext4Reader(data)
            assert reader.is_valid(), "real version-API control needs a valid ext4 image"
            binary = reader.read_file(path_in_image, max_size=32 * 1024 * 1024)
    else:
        extracted = Path("/home/kali/Desktop/work/project/vulnscan/mnt_system") / path_in_image.lstrip("/")
        if not extracted.is_file():
            pytest.skip("set FIRMWARE_SYSTEM_IMAGE for the read-only version-API control")
        binary = extracted.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == expected_sha256
    return binary


def test_arm_string_getter_preserves_vendor_suffix_from_real_file():
    from firmware_scanner.extraction.semantic_version import SemanticVersionExtractor

    binary = _real_version_api_file(
        "/system/lib/arm/libz.so",
        "276054faa3ab5bd3626187805af092d54c25b1841d88ad93966dae5dee697eb4",
    )
    matches = SemanticVersionExtractor().extract(binary)

    assert ("zlib", "1.3.0.1-motley") in {(match.name, match.version) for match in matches}


def test_icu_real_getter_keeps_static_version_match_output():
    from firmware_scanner.extraction.icu_version import extract_icu

    binary = _real_version_api_file(
        "/system/lib64/arm64/libicuuc.so",
        "de58b2d3c51fefdbdbb8d66831f9fb1ace3559e3d1f6f89f28341fc7ee3a42ca",
    )
    matches = extract_icu(binary)

    assert [(match.name, match.version, match.confidence) for match in matches] == [("ICU", "76.1", 0.98)]
    assert json.loads(matches[0].evidence)["probe"] == "icu-version-getter-v1"


@pytest.mark.parametrize("branch", ["jl", "jge"])
def test_protobuf_mutually_exclusive_call_counterexample_is_refused(tmp_path, cc, branch):
    from firmware_scanner.extraction.semantic_version import SemanticVersionExtractor

    source = f"""
    .text
    .globl _ZN6google8protobuf8internal13VerifyVersionEiiPKc
    .type _ZN6google8protobuf8internal13VerifyVersionEiiPKc,@function
    _ZN6google8protobuf8internal13VerifyVersionEiiPKc:
      cmp $3021013, %esi
      {branch} .Lother
      mov $3021012, %esi
      call _ZN6google8protobuf8internal13VersionStringEi@PLT
      ret
    .Lother:
      mov $3021012, %esi
      call _ZN6google8protobuf8internal13VersionStringEi@PLT
      ret
    .size _ZN6google8protobuf8internal13VerifyVersionEiiPKc, .-_ZN6google8protobuf8internal13VerifyVersionEiiPKc
    .globl _ZN6google8protobuf8internal13VersionStringEi
    .type _ZN6google8protobuf8internal13VersionStringEi,@function
    _ZN6google8protobuf8internal13VersionStringEi:
      ret
    .size _ZN6google8protobuf8internal13VersionStringEi, .-_ZN6google8protobuf8internal13VersionStringEi
    .section .rodata
    .asciz "This program requires version "
    .asciz "but the installed version is "
    .section .note.GNU-stack,"",@progbits
    """
    data = _compile_shared(tmp_path, cc, "protobuf_exclusive", source, language="asm", flags=("-nostdlib",))

    assert SemanticVersionExtractor().extract(data) == []


def test_386_pic_constant_integer_getters_are_static_version_matches(tmp_path, cc):
    from firmware_scanner.extraction.semantic_version import SemanticVersionExtractor

    data = _compile_shared(
        tmp_path,
        cc,
        "x86_32_constant_getters",
        """
        int LZ4_versionNumber(void) { return 10902; }
        int sqlite3_libversion_number(void) { return 3044003; }
        int WebPGetDecoderVersion(void) { return 0x020c03; }
        """,
        flags=("-m32", "-O2", "-nostdlib"),
    )

    matches = SemanticVersionExtractor().extract(data)

    assert {(match.name, match.version) for match in matches} == {
        ("LZ4", "1.9.2"),
        ("SQLite", "3.44.3"),
        ("libwebp", "2.12.3"),
    }


def test_386_pic_cronet_getter_preserves_complete_release_string(tmp_path, cc):
    from firmware_scanner.extraction.semantic_version import SemanticVersionExtractor

    data = _compile_shared(
        tmp_path,
        cc,
        "x86_32_cronet_getter",
        'const char *Cronet_Engine_GetVersionString(void) { return "141.0.7340.3-vendor"; }\n',
        flags=("-m32", "-O2", "-nostdlib"),
    )

    matches = SemanticVersionExtractor().extract(data)

    assert [(match.name, match.version) for match in matches] == [("Cronet", "141.0.7340.3-vendor")]
    assert json.loads(matches[0].evidence)["mode"] == "x86-32-pic"


@pytest.mark.parametrize(
    "source",
    [
        ("extern int Cronet_Engine_GetVersionString(void);\n"
         "int (*version_getter)(void) = Cronet_Engine_GetVersionString;\n"),
        ("volatile int use_other; extern const char release_a[], release_b[];\n"
        "const char *Cronet_Engine_GetVersionString(void) { "
         "return use_other ? release_a : release_b; }\n"),
    ],
    ids=("undefined-import-only", "conditional-pointer-return"),
)
def test_386_cronet_undefined_or_conditional_getter_is_refused(tmp_path, cc, source):
    from firmware_scanner.extraction.semantic_version import SemanticVersionExtractor

    data = _compile_shared(
        tmp_path,
        cc,
        "x86_32_cronet_negative",
        source,
        flags=("-m32", "-O2", "-nostdlib"),
    )

    assert SemanticVersionExtractor().extract(data) == []


def test_icu_rejects_non_elf_and_unsupported_architecture(tmp_path, cc):
    from firmware_scanner.extraction.icu_version import extract_icu

    x86 = _compile_shared(
        tmp_path,
        cc,
        "x86_icu_named_symbols",
        "void u_versionFromString_76(void *out, const char *version) { (void)out; (void)version; }\n"
        "void u_getVersion_76(void *out) { u_versionFromString_76(out, \"76.1\"); }\n",
        flags=("-O2",),
    )

    assert extract_icu(b"not an ELF") == []
    assert extract_icu(x86) == []
