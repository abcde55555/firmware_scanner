import os
import shutil
import subprocess
from pathlib import Path

import pytest


def _compile(tmp_path: Path, source: str) -> bytes:
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        pytest.skip("C compiler unavailable for the non-executed ELF fixture")
    c_path = tmp_path / "freetype_fixture.c"
    so_path = tmp_path / "libft2_fixture.so"
    c_path.write_text(source)
    subprocess.run(
        [compiler, "-shared", "-fPIC", "-O2", "-fno-stack-protector",
         "-Wl,--build-id=none", "-o", str(so_path), str(c_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return so_path.read_bytes()


def _source(
    *, assignments: str | None = None, getter_patch: str = "version_patch",
    allocation_check: bool = True, getter_extra: str = "",
    getter_prefix: str = "", getter_skip: str = "",
    allocator_body: str | None = None,
    bypass_allocator: bool = False,
) -> str:
    stores = assignments or """
    library->version_major = FREETYPE_MAJOR;
    library->version_minor = FREETYPE_MINOR;
    library->version_patch = FREETYPE_PATCH;
    """
    allocator = allocator_body or """
      if (allocation_fails) return 0;
      return malloc(size);
    """
    if bypass_allocator:
        allocation = """
      Library *library;
      if (skip_allocator) { library = &arena; goto initialize; }
      library = FT_Memory_Alloc(sizeof(*library));
      if (!library) return 2;
      initialize:
        """
    else:
        allocation = """
      Library *library = FT_Memory_Alloc(sizeof(*library));
      if (!library) return 2;
        """
    return f"""
    #include <stddef.h>
    #include <stdlib.h>
    #define FREETYPE_MAJOR 2
    #define FREETYPE_MINOR 13
    #define FREETYPE_PATCH 3
    typedef struct Library {{
      void *memory;
      volatile int version_major;
      volatile int version_minor;
      volatile int version_patch;
      int refcount;
    }} Library;
    static Library arena;
    static volatile int choose_other;
    static volatile int allocation_fails;
    static volatile int skip_allocator;
    __attribute__((noinline)) static Library *FT_Memory_Alloc(size_t size) {{
      {allocator}
    }}
    __attribute__((visibility("default"), noinline, used))
    int FT_New_Library(void *memory, Library **alibrary) {{
      if (!memory || !alibrary) return 1;
      {allocation if allocation_check else allocation.replace("      if (!library) return 2;", "")}
      {stores}
      library->refcount = 1;
      *alibrary = library;
      return 0;
    }}
    __attribute__((visibility("default"), noinline, used))
    void FT_Library_Version(Library *library, int *major, int *minor, int *patch) {{
      {getter_prefix}
      if (library) {{
        {getter_skip}
        if (major) *major = library->version_major;
        if (minor) *minor = library->version_minor;
        if (patch) *patch = library->{getter_patch};
      }} else {{
        if (major) *major = 0;
        if (minor) *minor = 0;
        if (patch) *patch = 0;
      }}
      {getter_extra}
    }}
    """


def _extract(data: bytes):
    from firmware_scanner.extraction.freetype_version import extract_freetype

    return extract_freetype(data)


def test_legacy_generic_shape_is_fail_closed_without_android_pair_proof(tmp_path):
    assert _extract(_compile(tmp_path, _source())) == []


def test_initializer_that_overwrites_a_version_field_is_rejected(tmp_path):
    source = _source(assignments="""
      library->version_major = FREETYPE_MAJOR;
      library->version_minor = FREETYPE_MINOR;
      library->version_patch = FREETYPE_PATCH;
      library->version_patch = 4;
    """)

    assert _extract(_compile(tmp_path, source)) == []


def test_conditional_initializer_is_rejected(tmp_path):
    source = _source(assignments="""
      if (choose_other) {
        library->version_major = 2; library->version_minor = 12; library->version_patch = 9;
      } else {
        library->version_major = FREETYPE_MAJOR;
        library->version_minor = FREETYPE_MINOR;
        library->version_patch = FREETYPE_PATCH;
      }
    """)

    assert _extract(_compile(tmp_path, source)) == []


def test_getter_and_initializer_field_offsets_must_match(tmp_path):
    assert _extract(_compile(tmp_path, _source(getter_patch="refcount"))) == []


def test_initializer_without_allocation_success_guard_is_rejected(tmp_path):
    assert _extract(_compile(tmp_path, _source(allocation_check=False))) == []


def test_defined_allocator_name_without_malloc_semantics_is_rejected(tmp_path):
    source = _source(allocator_body="return &arena;")

    assert _extract(_compile(tmp_path, source)) == []


def test_wrong_field_assignment_does_not_supply_patch(tmp_path):
    source = _source(assignments="""
      library->version_major = FREETYPE_MAJOR;
      library->version_minor = FREETYPE_MINOR;
      library->refcount = FREETYPE_PATCH;
      library->refcount = 1;
    """)

    assert _extract(_compile(tmp_path, source)) == []


def test_getter_output_overwrite_is_rejected(tmp_path):
    assert _extract(_compile(tmp_path, _source(getter_extra="if (major) *major = 7;"))) == []


def test_getter_library_pointer_clobber_is_rejected(tmp_path):
    assert _extract(_compile(tmp_path, _source(getter_prefix="library = &arena;"))) == []


def test_getter_path_that_skips_all_output_copies_is_rejected(tmp_path):
    assert _extract(_compile(tmp_path, _source(getter_skip="if (choose_other) return;"))) == []


@pytest.mark.parametrize(
    ("abi", "offset", "before", "after"),
    (("x64", 0x3C690, "4885ff", "4885c0"),),
)
def test_actual_getter_wrong_register_null_guard_is_rejected(
    actual_system_libraries, abi, offset, before, after
):
    data = bytearray(actual_system_libraries[abi])
    original, replacement = bytes.fromhex(before), bytes.fromhex(after)
    assert data[offset:offset + len(original)] == original
    data[offset:offset + len(original)] = replacement

    assert _extract(bytes(data)) == []


@pytest.mark.parametrize(
    "assignments",
    (
        "((volatile unsigned char *)library)[offsetof(Library, version_major) + 1] = 1;",
        "Library *alias = library; ((volatile unsigned long long *)alias)[0] = 0x0000000d00000002ULL;",
    ),
)
def test_compiled_legacy_initializer_overlap_and_alias_writes_are_rejected(
    tmp_path, assignments
):
    source = _source(assignments=f"""
      library->version_major = FREETYPE_MAJOR;
      library->version_minor = FREETYPE_MINOR;
      library->version_patch = FREETYPE_PATCH;
      {assignments}
    """)

    assert _extract(_compile(tmp_path, source)) == []


def test_initializer_pointer_clobber_after_allocation_is_rejected(tmp_path):
    source = _source(assignments="""
      library = &arena;
      library->version_major = FREETYPE_MAJOR;
      library->version_minor = FREETYPE_MINOR;
      library->version_patch = FREETYPE_PATCH;
    """)

    assert _extract(_compile(tmp_path, source)) == []


def test_branch_into_initializer_block_that_bypasses_allocator_is_rejected(tmp_path):
    assert _extract(_compile(tmp_path, _source(bypass_allocator=True))) == []


def test_import_only_freetype_symbols_are_rejected(tmp_path):
    data = _compile(tmp_path, """
      extern void FT_Library_Version(void *, int *, int *, int *);
      extern int FT_New_Library(void *, void **);
      void *version_refs[] = {(void *)FT_Library_Version, (void *)FT_New_Library};
    """)

    assert _extract(data) == []


def test_non_elf_is_rejected():
    assert _extract(b"not an ELF") == []


def test_other_elf_architecture_is_rejected(tmp_path):
    data = bytearray(_compile(tmp_path, _source()))
    data[18:20] = (183).to_bytes(2, "little")  # EM_AARCH64, without changing code.

    assert _extract(bytes(data)) == []


_SYSTEM_LIBRARIES = {
    "x64": ("/system/lib64/libft2.so", "a6148b8f80bfdaa50eb8bcc8033f2f01aa1bb85e68108e0acf54af2687503433"),
    "i386": ("/system/lib/libft2.so", "74459d21265a9c6b73c5881a753a7dbb9f80aaeae73fc91320bd37697f29a798"),
    "aarch64": ("/system/lib64/arm64/libft2.so", "26718fa4ffa0f75cebc46841ce63f148185baaf42f827d76e702b049e4f5c4da"),
    "arm": ("/system/lib/arm/libft2.so", "ecb7a6bc46119032c3b6f215127828a5f7ff1a3535f6dc157ebb380b9677c35e"),
}


@pytest.fixture(scope="module")
def actual_system_libraries(tmp_path_factory):
    image = os.environ.get("FREETYPE_SYSTEM_IMAGE")
    if not image:
        pytest.skip("set FREETYPE_SYSTEM_IMAGE to run read-only real-image checks")
    image_path = Path(image)
    if not image_path.is_file():
        pytest.skip(f"FreeType system image is unavailable: {image_path}")
    debugfs = shutil.which("debugfs")
    if not debugfs:
        pytest.skip("debugfs is required for read-only ext image extraction")

    output = tmp_path_factory.mktemp("freetype-system-image")
    binaries = {}
    import hashlib

    for abi, (image_path_in_fs, expected_sha256) in _SYSTEM_LIBRARIES.items():
        extracted = output / f"{abi}-libft2.so"
        result = subprocess.run(
            [debugfs, "-R", f"dump {image_path_in_fs} {extracted}", str(image_path)],
            check=False, capture_output=True, text=True,
        )
        if result.returncode or not extracted.is_file():
            pytest.skip(f"{image_path_in_fs} is absent from {image_path}")
        data = extracted.read_bytes()
        assert hashlib.sha256(data).hexdigest() == expected_sha256
        binaries[abi] = data
    return binaries


def test_actual_system_image_libraries_recover_version(actual_system_libraries):
    expected = {
        "x64": [("FreeType", "2.13.2")],
        "i386": [],
        "aarch64": [("FreeType", "2.13.2")],
        "arm": [],
    }
    for abi, data in actual_system_libraries.items():
        matches = _extract(data)
        assert [(item.name, item.version) for item in matches] == expected[abi]
        if matches:
            assert "FT_Library_Version" in matches[0].evidence
            assert "FT_New_Library" in matches[0].evidence
            assert "allocation-success" in matches[0].evidence


def test_actual_x64_null_output_branch_cannot_skip_remaining_outputs(actual_system_libraries):
    data = bytearray(actual_system_libraries["x64"])
    assert data[0x3C6A3:0x3C6A5] == bytes.fromhex("7403")
    data[0x3C6A3:0x3C6A5] = bytes.fromhex("7412")  # jump to RET, skipping minor/patch
    assert _extract(bytes(data)) == []


@pytest.mark.parametrize(
    ("abi", "offset", "before", "after"),
    (
        ("x64", 0x3C63D, "4885c0", "4839c0"),
        ("i386", 0x3B1A4, "85c0", "39c0"),
        ("aarch64", 0x3BAB0, "600300b4", "1b000014"),
        ("arm", 0x2E35C, "000050e3", "000050e1"),
    ),
)
def test_actual_allocator_zero_result_branch_mutations_are_rejected(
    actual_system_libraries, abi, offset, before, after
):
    data = bytearray(actual_system_libraries[abi])
    original, replacement = bytes.fromhex(before), bytes.fromhex(after)
    assert data[offset:offset + len(original)] == original
    data[offset:offset + len(original)] = replacement

    assert _extract(bytes(data)) == []


@pytest.mark.parametrize(
    ("abi", "offset", "before", "after"),
    (
        ("x64", 0x3C64A, "31f6", "7533"),
        ("i386", 0x3B1AE, "0f1180c0000000", "0f856000000090"),
        ("aarch64", 0x3BAB4, "00e4006f", "400300b5"),
        ("arm", 0x2E364, "d010a0e3", "0b00001a"),
    ),
)
def test_actual_success_path_branch_mutations_that_skip_stores_are_rejected(
    actual_system_libraries, abi, offset, before, after
):
    data = bytearray(actual_system_libraries[abi])
    original, replacement = bytes.fromhex(before), bytes.fromhex(after)
    assert data[offset:offset + len(original)] == original
    data[offset:offset + len(original)] = replacement

    assert _extract(bytes(data)) == []


@pytest.mark.parametrize(
    ("abi", "offset", "before", "after"),
    (
        ("x64", 0x3C663, "49894f08", "48894f08"),
        ("i386", 0x3B1EF, "c7400402000000", "c7410402000000"),
        ("aarch64", 0x3BB08, "0a1100b9", "8a1200b9"),
        ("arm", 0x2E380, "030086e9", "030085e9"),
    ),
)
def test_actual_initializer_base_pointer_mutations_are_rejected(
    actual_system_libraries, abi, offset, before, after
):
    data = bytearray(actual_system_libraries[abi])
    original, replacement = bytes.fromhex(before), bytes.fromhex(after)
    assert data[offset:offset + len(original)] == original
    data[offset:offset + len(original)] = replacement

    assert _extract(bytes(data)) == []


@pytest.mark.parametrize(
    ("abi", "offset", "before", "after"),
    (
        ("x64", 0x3C667, "41c7471002000000", "41c7471402000000"),
        ("i386", 0x3B1FD, "c7400c02000000", "c7401002000000"),
        ("aarch64", 0x3BB08, "0a1100b9", "0a1500b9"),
        ("arm", 0x2E384, "0c0086e5", "100086e5"),
    ),
)
def test_actual_initializer_version_field_offset_mutations_are_rejected(
    actual_system_libraries, abi, offset, before, after
):
    data = bytearray(actual_system_libraries[abi])
    original, replacement = bytes.fromhex(before), bytes.fromhex(after)
    assert data[offset:offset + len(original)] == original
    data[offset:offset + len(original)] = replacement

    assert _extract(bytes(data)) == []


@pytest.mark.parametrize(
    ("abi", "offset", "before", "after"),
    (
        ("x64", 0x3C66F, "41c7878801000001000000", "41c7871000000001000000"),
        ("i386", 0x3B204, "c780cc00000001000000", "c7800c00000001000000"),
        ("aarch64", 0x3BB0C, "098901b9", "091100b9"),
        ("arm", 0x2E378, "cc0086e5", "040086e5"),
    ),
)
def test_actual_initializer_later_field_overwrites_are_rejected(
    actual_system_libraries, abi, offset, before, after
):
    data = bytearray(actual_system_libraries[abi])
    original, replacement = bytes.fromhex(before), bytes.fromhex(after)
    assert data[offset:offset + len(original)] == original
    data[offset:offset + len(original)] = replacement

    assert _extract(bytes(data)) == []


@pytest.mark.parametrize(
    ("abi", "offset", "before", "after"),
    (
        ("x64", 0x3C659, "48b9020000000d000000", "48c7c1020000004831c9"),
        ("i386", 0x3B1A8, "0f57c0", "31c090"),
        ("aarch64", 0x3BAC8, "008100ad", "4a050011"),
        ("arm", 0x2E378, "cc0086e5", "011081e2"),
    ),
)
def test_actual_initializer_tracked_register_clobbers_are_rejected(
    actual_system_libraries, abi, offset, before, after
):
    data = bytearray(actual_system_libraries[abi])
    original, replacement = bytes.fromhex(before), bytes.fromhex(after)
    assert data[offset:offset + len(original)] == original
    data[offset:offset + len(original)] = replacement

    assert _extract(bytes(data)) == []


@pytest.mark.parametrize(
    ("abi", "offset", "before", "after"),
    (
        ("x64", 0x3C66F, "41c7878801000001000000", "c647090190909090909090"),
        ("i386", 0x3B204, "c780cc00000001000000", "c6400501909090909090"),
        ("aarch64", 0x3BB0C, "098901b9", "09250039"),
        ("arm", 0x2E378, "cc0086e5", "0500c6e5"),
    ),
)
def test_actual_initializer_field_interior_byte_writes_are_rejected(
    actual_system_libraries, abi, offset, before, after
):
    data = bytearray(actual_system_libraries[abi])
    original, replacement = bytes.fromhex(before), bytes.fromhex(after)
    assert len(original) == len(replacement)
    assert data[offset:offset + len(original)] == original
    data[offset:offset + len(original)] = replacement

    assert _extract(bytes(data)) == []


@pytest.mark.parametrize(
    ("abi", "offset", "before", "after"),
    (
        ("x64", 0x3C66F, "41c7878801000001000000", "49894f0990909090909090"),
        ("i386", 0x3B204, "c780cc00000001000000", "89480590909090909090"),
        ("aarch64", 0x3BB0C, "098901b9", "099000b8"),
        ("arm", 0x2E378, "cc0086e5", "050086e5"),
    ),
)
def test_actual_initializer_cross_field_writes_are_rejected(
    actual_system_libraries, abi, offset, before, after
):
    data = bytearray(actual_system_libraries[abi])
    original, replacement = bytes.fromhex(before), bytes.fromhex(after)
    assert len(original) == len(replacement)
    assert data[offset:offset + len(original)] == original
    data[offset:offset + len(original)] = replacement

    assert _extract(bytes(data)) == []
