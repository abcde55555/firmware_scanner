import mmap
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
    from experiments.version_coverage.freetype_version import extract_freetype

    return extract_freetype(data)


def test_defined_getter_and_allocation_success_initializer_recover_exact_release(tmp_path):
    matches = _extract(_compile(tmp_path, _source()))

    assert [(item.name, item.version) for item in matches] == [("FreeType", "2.13.3")]
    assert "FT_Library_Version" in matches[0].evidence
    assert "FT_New_Library" in matches[0].evidence
    assert "allocation-success" in matches[0].evidence


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


@pytest.mark.parametrize(
    "path",
    (
        "/system/lib64/libft2.so",
        "/system/lib/libft2.so",
        "/system/lib64/arm64/libft2.so",
        "/system/lib/arm/libft2.so",
    ),
)
def test_named_readable_system_library_if_available(path):
    library = Path(path)
    if not library.is_file():
        pytest.skip("named system library is not mounted in this host namespace")
    with library.open("rb") as source, mmap.mmap(
        source.fileno(), 0, access=mmap.ACCESS_READ
    ) as view:
        matches = _extract(bytes(view))

    assert isinstance(matches, list)
