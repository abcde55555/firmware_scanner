import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from firmware_scanner.extraction.static_version import StaticVersionExtractor


def _aarch64_elf(
    code_words: list[int],
    version: bytes,
    *,
    symbol_name: str = "LZ4_versionString",
    pointer_literal: bool = False,
) -> bytes:
    """Build a tiny ET_DYN ELF with fixed AArch64 instructions and one function symbol."""
    data = bytearray(0x2400)
    code_offset = 0x1000
    string_offset = 0x2100
    code = b"".join(struct.pack("<I", word) for word in code_words)
    data[code_offset:code_offset + len(code)] = code
    data[string_offset:string_offset + len(version) + 1] = version + b"\0"
    if pointer_literal:
        data[0x1080:0x1088] = struct.pack("<Q", string_offset)

    shstr = b"\0.strtab\0.symtab\0.shstrtab\0"
    shstr_off = 0x2180
    strtab = b"\0" + symbol_name.encode() + b"\0"
    strtab_off = 0x21A0
    symtab_off = 0x21C0
    shoff = 0x2200
    data[shstr_off:shstr_off + len(shstr)] = shstr
    data[strtab_off:strtab_off + len(strtab)] = strtab

    # ELF64 symbol: global STT_FUNC at VA 0x1000, size exactly the supplied body.
    data[symtab_off:symtab_off + 48] = bytes(24) + struct.pack(
        "<IBBHQQ", 1, 0x12, 0, 1, 0x1000, len(code)
    )

    # ELF header and one PT_LOAD mapping file offsets directly to virtual addresses.
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH", ident, 3, 183, 1, 0, 64, shoff, 0,
        64, 56, 1, 64, 4, 3,
    )
    data[:64] = ehdr
    data[64:120] = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, len(data), len(data), 0x1000)

    # Null, .strtab, .symtab, .shstrtab section headers.
    sections = [bytes(64)]
    sections.append(struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0))
    sections.append(struct.pack("<IIQQQQIIQQ", 9, 2, 0, 0, symtab_off, 48, 1, 1, 8, 24))
    sections.append(struct.pack("<IIQQQQIIQQ", 17, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0))
    data[shoff:shoff + 64 * 4] = b"".join(sections)
    return bytes(data)


def test_aarch64_adrp_add_ret_returns_complete_dev_version():
    # adrp x0, +0x1000; add x0, x0, #0x100; ret
    elf = _aarch64_elf([0xB0000000, 0x91040000, 0xD65F03C0], b"1.10.0-dev-gabc123")

    matches = StaticVersionExtractor().extract(elf)

    assert [(m.name, m.version) for m in matches] == [("LZ4", "1.10.0-dev-gabc123")]
    assert "LZ4_versionString" in matches[0].evidence


def test_aarch64_function_with_call_is_rejected():
    # bl #0; adrp x0, +0x1000; add x0, x0, #0x100; ret
    elf = _aarch64_elf([0x94000000, 0xB0000000, 0x91040000, 0xD65F03C0], b"1.10.0")

    assert StaticVersionExtractor().extract(elf) == []


def test_aarch64_literal_load_resolves_pointer_through_file_backed_mapping():
    # ldr x0, #0x1080; ret; the literal contains the VA 0x2100.
    elf = _aarch64_elf(
        [0x58000400, 0xD65F03C0], b"1.5.7+git-deadbeef",
        symbol_name="ZSTD_versionString", pointer_literal=True,
    )

    matches = StaticVersionExtractor().extract(elf)

    assert [(m.name, m.version) for m in matches] == [("zstd", "1.5.7+git-deadbeef")]


def test_aarch64_adrp_add_ret_uses_the_same_public_getter_registry():
    elf = _aarch64_elf(
        [0xB0000000, 0x91040000, 0xD65F03C0],
        b"1.12.3",
        symbol_name="nng_version",
    )

    assert [(match.name, match.version) for match in StaticVersionExtractor().extract(elf)] == [
        ("NNG", "1.12.3")
    ]


def test_malformed_elf_returns_no_matches():
    assert StaticVersionExtractor().extract(b"\x7fELF" + bytes(60)) == []


def test_truncated_elf_header_returns_no_matches():
    assert StaticVersionExtractor().extract(b"\x7fELF\x02\x01") == []


def test_x86_64_compiler_getter_fixture_returns_full_dev_git_version():
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        raise unittest.SkipTest("host C compiler unavailable")
    source = '''
        const char * volatile cjson_version = "9.9.9";
        __attribute__((visibility("default"), noinline, used))
        const char *cJSON_Version(void) {
            return cjson_version;
        }
        __attribute__((visibility("default"), noinline, used))
        const char *ZSTD_versionString(void) {
            return "1.5.7-dev-git-deadbeef";
        }
    '''
    with tempfile.TemporaryDirectory() as temp_dir:
        source_path = Path(temp_dir) / "getter.c"
        elf_path = Path(temp_dir) / "libgetter.so"
        source_path.write_text(source)
        subprocess.run(
            [compiler, "-shared", "-fPIC", "-O1", "-fno-stack-protector",
             "-Wl,--build-id=none", "-o", str(elf_path), str(source_path)],
            check=True,
        )

        matches = StaticVersionExtractor().extract(elf_path.read_bytes())

    assert [(m.name, m.version) for m in matches] == [("zstd", "1.5.7-dev-git-deadbeef")]


def test_libfuse_package_version_uses_the_release_string_pointer():
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        raise unittest.SkipTest("host C compiler unavailable")
    source = '''
        __attribute__((visibility("default"), noinline, used))
        const char *fuse_pkgversion(void) {
            return "3.18.1";
        }
        __attribute__((visibility("default"), noinline, used))
        int fuse_version(void) {
            return 318;
        }
    '''
    with tempfile.TemporaryDirectory() as temp_dir:
        source_path = Path(temp_dir) / "fuse.c"
        elf_path = Path(temp_dir) / "libfuse3.so.3"
        source_path.write_text(source)
        subprocess.run(
            [compiler, "-shared", "-fPIC", "-O2", "-fno-stack-protector",
             "-Wl,--build-id=none", "-o", str(elf_path), str(source_path)],
            check=True,
        )

        matches = StaticVersionExtractor().extract(elf_path.read_bytes())

    assert [(m.name, m.version) for m in matches] == [("libfuse", "3.18.1")]
    assert "fuse_pkgversion" in matches[0].evidence


def test_libarchive_and_json_c_release_string_getters():
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        raise unittest.SkipTest("host C compiler unavailable")
    source = '''
        __attribute__((visibility("default"), noinline, used))
        const char *archive_version_string(void) {
            return "libarchive 3.8.5";
        }
        __attribute__((visibility("default"), noinline, used))
        const char *json_c_version(void) {
            return "0.18";
        }
    '''
    with tempfile.TemporaryDirectory() as temp_dir:
        source_path = Path(temp_dir) / "getters.c"
        elf_path = Path(temp_dir) / "libgetters.so"
        source_path.write_text(source)
        subprocess.run(
            [compiler, "-shared", "-fPIC", "-O2", "-fno-stack-protector",
             "-Wl,--build-id=none", "-o", str(elf_path), str(source_path)],
            check=True,
        )

        matches = StaticVersionExtractor().extract(elf_path.read_bytes())

    assert {(m.name, m.version) for m in matches} == {
        ("libarchive", "3.8.5"),
        ("json-c", "0.18"),
    }


def test_nss_and_nspr_version_string_getters():
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        raise unittest.SkipTest("host C compiler unavailable")
    source = '''
        __attribute__((visibility("default"), noinline, used))
        const char *NSS_GetVersion(void) { return "3.121"; }
        __attribute__((visibility("default"), noinline, used))
        int NSS_VersionCheck(const char *value) { (void)value; return 1; }
        __attribute__((visibility("default"), noinline, used))
        const char *PR_GetVersion(void) { return "4.38.2"; }
        __attribute__((visibility("default"), noinline, used))
        int PR_VersionCheck(const char *value) { (void)value; return 1; }
    '''
    with tempfile.TemporaryDirectory() as temp_dir:
        source_path = Path(temp_dir) / "nss.c"
        elf_path = Path(temp_dir) / "libnss-combined.so"
        source_path.write_text(source)
        subprocess.run(
            [compiler, "-shared", "-fPIC", "-O2", "-fno-stack-protector",
             "-Wl,--build-id=none", "-o", str(elf_path), str(source_path)],
            check=True,
        )

        matches = StaticVersionExtractor().extract(elf_path.read_bytes())

    assert {(match.name, match.version) for match in matches} == {
        ("NSS", "3.121"),
        ("NSPR", "4.38.2"),
    }


def test_additional_documented_string_version_getters():
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        raise unittest.SkipTest("host C compiler unavailable")
    getters = {
        "jansson_version_str": "2.14",
        "MMDB_lib_version": "1.12.2",
        "orc_version_string": "0.4.42",
        "sodium_version_string": "1.0.18",
    }
    source = "\n".join(
        f'__attribute__((visibility("default"), noinline, used))\n'
        f'const char *{symbol}(void) {{ return "{version}"; }}'
        for symbol, version in getters.items()
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        source_path = Path(temp_dir) / "getters.c"
        elf_path = Path(temp_dir) / "libgetters.so"
        source_path.write_text(source)
        subprocess.run(
            [compiler, "-shared", "-fPIC", "-O2", "-fno-stack-protector",
             "-Wl,--build-id=none", "-o", str(elf_path), str(source_path)],
            check=True,
        )

        matches = StaticVersionExtractor().extract(elf_path.read_bytes())

    assert {(m.name, m.version) for m in matches} == {
        ("Jansson", "2.14"),
        ("libmaxminddb", "1.12.2"),
        ("liborc", "0.4.42"),
        ("libsodium", "1.0.18"),
    }


def test_additional_public_string_version_getters():
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        raise unittest.SkipTest("host C compiler unavailable")
    getters = {
        "nng_version": ("NNG", "1.12.3"),
        "amqp_version": ("librabbitmq", "0.15.0"),
        "QRcode_APIVersionString": ("libqrencode", "4.1.1"),
        "sp_get_package_version_string": ("libserialport", "0.1.1"),
        "mysql_get_client_info": ("libmariadb", "3.4.9"),
    }
    source = "\n".join(
        f'__attribute__((visibility("default"), noinline, used))\n'
        f'const char *{symbol}(void) {{ return "{version}"; }}'
        for symbol, (_component, version) in getters.items()
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        source_path = Path(temp_dir) / "getters.c"
        elf_path = Path(temp_dir) / "libgetters.so"
        source_path.write_text(source)
        subprocess.run(
            [compiler, "-shared", "-fPIC", "-O2", "-fno-stack-protector",
             "-Wl,--build-id=none", "-o", str(elf_path), str(source_path)],
            check=True,
        )

        matches = StaticVersionExtractor().extract(elf_path.read_bytes())

    assert {(match.name, match.version) for match in matches} == set(getters.values())


def test_libsrtp_prefixed_release_getter():
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        raise unittest.SkipTest("host C compiler unavailable")
    source = '''
        __attribute__((visibility("default"), noinline, used))
        const char *srtp_get_version_string(void) {
            return "libsrtp2 2.7.0";
        }
    '''
    with tempfile.TemporaryDirectory() as temp_dir:
        source_path = Path(temp_dir) / "srtp.c"
        elf_path = Path(temp_dir) / "libsrtp2.so.1"
        source_path.write_text(source)
        subprocess.run(
            [compiler, "-shared", "-fPIC", "-O2", "-fno-stack-protector",
             "-Wl,--build-id=none", "-o", str(elf_path), str(source_path)],
            check=True,
        )

        matches = StaticVersionExtractor().extract(elf_path.read_bytes())

    assert [(m.name, m.version) for m in matches] == [("libsrtp", "2.7.0")]
