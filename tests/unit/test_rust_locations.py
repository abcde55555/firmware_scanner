"""Controls for experimental source-position features, never version claims."""
from __future__ import annotations

import importlib.util
import shutil
import struct
import subprocess
from pathlib import Path

import pytest


def _module():
    path = Path(__file__).resolve().parents[2] / "experiments/version_coverage/rust_locations.py"
    spec = importlib.util.spec_from_file_location("rust_locations", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_relr_bitmap_addresses_and_bounds():
    decode = _module().decode_relr
    assert decode(struct.pack("<QQQ", 0x2000, 1 | 2 | 8, 0x2400)) == [0x2000, 0x2008, 0x2018, 0x2400]
    for raw in (b"x", struct.pack("<Q", 3), struct.pack("<QQ", 0x2000, 0x1ff8)):
        with pytest.raises(ValueError):
            decode(raw)
    with pytest.raises(ValueError):
        decode(struct.pack("<QQ", 0x2000, 0xffffffffffffffff), limit=5)


def _sleb(value):
    result = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        last = value == 0 and not byte & 0x40 or value == -1 and byte & 0x40
        result.append(byte if last else byte | 0x80)
        if last:
            return bytes(result)


def test_android_rela_grouped_and_individual_addends():
    decode = _module().decode_android_rela
    # Two grouped offsets/info and individual addends; next group resets addend.
    raw = b"APS2" + b"".join(_sleb(x) for x in (3, 0x2000, 2, 11, 8, 8, 10, -3, 1, 1, 8, 8))
    assert decode(raw) == [(0x2008, 8, 10), (0x2010, 8, 7), (0x2018, 8, 0)]
    grouped = b"APS2" + b"".join(_sleb(x) for x in (2, 0, 2, 15, 8, 8, -4))
    assert decode(grouped) == [(8, 8, -4), (16, 8, -4)]


@pytest.mark.parametrize("raw", [
    b"APS1", b"APS2", b"APS2\x80", b"APS2" + b"\x80" * 11,
    b"APS2" + b"".join(_sleb(x) for x in (1, 0, 0, 0)),
    b"APS2" + b"".join(_sleb(x) for x in (1, 0, 2, 0)),
    b"APS2" + b"".join(_sleb(x) for x in (1, 0, 1, 16)),
    b"APS2" + b"".join(_sleb(x) for x in (1, 0, 1, 4)),
    b"APS2" + b"".join(_sleb(x) for x in (1, 0, 1, 0, -8, 8)),
])
def test_invalid_android_rela_stream_is_refused(raw):
    with pytest.raises(ValueError):
        _module().decode_android_rela(raw)


def _binary(tmp_path, *, path="external/rust/android-crates-io/crates/example/src/lib.rs",
            line=12, column=7, writable_path=False, writable_record=False,
            length_delta=0, relocate=True, callee=None, clobber=False, argument="rdx"):
    compiler = shutil.which("cc")
    if not compiler:
        pytest.skip("host assembler/linker required")
    source = tmp_path / "location.S"
    binary = tmp_path / "location.so"
    path_section = ".data" if writable_path else ".rodata"
    record_section = ".data" if writable_record else ".data.rel.ro"
    pointer = ".Lpath" if relocate else "0"
    call = f"call *{callee}@GOTPCREL(%rip)" if callee else ""
    overwrite = "xor %edx,%edx" if clobber else ""
    source.write_text(f"""
.text
.global example_function
.type example_function,@function
example_function:
    lea .Llocation(%rip),%{argument}
    {overwrite}
    {call}
    ret
.size example_function,.-example_function
.section {path_section}
.Lpath: .ascii "{path}"
.section {record_section}
.balign 8
.Llocation: .quad {pointer}
    .quad {len(path.encode()) + length_delta}
    .long {line},{column}
.section .note.GNU-stack,"",@progbits
""")
    subprocess.run([compiler, "-shared", "-nostdlib", "-Wl,-z,relro", str(source),
                    "-o", str(binary)], check=True, capture_output=True)
    return binary.read_bytes()


def test_structured_record_preserves_coordinates_and_reference(tmp_path):
    result = _module().extract_locations(_binary(tmp_path))
    assert result["status"] == "analyzed"
    assert len(result["locations"]) == 1
    site = result["locations"][0]
    assert (site["crate"], site["source_file"], site["line"], site["column"]) == (
        "example", "src/lib.rs", 12, 7,
    )
    assert site["code_references"]
    assert "version" not in site


def test_call_context_requires_a_preserved_argument_and_core_panic_import(tmp_path):
    extract = _module().extract_locations
    panic = "_ZN4core9panicking18panic_bounds_check17h0123456789abcdefE"
    result = extract(_binary(tmp_path, callee=panic))
    assert result["locations"][0]["corroborated_calls"][0]["symbol"] == panic
    assert not extract(_binary(tmp_path, callee="unrelated_print"))["locations"][0]["corroborated_calls"]
    assert not extract(_binary(tmp_path, callee=panic, clobber=True))["locations"][0]["corroborated_calls"]


@pytest.mark.parametrize("argument", ["rsi", "rcx", "edx"])
def test_wrong_argument_or_truncated_pointer_is_not_corroborated(tmp_path, argument):
    panic = "_ZN4core9panicking18panic_bounds_check17h0123456789abcdefE"
    result = _module().extract_locations(_binary(tmp_path, callee=panic, argument=argument))
    assert not result["locations"][0]["corroborated_calls"]


def test_a_name_containing_core_and_panic_is_not_a_rust_helper(tmp_path):
    result = _module().extract_locations(_binary(tmp_path, callee="fake4core_panic_bounds_check"))
    assert not result["locations"][0]["corroborated_calls"]


@pytest.mark.parametrize("arguments", [
    {"writable_path": True}, {"writable_record": True}, {"relocate": False},
    {"line": 0}, {"column": 0}, {"line": 2**32 - 1}, {"length_delta": 1},
    {"path": "external/rust/android-crates-io/crates/example/../lib.rs"},
    {"path": "external/rust/android-crates-io/crates/example/src/lib.rsTRAILER"},
    {"path": "external/rust/android-crates-io/crates/example/src/lib.c"},
    {"path": "/home/user/.cargo/registry/src/example-1.2.3/src/lib.rs"},
])
def test_unproven_or_malformed_records_are_not_features(tmp_path, arguments):
    assert _module().extract_locations(_binary(tmp_path, **arguments))["locations"] == []


def test_malformed_input_is_bounded_and_empty():
    for raw in (b"", b"not ELF", b"\x7fELF" + b"\0" * 128):
        result = _module().extract_locations(raw)
        assert not result["locations"]
        assert result["status"] in ("unsupported", "invalid")
