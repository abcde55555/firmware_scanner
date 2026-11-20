from __future__ import annotations

import mmap
from pathlib import Path
from types import SimpleNamespace

import pytest
from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

from firmware_scanner.android.ext4_reader import Ext4Reader
from firmware_scanner.extraction.protobuf_version import (
    _arm_value,
    classify_version_roles,
    inspect_elf,
    recover_arm_version,
    recover_x86_32_version,
)
from firmware_scanner.extraction.semantic_version import ELFView

ROOT = Path(__file__).parents[2]
ALLWINNER_IMAGE = ROOT / "reports/accuracy-20261118/evidence/allwinner-system.img"
X86_IMAGE = Path("/home/kali/Desktop/work/project/vulnscan/system.img")


def _file_offset(image: ELFView, address: int) -> int:
    segment = next(
        s
        for s in image.loads
        if int(s["p_vaddr"]) <= address < int(s["p_vaddr"]) + int(s["p_filesz"])
    )
    return int(segment["p_offset"]) + address - int(segment["p_vaddr"])


def _read_ext4_file(image_path: Path, path: str, max_size: int = 64 * 1024 * 1024) -> bytes:
    with (
        image_path.open("rb") as source,
        mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data,
    ):
        reader = Ext4Reader(data)
        assert reader.is_valid()
        result = reader.read_file(path, max_size=max_size)
        assert result is not None
        return result


def test_version_roles_keep_header_and_minimum_distinct():
    roles = classify_version_roles(3006001, 3005000, 3004000)
    assert roles == {
        "header_version": "3.6.1",
        "min_library_version": "3.5.0",
        "library_version": "unknown",
        "min_header_version": "3.4.0",
    }


def test_arm_rejects_header_version_as_library_version():
    proof = SimpleNamespace(
        comparison_role="min_header_version",
        comparison_constant=3005000,
        version_string_inputs=(3006001, 3006001),
        failure_messages=("compiled against version", "installed version"),
    )
    assert recover_arm_version(proof) is None


def test_arm_accepts_library_constant_on_minimum_library_failure_edge():
    proof = SimpleNamespace(
        comparison_role="min_library_version",
        comparison_constant=3006001,
        version_string_inputs=("min_library_version", 3006001),
        failure_messages=("This program requires version", "installed version"),
        failure_edge=True,
        architecture="arm-thumb",
        function_vaddr=0x1001,
    )
    result = recover_arm_version(proof)
    assert result == {"version": "3.6.1", "library_version": 3006001, "function_vaddr": "0x1000"}


def test_x86_32_rejects_unknown_or_unproven_function():
    assert recover_x86_32_version(None) is None
    assert (
        recover_x86_32_version(
            SimpleNamespace(
                comparison_role="min_library_version",
                comparison_constant=3005000,
                version_string_inputs=("min_library_version", 3005000),
                failure_messages=("requires version", "installed version"),
                failure_edge=False,
                architecture="x86-32",
                function_vaddr=0x8049000,
            )
        )
        is None
    )


def test_x86_32_accepts_proven_installed_library_constant():
    result = recover_x86_32_version(
        SimpleNamespace(
            comparison_role="min_library_version",
            comparison_constant=3021012,
            comparison_boundary=3021013,
            version_string_inputs=("min_library_version", 3021012),
            failure_messages=("This program requires version", "installed version is"),
            failure_edge=True,
            architecture="x86-32",
            function_vaddr=0x105050,
        )
    )
    assert result == {
        "version": "3.21.12",
        "library_version": 3021012,
        "function_vaddr": "0x105050",
    }


def test_x86_32_rejects_header_value_even_when_version_string_calls_match():
    assert (
        recover_x86_32_version(
            SimpleNamespace(
                comparison_role="min_header_version",
                comparison_constant=3021012,
                version_string_inputs=("header_version", 3021012),
                failure_messages=("This program requires version", "installed version is"),
                failure_edge=True,
                architecture="x86-32",
                function_vaddr=0x105050,
            )
        )
        is None
    )


def test_x86_32_requires_library_constant_to_match_failure_threshold():
    assert (
        recover_x86_32_version(
            SimpleNamespace(
                comparison_role="min_library_version",
                comparison_constant=3021012,
                comparison_boundary=3021014,
                version_string_inputs=("min_library_version", 3021012),
                failure_messages=("This program requires version", "installed version is"),
                failure_edge=True,
                architecture="x86-32",
                function_vaddr=0x105050,
            )
        )
        is None
    )


@pytest.mark.skipif(not ALLWINNER_IMAGE.is_file(), reason="Allwinner ext4 fixture unavailable")
def test_real_thumb_unconditional_branch_mutation_loses_failure_proof():
    elf = _read_ext4_file(ALLWINNER_IMAGE, "/lib/libGLES_trace.so")
    original = inspect_elf(elf)
    assert original["status"] == "matched"
    assert original["version"] == "2.3.0"
    assert original["proof"]["branch_vaddr"] == 0x44BAA
    assert original["proof"]["failure_block_vaddr"] == 0x44BAC

    image = ELFView(elf)
    offset = _file_offset(image, 0x44BAA)
    assert elf[offset : offset + 2] == bytes.fromhex("3bdd")
    mutated = bytearray(elf)
    mutated[offset : offset + 2] = bytes.fromhex("3be0")
    rejected = inspect_elf(bytes(mutated))
    assert rejected["status"] == "rejected-unproven"

    wrong_relation = bytearray(elf)
    wrong_relation[offset : offset + 2] = bytes.fromhex("3bd1")  # bne to the same target
    assert inspect_elf(bytes(wrong_relation))["status"] == "rejected-unproven"

    failure_branch = bytearray(elf)
    failure_offset = _file_offset(image, 0x44BAC)
    failure_branch[failure_offset : failure_offset + 2] = bytes.fromhex("00e0")
    assert inspect_elf(bytes(failure_branch))["status"] == "rejected-unproven"


def test_thumb_conditional_write_and_branch_do_not_leak_linear_state():
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    instructions = list(decoder.disasm(bytes.fromhex("18bf01469142"), 0x1000))
    assert [i.mnemonic for i in instructions] == ["it", "movne", "cmp"]
    _state, compares = _arm_value(object(), instructions, 2, thumb=True)
    assert compares[-1][1] is None

    branched = list(decoder.disasm(bytes.fromhex("00e09142"), 0x2000))
    state, compares = _arm_value(object(), branched, len(branched) - 1, thumb=True)
    assert state == {}
    assert compares == []


@pytest.mark.skipif(not X86_IMAGE.is_file(), reason="x86 ext4 fixture unavailable")
def test_real_x86_32_library_compare_threshold_is_constant_plus_one():
    elf = _read_ext4_file(X86_IMAGE, "/system/lib/libprotobuf-cpp-full.so")
    result = inspect_elf(elf)
    assert result["status"] == "matched"
    proof = result["proof"]
    assert proof["comparison_boundary"] == proof["comparison_constant"] + 1
    assert proof["comparison_instruction"] == "cmp edi, 0x2e18d5"

    image = ELFView(elf)
    compare = next(i for i in image.instructions(0x105050, 692) if i.address == 0x105071)
    assert compare.mnemonic == "cmp"
    offset = _file_offset(image, compare.address) + 2
    mutant = bytearray(elf)
    mutant[offset : offset + 4] = (3021014).to_bytes(4, "little")
    assert inspect_elf(bytes(mutant))["status"] == "rejected-unproven"


@pytest.mark.skipif(not ALLWINNER_IMAGE.is_file(), reason="Allwinner ext4 fixture unavailable")
def test_real_thumb_entry_return_and_failure_block_register_clobber_reject():
    elf = _read_ext4_file(ALLWINNER_IMAGE, "/lib/libGLES_trace.so")
    assert inspect_elf(elf)["version"] == "2.3.0"
    image = ELFView(elf)
    entry = image.functions["_ZN6google8protobuf8internal13VerifyVersionEiiPKc"][0] & ~1
    early = bytearray(elf)
    offset = _file_offset(image, entry)
    early[offset : offset + 2] = bytes.fromhex("7047")  # bx lr
    assert inspect_elf(bytes(early))["status"] == "rejected-unproven"

    popped = bytearray(elf)
    popped[offset : offset + 2] = bytes.fromhex("00bd")  # pop {pc}
    assert inspect_elf(bytes(popped))["status"] == "rejected-unproven"

    clobbered = bytearray(elf)
    # Replace `mov r1, r7` before installed-VersionString with `ldr r7,[r0]`.
    clobber_offset = _file_offset(image, 0x44BE2)
    assert elf[clobber_offset : clobber_offset + 2] == bytes.fromhex("3946")
    clobbered[clobber_offset : clobber_offset + 2] = bytes.fromhex("0768")
    assert inspect_elf(bytes(clobbered))["status"] == "rejected-unproven"


@pytest.mark.skipif(not X86_IMAGE.is_file(), reason="x86 ext4 fixture unavailable")
def test_real_x86_32_entry_return_and_unframed_ebp_argument_reject():
    elf = _read_ext4_file(X86_IMAGE, "/system/lib/libprotobuf-cpp-lite.so")
    assert inspect_elf(elf)["version"] == "3.21.12"
    image = ELFView(elf)
    entry = image.functions["_ZN6google8protobuf8internal13VerifyVersionEiiPKc"][0]
    offset = _file_offset(image, entry)
    assert elf[offset : offset + 3] == bytes.fromhex("5589e5")

    returned = bytearray(elf)
    returned[offset] = 0xC3  # ret
    assert inspect_elf(bytes(returned))["status"] == "rejected-unproven"

    no_frame = bytearray(elf)
    no_frame[offset : offset + 3] = bytes.fromhex("909090")
    assert inspect_elf(bytes(no_frame))["status"] == "rejected-unproven"
