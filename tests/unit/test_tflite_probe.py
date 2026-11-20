from __future__ import annotations

import hashlib
import mmap
import struct
import sys
import zipfile
from io import BytesIO
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

sys.path.insert(0, str(Path(__file__).parents[2] / "experiments/version_coverage"))

from tflite_probe import inspect_elf

from firmware_scanner.android.archive_reader import FilesystemFile
from firmware_scanner.android.ext4_reader import Ext4Reader

IMAGE = Path("/home/kali/Desktop/work/project/vulnscan/system.img")
APK = "/product/priv-app/Tubesky/Tubesky.apk"
ABIS = {
    "arm64-v8a": "709f663f8b3e0fe7379bab60e68914256f086856d9496d15bc162b84317a4c45",
    "armeabi-v7a": "910568efea783379985f6ec27f3961701f437a195c1964be5eaded291d6be291",
    "x86": "a10b9161a2e51f6bdfd3bfb24eb4442b71c867e061572f72493934c40280fc04",
    "x86_64": "b0537d6cbc203291ed8aebfe8d4a4e76a6ec4f224357296e825819f7488fc02d",
}


def _read_targets() -> dict[str, bytes]:
    if not IMAGE.is_file():
        pytest.skip("Tubesky system image unavailable")
    result = {}
    with (
        IMAGE.open("rb") as source,
        mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mapped,
    ):
        fs = Ext4Reader(mapped)
        assert fs.is_valid()
        with FilesystemFile(fs, APK) as apk_stream, zipfile.ZipFile(apk_stream) as apk:
            for abi in ABIS:
                result[abi] = apk.read(f"lib/{abi}/libtensorflowlite_jni.so")
    return result


def _offset_for_vaddr(elf: ELFFile, address: int) -> int:
    segment = next(
        s
        for s in elf.iter_segments()
        if int(s["p_vaddr"]) <= address < int(s["p_vaddr"]) + int(s["p_filesz"])
    )
    return int(segment["p_offset"]) + address - int(segment["p_vaddr"])


def _mutate_vaddr(data: bytes, address: int, replacement: bytes) -> bytes:
    changed = bytearray(data)
    offset = _offset_for_vaddr(ELFFile(BytesIO(data)), address)
    changed[offset : offset + len(replacement)] = replacement
    return bytes(changed)


def test_real_runtime_version_jni_proves_same_runtime_version_for_all_abis():
    binaries = _read_targets()
    assert set(binaries) == set(ABIS)
    for abi, binary in binaries.items():
        assert hashlib.sha256(binary).hexdigest() == ABIS[abi]
        result = inspect_elf(binary)
        assert result["status"] == "matched"
        assert result["version"] == "2.22.0"
        assert result["proof"]["field"] == "tflite_runtime_version"
        assert result["proof"]["artifact_version"] is None


def test_product_emits_runtime_component_without_versioning_jni_artifact():
    import json

    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    data = _read_targets()["x86_64"]
    components = BinaryInventory().extract(
        data, "libtensorflowlite_jni.so", "/lib/libtensorflowlite_jni.so"
    )
    assert components[0].resolved_version == ""
    runtime = next(c for c in components if c.name == "TensorFlowLite-runtime")
    assert runtime.resolved_version == "2.22.0"
    assert {"name": "firmware:version:kind", "value": "runtime"} in runtime.properties
    assert all(json.loads(v.evidence)["artifact_version"] is None for v in runtime.versions)


def test_thumb_writable_address_pool_cannot_prove_runtime_version():
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    data = bytearray(_read_targets()["armeabi-v7a"])
    # Split the original RX mapping around the helper's address pool. The
    # version bytes remain RX: only the delta used to form their pointer is RWX.
    for index, offset, size, flags in [
        (1, 0, 0x1C000, 5),
        (6, 0x1C000, 0x4000, 7),
        (7, 0x20000, 0x7B790 - 0x20000, 5),
    ]:
        struct.pack_into(
            "<8I", data, 52 + 32 * index, 1, offset, offset, offset, size, size, flags, 0x4000
        )
    binary = bytes(data)
    assert inspect_elf(binary)["status"] == "rejected-unproven"
    components = BinaryInventory().extract(
        binary, "libtensorflowlite_jni.so", "/lib/libtensorflowlite_jni.so"
    )
    assert not any(c.name == "TensorFlowLite-runtime" and c.resolved_version for c in components)


def test_unknown_branch_or_register_write_cannot_supply_runtime_version():
    binary = bytearray(_read_targets()["x86_64"])
    elf = ELFFile(BytesIO(binary))
    helper = 0x43B20
    start = _offset_for_vaddr(elf, helper)

    branch = bytearray(binary)
    branch[start : start + 8] = b"\x75\x01\xc3\xc3\x90\x90\x90\x90"
    assert inspect_elf(bytes(branch))["status"] == "rejected-unproven"

    unknown_write = bytearray(binary)
    unknown_write[start : start + 8] = b"\x31\xc0\xc3\x90\x90\x90\x90\x90"
    assert inspect_elf(bytes(unknown_write))["status"] == "rejected-unproven"


def test_arm_return_and_epilogue_cannot_redirect_or_overwrite_version_argument():
    from io import BytesIO

    binaries = _read_targets()
    controls = [
        ("arm64-v8a", 0x38B94, "00005fd6"),  # ret x0, instead of LR
        ("arm64-v8a", 0x2AF34, "e14fc1a8"),  # ldp x1,x19 overwrites bytes arg
        ("armeabi-v7a", 0x13A7A, "bde81240"),  # pop.w r1,r4,lr overwrites bytes arg
    ]
    for abi, address, replacement in controls:
        data = binaries[abi]
        offset = _offset_for_vaddr(ELFFile(BytesIO(data)), address)
        mutant = bytearray(data)
        raw = bytes.fromhex(replacement)
        mutant[offset : offset + len(raw)] = raw
        assert inspect_elf(bytes(mutant))["status"] == "rejected-unproven"


def test_imported_helper_and_unrelated_version_literal_are_not_mistaken_for_runtime():
    binary = bytearray(_read_targets()["x86_64"])
    elf = ELFFile(BytesIO(binary))
    helper = 0x43B20
    start = _offset_for_vaddr(elf, helper)
    rel_plt = next(
        s for s in elf.iter_sections() if isinstance(s, RelocationSection) and s.name == ".rela.plt"
    )
    plt = next(s for s in elf.iter_sections() if s.name == ".plt")
    imported_stub = int(plt["sh_addr"]) + 16  # first imported PLT entry after the resolver slot

    imported = bytearray(binary)
    displacement = imported_stub - (helper + 5)
    imported[start : start + 8] = (
        b"\xe9" + displacement.to_bytes(4, "little", signed=True) + b"\xc3\x90\x90"
    )
    assert rel_plt.num_relocations() > 0
    assert inspect_elf(bytes(imported))["status"] == "rejected-unproven"

    # Add a semver-shaped string in writable data, with no code reference to it.
    data_segment = next(
        s
        for s in elf.iter_segments()
        if s["p_type"] == "PT_LOAD" and int(s["p_flags"]) & 2 and int(s["p_filesz"]) >= 16
    )
    data_offset = int(data_segment["p_offset"]) + int(data_segment["p_filesz"]) - 8
    unrelated = bytearray(binary)
    unrelated[data_offset : data_offset + 8] = b"9.99.9\0\0"
    result = inspect_elf(bytes(unrelated))
    assert result["status"] == "matched"
    assert result["version"] == "2.22.0"


def test_jni_receiver_table_target_and_return_register_must_have_exact_provenance():
    binary = _read_targets()["x86_64"]
    # Return value must remain in RAX until copied to RSI, and JNIEnv's own
    # table slot must supply the exact target eventually reached by JMP RCX.
    assert (
        inspect_elf(_mutate_vaddr(binary, 0x362DF, bytes.fromhex("4889de")))["status"]
        == "rejected-unproven"
    )
    assert (
        inspect_elf(_mutate_vaddr(binary, 0x362D2, bytes.fromhex("488b0e")))["status"]
        == "rejected-unproven"
    )
    assert (
        inspect_elf(_mutate_vaddr(binary, 0x362D5, bytes.fromhex("488b8930050000")))["status"]
        == "rejected-unproven"
    )
    assert (
        inspect_elf(_mutate_vaddr(binary, 0x362E3, bytes.fromhex("ffe0")))["status"]
        == "rejected-unproven"
    )
    # Returning before the version helper invalidates the whole JNI path.
    assert (
        inspect_elf(_mutate_vaddr(binary, 0x362CD, bytes.fromhex("c390909090")))["status"]
        == "rejected-unproven"
    )


def test_x86_helper_requires_exact_stack_restore_and_unindexed_literal_address():
    binary = _read_targets()["x86"]
    assert (
        inspect_elf(_mutate_vaddr(binary, 0x39E78, bytes.fromhex("89c4")))["status"]
        == "rejected-unproven"
    )
    # Turn LEA EAX,[EAX+disp32] into LEA EAX,[EAX+EAX+disp24].
    assert (
        inspect_elf(_mutate_vaddr(binary, 0x39E72, bytes.fromhex("8d8400e69cf0")))["status"]
        == "rejected-unproven"
    )
