"""Recognize the IJG JPEG ABI guard used by historical Android libjpeg."""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from io import BytesIO

from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_X86,
    CS_MODE_64,
    CS_MODE_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_THUMB,
    Cs,
    CsError,
)
from capstone.arm import ARM_OP_IMM
from capstone.arm64 import ARM64_OP_IMM
from capstone.x86 import X86_OP_IMM
from elftools.common.exceptions import ELFError
from elftools.elf.constants import P_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

_SOURCE = "https://android.googlesource.com/platform/external/jpeg/+/android-4.4.4_r2/jpeglib.h"
_ABI_RELEASES = {
    62: "62",
}
_REQUIRED_SYMBOLS = {"jpeg_CreateDecompress", "jpeg_read_header"}
_LIBJPEG_TURBO_BANNER = re.compile(rb"libjpeg-turbo(?:\s+version)?", re.IGNORECASE)


@dataclass(frozen=True)
class JpegAbiEvidence:
    abi_version: int
    evidence: str
    confidence: float = 0.97


def extract_jpeg_abi_evidence(data: bytes) -> JpegAbiEvidence | None:
    """Extract the libjpeg ABI guard without claiming an implementation release."""
    if (
        not data.startswith(b"\x7fELF")
        or b"jpeg_CreateDecompress\0" not in data
        or _LIBJPEG_TURBO_BANNER.search(data)
    ):
        return None
    try:
        image = ELFFile(BytesIO(data))
        symbols = _defined_functions(image)
        if not _REQUIRED_SYMBOLS.issubset(symbols):
            return None
        address, size = symbols["jpeg_CreateDecompress"]
        function = _function_bytes(image, data, address, size)
        if function is None:
            return None
        code, function_offset = function
        guard = _abi_guard(image, code, address)
        if guard is None:
            return None
        abi, guard_offset = guard
        abi_label = _ABI_RELEASES.get(abi)
        if abi_label is None:
            return None
        evidence = json.dumps(
            {
                "probe": "ijg-jpeg-abi-guard-v1",
                "abi_version": abi,
                "abi_label": abi_label,
                "release_semantics": "abi-compatibility-not-implementation-release",
                "function": "jpeg_CreateDecompress",
                "function_vaddr": hex(address),
                "function_file_offset": function_offset,
                "guard_file_offset": function_offset + guard_offset,
                "required_symbols": sorted(_REQUIRED_SYMBOLS),
                "identifier_type": "documented-abi-to-release",
                "source": _SOURCE,
            },
            sort_keys=True,
        )
        return JpegAbiEvidence(abi, evidence)
    except (
        ELFError,
        CsError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        struct.error,
        OverflowError,
    ):
        return None


def _defined_functions(image: ELFFile) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for section in image.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            if (
                symbol.name not in _REQUIRED_SYMBOLS
                or symbol["st_info"]["type"] != "STT_FUNC"
                or not symbol["st_shndx"]
                or symbol["st_shndx"] == "SHN_UNDEF"
            ):
                continue
            size = int(symbol["st_size"])
            if 0 < size <= 1024:
                result.setdefault(symbol.name, (int(symbol["st_value"]), size))
    return result


def _function_bytes(
    image: ELFFile,
    data: bytes,
    address: int,
    size: int,
) -> tuple[bytes, int] | None:
    for segment in image.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not int(segment["p_flags"]) & P_FLAGS.PF_X:
            continue
        start = int(segment["p_vaddr"])
        delta = address - start
        if 0 <= delta and delta + size <= int(segment["p_filesz"]):
            offset = int(segment["p_offset"]) + delta
            if offset + size <= len(data):
                return data[offset : offset + size], offset
    return None


def _abi_guard(
    image: ELFFile,
    code: bytes,
    address: int,
) -> tuple[int, int] | None:
    machine = image.header["e_machine"]
    if machine == "EM_ARM" and image.elfclass == 32:
        thumb = bool(address & 1)
        disassembler = Cs(
            CS_ARCH_ARM,
            (CS_MODE_THUMB if thumb else CS_MODE_ARM) | CS_MODE_LITTLE_ENDIAN,
        )
        code_address = address & ~1
        immediate_type = ARM_OP_IMM
    elif machine == "EM_AARCH64" and image.elfclass == 64:
        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        code_address = address
        immediate_type = ARM64_OP_IMM
    elif machine == "EM_X86_64" and image.elfclass == 64:
        disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        code_address = address
        immediate_type = X86_OP_IMM
    else:
        return None
    disassembler.detail = True
    for instruction in disassembler.disasm(code, code_address):
        if instruction.mnemonic not in {"cmp", "sub", "subs"}:
            continue
        for operand in instruction.operands:
            if operand.type != immediate_type:
                continue
            value = int(operand.imm)
            if value in _ABI_RELEASES:
                return value, instruction.address - code_address
    return None
