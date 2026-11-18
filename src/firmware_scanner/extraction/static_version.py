"""Conservative static extraction from known version getter functions in ELF files.

This module never loads or executes firmware code. It follows only a small set of
straight-line return-pointer instruction sequences and rejects everything else.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from io import BytesIO

from capstone import (
    CS_ARCH_ARM64,
    CS_ARCH_X86,
    CS_MODE_64,
    CS_MODE_LITTLE_ENDIAN,
    Cs,
    CsError,
)
from capstone.arm64 import (
    ARM64_INS_ADD,
    ARM64_INS_ADR,
    ARM64_INS_ADRP,
    ARM64_INS_LDR,
    ARM64_INS_RET,
)
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG
from capstone.x86 import (
    X86_INS_ENDBR64,
    X86_INS_LEA,
    X86_INS_NOP,
    X86_INS_RET,
    X86_OP_MEM,
    X86_OP_REG,
)
from elftools.elf.constants import P_FLAGS

try:
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:  # pyelftools is optional in the existing project dependency set.
    ELFError = Exception
    ELFFile = None
    SymbolTableSection = ()


@dataclass(frozen=True)
class StaticVersionMatch:
    name: str
    version: str
    evidence: str
    confidence: float = 0.95


_GETTERS: dict[str, tuple[str, str]] = {
    "LZ4_versionString": ("LZ4", "direct"),
    "ZSTD_versionString": ("zstd", "direct"),
    "hb_version_string": ("HarfBuzz", "direct"),
    "sqlite3_libversion": ("SQLite", "direct"),
    "pcap_lib_version": ("libpcap", "prefixed"),
    "cJSON_Version": ("cJSON", "direct"),
    "uv_version_string": ("libuv", "direct"),
    "opus_get_version_string": ("Opus", "prefixed"),
}
_VERSION = re.compile(r"v?(\d+\.\d+(?:\.\d+)*[A-Za-z0-9.+_-]*)\Z")


def _vaddr_to_offset(
    load_segments: list[tuple[int, int, int, int]],
    address: int,
    size: int,
    *,
    executable: bool = False,
) -> int | None:
    """Map a VA only when the complete range is backed by bytes in a PT_LOAD."""
    for vaddr, offset, filesz, flags in load_segments:
        if executable and not flags & P_FLAGS.PF_X:
            continue
        if vaddr <= address and address + size <= vaddr + filesz:
            return offset + (address - vaddr)
    return None


def _version_from_text(name: str, style: str, text: str) -> str | None:
    value = text.strip()
    if style == "prefixed":
        prefixes = {
            "libpcap": r"libpcap version\s+",
            "Opus": r"libopus\s+",
        }
        prefix = prefixes[name]
        match = re.match(prefix + r"(v?\d+\.\d+(?:\.\d+)*[A-Za-z0-9.+_-]*)", value, re.IGNORECASE)
        return match.group(1) if match else None
    match = _VERSION.fullmatch(value)
    return match.group(0) if match else None


class StaticVersionExtractor:
    """Extract versions exposed by a known getter with a provable pointer return."""

    def extract(self, data: bytes) -> list[StaticVersionMatch]:
        if (ELFFile is None or not isinstance(data, bytes) or len(data) < 64
                or data[:4] != b"\x7fELF"):
            return []
        if not any(name.encode('ascii') in data for name in _GETTERS):
            return []
        try:
            elf = ELFFile(BytesIO(data))
            machine = elf.header["e_machine"]
            if machine == "EM_AARCH64" and elf.elfclass == 64 and elf.little_endian:
                architecture = "aarch64"
                disassembler = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
                disassembler.detail = True
            elif machine == "EM_X86_64" and elf.elfclass == 64 and elf.little_endian:
                architecture = "x86_64"
                disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
                disassembler.detail = True
            else:
                return []

            load_segments = [
                (
                    int(segment["p_vaddr"]),
                    int(segment["p_offset"]),
                    int(segment["p_filesz"]),
                    int(segment["p_flags"]),
                )
                for segment in elf.iter_segments()
                if segment["p_type"] == "PT_LOAD"
            ]
            functions: dict[str, tuple[int, int]] = {}
            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                for symbol in section.iter_symbols():
                    if symbol.name not in _GETTERS or symbol["st_info"]["type"] != "STT_FUNC":
                        continue
                    if not symbol["st_shndx"] or symbol["st_shndx"] == "SHN_UNDEF":
                        continue
                    address = int(symbol["st_value"])
                    size = int(symbol["st_size"])
                    if 0 < size <= 256:
                        functions.setdefault(symbol.name, (address, size))

            matches: list[StaticVersionMatch] = []
            for getter, (address, size) in functions.items():
                component, style = _GETTERS[getter]
                code_offset = _vaddr_to_offset(load_segments, address, size, executable=True)
                if code_offset is None or code_offset + size > len(data):
                    continue
                code = data[code_offset:code_offset + size]
                result_pointer = self._returned_pointer(disassembler, architecture, code, address)
                if result_pointer is None:
                    continue
                pointer, is_literal = result_pointer
                if is_literal:
                    pointer_size = 8 if architecture == "aarch64" else 4
                    literal_offset = _vaddr_to_offset(load_segments, pointer, pointer_size)
                    if literal_offset is None or literal_offset + pointer_size > len(data):
                        continue
                    pointer = int.from_bytes(data[literal_offset:literal_offset + pointer_size], "little")
                text = self._read_c_string(data, load_segments, pointer)
                if text is None:
                    continue
                version = _version_from_text(component, style, text)
                if version is None:
                    continue
                string_offset = _vaddr_to_offset(load_segments, pointer, len(text) + 1)
                if string_offset is None:
                    continue
                evidence = (
                    f"defined function {getter} at VA 0x{address:x} returns a pointer to "
                    f"NUL-terminated string at VA 0x{pointer:x} (file offset 0x{string_offset:x}): "
                    f"{text!r}; straight-line {architecture} return path"
                )
                matches.append(StaticVersionMatch(component, version, evidence))
            return matches
        except (ELFError, CsError, OSError, ValueError, TypeError, KeyError, IndexError,
                struct.error, OverflowError):
            return []

    @staticmethod
    def _read_c_string(
        data: bytes, load_segments: list[tuple[int, int, int, int]], address: int
    ) -> str | None:
        offset = _vaddr_to_offset(load_segments, address, 1)
        if offset is None:
            return None
        limit = min(len(data), offset + 4097)
        end = data.find(b"\0", offset, limit)
        if end < 0 or end == offset:
            return None
        raw = data[offset:end]
        if any(byte < 0x20 or byte > 0x7e for byte in raw):
            return None
        return raw.decode("ascii")

    @staticmethod
    def _returned_pointer(
        disassembler: Cs, architecture: str, code: bytes, address: int
    ) -> tuple[int, bool] | None:
        instructions = list(disassembler.disasm(code, address))
        if not instructions or sum(insn.size for insn in instructions) != len(code):
            return None

        if architecture == "aarch64":
            return StaticVersionExtractor._aarch64_pointer(instructions)
        return StaticVersionExtractor._x86_64_pointer(instructions)

    @staticmethod
    def _x86_64_pointer(instructions) -> tuple[int, bool] | None:
        pointer: int | None = None
        for index, insn in enumerate(instructions):
            if insn.id in (X86_INS_ENDBR64, X86_INS_NOP):
                continue
            if insn.id == X86_INS_LEA and pointer is None:
                operands = insn.operands
                if (len(operands) != 2 or operands[0].type != X86_OP_REG
                        or insn.reg_name(operands[0].reg) != "rax" or operands[1].type != X86_OP_MEM
                        or insn.reg_name(operands[1].mem.base) != "rip"
                        or operands[1].mem.index != 0 or operands[1].mem.scale != 1):
                    return None
                pointer = insn.address + insn.size + int(operands[1].mem.disp)
                continue
            if insn.id == X86_INS_RET and index == len(instructions) - 1 and pointer is not None:
                return pointer, False
            return None
        return None

    @staticmethod
    def _aarch64_pointer(instructions) -> tuple[int, bool] | None:
        base: int | None = None
        pointer: int | None = None
        literal = False
        for index, insn in enumerate(instructions):
            operands = insn.operands
            if insn.id == ARM64_INS_RET:
                if index != len(instructions) - 1 or base is not None or pointer is None:
                    return None
                return pointer, literal
            if index == len(instructions) - 1:
                return None

            if insn.id == ARM64_INS_ADR and len(operands) == 2 and operands[0].type == ARM64_OP_REG:
                if insn.reg_name(operands[0].reg) != "x0" or operands[1].type != ARM64_OP_IMM or pointer is not None:
                    return None
                pointer = int(operands[1].imm)
                continue
            if insn.id == ARM64_INS_ADRP and len(operands) == 2 and operands[0].type == ARM64_OP_REG:
                if insn.reg_name(operands[0].reg) != "x0" or operands[1].type != ARM64_OP_IMM or pointer is not None:
                    return None
                base = int(operands[1].imm)
                continue
            if insn.id == ARM64_INS_ADD and len(operands) >= 3:
                if (operands[0].type != ARM64_OP_REG or insn.reg_name(operands[0].reg) != "x0"
                        or operands[1].type != ARM64_OP_REG or insn.reg_name(operands[1].reg) != "x0"
                        or operands[2].type != ARM64_OP_IMM or base is None or pointer is not None):
                    return None
                pointer = base + int(operands[2].imm)
                base = None
                continue
            if insn.id == ARM64_INS_LDR and len(operands) == 2 and operands[0].type == ARM64_OP_REG:
                if insn.reg_name(operands[0].reg) != "x0" or operands[1].type != ARM64_OP_IMM or pointer is not None:
                    return None
                # The literal is an address holding the pointer, not the string itself.
                pointer = int(operands[1].imm)
                literal = True
                continue
            return None
        return None
