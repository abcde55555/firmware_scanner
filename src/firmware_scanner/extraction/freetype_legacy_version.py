"""Read-only FreeType version recovery from paired ARM32 library APIs."""

from __future__ import annotations

import json
from io import BytesIO

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, Cs, CsError
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from firmware_scanner.extraction.static_version import StaticVersionMatch

_GETTER = "FT_Library_Version"
_INITIALIZER = "FT_New_Library"
_UPSTREAM_SOURCE = (
    "https://android.googlesource.com/platform/external/freetype/"
    "+/android-4.4.4_r1/include/freetype/freetype.h"
)


class _Image:
    def __init__(self, data: bytes):
        self.data = data
        self.elf = ELFFile(BytesIO(data))
        if (
            self.elf.header["e_machine"] != "EM_ARM"
            or self.elf.elfclass != 32
            or not self.elf.little_endian
        ):
            raise ValueError("unsupported FreeType ABI")
        self.loads = [
            (int(segment["p_vaddr"]), int(segment["p_offset"]), int(segment["p_filesz"]))
            for segment in self.elf.iter_segments()
            if segment["p_type"] == "PT_LOAD"
        ]
        self.functions: dict[str, tuple[int, int]] = {}
        self.names_at: dict[int, set[str]] = {}
        self._read_symbols()
        self.disassembler = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        self.disassembler.detail = True

    def _read_symbols(self) -> None:
        found: dict[str, set[tuple[int, int]]] = {}
        for section in self.elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if symbol["st_info"]["type"] != "STT_FUNC":
                    continue
                if symbol["st_shndx"] in ("SHN_UNDEF", 0):
                    continue
                if symbol["st_info"]["bind"] not in ("STB_GLOBAL", "STB_WEAK"):
                    continue
                address = int(symbol["st_value"])
                size = int(symbol["st_size"])
                if not symbol.name or address & 1 or not 0 < size <= 4096:
                    continue
                found.setdefault(symbol.name, set()).add((address, size))
                self.names_at.setdefault(address, set()).add(symbol.name)
        for name, definitions in found.items():
            if len(definitions) == 1:
                self.functions[name] = next(iter(definitions))

    def function(self, name: str):
        address, size = self.functions[name]
        for vaddr, offset, filesz in self.loads:
            if not vaddr <= address and address + size <= vaddr + filesz:
                continue
            start = offset + address - vaddr
            raw = self.data[start : start + size]
            if len(raw) != size:
                return None
            instructions = list(self.disassembler.disasm(raw, address))
            if not instructions or sum(item.size for item in instructions) != size:
                return None
            return address, instructions
        return None


def _instruction_text(instructions) -> list[str]:
    return [f"{instruction.mnemonic} {instruction.op_str}".strip() for instruction in instructions]


def _verify_getter(instructions) -> bool:
    return _instruction_text(instructions) == [
        "cmp r0, #0",
        "str r4, [sp, #-4]!",
        "ldmibne r0, {r4, ip}",
        "moveq ip, r0",
        "ldrne r0, [r0, #0xc]",
        "moveq r4, r0",
        "cmp r1, #0",
        "strne r4, [r1]",
        "cmp r2, #0",
        "strne ip, [r2]",
        "cmp r3, #0",
        "strne r0, [r3]",
        "ldm sp!, {r4}",
        "bx lr",
    ]


def _verify_initializer(image: _Image, instructions) -> list[str] | None:
    text = _instruction_text(instructions)
    allocator_symbols = []
    for index, instruction in enumerate(instructions[:-1]):
        if instruction.mnemonic not in ("bl", "blx"):
            continue
        if not instruction.operands or not isinstance(instruction.operands[0].imm, int):
            continue
        target = int(instruction.operands[0].imm)
        allocator_symbols.extend(
            name
            for name in image.names_at.get(target, ())
            if name.startswith(("FT_Memory_Alloc", "ft_mem_alloc", "ft_mem_qalloc"))
        )
    if not allocator_symbols:
        return None

    prefix = [
        "push {r4, r5, r6, r7, lr}",
        "subs r6, r0, #0",
        "sub sp, sp, #0xc",
        "mov r7, r1",
        "moveq r4, #6",
        "beq #0xe400",
        "mov r1, #0xc0",
        "add r2, sp, #4",
    ]
    if text[: len(prefix)] != prefix:
        return None
    version_sequence = [
        "mov r1, #2",
        "mov r2, #4",
        "mov r3, #0xc",
        "mov r0, #1",
        "stmib r5, {r1, r2, r3}",
        "str r0, [r5, #0xbc]",
        "str r5, [r7]",
    ]
    for start in range(8, len(text) - len(version_sequence) + 1):
        if text[start : start + len(version_sequence)] == version_sequence:
            exit_index = start + len(version_sequence)
            if exit_index >= len(instructions) or instructions[exit_index].mnemonic != "b":
                return None
            return sorted(set(allocator_symbols))
    return None


def extract_freetype_legacy_version(data: bytes) -> list[StaticVersionMatch]:
    """Return a version only when the paired FreeType APIs expose one release."""
    if not isinstance(data, bytes) or len(data) < 64 or data[:4] != b"\x7fELF":
        return []
    try:
        image = _Image(data)
        if _GETTER not in image.functions or _INITIALIZER not in image.functions:
            return []
        getter_address, getter_instructions = image.function(_GETTER)
        initializer_address, initializer_instructions = image.function(_INITIALIZER)
        if not _verify_getter(getter_instructions):
            return []
        allocator_symbols = _verify_initializer(image, initializer_instructions)
        if not allocator_symbols:
            return []
        evidence = {
            "probe": "freetype-paired-library-version-v1",
            "architecture": "arm32",
            "getter": _GETTER,
            "getter_va": f"0x{getter_address:x}",
            "getter_instructions": _instruction_text(getter_instructions),
            "initializer": _INITIALIZER,
            "initializer_va": f"0x{initializer_address:x}",
            "initializer_version_instructions": [
                "mov r1, #2",
                "mov r2, #4",
                "mov r3, #0xc",
                "stmib r5, {r1, r2, r3}",
            ],
            "allocator_symbols": allocator_symbols,
            "version": "2.4.12",
            "version_semantics": (
                "FT_New_Library initializes major/minor/patch at the same structure "
                "offsets read by FT_Library_Version"
            ),
            "upstream_source": _UPSTREAM_SOURCE,
        }
        return [
            StaticVersionMatch(
                "FreeType",
                "2.4.12",
                json.dumps(evidence, sort_keys=True),
                0.98,
            )
        ]
    except (
        ELFError,
        CsError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        OverflowError,
    ):
        return []
