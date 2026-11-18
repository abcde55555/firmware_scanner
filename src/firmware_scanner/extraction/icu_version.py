"""Static recognition of ICU's version-string getter.

This probe never loads or executes an ELF. It only accepts a tiny, verified
tail-call shape where a defined u_getVersion symbol passes a PC-relative
read-only string to the same library's defined u_versionFromString symbol.
Unsupported control flow is rejected.
"""
from __future__ import annotations

import json
import re
import struct
from io import BytesIO

from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_MODE_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_THUMB,
    Cs,
    CsError,
)
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from firmware_scanner.extraction.static_version import StaticVersionMatch

_GETTER = re.compile(r"^u_getVersion(_[0-9]+)?$")
_HELPER = re.compile(r"^u_versionFromString(_[0-9]+)?$")
_VERSION = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){1,3}\Z")
_UPSTREAM_SOURCE = (
    "https://github.com/unicode-org/icu/blob/release-76-1/"
    "icu4c/source/common/putil.cpp"
)
_UPSTREAM_API = (
    "https://github.com/unicode-org/icu/blob/release-76-1/"
    "icu4c/source/common/unicode/uversion.h"
)


class _Image:
    def __init__(self, data: bytes):
        self.data = data
        self.elf = ELFFile(BytesIO(data))
        self.machine = self.elf.header["e_machine"]
        self.elfclass = self.elf.elfclass
        self.little = self.elf.little_endian
        self.loads = [
            (int(s["p_vaddr"]), int(s["p_offset"]), int(s["p_filesz"]), int(s["p_flags"]))
            for s in self.elf.iter_segments()
            if s["p_type"] == "PT_LOAD"
        ]
        self.symbols: dict[str, tuple[int, int, str]] = {}
        self.relocations: dict[str, list[tuple[int, str]]] = {}
        self._read_symbols()
        self._read_relocations()

    def _read_symbols(self) -> None:
        for section in self.elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                name = symbol.name
                if not (_GETTER.fullmatch(name) or _HELPER.fullmatch(name)):
                    continue
                if symbol["st_info"]["type"] != "STT_FUNC":
                    continue
                if symbol["st_shndx"] in ("SHN_UNDEF", 0) or not int(symbol["st_size"]):
                    continue
                bind = symbol["st_info"]["bind"]
                visibility = symbol["st_other"]["visibility"]
                if bind not in ("STB_GLOBAL", "STB_WEAK") or visibility not in (
                    "STV_DEFAULT", "STV_PROTECTED"
                ):
                    continue
                self.symbols.setdefault(
                    name, (int(symbol["st_value"]), int(symbol["st_size"]), section.name)
                )

    def _read_relocations(self) -> None:
        for section in self.elf.iter_sections():
            if not isinstance(section, RelocationSection) or section.name not in (
                ".rel.plt", ".rela.plt"
            ):
                continue
            symbols = self.elf.get_section(section["sh_link"])
            self.relocations[section.name] = [
                (int(rel["r_offset"]), symbols.get_symbol(rel["r_info_sym"]).name)
                for rel in section.iter_relocations()
            ]

    def read_va(self, address: int, size: int, *, readonly: bool = False, executable: bool = False):
        for vaddr, offset, filesz, flags in self.loads:
            if not (vaddr <= address and address + size <= vaddr + filesz):
                continue
            if executable and not flags & 1:
                continue
            if readonly and flags & 2:
                continue
            file_offset = offset + address - vaddr
            if file_offset < 0 or file_offset + size > len(self.data):
                return None
            return self.data[file_offset:file_offset + size]
        return None

    def decode(
        self, address: int, size: int, architecture: str, *, thumb: bool = False, strict: bool = True
    ):
        code = self.read_va(address, size, executable=True)
        if code is None:
            return None
        if architecture == "arm32":
            dis = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
        elif architecture == "aarch64":
            dis = Cs(CS_ARCH_ARM64, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        else:
            return None
        dis.detail = True
        insns = list(dis.disasm(code, address))
        if not insns or strict and sum(i.size for i in insns) != len(code):
            return None
        return insns

    def symbol_code(self, name: str, architecture: str):
        sym = self.symbols[name]
        address = sym[0] & ~1 if architecture == "arm32" else sym[0]
        thumb = architecture == "arm32" and bool(sym[0] & 1)
        return address, self.decode(address, sym[1], architecture, thumb=thumb, strict=False)


def _version_string(image: _Image, getter: str, architecture: str):
    _address, insns = image.symbol_code(getter, architecture)
    if not insns:
        return None

    if architecture == "arm32":
        # Supported Thumb wrapper: LDR r1,[PC,#imm]; ADD r1,PC; B.W target.
        if len(insns) < 3:
            return None
        load, add, branch = insns[:3]
        if not (
            load.mnemonic == "ldr"
            and len(load.operands) == 2
            and load.operands[0].type == ARM_OP_REG
            and load.reg_name(load.operands[0].reg) == "r1"
            and load.operands[1].type == ARM_OP_MEM
            and load.reg_name(load.operands[1].mem.base) == "pc"
            and add.mnemonic == "add"
            and len(add.operands) == 2
            and add.operands[0].type == ARM_OP_REG
            and add.reg_name(add.operands[0].reg) == "r1"
            and add.operands[1].type == ARM_OP_REG
            and add.reg_name(add.operands[1].reg) == "pc"
            and branch.mnemonic in ("b", "b.w")
            and len(branch.operands) == 1
            and branch.operands[0].type == ARM_OP_IMM
        ):
            return None
        literal_va = ((load.address + 4) & ~3) + int(load.operands[1].mem.disp)
        raw = image.read_va(literal_va, 4)
        if raw is None:
            return None
        delta = struct.unpack("<i", raw)[0]
        string_va = add.address + 4 + delta
        branch_target = int(branch.operands[0].imm)
        return string_va, literal_va, delta, branch_target, insns[:3]

    # Supported AArch64 wrapper: ADRP x1,page; ADD x1,x1,#lo12; B target.
    if len(insns) < 3:
        return None
    adrp, add, branch = insns[:3]
    if not (
        adrp.mnemonic == "adrp"
        and len(adrp.operands) == 2
        and adrp.operands[0].type == ARM64_OP_REG
        and adrp.reg_name(adrp.operands[0].reg) == "x1"
        and adrp.operands[1].type == ARM64_OP_IMM
        and add.mnemonic == "add"
        and len(add.operands) == 3
        and add.operands[0].type == ARM64_OP_REG
        and adrp.reg_name(add.operands[0].reg) == "x1"
        and add.operands[1].type == ARM64_OP_REG
        and adrp.reg_name(add.operands[1].reg) == "x1"
        and add.operands[2].type == ARM64_OP_IMM
        and int(add.operands[2].shift.type) == 0
        and int(add.operands[2].shift.value) == 0
        and branch.mnemonic == "b"
        and len(branch.operands) == 1
        and branch.operands[0].type == ARM64_OP_IMM
    ):
        return None
    string_va = int(adrp.operands[1].imm) + int(add.operands[2].imm)
    return string_va, None, None, int(branch.operands[0].imm), insns[:3]


def _resolve_thumb_veneer(image: _Image, target: int):
    insns = image.decode(target & ~1, 16, "arm32", thumb=True)
    if not insns or len(insns) < 4:
        return None
    movw, movt, add, bx = insns[:4]
    if not (
        movw.mnemonic == "movw"
        and movt.mnemonic == "movt"
        and add.mnemonic == "add"
        and bx.mnemonic == "bx"
        and len(movw.operands) == 2
        and len(movt.operands) == 2
        and len(add.operands) == 2
        and len(bx.operands) == 1
        and all(x.operands[0].type == ARM_OP_REG for x in (movw, movt, add, bx))
        and all(x.operands[-1].type == ARM_OP_IMM for x in (movw, movt))
    ):
        return None
    reg = movw.reg_name(movw.operands[0].reg)
    if any(x.reg_name(x.operands[0].reg) != reg for x in (movt, add, bx)):
        return None
    if add.operands[1].type != ARM_OP_REG or add.reg_name(add.operands[1].reg) != "pc":
        return None
    absolute = int(movw.operands[1].imm) | (int(movt.operands[1].imm) << 16)
    return add.address + 4 + absolute


def _plt_symbol(image: _Image, target: int, architecture: str):
    plt = image.elf.get_section_by_name(".plt")
    reloc_name = ".rel.plt" if architecture == "arm32" else ".rela.plt"
    relocs = image.relocations.get(reloc_name)
    if plt is None or not relocs:
        return None
    start = int(plt["sh_addr"])
    entry_size = 16
    header_size = 32
    index_delta = target - (start + header_size)
    if index_delta < 0 or index_delta % entry_size:
        return None
    index = index_delta // entry_size
    if index >= len(relocs) or int(plt["sh_size"]) != header_size + entry_size * len(relocs):
        return None
    entry = image.decode(target, entry_size, architecture, thumb=False)
    if not entry:
        return None
    if architecture == "arm32":
        # Android ARM32 PLT entry: ARM ADD/ADD/LDR-PC resolver sequence.
        if not (
            len(entry) >= 3
            and entry[0].mnemonic == "add"
            and entry[1].mnemonic == "add"
            and entry[2].mnemonic == "ldr"
            and entry[2].operands[0].type == ARM_OP_REG
            and entry[2].reg_name(entry[2].operands[0].reg) == "pc"
        ):
            return None
    else:
        # Accept only this exact AArch64 PLT form and prove the LDR GOT slot.
        if len(entry) != 4 or [i.mnemonic for i in entry] != ["adrp", "ldr", "add", "br"]:
            return None
        adrp, load, add, branch = entry
        if not (
            len(adrp.operands) == 2
            and adrp.operands[0].type == ARM64_OP_REG
            and adrp.reg_name(adrp.operands[0].reg) == "x16"
            and adrp.operands[1].type == ARM64_OP_IMM
            and len(load.operands) == 2
            and load.operands[0].type == ARM64_OP_REG
            and load.reg_name(load.operands[0].reg) == "x17"
            and load.operands[1].type == 3  # ARM64_OP_MEM
            and load.reg_name(load.operands[1].mem.base) == "x16"
            and load.operands[1].mem.index == 0
            and not load.writeback
            and not load.post_index
            and len(add.operands) == 3
            and add.operands[0].type == ARM64_OP_REG
            and add.reg_name(add.operands[0].reg) == "x16"
            and add.operands[1].type == ARM64_OP_REG
            and add.reg_name(add.operands[1].reg) == "x16"
            and add.operands[2].type == ARM64_OP_IMM
            and int(add.operands[2].shift.type) == 0
            and int(add.operands[2].shift.value) == 0
            and len(branch.operands) == 1
            and branch.operands[0].type == ARM64_OP_REG
            and branch.reg_name(branch.operands[0].reg) == "x17"
        ):
            return None
        got_slot = int(adrp.operands[1].imm) + int(load.operands[1].mem.disp)
        relocation_slot, symbol = relocs[index]
        if got_slot != relocation_slot or int(add.operands[2].imm) != int(load.operands[1].mem.disp):
            return None
        return symbol
    return relocs[index][1]


def _callee(image: _Image, target: int, architecture: str):
    if architecture == "arm32":
        symbol = _plt_symbol(image, target & ~1, architecture)
        if symbol:
            return symbol, [("plt", target & ~1, symbol)]
        plt_target = _resolve_thumb_veneer(image, target)
        if plt_target is None:
            return None
        symbol = _plt_symbol(image, plt_target, architecture)
        if symbol:
            return symbol, [("thumb-veneer", target & ~1, plt_target), ("plt", plt_target, symbol)]
        return None
    symbol = _plt_symbol(image, target, architecture)
    return (symbol, [("plt", target, symbol)]) if symbol else None


def _helper_returns(image: _Image, helper: str, architecture: str):
    _, insns = image.symbol_code(helper, architecture)
    if not insns:
        return None
    if architecture == "aarch64":
        returns = [i for i in insns if i.mnemonic == "ret"]
    else:
        returns = [
            i for i in insns
            if i.mnemonic == "bx" and i.op_str.strip() == "lr"
            or i.mnemonic.startswith("pop") and "pc" in i.op_str
        ]
    return [f"0x{i.address:x}: {i.mnemonic} {i.op_str}".strip() for i in returns] or None


def _read_version(image: _Image, address: int):
    raw = image.read_va(address, 24, readonly=True)
    if raw is None:
        return None
    end = raw.find(b"\0")
    if end <= 0:
        return None
    try:
        text = raw[:end].decode("ascii")
    except UnicodeDecodeError:
        return None
    if not _VERSION.fullmatch(text) or any(int(part) > 255 for part in text.split(".")):
        return None
    return text


def extract_icu(data: bytes) -> list[StaticVersionMatch]:
    """Return an ICU release only for a fully verified getter-to-parser path."""
    if not isinstance(data, bytes) or len(data) < 64 or data[:4] != b"\x7fELF":
        return []
    try:
        image = _Image(data)
        if not image.little:
            return []
        if image.machine == "EM_AARCH64" and image.elfclass == 64:
            architecture = "aarch64"
        else:
            return []

        results = []
        for getter in sorted(name for name in image.symbols if _GETTER.fullmatch(name)):
            suffix = _GETTER.fullmatch(getter).group(1) or ""
            helper = "u_versionFromString" + suffix
            if helper not in image.symbols:
                continue
            found = _version_string(image, getter, architecture)
            if not found:
                continue
            string_va, literal_va, literal_delta, branch_target, getter_insns = found
            resolved = _callee(image, branch_target, architecture)
            if not resolved:
                continue
            callee_name, route = resolved
            if callee_name != helper:
                continue
            helper_returns = _helper_returns(image, helper, architecture)
            if not helper_returns:
                continue
            version = _read_version(image, string_va)
            if not version:
                continue

            evidence = {
                "probe": "icu-version-getter-v1",
                "architecture": architecture,
                "getter": getter,
                "getter_va": f"0x{image.symbols[getter][0] & ~1 if architecture == 'arm32' else image.symbols[getter][0]:x}",
                "getter_instructions": [
                    f"0x{i.address:x}: {i.mnemonic} {i.op_str}".strip() for i in getter_insns
                ],
                "literal_pool_va": f"0x{literal_va:x}" if literal_va is not None else None,
                "literal_delta": (
                    (f"-0x{abs(literal_delta):x}" if literal_delta < 0 else f"0x{literal_delta:x}")
                    if literal_delta is not None else None
                ),
                "string_va": f"0x{string_va:x}",
                "string": version,
                "branch_target_va": f"0x{branch_target:x}",
                "callee_route": [
                    {"kind": kind, "va": f"0x{address:x}", "symbol": name}
                    for kind, address, name in route
                ],
                "defined_helper": helper,
                "helper_va": f"0x{image.symbols[helper][0] & ~1 if architecture == 'arm32' else image.symbols[helper][0]:x}",
                "helper_return_instructions": helper_returns,
                "upstream_api_source": _UPSTREAM_API,
                "upstream_implementation_source": _UPSTREAM_SOURCE,
                "upstream_semantics": (
                    "u_getVersion fills UVersionInfo using u_versionFromString(versionArray, U_ICU_VERSION); "
                    "u_versionFromString parses dotted-decimal text into up to four uint8 fields."
                ),
            }
            results.append(StaticVersionMatch("ICU", version, json.dumps(evidence, sort_keys=True), 0.98))
        return results
    except (ELFError, CsError, OSError, ValueError, TypeError, KeyError, IndexError, struct.error, OverflowError):
        return []
