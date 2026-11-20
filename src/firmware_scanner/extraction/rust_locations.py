"""Experimental Rust source-position features; no version assignments or execution.

The 24-byte shape is an explicitly bounded hypothesis for ELF64 little-endian
builds. Locations need a relative relocation, a GNU_RELRO record and a read-only
source path. Code references are retained for subsequent differential analysis;
they do not by themselves establish panic semantics or a source version.
"""
from __future__ import annotations

import io
import re
import struct

from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_INT, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

MAX_RELOCATIONS = 500_000
MAX_ELF_BYTES = 32 * 1024 * 1024
PATH_RE = re.compile(
    rb"external/rust/android-crates-io/crates/([A-Za-z0-9_-]+)/"
    rb"([A-Za-z0-9_-]+(?:/[A-Za-z0-9_.-]+)*\.rs)"
)


def _panic_location_argument(symbol: str) -> str | None:
    """Narrow x86-64 profiles; no Rust-wide ABI or demangler claim.

    Only exact legacy/v0 core paths with known argument shapes are supported.
    In particular a nearby pointer in an arbitrary argument is not corroborated.
    """
    profiles = {"panic_bounds_check": "rdx", "panic": "rdx", "panic_fmt": "rsi"}
    for name, register in profiles.items():
        tail = f"{len(name)}{name}"
        legacy = rf"_ZN4core9panicking{tail}17h[0-9a-f]{{16}}E"
        v0 = rf"_RNvNtC(?:s[A-Za-z0-9]+_)?4core9panicking{tail}"
        if re.fullmatch(legacy, symbol) or re.fullmatch(v0, symbol):
            return register
    constant = r"(\d+)(panic_const_(?:add|sub|mul|neg|shl|shr|div|rem)_(?:overflow|by_zero))"
    for pattern in (rf"_ZN4core9panicking11panic_const{constant}17h[0-9a-f]{{16}}E",
                    rf"_RNvNtNtC(?:s[A-Za-z0-9]+_)?4core9panicking11panic_const{constant}"):
        match = re.fullmatch(pattern, symbol)
        if match and int(match[1]) == len(match[2]):
            return "rdi"
    return None


def decode_relr(data: bytes, limit: int = MAX_RELOCATIONS) -> list[int]:
    """Decode monotonically ordered ELF64 RELR addresses with a hard budget."""
    if len(data) % 8 or len(data) // 8 > limit:
        raise ValueError("invalid or oversized RELR section")
    addresses = []
    base = None
    for (word,) in struct.iter_unpack("<Q", data):
        if word & 1:
            if base is None or base + 63 * 8 >= 2**64:
                raise ValueError("invalid RELR bitmap base")
            addresses.extend(base + (bit - 1) * 8 for bit in range(1, 64) if word & (1 << bit))
            base += 63 * 8
        else:
            if word % 8 or (base is not None and word < base) or word + 8 >= 2**64:
                raise ValueError("invalid RELR address")
            addresses.append(word)
            base = word + 8
        if len(addresses) > limit:
            raise ValueError("RELR expansion exceeds budget")
    return addresses


def decode_android_rela(data: bytes, limit: int = MAX_RELOCATIONS) -> list[tuple[int, int, int]]:
    """Decode the distinct APS2 format, with bounded signed LEB128 arithmetic."""
    if not data.startswith(b"APS2"):
        raise ValueError("missing APS2 header")
    position = 4

    def integer():
        nonlocal position
        value = 0
        for index in range(10):
            if position >= len(data):
                raise ValueError("truncated SLEB128")
            byte = data[position]
            position += 1
            value |= (byte & 127) << (index * 7)
            if not byte & 128:
                if byte & 64:
                    value -= 1 << ((index + 1) * 7)
                if not -(2**63) <= value < 2**63:
                    raise ValueError("SLEB128 overflow")
                return value
        raise ValueError("oversized SLEB128")

    count, offset = integer(), integer()
    if not 0 <= count <= limit or not 0 <= offset < 2**64:
        raise ValueError("invalid APS2 count or offset")
    rows, addend = [], 0
    while len(rows) < count:
        size, flags = integer(), integer()
        if (not 0 < size <= count - len(rows) or not 0 <= flags <= 15
                or flags & 4 and not flags & 8):
            raise ValueError("invalid APS2 group")
        delta = integer() if flags & 2 else None
        info = integer() if flags & 1 else None
        if flags & 8 and flags & 4:
            addend += integer()
        elif not flags & 8:
            addend = 0
        for _ in range(size):
            offset += delta if flags & 2 else integer()
            if not flags & 1:
                info = integer()
            if flags & 8 and not flags & 4:
                addend += integer()
            if not 0 <= offset < 2**64 or not 0 <= info < 2**64 or not -(2**63) <= addend < 2**63:
                raise ValueError("APS2 arithmetic overflow")
            rows.append((offset, info, addend))
    if position != len(data):
        raise ValueError("trailing APS2 bytes")
    return rows


def _read(data, loads, address, size, *, readonly=False):
    mappings = []
    for segment in loads:
        start, length = int(segment["p_vaddr"]), int(segment["p_filesz"])
        if start <= address and address + size <= start + length:
            if readonly and int(segment["p_flags"]) & 2:
                return None
            offset = int(segment["p_offset"]) + address - start
            if 0 <= offset and offset + size <= len(data):
                mappings.append(data[offset:offset + size])
    return mappings[0] if len(mappings) == 1 else None


def _relative_pointers(elf, data, loads):
    pointers = {}
    unsupported = []
    imports = {}

    def record(section, address, info, addend):
        kind, index = info & 0xffffffff, info >> 32
        if kind == 8 and index == 0:
            add(address, addend)
        elif kind in (6, 7) and index:
            table = elf.get_section(section["sh_link"])
            if not isinstance(table, SymbolTableSection) or not 0 < index < table.num_symbols():
                raise ValueError("invalid relocation symbol index")
            symbol = table.get_symbol(index)
            if symbol["st_shndx"] == "SHN_UNDEF":
                if address in imports:
                    raise ValueError("duplicate import relocation")
                imports[address] = symbol.name

    def add(address, pointer):
        if address in pointers or address % 8 or not 0 <= pointer < 2**64:
            raise ValueError("duplicate, unaligned or invalid relative relocation")
        pointers[address] = pointer
        if len(pointers) > MAX_RELOCATIONS:
            raise ValueError("relative relocation budget exceeded")

    for section in elf.iter_sections():
        kind = section["sh_type"]
        if kind in ("SHT_RELR", 19, 0x6FFFFF00):
            for address in decode_relr(section.data()):
                raw = _read(data, loads, address, 8)
                if raw is None:
                    raise ValueError("unmapped RELR pointer")
                add(address, struct.unpack("<Q", raw)[0])
        elif isinstance(section, RelocationSection):
            if section.num_relocations() > MAX_RELOCATIONS:
                raise ValueError("relocation section exceeds budget")
            for relocation in section.iter_relocations():
                if relocation.is_RELA():
                    record(section, int(relocation["r_offset"]), int(relocation["r_info"]),
                           int(relocation["r_addend"]))
        elif kind == 0x60000002:
            for address, info, addend in decode_android_rela(section.data()):
                record(section, address, info, addend)
        elif kind == 0x60000001:
            unsupported.append(section.name)
    return pointers, unsupported, imports


def _code_references(elf, data, loads, sites, imports):
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    complete = True

    def argument(register):
        for aliases in (("rdi", "edi", "di", "dil"), ("rsi", "esi", "si", "sil"),
                        ("rdx", "edx", "dx", "dl", "dh"), ("rcx", "ecx", "cx", "cl", "ch"),
                        ("r8", "r8d", "r8w", "r8b"), ("r9", "r9d", "r9w", "r9b")):
            if register in aliases:
                return aliases[0]
        return None

    def imported_call(instruction):
        operands = instruction.operands
        if len(operands) != 1:
            return None
        if operands[0].type == X86_OP_MEM:
            memory = operands[0].mem
            if instruction.reg_name(memory.base) == "rip" and not memory.index:
                return imports.get(instruction.address + instruction.size + int(memory.disp))
        if operands[0].type == X86_OP_IMM:
            address = int(operands[0].imm)
            raw = _read(data, loads, address, 16, readonly=True)
            if raw:
                for stub in disassembler.disasm(raw, address):
                    if stub.mnemonic in ("nop", "endbr64"):
                        continue
                    if stub.mnemonic == "jmp":
                        return imported_call(stub) if stub.operands[0].type == X86_OP_MEM else None
                    break
        return None

    for section in elf.iter_sections():
        if not int(section["sh_flags"]) & 4 or section["sh_type"] != "SHT_PROGBITS":
            continue
        start, size = int(section["sh_addr"]), int(section["sh_size"])
        raw = _read(data, loads, start, size, readonly=True)
        if raw is None or size > MAX_ELF_BYTES:
            complete = False
            continue
        decoded = 0
        pending = []
        for instruction in disassembler.disasm(raw, start):
            decoded += instruction.size
            operands = instruction.operands
            if instruction.group(CS_GRP_CALL):
                symbol = imported_call(instruction)
                expected_argument = _panic_location_argument(symbol) if symbol else None
                if expected_argument:
                    for site, register, _ in pending:
                        if register == expected_argument:
                            sites[site]["corroborated_calls"].append({
                                "vaddr": hex(instruction.address), "symbol": symbol, "argument": register,
                                "profile": "bounded-x86_64-core-panic-arguments-v1",
                            })
                pending.clear()
            elif any(instruction.group(group) for group in (CS_GRP_JUMP, CS_GRP_RET, CS_GRP_INT)):
                pending.clear()
            else:
                _, writes = instruction.regs_access()
                changed = {argument(instruction.reg_name(reg)) for reg in writes}
                pending = [(site, register, age + 1) for site, register, age in pending
                           if register not in changed and age < 8]
            if instruction.mnemonic != "lea" or len(operands) != 2 or operands[1].type != X86_OP_MEM:
                continue
            memory = operands[1].mem
            if memory.index or instruction.reg_name(memory.base) != "rip":
                continue
            address = instruction.address + instruction.size + int(memory.disp)
            if address in sites:
                sites[address]["code_references"].append({
                    "vaddr": hex(instruction.address),
                    "instruction": f"{instruction.mnemonic} {instruction.op_str}",
                })
                register = argument(instruction.reg_name(operands[0].reg))
                if register is not None and operands[0].size == 8:
                    pending.append((address, register, 0))
        complete &= decoded == size
    return complete


def extract_locations(data: bytes) -> dict:
    """Return candidate features only, including unsupported and decode boundaries."""
    empty = {"locations": [], "status": "unsupported"}
    if not data.startswith(b"\x7fELF") or len(data) > MAX_ELF_BYTES:
        return empty
    try:
        elf = ELFFile(io.BytesIO(data))
        if elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_X86_64":
            return empty
        loads = [segment for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]
        relro = [segment for segment in elf.iter_segments() if segment["p_type"] == "PT_GNU_RELRO"]
        pointers, unsupported, imports = _relative_pointers(elf, data, loads)
        sites = {}
        for address, pointer in pointers.items():
            if not any(int(s["p_vaddr"]) <= address
                       and address + 24 <= int(s["p_vaddr"]) + int(s["p_memsz"]) for s in relro):
                continue
            raw = _read(data, loads, address, 24)
            if raw is None:
                continue
            _, length, line, column = struct.unpack("<QQII", raw)
            if not 10 < length <= 400 or not 0 < line < 1_000_000 or not 0 < column < 1_000_000:
                continue
            path = _read(data, loads, pointer, length, readonly=True)
            match = PATH_RE.fullmatch(path) if path else None
            if match is None or any(part in (b".", b"..") for part in match[2].split(b"/")):
                continue
            sites[address] = {"vaddr": hex(address), "path_vaddr": hex(pointer),
                              "crate": match[1].decode(), "source_file": match[2].decode(),
                              "path": path.decode(), "line": line, "column": column,
                              "code_references": [], "corroborated_calls": []}
        complete = _code_references(elf, data, loads, sites, imports) if sites else None
        return {"status": "analyzed", "locations": list(sites.values()),
                "relative_pointers": len(pointers), "unsupported_relocation_sections": unsupported,
                "code_decode_complete": complete,
                "warning": "source-position candidates, not verified panic semantics or exact versions"}
    except (ELFError, ValueError, TypeError, KeyError, IndexError, struct.error, UnicodeError) as exc:
        return {"locations": [], "status": "invalid", "error": f"{type(exc).__name__}: {exc}"}
