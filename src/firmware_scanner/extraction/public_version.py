"""Conservative probes for documented public version APIs and globals."""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from io import BytesIO

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsError
from capstone.x86 import (
    X86_INS_LEA,
    X86_INS_MOV,
    X86_INS_RET,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_RIP,
)
from elftools.common.exceptions import ELFError
from elftools.elf.constants import P_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .static_version import StaticVersionMatch


@dataclass(frozen=True)
class _BannerRule:
    name: str
    required_symbols: frozenset[str]
    pattern: re.Pattern[bytes]
    source: str
    confidence: float = 0.97


_BANNER_RULES = (
    _BannerRule(
        "libassuan",
        frozenset({"assuan_check_version", "assuan_pipe_connect"}),
        re.compile(rb"This is Libassuan (\d+\.\d+\.\d+) - The GnuPG IPC Library"),
        "https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libassuan.git;a=blob_plain;f=src/version.c;hb=HEAD",
    ),
    _BannerRule(
        "GPGME",
        frozenset({"gpgme_check_version_internal", "gpgme_new"}),
        re.compile(rb"This is GPGME (\d+\.\d+\.\d+) - The GnuPG Made Easy library"),
        "https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gpgme.git;a=blob_plain;f=src/version.c;hb=HEAD",
    ),
    _BannerRule(
        "libksba",
        frozenset({"ksba_check_version", "ksba_reader_new"}),
        re.compile(rb"This is Libksba (\d+\.\d+\.\d+) - An X\.509 and CMS Library"),
        "https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libksba.git;a=blob_plain;f=src/version.c;hb=HEAD",
    ),
    _BannerRule(
        "nPth",
        frozenset({"npth_get_version", "npth_init"}),
        re.compile(rb"This is nPth (\d+\.\d+) - The New GNU Portable Threads Library"),
        "https://git.gnupg.org/cgi-bin/gitweb.cgi?p=npth.git;a=blob_plain;f=src/npth.c;hb=HEAD",
    ),
    _BannerRule(
        "libcap",
        frozenset({"cap_get_proc", "cap_to_text"}),
        re.compile(rb"shared library version: libcap-(\d+\.\d+)"),
        "https://git.kernel.org/pub/scm/libs/libcap/libcap.git/tree/libcap/cap_text.c",
    ),
    _BannerRule(
        "libdevmapper",
        frozenset({"dm_get_library_version", "dm_task_create"}),
        re.compile(rb"(\d+\.\d+\.\d+) \(\d{4}-\d{2}-\d{2}\)"),
        "https://gitlab.com/lvmteam/lvm2/-/blob/main/libdm/libdm-common.c",
    ),
)
_PREFILTER = (
    b"assuan_check_version",
    b"gpgme_check_version_internal",
    b"ksba_check_version",
    b"npth_get_version",
    b"cap_get_proc",
    b"dm_get_library_version",
    b"stringprep_check_version",
    b"rl_library_version",
    b"gdbm_version",
    b"magic_version",
    b"cmsGetEncodedCMMversion",
)


def extract_public_versions(data: bytes) -> list[StaticVersionMatch]:
    """Extract only APIs whose release semantics are documented by the project."""
    if not data.startswith(b"\x7fELF") or not any(name in data for name in _PREFILTER):
        return []
    try:
        image = ELFFile(BytesIO(data))
        symbols = _symbols(image)
        defined = {
            name
            for name, symbol in symbols.items()
            if symbol["type"] in ("STT_FUNC", "STT_OBJECT")
            and symbol["shndx"] not in (0, "SHN_UNDEF", "SHN_ABS")
        }
        matches = []
        for rule in _BANNER_RULES:
            if not rule.required_symbols.issubset(defined):
                continue
            versions = {found.group(1).decode("ascii") for found in rule.pattern.finditer(data)}
            if len(versions) != 1:
                continue
            version = versions.pop()
            matches.append(
                StaticVersionMatch(
                    rule.name,
                    version,
                    _evidence(
                        "required-banner-and-api",
                        version=version,
                        symbols=sorted(rule.required_symbols),
                        rule=rule.pattern.pattern.decode("ascii"),
                        source=rule.source,
                    ),
                    rule.confidence,
                )
            )
        for extractor in (
            _libidn_version,
            _readline_version,
            _gdbm_version,
            _magic_version,
            _lcms2_version,
        ):
            hit = extractor(data, image, symbols)
            if hit is not None:
                matches.append(hit)
        return _deduplicate(matches)
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
        return []


def _libidn_version(data, image, symbols) -> StaticVersionMatch | None:
    functions = {"stringprep_check_version", "stringprep_4i"}
    if not functions.issubset(symbols):
        return None
    strings, offsets = _x86_returned_strings(image, data, "stringprep_check_version")
    versions = {
        match.group(1) for value in strings if (match := re.fullmatch(r"(\d+\.\d+)", value))
    }
    if len(versions) != 1:
        return None
    version = versions.pop()
    return StaticVersionMatch(
        "libidn",
        version,
        _evidence(
            "defined-check-version-string",
            version=version,
            symbol="stringprep_check_version",
            string_file_offsets=offsets,
            source="https://git.savannah.gnu.org/cgit/libidn.git/tree/lib/version.c",
        ),
        0.97,
    )


def _readline_version(data, image, symbols) -> StaticVersionMatch | None:
    required = {
        "rl_library_version": "STT_OBJECT",
        "rl_readline_version": "STT_OBJECT",
        "readline": "STT_FUNC",
    }
    if not all(
        name in symbols and symbols[name]["type"] == kind for name, kind in required.items()
    ):
        return None
    pointer = _read_integer_object(image, data, "rl_library_version", image.elfclass // 8)
    packed = _read_integer_object(image, data, "rl_readline_version", 4)
    if pointer is None or packed is None:
        return None
    value = _read_c_string(image, data, pointer)
    if value is None:
        return None
    match = re.fullmatch(r"(\d+)\.(\d+)", value)
    if match is None:
        return None
    major, minor = map(int, match.groups())
    if packed != (major << 8) | minor:
        return None
    return StaticVersionMatch(
        "Readline",
        value,
        _evidence(
            "defined-version-pointer-and-packed-object",
            version=value,
            pointer_symbol="rl_library_version",
            packed_symbol="rl_readline_version",
            packed_value=packed,
            source="https://git.savannah.gnu.org/cgit/readline.git/tree/readline.c",
        ),
        0.97,
    )


def _gdbm_version(data, image, symbols) -> StaticVersionMatch | None:
    required = {"gdbm_open", "gdbm_fetch", "gdbm_version_number"}
    if not required.issubset(symbols):
        return None
    version_symbol = symbols["gdbm_version_number"]
    if (
        version_symbol["type"] != "STT_OBJECT"
        or version_symbol["shndx"] in (0, "SHN_UNDEF", "SHN_ABS")
        or version_symbol["size"] < 8
    ):
        return None
    offset = _object_offset(image, int(version_symbol["value"]), 8)
    if offset is None:
        return None
    endian = "<" if image.little_endian else ">"
    major, minor = struct.unpack_from(endian + "II", data, offset)
    if not (0 < major < 100 and 0 <= minor < 100):
        return None
    version = f"{major}.{minor}"
    return StaticVersionMatch(
        "GDBM",
        version,
        _evidence(
            "defined-version-object",
            version=version,
            symbol="gdbm_version_number",
            file_offset=offset,
            source="https://git.gnu.org.ua/cgit/gdbm.git/tree/src/gdbmdefs.h",
        ),
        0.97,
    )


def _magic_version(data, image, symbols) -> StaticVersionMatch | None:
    if not {"magic_version", "magic_open"}.issubset(symbols):
        return None
    value = _x86_immediate_return(image, data, "magic_version")
    if value is None or value < 100:
        return None
    version = f"{value // 100}.{value % 100:02d}"
    return StaticVersionMatch(
        "libmagic",
        version,
        _evidence(
            "defined-integer-version-getter",
            version=version,
            symbol="magic_version",
            encoded_value=value,
            encoding="major * 100 + minor",
            resolution_state="estimated",
            version_kind="interface",
            source="https://github.com/file/file/blob/master/src/magic.c",
        ),
        0.88,
    )


def _lcms2_version(data, image, symbols) -> StaticVersionMatch | None:
    if not {"cmsGetEncodedCMMversion", "cmsCreateTransform"}.issubset(symbols):
        return None
    value = _x86_immediate_return(image, data, "cmsGetEncodedCMMversion")
    if value is None or value < 1000:
        return None
    major, remainder = divmod(value, 1000)
    minor, patch = divmod(remainder, 10)
    version = f"{major}.{minor}" + (f".{patch}" if patch else "")
    return StaticVersionMatch(
        "lcms2",
        version,
        _evidence(
            "defined-integer-version-getter",
            version=version,
            symbol="cmsGetEncodedCMMversion",
            encoded_value=value,
            encoding="major * 1000 + minor * 10",
            source="https://github.com/mm2/Little-CMS/blob/master/src/cmsio0.c",
        ),
        0.97,
    )


def _symbols(image: ELFFile) -> dict[str, dict]:
    result = {}
    for section in image.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            if not symbol.name:
                continue
            result.setdefault(
                symbol.name,
                {
                    "type": symbol["st_info"]["type"],
                    "shndx": symbol["st_shndx"],
                    "value": int(symbol["st_value"]),
                    "size": int(symbol["st_size"]),
                },
            )
    return result


def _object_offset(image: ELFFile, address: int, size: int) -> int | None:
    for segment in image.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        delta = address - int(segment["p_vaddr"])
        if 0 <= delta and delta + size <= int(segment["p_filesz"]):
            return int(segment["p_offset"]) + delta
    return None


def _read_integer_object(image, data: bytes, name: str, size: int) -> int | None:
    symbol = _symbols(image).get(name)
    if symbol is None or symbol["type"] != "STT_OBJECT" or symbol["size"] != size:
        return None
    offset = _object_offset(image, symbol["value"], size)
    if offset is None or offset + size > len(data):
        return None
    return int.from_bytes(data[offset : offset + size], "little" if image.little_endian else "big")


def _read_c_string(image, data: bytes, address: int) -> str | None:
    offset = _object_offset(image, address, 1)
    if offset is None:
        return None
    end = data.find(b"\0", offset, min(len(data), offset + 257))
    if end <= offset:
        return None
    try:
        return data[offset:end].decode("ascii")
    except UnicodeDecodeError:
        return None


def _function_bytes(image, data: bytes, name: str) -> tuple[bytes, int] | None:
    symbol = _symbols(image).get(name)
    if symbol is None or symbol["type"] != "STT_FUNC" or not (0 < symbol["size"] <= 4096):
        return None
    for segment in image.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not int(segment["p_flags"]) & P_FLAGS.PF_X:
            continue
        delta = symbol["value"] - int(segment["p_vaddr"])
        if 0 <= delta and delta + symbol["size"] <= int(segment["p_filesz"]):
            offset = int(segment["p_offset"]) + delta
            if offset + symbol["size"] <= len(data):
                return data[offset : offset + symbol["size"]], offset
    return None


def _x86_returned_strings(image, data: bytes, name: str) -> tuple[set[str], list[int]]:
    if image.header["e_machine"] != "EM_X86_64" or image.elfclass != 64:
        return set(), []
    function = _function_bytes(image, data, name)
    if function is None:
        return set(), []
    code, _ = function
    address = int(_symbols(image)[name]["value"])
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    strings = set()
    offsets = []
    instructions = list(disassembler.disasm(code, address))
    for index, instruction in enumerate(instructions):
        if instruction.id != X86_INS_LEA or len(instruction.operands) < 2:
            continue
        destination = instruction.operands[0]
        operand = instruction.operands[1]
        if (
            destination.type != X86_OP_REG
            or instruction.reg_name(destination.reg) != "rax"
            or operand.type != X86_OP_MEM
            or operand.mem.base != X86_REG_RIP
        ):
            continue
        if index + 1 >= len(instructions) or instructions[index + 1].id != X86_INS_RET:
            continue
        target = instruction.address + instruction.size + int(operand.mem.disp)
        value = _read_c_string(image, data, target)
        offset = _object_offset(image, target, 1)
        if value is not None and offset is not None:
            strings.add(value)
            offsets.append(offset)
    return strings, sorted(set(offsets))


def _x86_immediate_return(image, data: bytes, name: str) -> int | None:
    if image.header["e_machine"] != "EM_X86_64" or image.elfclass != 64:
        return None
    function = _function_bytes(image, data, name)
    if function is None:
        return None
    code, _ = function
    address = int(_symbols(image)[name]["value"])
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    instructions = list(disassembler.disasm(code, address))
    value = None
    for instruction in instructions:
        if instruction.id == X86_INS_MOV and len(instruction.operands) == 2:
            destination, source = instruction.operands
            if (
                destination.type == X86_OP_REG
                and instruction.reg_name(destination.reg) == "eax"
                and source.type == X86_OP_IMM
            ):
                value = int(source.imm)
        elif instruction.id == X86_INS_RET:
            return value
    return None


def _evidence(probe: str, **fields) -> str:
    return json.dumps({"probe": probe, **fields}, sort_keys=True)


def _deduplicate(matches: list[StaticVersionMatch]) -> list[StaticVersionMatch]:
    result = {}
    for match in matches:
        key = (match.name, match.version)
        current = result.get(key)
        if current is None or match.confidence > current.confidence:
            result[key] = match
    return sorted(result.values(), key=lambda item: item.name)
