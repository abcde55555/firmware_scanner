"""Conservative probes for documented public version APIs and globals."""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

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

from .static_version import StaticVersionExtractor, StaticVersionMatch


@dataclass(frozen=True)
class _BannerRule:
    name: str
    required_symbols: frozenset[str]
    pattern: re.Pattern[bytes]
    source: str
    confidence: float = 0.97


@dataclass(frozen=True)
class _OutputVersionRule:
    component: str
    outputs: tuple[str, ...]
    source: str


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
    _BannerRule(
        "jemalloc",
        frozenset({"mallctl", "malloc_stats_print"}),
        re.compile(rb"\b(\d+\.\d+\.\d+)(?:-[0-9]+-g[0-9a-f]{12,40})\b"),
        "https://github.com/jemalloc/jemalloc",
        confidence=0.95,
    ),
)
_OUTPUT_VERSION_RULES = {
    "zmq_version": _OutputVersionRule(
        "libzmq",
        ("major", "minor", "patch"),
        "https://github.com/zeromq/libzmq/blob/master/src/zmq.cpp",
    ),
    "zsys_version": _OutputVersionRule(
        "CZMQ",
        ("major", "minor", "patch"),
        "https://github.com/zeromq/czmq/blob/master/src/zsys.c",
    ),
    "mosquitto_lib_version": _OutputVersionRule(
        "Mosquitto",
        ("major", "minor", "patch"),
        "https://github.com/eclipse-mosquitto/mosquitto/blob/master/lib/version.c",
    ),
    "iio_library_get_version": _OutputVersionRule(
        "libiio",
        ("major", "minor"),
        "https://github.com/analogdevicesinc/libiio/blob/main/iio.c",
    ),
    "QRcode_APIVersion": _OutputVersionRule(
        "libqrencode",
        ("major", "minor", "patch"),
        "https://github.com/fukuchi/libqrencode/blob/master/qrencode.c",
    ),
}
_RELEASE_TEXT = re.compile(r"v?(\d+\.\d+(?:\.\d+)*[A-Za-z0-9.+_-]*)\Z")
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
    b"libevent using: %s",
    b"$LuaVersion:",
    b"db_full_version",
    b"malloc_stats_print",
    b"blkid_get_library_version",
    b"Z3_get_version",
    b"zmq_version",
    b"zsys_version",
    b"mosquitto_lib_version",
    b"iio_library_get_version",
    b"QRcode_APIVersion",
    b"libmodbus_version_major",
    b"libusb_get_version",
    b"ftdi_get_library_version",
    b"gp_library_version",
    b"gpiod_api_version",
)


def extract_public_versions(data: bytes, filename: str = "") -> list[StaticVersionMatch]:
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
        libevent = _libevent_adjacent_version(data)
        if libevent is not None:
            matches.append(libevent)
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
            _lua_version,
            _berkeley_db_version,
            _z3_version,
        ):
            hit = extractor(data, image, symbols)
            if hit is not None:
                matches.append(hit)
        for function, rule in _OUTPUT_VERSION_RULES.items():
            hit = _output_parameter_version(data, image, symbols, function, rule)
            if hit is not None:
                matches.append(hit)
        for helper in (
            _modbus_version,
            _libusb_version,
            _ftdi_version,
            _gphoto_version,
            _gpiod_api_version,
        ):
            hit = helper(data, image, symbols)
            if hit is not None:
                matches.append(hit)
        blkid = _blkid_version(data, image, symbols, filename)
        if blkid is not None:
            matches.append(blkid)
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


def _libevent_adjacent_version(data: bytes) -> StaticVersionMatch | None:
    """Read libevent 1.x's adjacent release only with an upstream identity API."""
    if b"event_base_new\0" not in data:
        return None
    marker = b"libevent using: %s"
    versions = {}
    for found in re.finditer(re.escape(marker), data):
        window_start = found.end()
        window = data[window_start : window_start + 160]
        for raw in window.split(b"\0"):
            value = raw.strip().decode("ascii", errors="ignore")
            match = re.fullmatch(
                r"(\d+\.\d+\.\d+-(?:stable|beta|alpha)[A-Za-z0-9.+_-]*)",
                value,
            )
            if match:
                versions.setdefault(match.group(1), []).append(
                    window_start + raw.find(match.group(1).encode("ascii"))
                )
    if len(versions) != 1:
        return None
    version, offsets = next(iter(versions.items()))
    return StaticVersionMatch(
        "libevent",
        version,
        _evidence(
            "documented-identity-banner-and-adjacent-release-v1",
            version=version,
            identity_banner=marker.decode("ascii"),
            identity_api="event_base_new",
            version_file_offsets=offsets,
            source="https://github.com/libevent/libevent/blob/release-1.4.13-stable/event.c",
        ),
        0.93,
    )


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


def _lua_version(data, image, symbols) -> StaticVersionMatch | None:
    if not {"lua_version", "luaL_checkversion_"}.issubset(symbols):
        return None
    function = _function_bytes(image, data, "lua_version")
    if function is None or image.header["e_machine"] != "EM_X86_64":
        return None
    code, file_offset = function
    address = int(symbols["lua_version"]["value"])
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    instructions = list(disassembler.disasm(code, address))
    instructions = [
        instruction
        for instruction in instructions
        if instruction.mnemonic not in ("endbr64", "nop")
    ]
    if len(instructions) != 2:
        return None
    load, ret = instructions
    if (
        load.mnemonic != "movsd"
        or len(load.operands) != 2
        or load.operands[0].type != X86_OP_REG
        or load.reg_name(load.operands[0].reg) != "xmm0"
        or load.operands[1].type != X86_OP_MEM
        or load.reg_name(load.operands[1].mem.base) != "rip"
        or load.operands[1].mem.index
        or ret.mnemonic != "ret"
    ):
        return None
    constant_address = load.address + load.size + int(load.operands[1].mem.disp)
    constant_offset = _object_offset(image, constant_address, 8)
    if constant_offset is None:
        return None
    numeric_version = struct.unpack_from("<d", data, constant_offset)[0]
    banner_versions = {
        match.group(1)
        for match in re.finditer(rb"\$LuaVersion:\s+Lua\s+(\d+\.\d+\.\d+)", data)
    }
    if len(banner_versions) != 1:
        return None
    version = banner_versions.pop().decode("ascii")
    major, minor, _patch = map(int, version.split("."))
    if numeric_version != float(major * 100 + minor):
        return None
    return StaticVersionMatch(
        "Lua",
        version,
        _evidence(
            "api-number-and-official-banner-agree",
            version=version,
            function="lua_version",
            numeric_value=numeric_version,
            function_file_offset=file_offset,
            constant_file_offset=constant_offset,
            supporting_api="luaL_checkversion_",
            source="https://www.lua.org/source/5.4/lua.h.html",
        ),
        0.96,
    )


def _berkeley_db_version(data, image, symbols) -> StaticVersionMatch | None:
    if not {"db_version", "db_full_version"}.issubset(symbols):
        return None
    if image.header["e_machine"] != "EM_X86_64":
        return None
    function = _function_bytes(image, data, "db_version")
    if function is None:
        return None
    code, file_offset = function
    address = int(symbols["db_version"]["value"])
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    instructions = list(disassembler.disasm(code, address))
    parts = {}
    returned_pointer = None
    for index, instruction in enumerate(instructions):
        if (
            instruction.mnemonic == "mov"
            and len(instruction.operands) == 2
            and instruction.operands[0].type == X86_OP_MEM
            and instruction.operands[1].type == X86_OP_IMM
        ):
            memory = instruction.operands[0].mem
            if not memory.index and instruction.reg_name(memory.base) in ("rdi", "rsi", "rdx"):
                parts[instruction.reg_name(memory.base)] = int(instruction.operands[1].imm)
        if (
            instruction.id == X86_INS_LEA
            and len(instruction.operands) == 2
            and instruction.operands[0].type == X86_OP_REG
            and instruction.reg_name(instruction.operands[0].reg) == "rax"
            and instruction.operands[1].type == X86_OP_MEM
            and instruction.reg_name(instruction.operands[1].mem.base) == "rip"
            and index + 1 < len(instructions)
            and instructions[index + 1].id == X86_INS_RET
        ):
            returned_pointer = (
                instruction.address
                + instruction.size
                + int(instruction.operands[1].mem.disp)
            )
    if set(parts) != {"rdi", "rsi", "rdx"} or returned_pointer is None:
        return None
    major, minor, patch = parts["rdi"], parts["rsi"], parts["rdx"]
    if not (0 < major <= 99 and 0 <= minor <= 99 and 0 <= patch <= 99):
        return None
    version = f"{major}.{minor}.{patch}"
    text = _read_c_string(image, data, returned_pointer)
    if text is None or not text.startswith("Berkeley DB ") or version not in text:
        return None
    return StaticVersionMatch(
        "Berkeley DB",
        version,
        _evidence(
            "defined-output-parameter-version-getter",
            version=version,
            function="db_version",
            function_file_offset=file_offset,
            output_values={"major": major, "minor": minor, "patch": patch},
            returned_string=text,
            supporting_api="db_full_version",
            source="https://github.com/berkeleydb/libdb",
        ),
        0.96,
    )


def _blkid_version(data, image, symbols, filename: str) -> StaticVersionMatch | None:
    required = {"blkid_get_library_version", "blkid_parse_version_string"}
    if not required.issubset(symbols) or image.header["e_machine"] != "EM_X86_64":
        return None
    basename = Path(filename).name.casefold()
    if basename.startswith("libext2_blkid"):
        component = "e2fsprogs"
        source_url = "https://github.com/tytso/e2fsprogs/blob/master/lib/blkid/version.c"
    elif basename.startswith("libblkid"):
        component = "libblkid"
        source_url = (
            "https://github.com/util-linux/util-linux/blob/master/"
            "libblkid/src/version.c"
        )
    else:
        return None
    function = _function_bytes(image, data, "blkid_get_library_version")
    if function is None:
        return None
    code, function_offset = function
    address = int(symbols["blkid_get_library_version"]["value"])
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    register_strings = {}
    output_pointer_origins = {"rdi": "rdi", "rsi": "rsi"}
    output_strings = {}
    for instruction in disassembler.disasm(code, address):
        if instruction.id == X86_INS_MOV and len(instruction.operands) == 2:
            destination, source = instruction.operands
            if destination.type == X86_OP_REG and source.type == X86_OP_REG:
                destination_name = instruction.reg_name(destination.reg)
                source_name = instruction.reg_name(source.reg)
                if source_name in output_pointer_origins:
                    output_pointer_origins[destination_name] = output_pointer_origins[
                        source_name
                    ]
                else:
                    output_pointer_origins.pop(destination_name, None)
                register_strings.pop(destination_name, None)
        if instruction.id == X86_INS_LEA and len(instruction.operands) == 2:
            destination, operand = instruction.operands
            if (
                destination.type == X86_OP_REG
                and operand.type == X86_OP_MEM
                and operand.mem.base == X86_REG_RIP
            ):
                destination_name = instruction.reg_name(destination.reg)
                register_strings[destination_name] = (
                    instruction.address
                    + instruction.size
                    + int(operand.mem.disp)
                )
                output_pointer_origins.pop(destination_name, None)
            continue
        if instruction.id != X86_INS_MOV or len(instruction.operands) != 2:
            continue
        destination, source = instruction.operands
        if destination.type != X86_OP_MEM or source.type != X86_OP_REG:
            continue
        base_register = instruction.reg_name(destination.mem.base)
        output_register = output_pointer_origins.get(base_register)
        target = register_strings.get(instruction.reg_name(source.reg))
        if output_register not in {"rdi", "rsi"} or target is None:
            continue
        value = _read_c_string(image, data, target)
        offset = _object_offset(image, target, 1)
        if value is not None and offset is not None:
            output_strings[output_register] = (value, offset)
    version_strings = {
        value: offset
        for value, offset in output_strings.values()
        if re.fullmatch(r"\d+\.\d+\.\d+", value)
    }
    if len(version_strings) != 1:
        return None
    version, version_offset = next(iter(version_strings.items()))
    return StaticVersionMatch(
        component,
        version,
        _evidence(
            "defined-output-parameter-version-getter",
            version=version,
            function="blkid_get_library_version",
            function_file_offset=function_offset,
            version_file_offset=version_offset,
            output_strings={
                register: value for register, (value, _offset) in output_strings.items()
            },
            supporting_api="blkid_parse_version_string",
            source=source_url,
        ),
        0.97,
    )


def _z3_version(data, image, symbols) -> StaticVersionMatch | None:
    required = {"Z3_get_version", "Z3_get_full_version"}
    if not required.issubset(symbols) or image.header["e_machine"] != "EM_X86_64":
        return None
    function = _function_bytes(image, data, "Z3_get_version")
    if function is None:
        return None
    code, function_offset = function
    address = int(symbols["Z3_get_version"]["value"])
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    parts = {}
    for instruction in disassembler.disasm(code, address):
        if instruction.id != X86_INS_MOV or len(instruction.operands) != 2:
            continue
        destination, source = instruction.operands
        if destination.type != X86_OP_MEM or source.type != X86_OP_IMM:
            continue
        base = instruction.reg_name(destination.mem.base)
        if destination.mem.index or base not in {"rdi", "rsi", "rdx", "rcx"}:
            continue
        parts[base] = int(source.imm)
    if set(parts) != {"rdi", "rsi", "rdx", "rcx"}:
        return None
    major, minor, patch = parts["rdi"], parts["rsi"], parts["rdx"]
    if not (0 < major <= 99 and 0 <= minor <= 99 and 0 <= patch <= 99):
        return None
    version = f"{major}.{minor}.{patch}"
    return StaticVersionMatch(
        "Z3",
        version,
        _evidence(
            "defined-output-parameter-version-getter",
            version=version,
            function="Z3_get_version",
            function_file_offset=function_offset,
            output_values={
                "major": major,
                "minor": minor,
                "patch": patch,
                "build": parts["rcx"],
            },
            supporting_api="Z3_get_full_version",
            source="https://github.com/Z3Prover/z3/blob/master/src/api/api_util.cpp",
        ),
        0.97,
    )


def _output_parameter_version(
    data,
    image,
    symbols,
    function: str,
    rule: _OutputVersionRule,
) -> StaticVersionMatch | None:
    """Read up to three integer outputs from a bounded x86-64 API function."""
    if image.header["e_machine"] != "EM_X86_64" or image.elfclass != 64:
        return None
    function_data = _function_bytes(image, data, function)
    if function_data is None:
        return None
    code, file_offset = function_data
    address = int(symbols[function]["value"])
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    arguments = {"rdi": "major", "rsi": "minor", "rdx": "patch"}
    values = {}
    for instruction in disassembler.disasm(code, address):
        if instruction.id != X86_INS_MOV or len(instruction.operands) != 2:
            continue
        destination, source = instruction.operands
        if (
            destination.type != X86_OP_MEM
            or destination.mem.index
            or destination.mem.disp
            or source.type != X86_OP_IMM
        ):
            continue
        argument = instruction.reg_name(destination.mem.base)
        if argument not in arguments or int(destination.size) != 4:
            continue
        value = int(source.imm)
        if argument in values and values[argument] != value:
            return None
        values[argument] = value
    required = {argument for argument, name in arguments.items() if name in rule.outputs}
    if not required.issubset(values):
        return None
    version_parts = [values[argument] for argument in ("rdi", "rsi", "rdx") if argument in required]
    if not version_parts or any(version_parts) == 0 or not 0 <= version_parts[0] <= 99:
        return None
    if any(not 0 <= part <= 999 for part in version_parts[1:]):
        return None
    version = ".".join(map(str, version_parts))
    return StaticVersionMatch(
        rule.component,
        version,
        _evidence(
            "defined-output-parameter-version-getter",
            version=version,
            function=function,
            function_file_offset=file_offset,
            output_values={
                arguments[argument]: value
                for argument, value in values.items()
                if arguments[argument] in rule.outputs
            },
            source=rule.source,
        ),
        0.96,
    )


def _modbus_version(data, image, symbols) -> StaticVersionMatch | None:
    names = (
        "libmodbus_version_major",
        "libmodbus_version_minor",
        "libmodbus_version_micro",
    )
    if "modbus_new_tcp" not in symbols or not all(name in symbols for name in names):
        return None
    parts = [_read_integer_object(image, data, name, 4) for name in names]
    if any(part is None for part in parts):
        return None
    major, minor, patch = (int(part) for part in parts)
    if not 0 < major <= 99 or not 0 <= minor <= 99 or not 0 <= patch <= 99:
        return None
    version = f"{major}.{minor}.{patch}"
    return StaticVersionMatch(
        "libmodbus",
        version,
        _evidence(
            "defined-version-object-triplet",
            version=version,
            objects={name: part for name, part in zip(names, parts, strict=True)},
            supporting_api="modbus_new_tcp",
            source="https://github.com/stephane/libmodbus/blob/master/src/modbus.c",
        ),
        0.97,
    )


def _libusb_version(data, image, symbols) -> StaticVersionMatch | None:
    if (
        not {"libusb_get_version", "libusb_init"}.issubset(symbols)
        or image.header["e_machine"] != "EM_X86_64"
        or image.elfclass != 64
    ):
        return None
    function = _function_bytes(image, data, "libusb_get_version")
    if function is None:
        return None
    code, function_offset = function
    address = int(symbols["libusb_get_version"]["value"])
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    returned = StaticVersionExtractor._returned_pointer(
        disassembler,
        "x86_64",
        code,
        address,
    )
    if returned is None or returned[1]:
        return None
    struct_offset = _object_offset(image, returned[0], 8)
    if struct_offset is None:
        return None
    byteorder = "little" if image.little_endian else "big"
    parts = struct.unpack_from(("<" if byteorder == "little" else ">") + "HHHH", data, struct_offset)
    major, minor, patch, nano = parts
    if not 0 < major <= 99 or minor > 99 or patch > 999:
        return None
    version = f"{major}.{minor}.{patch}"
    return StaticVersionMatch(
        "libusb",
        version,
        _evidence(
            "defined-returned-version-struct",
            version=version,
            function="libusb_get_version",
            function_file_offset=function_offset,
            struct_vaddr=hex(returned[0]),
            struct_file_offset=struct_offset,
            output_values={"major": major, "minor": minor, "patch": patch, "nano": nano},
            source="https://github.com/libusb/libusb/blob/master/libusb/version.c",
        ),
        0.97,
    )


def _ftdi_version(data, image, symbols) -> StaticVersionMatch | None:
    required = {
        "ftdi_get_library_version",
        "ftdi_init",
        "FTDI_VERSION_STRING",
    }
    if not required.issubset(symbols):
        return None
    symbol = symbols["FTDI_VERSION_STRING"]
    if symbol["type"] != "STT_OBJECT" or not 1 <= symbol["size"] <= 64:
        return None
    text = _read_c_string(image, data, symbol["value"])
    match = _RELEASE_TEXT.fullmatch(text or "")
    if match is None:
        return None
    version = match.group(1)
    return StaticVersionMatch(
        "libftdi",
        version,
        _evidence(
            "defined-version-string-object",
            version=version,
            object="FTDI_VERSION_STRING",
            object_vaddr=hex(symbol["value"]),
            supporting_apis=["ftdi_get_library_version", "ftdi_init"],
            source="https://www.intra2net.com/en/developer/libftdi/",
        ),
        0.97,
    )


def _gphoto_version(data, image, symbols) -> StaticVersionMatch | None:
    if (
        not {"gp_library_version", "gp_camera_new"}.issubset(symbols)
        or image.header["e_machine"] != "EM_X86_64"
        or image.elfclass != 64
    ):
        return None
    function = _function_bytes(image, data, "gp_library_version")
    if function is None:
        return None
    code, function_offset = function
    address = int(symbols["gp_library_version"]["value"])
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    tables = set()
    for instruction in disassembler.disasm(code, address):
        if instruction.id != X86_INS_LEA or len(instruction.operands) != 2:
            continue
        destination, source = instruction.operands
        if (
            destination.type != X86_OP_REG
            or instruction.reg_name(destination.reg) not in {"rax", "rdx"}
            or source.type != X86_OP_MEM
            or source.mem.base != X86_REG_RIP
            or source.mem.index
        ):
            continue
        tables.add(instruction.address + instruction.size + int(source.mem.disp))
    found = {}
    pointer_size = image.elfclass // 8
    for table in sorted(tables):
        for index in range(8):
            slot = table + index * pointer_size
            slot_offset = _object_offset(image, slot, pointer_size)
            if slot_offset is None:
                break
            byteorder = "little" if image.little_endian else "big"
            pointer = int.from_bytes(data[slot_offset : slot_offset + pointer_size], byteorder)
            if pointer == 0:
                break
            text = _read_c_string(image, data, pointer)
            match = _RELEASE_TEXT.fullmatch(text or "")
            if match is not None:
                found.setdefault(match.group(1), []).append(
                    {"table_vaddr": hex(table), "entry": index}
                )
    if len(found) != 1:
        return None
    version, locations = next(iter(found.items()))
    return StaticVersionMatch(
        "libgphoto2",
        version,
        _evidence(
            "defined-returned-version-pointer-table",
            version=version,
            function="gp_library_version",
            function_file_offset=function_offset,
            locations=locations,
            supporting_api="gp_camera_new",
            source="https://github.com/gphoto/libgphoto2",
        ),
        0.96,
    )


def _gpiod_api_version(data, image, symbols) -> StaticVersionMatch | None:
    """Keep gpiod's explicitly named API version separate from its release."""
    if (
        not {"gpiod_api_version", "gpiod_line_request_release"}.issubset(symbols)
        or image.header["e_machine"] != "EM_X86_64"
        or image.elfclass != 64
    ):
        return None
    function = _function_bytes(image, data, "gpiod_api_version")
    if function is None:
        return None
    code, function_offset = function
    address = int(symbols["gpiod_api_version"]["value"])
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    returned = StaticVersionExtractor._returned_pointer(
        disassembler,
        "x86_64",
        code,
        address,
    )
    if returned is None or returned[1]:
        return None
    text = _read_c_string(image, data, returned[0])
    match = _RELEASE_TEXT.fullmatch(text or "")
    if match is None:
        return None
    version = match.group(1)
    return StaticVersionMatch(
        "libgpiod",
        version,
        _evidence(
            "defined-api-version-string-getter",
            version=version,
            version_kind="interface",
            function="gpiod_api_version",
            function_file_offset=function_offset,
            returned_string=text,
            supporting_api="gpiod_line_request_release",
            source=(
                "https://kernel.googlesource.com/pub/scm/libs/libgpiod/"
                "libgpiod/+/refs/heads/master/include/gpiod.h"
            ),
        ),
        0.88,
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
