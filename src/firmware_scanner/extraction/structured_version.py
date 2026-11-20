"""Recover versions from documented public version-info structures.

nghttp2, nghttp3 and ngtcp2 expose a stable three-field structure through a
defined getter. The first two fields are integers and the third is a relocated
pointer to the release string. This module reads that structure and its
relative relocation without executing target code.
"""

from __future__ import annotations

import json
import re
import struct
from io import BytesIO

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from .static_version import StaticVersionExtractor, StaticVersionMatch

_STRING_APIS = {
    "nghttp2_version": ("nghttp2", "https://nghttp2.org/documentation/nghttp2.h.html"),
    "nghttp3_version": ("nghttp3", "https://nghttp3.org/library/nghttp3.h.html"),
    "ngtcp2_version": ("ngtcp2", "https://ngtcp2.org/ngtcp2.h.html"),
}
_INTEGER_STRUCT_APIS = {
    "seccomp_version": (
        "seccomp",
        "https://github.com/seccomp/libseccomp/blob/main/include/seccomp.h.in",
    ),
}
_RELATIVE_TYPES = {
    "EM_386": 8,
    "EM_X86_64": 8,
    "EM_ARM": 23,
    "EM_AARCH64": 1027,
}
_RELEASE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def extract_structured_versions(data: bytes) -> list[StaticVersionMatch]:
    if not data.startswith(b"\x7fELF") or not any(
        name.encode("ascii") in data
        for name in (*_STRING_APIS, *_INTEGER_STRUCT_APIS)
    ):
        return []
    try:
        image = ELFFile(BytesIO(data))
        machine = image["e_machine"]
        relative_type = _RELATIVE_TYPES.get(machine)
        if relative_type is None or image.elfclass not in (32, 64):
            return []
        byteorder = "little" if image.little_endian else "big"
        struct_prefix = "<" if image.little_endian else ">"
        pointer_size = image.elfclass // 8
        loads = [
            segment for segment in image.iter_segments()
            if segment["p_type"] == "PT_LOAD"
        ]

        def offset_for(address: int, size: int) -> int | None:
            if address < 0 or size <= 0:
                return None
            for segment in loads:
                delta = address - int(segment["p_vaddr"])
                offset = int(segment["p_offset"]) + delta
                if (0 <= delta and delta + size <= int(segment["p_filesz"])
                        and 0 <= offset and offset + size <= len(data)):
                    return offset
            return None

        functions: dict[str, tuple[int, int]] = {}
        for section in image.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if ((symbol.name in _STRING_APIS or symbol.name in _INTEGER_STRUCT_APIS)
                        and symbol["st_info"]["type"] == "STT_FUNC"
                        and symbol["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK")
                        and symbol["st_shndx"] not in (0, "SHN_UNDEF", "SHN_ABS")
                        and 0 < int(symbol["st_size"]) <= 256):
                    functions.setdefault(
                        symbol.name,
                        (int(symbol["st_value"]), int(symbol["st_size"])),
                    )
        if not functions:
            return []

        matches = []
        seen = set()
        for api in sorted(set(functions) & set(_STRING_APIS)):
            component, source = _STRING_APIS[api]
            for section in image.iter_sections():
                if not isinstance(section, RelocationSection):
                    continue
                for relocation in section.iter_relocations():
                    if int(relocation["r_info_type"]) != relative_type:
                        continue
                    pointer_address = int(relocation["r_offset"])
                    struct_address = pointer_address - 8
                    header_offset = offset_for(struct_address, 8)
                    if header_offset is None:
                        continue
                    age, version_number = struct.unpack_from(
                        struct_prefix + "ii",
                        data,
                        header_offset,
                    )
                    if age != 1 or version_number <= 0:
                        continue
                    string_address = int(relocation["r_addend"])
                    if string_address <= 0:
                        string_offset = offset_for(pointer_address, pointer_size)
                        if string_offset is None:
                            continue
                        string_address = int.from_bytes(
                            data[string_offset : string_offset + pointer_size],
                            byteorder,
                        )
                        if string_address <= 0:
                            continue
                    string_offset = offset_for(string_address, 1)
                    if string_offset is None:
                        continue
                    end = data.find(
                        b"\0",
                        string_offset,
                        min(len(data), string_offset + 64),
                    )
                    if end < 0:
                        continue
                    raw = data[string_offset:end]
                    try:
                        version = raw.decode("ascii")
                    except UnicodeDecodeError:
                        continue
                    match = _RELEASE.fullmatch(version)
                    if match is None:
                        continue
                    parts = tuple(int(part) for part in match.groups())
                    if parts[0] > 255 or parts[1] > 255 or parts[2] > 255:
                        continue
                    if version_number != (parts[0] << 16 | parts[1] << 8 | parts[2]):
                        continue
                    key = (component, version)
                    if key in seen:
                        continue
                    seen.add(key)
                    evidence = json.dumps({
                        "probe": "structured-version-getter-v1",
                        "api": api,
                        "struct_vaddr": hex(struct_address),
                        "pointer_slot_vaddr": hex(pointer_address),
                        "string_vaddr": hex(string_address),
                        "age": age,
                        "version_number": version_number,
                        "value": version,
                        "relocation_type": relative_type,
                        "source": source,
                    }, sort_keys=True)
                    matches.append(
                        StaticVersionMatch(component, version, evidence, 0.96)
                    )
        if machine == "EM_X86_64" and image.elfclass == 64 and image.little_endian:
            disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
            disassembler.detail = True
            for api in sorted(set(functions) & set(_INTEGER_STRUCT_APIS)):
                component, source = _INTEGER_STRUCT_APIS[api]
                address, size = functions[api]
                code_offset = offset_for(address, size)
                if code_offset is None:
                    continue
                pointer = StaticVersionExtractor._returned_pointer(
                    disassembler,
                    "x86_64",
                    data[code_offset : code_offset + size],
                    address,
                )
                if pointer is None or pointer[1]:
                    continue
                struct_offset = offset_for(pointer[0], 12)
                if struct_offset is None:
                    continue
                parts = struct.unpack_from("<III", data, struct_offset)
                if not 0 < parts[0] <= 99 or not all(part <= 99 for part in parts):
                    continue
                version = ".".join(map(str, parts))
                if (component, version) in seen:
                    continue
                seen.add((component, version))
                evidence = json.dumps({
                    "probe": "structured-integer-getter-v1",
                    "api": api,
                    "function_vaddr": hex(address),
                    "struct_vaddr": hex(pointer[0]),
                    "file_offset": struct_offset,
                    "value": version,
                    "source": source,
                }, sort_keys=True)
                matches.append(
                    StaticVersionMatch(component, version, evidence, 0.96)
                )
        return matches
    except (ELFError, ValueError, TypeError, KeyError, IndexError, OSError,
            struct.error, OverflowError):
        return []
