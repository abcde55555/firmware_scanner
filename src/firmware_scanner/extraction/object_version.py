"""Recover a release declared by a defined, bounded ELF version object.

CryptoAuthLib's historical atca_version array contains its yyyymmdd release
identifier. It is distinct from compilation dates, chip revisions and protocol
versions. SQLite declares its own release in the read-only sqlite3_version
array. Only documented objects plus defined library APIs are accepted.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from io import BytesIO

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .static_version import StaticVersionMatch

_SOURCE = (
    "https://github.com/MicrochipTech/cryptoauth-openssl-engine/"
    "blob/master/cryptoauthlib/lib/basic/atca_basic.c"
)
_APIS = {"atcab_version", "atcab_init"}
_SQLITE_APIS = {"sqlite3_libversion", "sqlite3_libversion_number", "sqlite3_sourceid"}
_SQLITE_SOURCE = "https://www.sqlite.org/c3ref/libversion.html"


def extract_object_versions(data: bytes) -> list[StaticVersionMatch]:
    if not data.startswith(b"\x7fELF"):
        return []
    return _cryptoauth_versions(data) + _sqlite_versions(data)


def _sqlite_versions(data: bytes) -> list[StaticVersionMatch]:
    if b"sqlite3_version\0" not in data:
        return []
    try:
        image = ELFFile(BytesIO(data))
        loads = [segment for segment in image.iter_segments() if segment["p_type"] == "PT_LOAD"]

        def file_offset(address, size, *, executable=False):
            if address < 0 or size <= 0:
                return None
            for segment in loads:
                flags = int(segment["p_flags"])
                if not flags & 4 or (executable and not flags & 1):
                    continue
                if not executable and flags & 2:
                    continue
                delta = address - int(segment["p_vaddr"])
                offset = int(segment["p_offset"]) + delta
                if (0 <= delta and delta + size <= int(segment["p_filesz"])
                        and 0 <= offset and offset + size <= len(data)):
                    return offset
            return None

        functions, objects = set(), set()
        for section in image.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if (symbol["st_shndx"] in (0, "SHN_UNDEF", "SHN_ABS")
                        or symbol["st_info"]["bind"] not in ("STB_GLOBAL", "STB_WEAK")):
                    continue
                address, size = int(symbol["st_value"]), int(symbol["st_size"])
                kind = symbol["st_info"]["type"]
                if kind == "STT_FUNC" and symbol.name in _SQLITE_APIS:
                    if image["e_machine"] == "EM_ARM":
                        address &= ~1
                    if file_offset(address, size, executable=True) is not None:
                        functions.add(symbol.name)
                if kind == "STT_OBJECT" and symbol.name == "sqlite3_version":
                    objects.add((address, size))
        if not _SQLITE_APIS.issubset(functions) or len(objects) != 1:
            return []
        address, size = objects.pop()
        if not 6 <= size <= 64:
            return []
        offset = file_offset(address, size)
        if offset is None:
            return []
        raw = data[offset : offset + size]
        if not re.fullmatch(rb"[0-9]{1,2}(?:\.[0-9]{1,3}){2,3}(?:[-+][A-Za-z0-9._+-]+)?\x00", raw):
            return []
        version = raw[:-1].decode("ascii")
        evidence = json.dumps({
            "probe": "defined-release-object-v1",
            "symbol": "sqlite3_version", "vaddr": hex(address),
            "file_offset": offset, "size": size, "value": version,
            "identifier_type": "library-declared-release",
            "identity_functions": sorted(_SQLITE_APIS), "source": _SQLITE_SOURCE,
        }, sort_keys=True)
        return [StaticVersionMatch("SQLite", version, evidence, 0.96)]
    except (ELFError, ValueError, TypeError, KeyError, IndexError, OSError):
        return []


def _cryptoauth_versions(data: bytes) -> list[StaticVersionMatch]:
    if not data.startswith(b"\x7fELF") or b"atca_version\0" not in data:
        return []
    try:
        image = ELFFile(BytesIO(data))
        functions = set()
        objects = set()
        for section in image.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if symbol["st_shndx"] in ("SHN_UNDEF", "SHN_ABS") or symbol["st_info"][
                    "bind"
                ] not in ("STB_GLOBAL", "STB_WEAK"):
                    continue
                kind = symbol["st_info"]["type"]
                if symbol.name in _APIS and kind == "STT_FUNC" and symbol["st_size"]:
                    functions.add(symbol.name)
                if symbol.name == "atca_version" and kind == "STT_OBJECT":
                    objects.add((int(symbol["st_value"]), int(symbol["st_size"])))
        if not _APIS.issubset(functions) or len(objects) != 1:
            return []
        address, size = objects.pop()
        if size != 9:
            return []
        for segment in image.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            start = int(segment["p_vaddr"])
            if not start <= address or address + size > start + int(segment["p_filesz"]):
                continue
            offset = int(segment["p_offset"]) + address - start
            raw = data[offset : offset + size]
            if not re.fullmatch(rb"[12][0-9]{7}\x00", raw):
                return []
            version = raw[:-1].decode("ascii")
            datetime.strptime(version, "%Y%m%d")
            evidence = json.dumps(
                {
                    "probe": "defined-release-object-v1",
                    "symbol": "atca_version",
                    "vaddr": hex(address),
                    "file_offset": offset,
                    "size": size,
                    "value": version,
                    "encoding": "upstream-yyyymmdd-release",
                    "identity_functions": sorted(_APIS),
                    "source": _SOURCE,
                },
                sort_keys=True,
            )
            return [StaticVersionMatch("CryptoAuthLib", version, evidence, 0.96)]
    except (ELFError, ValueError, TypeError, KeyError, IndexError, OSError):
        return []
    return []
