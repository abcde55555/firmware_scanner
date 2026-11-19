"""Recover a release declared by a defined, bounded ELF version object.

CryptoAuthLib's historical atca_version array contains its yyyymmdd release
identifier. It is distinct from compilation dates, chip revisions and protocol
versions. SQLite declares its own release in the read-only sqlite3_version
array. Only documented objects plus defined library APIs are accepted.
"""

from __future__ import annotations

import json
import re
import struct
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
_GMP_SOURCE = (
    "https://gmplib.org/repo/gmp/file/tip/version.c"
)
_UNISTRING_SOURCE = "https://git.savannah.gnu.org/git/libunistring.git"
_GDK_PIXBUF_SOURCE = "https://gitlab.gnome.org/GNOME/gdk-pixbuf"


def extract_object_versions(data: bytes) -> list[StaticVersionMatch]:
    if not data.startswith(b"\x7fELF"):
        return []
    return (
        _cryptoauth_versions(data)
        + _sqlite_versions(data)
        + _gmp_versions(data)
        + _unistring_versions(data)
        + _gdk_pixbuf_versions(data)
    )


def _object_offset(
    data: bytes,
    image,
    address: int,
    size: int,
) -> int | None:
    for segment in image.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        delta = address - int(segment["p_vaddr"])
        offset = int(segment["p_offset"]) + delta
        if (0 <= delta and delta + size <= int(segment["p_filesz"])
                and 0 <= offset and offset + size <= len(data)):
            return offset
    return None


def _unistring_versions(data: bytes) -> list[StaticVersionMatch]:
    if b"_libunistring_version\0" not in data:
        return []
    try:
        image = ELFFile(BytesIO(data))
        values = set()
        for section in image.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if (symbol.name == "_libunistring_version"
                        and symbol["st_info"]["type"] == "STT_OBJECT"
                        and symbol["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK")
                        and symbol["st_shndx"] not in (0, "SHN_UNDEF", "SHN_ABS")
                        and int(symbol["st_size"]) == 4):
                    values.add(int(symbol["st_value"]))
        if len(values) != 1:
            return []
        address = values.pop()
        offset = _object_offset(data, image, address, 4)
        if offset is None:
            return []
        packed = int.from_bytes(
            data[offset : offset + 4],
            "little" if image.little_endian else "big",
        )
        parts = (packed >> 16) & 0xFF, (packed >> 8) & 0xFF, packed & 0xFF
        if not all(0 < part <= 99 for part in parts):
            return []
        version = ".".join(map(str, parts))
        evidence = json.dumps({
            "probe": "defined-packed-version-object-v1",
            "symbol": "_libunistring_version",
            "vaddr": hex(address),
            "file_offset": offset,
            "value": version,
            "source": _UNISTRING_SOURCE,
        }, sort_keys=True)
        return [StaticVersionMatch("libunistring", version, evidence, 0.96)]
    except (ELFError, ValueError, TypeError, KeyError, IndexError, OSError,
            struct.error, OverflowError):
        return []


def _gdk_pixbuf_versions(data: bytes) -> list[StaticVersionMatch]:
    names = (
        "gdk_pixbuf_major_version",
        "gdk_pixbuf_minor_version",
        "gdk_pixbuf_micro_version",
    )
    if not all(name.encode("ascii") + b"\0" in data for name in names):
        return []
    try:
        image = ELFFile(BytesIO(data))
        objects: dict[str, set[int]] = {name: set() for name in names}
        for section in image.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if (symbol.name in objects
                        and symbol["st_info"]["type"] == "STT_OBJECT"
                        and symbol["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK")
                        and symbol["st_shndx"] not in (0, "SHN_UNDEF", "SHN_ABS")
                        and int(symbol["st_size"]) == 4):
                    objects[symbol.name].add(int(symbol["st_value"]))
        if any(len(addresses) != 1 for addresses in objects.values()):
            return []
        values = []
        offsets = []
        for name in names:
            address = next(iter(objects[name]))
            offset = _object_offset(data, image, address, 4)
            if offset is None:
                return []
            value = int.from_bytes(
                data[offset : offset + 4],
                "little" if image.little_endian else "big",
            )
            if not 0 <= value <= 99:
                return []
            values.append(value)
            offsets.append(offset)
        if values[0] <= 0:
            return []
        version = ".".join(map(str, values))
        evidence = json.dumps({
            "probe": "defined-version-triplet-v1",
            "symbols": {
                name: {"vaddr": hex(next(iter(objects[name]))), "file_offset": offset}
                for name, offset in zip(names, offsets, strict=True)
            },
            "value": version,
            "source": _GDK_PIXBUF_SOURCE,
        }, sort_keys=True)
        return [StaticVersionMatch("GdkPixbuf", version, evidence, 0.96)]
    except (ELFError, ValueError, TypeError, KeyError, IndexError, OSError,
            struct.error, OverflowError):
        return []


def _gmp_versions(data: bytes) -> list[StaticVersionMatch]:
    """Read GMP's documented ``const char *__gmp_version`` release object."""
    if b"__gmp_version\0" not in data:
        return []
    try:
        image = ELFFile(BytesIO(data))
        if not image.little_endian or image.elfclass not in (32, 64):
            return []
        objects = set()
        for section in image.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if (symbol.name != "__gmp_version"
                        or symbol["st_info"]["type"] != "STT_OBJECT"
                        or symbol["st_info"]["bind"] not in ("STB_GLOBAL", "STB_WEAK")
                        or symbol["st_shndx"] in (0, "SHN_UNDEF", "SHN_ABS")):
                    continue
                objects.add((int(symbol["st_value"]), int(symbol["st_size"])))
        if len(objects) != 1:
            return []
        object_address, object_size = objects.pop()
        pointer_size = image.elfclass // 8
        if object_size != pointer_size:
            return []
        loads = [
            segment for segment in image.iter_segments()
            if segment["p_type"] == "PT_LOAD"
        ]

        def offset_for(address: int, size: int, *, writable: bool | None = None):
            for segment in loads:
                flags = int(segment["p_flags"])
                if writable is True and not flags & 2:
                    continue
                if writable is False and flags & 2:
                    continue
                delta = address - int(segment["p_vaddr"])
                offset = int(segment["p_offset"]) + delta
                if (0 <= delta and delta + size <= int(segment["p_filesz"])
                        and offset + size <= len(data)):
                    return offset
            return None

        object_offset = offset_for(object_address, pointer_size)
        if object_offset is None:
            return []
        string_address = int.from_bytes(
            data[object_offset : object_offset + pointer_size],
            "little",
        )
        string_offset = offset_for(string_address, 1, writable=False)
        if string_offset is None:
            return []
        end = data.find(b"\0", string_offset, min(len(data), string_offset + 65))
        if end < 0:
            return []
        raw = data[string_offset:end]
        if not re.fullmatch(rb"\d+\.\d+(?:\.\d+){0,2}", raw):
            return []
        version = raw.decode("ascii")
        evidence = json.dumps({
            "probe": "defined-release-object-v1",
            "symbol": "__gmp_version",
            "object_vaddr": hex(object_address),
            "object_file_offset": object_offset,
            "string_vaddr": hex(string_address),
            "string_file_offset": string_offset,
            "value": version,
            "identifier_type": "library-declared-release",
            "source": _GMP_SOURCE,
        }, sort_keys=True)
        return [StaticVersionMatch("GMP", version, evidence, 0.96)]
    except (ELFError, ValueError, TypeError, KeyError, IndexError, OSError,
            struct.error, OverflowError):
        return []


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
