"""Recover a release declared by a defined, bounded ELF version object.

CryptoAuthLib's historical atca_version array contains its yyyymmdd release
identifier. It is distinct from compilation dates, chip revisions and protocol
versions. Only the documented object plus defined library APIs is accepted.
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


def extract_object_versions(data: bytes) -> list[StaticVersionMatch]:
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
