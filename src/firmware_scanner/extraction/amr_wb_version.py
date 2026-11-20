"""Attribute an embedded 3GPP AMR-WB decoder from its release banner and APIs."""

from __future__ import annotations

import json
import re
from io import BytesIO

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .static_version import StaticVersionMatch

_BANNER = b"3GPP AMR-WB Floating-point Speech Decoder, v6.0.0, Dec 14, 2004"
_SOURCE = "https://www.3gpp.org/ftp/Specs/archive/26_series/26.204/26204-600.zip"
_DECODE_API = re.compile(r"Speech_Decode_Frame$")
_AMR_WB_API = re.compile(r"(?:AMRWBDec_main|Decoder_amr_wb)$")


def extract_amr_wb_version(data: bytes) -> list[StaticVersionMatch]:
    """Return the official v6.0.0 decoder only when linked APIs corroborate it."""
    if not data.startswith(b"\x7fELF") or _BANNER not in data:
        return []
    try:
        image = ELFFile(BytesIO(data))
        symbols: set[str] = set()
        for section in image.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if (
                    symbol["st_info"]["type"] == "STT_FUNC"
                    and symbol["st_shndx"]
                    and symbol["st_shndx"] != "SHN_UNDEF"
                ):
                    symbols.add(symbol.name)
        decode_symbols = sorted(name for name in symbols if _DECODE_API.search(name))
        wb_symbols = sorted(name for name in symbols if _AMR_WB_API.search(name))
        if not decode_symbols or not wb_symbols:
            return []
        evidence = json.dumps(
            {
                "probe": "3gpp-amr-wb-banner-v1",
                "banner": _BANNER.decode("ascii"),
                "decode_symbols": decode_symbols,
                "amr_wb_symbols": wb_symbols,
                "identifier_type": "official-codec-release",
                "source": _SOURCE,
            },
            sort_keys=True,
        )
        return [
            StaticVersionMatch(
                "3GPP AMR-WB decoder",
                "6.0.0",
                evidence,
                0.98,
            )
        ]
    except (ELFError, OSError, ValueError, TypeError, KeyError, IndexError):
        return []
