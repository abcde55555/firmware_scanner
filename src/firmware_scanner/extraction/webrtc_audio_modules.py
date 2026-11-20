"""Recognize versioned WebRTC audio-processing modules in stripped ELF files."""

from __future__ import annotations

import json
from dataclasses import dataclass
from io import BytesIO

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .static_version import StaticVersionMatch


@dataclass(frozen=True)
class _ModuleRule:
    name: str
    getter: str
    supporting_symbols: frozenset[str]
    literal: bytes
    version: str
    source: str


_RULES = (
    _ModuleRule(
        "WebRTC SPL",
        "WebRtcSpl_get_version",
        frozenset(
            {
                "WebRtcSpl_ComplexFFT",
                "WebRtcSpl_LevinsonDurbin",
                "WebRtcSpl_AllPassQMF",
            }
        ),
        b"1.2.0\0",
        "1.2.0",
        (
            "https://android.googlesource.com/platform/external/webrtc/"
            "+/4b6dc1ec58105d17dc8c2f550124cc0621dc93b7/"
            "src/common_audio/signal_processing_library/main/source/spl_version.c"
        ),
    ),
    _ModuleRule(
        "WebRTC VAD",
        "WebRtcVad_get_version",
        frozenset({"WebRtcVad_Init", "WebRtcVad_Process"}),
        b"VAD 1.2.0\0",
        "1.2.0",
        (
            "https://android.googlesource.com/platform/external/webrtc/"
            "+/4b6dc1ec58105d17dc8c2f550124cc0621dc93b7/"
            "src/common_audio/vad/main/source/webrtc_vad.c"
        ),
    ),
    _ModuleRule(
        "WebRTC NS",
        "WebRtcNsx_get_version",
        frozenset({"WebRtcNsx_InitCore", "WebRtcNsx_ProcessCore"}),
        b"NS\t3.1.0\0",
        "3.1.0",
        (
            "https://android.googlesource.com/platform/external/webrtc/"
            "+/4b6dc1ec58105d17dc8c2f550124cc0621dc93b7/"
            "src/modules/audio_processing/ns/main/source/noise_suppression_x.c"
        ),
    ),
    _ModuleRule(
        "WebRTC AEC",
        "WebRtcAec_get_version",
        frozenset({"WebRtcAec_Init", "WebRtcAec_Process"}),
        b"AEC 2.5.0\0",
        "2.5.0",
        (
            "https://android.googlesource.com/platform/external/webrtc/"
            "+/4b6dc1ec58105d17dc8c2f550124cc0621dc93b7/"
            "src/modules/audio_processing/aec/main/source/echo_cancellation.c"
        ),
    ),
    _ModuleRule(
        "WebRTC AGC",
        "WebRtcAgc_Version",
        frozenset({"WebRtcAgc_Init", "WebRtcAgc_Process"}),
        b"AGC 1.7.0\0",
        "1.7.0",
        (
            "https://android.googlesource.com/platform/external/webrtc/"
            "+/c55a96383497a772a307b346368133960b02ad03/"
            "src/modules/audio_processing/agc/analog_agc.c"
        ),
    ),
    _ModuleRule(
        "WebRTC AECM",
        "WebRtcAecm_get_version",
        frozenset({"WebRtcAecm_Init", "WebRtcAecm_Process"}),
        b"AECM 1.2.0\0",
        "1.2.0",
        (
            "https://android.googlesource.com/platform/external/webrtc/"
            "+/c55a96383497a772a307b346368133960b02ad03/"
            "src/modules/audio_processing/aecm/aecm_core.c"
        ),
    ),
)


def extract_webrtc_audio_modules(data: bytes) -> list[StaticVersionMatch]:
    """Require the documented module getter, peer APIs and exact release literal."""
    if not data.startswith(b"\x7fELF") or not any(
        rule.getter.encode("ascii") in data for rule in _RULES
    ):
        return []
    try:
        with ELFFile(BytesIO(data)) as image:
            defined_functions = {
                symbol.name
                for section in image.iter_sections()
                if isinstance(section, SymbolTableSection)
                for symbol in section.iter_symbols()
                if symbol.name
                and symbol["st_info"]["type"] == "STT_FUNC"
                and symbol["st_shndx"] not in (0, "SHN_UNDEF", "SHN_ABS")
            }
    except (ELFError, OSError, ValueError, TypeError):
        return []

    matches = []
    for rule in _RULES:
        required = {rule.getter, *rule.supporting_symbols}
        if not required.issubset(defined_functions):
            continue
        offsets = []
        start = 0
        while (offset := data.find(rule.literal, start)) >= 0:
            offsets.append(offset)
            start = offset + 1
        if not offsets:
            continue
        evidence = json.dumps(
            {
                "probe": "documented-webrtc-module-version-v1",
                "version": rule.version,
                "version_kind": "runtime",
                "getter": rule.getter,
                "supporting_symbols": sorted(rule.supporting_symbols),
                "literal_file_offsets": offsets,
                "source": rule.source,
            },
            sort_keys=True,
        )
        matches.append(StaticVersionMatch(rule.name, rule.version, evidence, 0.95))
    return matches
