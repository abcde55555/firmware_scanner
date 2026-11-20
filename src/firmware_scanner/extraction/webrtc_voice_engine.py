"""Identify the embedded WebRTC VoiceEngine from independent release markers."""

from __future__ import annotations

import json

from .static_version import StaticVersionMatch

_BANNER = b"VoiceEngine 4.1.0"
_SOURCE_PATH_MARKERS = (
    b"external/webrtc/",
    b"../../webrtc/voice_engine/",
)
_REQUIRED_MARKERS = (
    b"VoEBaseImpl",
    b"GetVersion() =>",
    b"StartPlayout() failed to initialize playout",
)


def extract_webrtc_voice_engine(data: bytes) -> list[StaticVersionMatch]:
    """Return a release only when the banner, source tree and APIs agree."""
    if (
        not data.startswith(b"\x7fELF")
        or _BANNER not in data
        or not any(marker in data for marker in _SOURCE_PATH_MARKERS)
        or any(marker not in data for marker in _REQUIRED_MARKERS)
    ):
        return []
    evidence = json.dumps(
        {
            "probe": "webrtc-voice-engine-v1",
            "banner": _BANNER.decode("ascii"),
            "source_path_markers": [
                marker.decode("ascii")
                for marker in _SOURCE_PATH_MARKERS
                if marker in data
            ],
            "api_markers": [marker.decode("ascii") for marker in _REQUIRED_MARKERS],
            "identifier_type": "embedded-release-banner",
        },
        sort_keys=True,
    )
    return [
        StaticVersionMatch(
            "WebRTC VoiceEngine",
            "4.1.0",
            evidence,
            0.94,
        )
    ]
