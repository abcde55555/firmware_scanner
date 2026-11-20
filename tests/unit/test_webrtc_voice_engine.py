"""WebRTC VoiceEngine release evidence must agree across several markers."""

import json

from firmware_scanner.extraction.binary_inventory import BinaryInventory
from firmware_scanner.extraction.webrtc_voice_engine import extract_webrtc_voice_engine


def _fixture() -> bytes:
    return (
        b"\x7fELF"
        b"\0VoiceEngine 4.1.0\0"
        b"external/webrtc/src/voice_engine/voe_base_impl.cc\0"
        b"VoEBaseImpl\0"
        b"GetVersion() =>\0"
        b"StartPlayout() failed to initialize playout\0"
    )


def test_webrtc_voice_engine_banner_and_source_path_prove_release():
    hits = extract_webrtc_voice_engine(_fixture())

    assert [(hit.name, hit.version, hit.confidence) for hit in hits] == [
        ("WebRTC VoiceEngine", "4.1.0", 0.94)
    ]
    evidence = json.loads(hits[0].evidence)
    assert evidence["probe"] == "webrtc-voice-engine-v1"
    assert evidence["source_path_markers"] == ["external/webrtc/"]


def test_webrtc_voice_engine_rejects_banner_only_or_api_only_fragments():
    assert extract_webrtc_voice_engine(b"\x7fELF\0VoiceEngine 4.1.0\0") == []
    assert (
        extract_webrtc_voice_engine(
            b"\x7fELF\0external/webrtc/\0VoEBaseImpl\0GetVersion() =>\0"
        )
        == []
    )


def test_webrtc_voice_engine_is_a_contained_component():
    components = BinaryInventory().extract(
        _fixture(),
        "libvideochat_jni.so",
        "/lib/libvideochat_jni.so",
    )

    assert components[0].resolved_version == ""
    voice = next(
        component for component in components if component.name == "WebRTC VoiceEngine"
    )
    assert voice.resolved_version == "4.1.0"
    assert voice.component_type == "library"
    assert voice.versions[0].confidence == 0.94
