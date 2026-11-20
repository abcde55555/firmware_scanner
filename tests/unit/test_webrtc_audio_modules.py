import shutil
import subprocess

import pytest

from firmware_scanner.android.provenance import apply_component_taxonomy
from firmware_scanner.extraction.binary_inventory import BinaryInventory
from firmware_scanner.extraction.webrtc_audio_modules import (
    extract_webrtc_audio_modules,
)


def _compile(tmp_path, source: str):
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is required for WebRTC module fixtures")
    source_path = tmp_path / "webrtc.c"
    output = tmp_path / "libwebrtc_audio_preprocessing.so"
    source_path.write_text(source)
    subprocess.run(
        [compiler, "-shared", "-fPIC", "-O2", str(source_path), "-o", str(output)],
        check=True,
        capture_output=True,
    )
    return output.read_bytes()


def test_webrtc_audio_modules_require_getter_peer_apis_and_literal(tmp_path):
    source = """
    const char *WebRtcSpl_get_version(void) { return "1.2.0"; }
    void WebRtcSpl_ComplexFFT(void) {}
    void WebRtcSpl_LevinsonDurbin(void) {}
    void WebRtcSpl_AllPassQMF(void) {}
    const char *WebRtcVad_get_version(void) { return "VAD 1.2.0"; }
    void WebRtcVad_Init(void) {}
    void WebRtcVad_Process(void) {}
    const char *WebRtcNsx_get_version(void) { return "NS\\t3.1.0"; }
    void WebRtcNsx_InitCore(void) {}
    void WebRtcNsx_ProcessCore(void) {}
    const char *WebRtcAec_get_version(void) { return "AEC 2.5.0"; }
    void WebRtcAec_Init(void) {}
    void WebRtcAec_Process(void) {}
    const char *WebRtcAgc_Version(void) { return "AGC 1.7.0"; }
    void WebRtcAgc_Init(void) {}
    void WebRtcAgc_Process(void) {}
    const char *WebRtcAecm_get_version(void) { return "AECM 1.2.0"; }
    void WebRtcAecm_Init(void) {}
    void WebRtcAecm_Process(void) {}
    """
    data = _compile(tmp_path, source)

    assert {(match.name, match.version) for match in extract_webrtc_audio_modules(data)} == {
        ("WebRTC SPL", "1.2.0"),
        ("WebRTC VAD", "1.2.0"),
        ("WebRTC NS", "3.1.0"),
        ("WebRTC AEC", "2.5.0"),
        ("WebRTC AGC", "1.7.0"),
        ("WebRTC AECM", "1.2.0"),
    }

    components = BinaryInventory().extract(
        data,
        "libwebrtc_audio_preprocessing.so",
        "/lib/libwebrtc_audio_preprocessing.so",
    )
    assert {
        (component.name, component.resolved_version)
        for component in components
        if component.name.startswith("WebRTC ")
    } == {
        ("WebRTC SPL", "1.2.0"),
        ("WebRTC VAD", "1.2.0"),
        ("WebRTC NS", "3.1.0"),
        ("WebRTC AEC", "2.5.0"),
        ("WebRTC AGC", "1.7.0"),
        ("WebRTC AECM", "1.2.0"),
    }
    apply_component_taxonomy(components)
    assert all(
        any(
            prop.get("name") == "firmware:taxonomy"
            and prop.get("value") == "third-party-oss"
            for prop in component.properties
        )
        for component in components
        if component.name.startswith("WebRTC ")
    )


def test_webrtc_module_is_rejected_when_its_peer_api_set_is_incomplete(tmp_path):
    data = _compile(
        tmp_path,
        'const char *WebRtcAec_get_version(void) { return "AEC 2.5.0"; }\n'
        "void WebRtcAec_Init(void) {}\n",
    )

    assert extract_webrtc_audio_modules(data) == []
