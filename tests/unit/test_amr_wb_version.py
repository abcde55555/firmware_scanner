"""AMR-WB release evidence requires both the official banner and decoder APIs."""

import json
import shutil
import subprocess

import pytest

from firmware_scanner.extraction.amr_wb_version import extract_amr_wb_version
from firmware_scanner.extraction.binary_inventory import BinaryInventory


def _compile(tmp_path, source: str) -> bytes:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is required for the AMR-WB fixture")
    path = tmp_path / "amr.c"
    output = tmp_path / "libnormal_audio.so"
    path.write_text(source)
    subprocess.run(
        [compiler, "-shared", "-fPIC", "-O2", str(path), "-o", str(output)],
        check=True,
        capture_output=True,
    )
    return output.read_bytes()


def test_official_amr_wb_banner_and_apis_identify_release(tmp_path):
    data = _compile(
        tmp_path,
        "void AudioAMRSpeech_Decode_Frame(void) {}\n"
        "void AudioAMRAMRWBDec_main(void) {}\n"
        'const char banner[] = "3GPP AMR-WB Floating-point Speech Decoder, '
        'v6.0.0, Dec 14, 2004";\n'
        "const char *get_banner(void) { return banner; }\n",
    )

    hits = extract_amr_wb_version(data)

    assert [(hit.name, hit.version) for hit in hits] == [("3GPP AMR-WB decoder", "6.0.0")]
    evidence = json.loads(hits[0].evidence)
    assert evidence["probe"] == "3gpp-amr-wb-banner-v1"
    assert evidence["decode_symbols"] == ["AudioAMRSpeech_Decode_Frame"]
    assert evidence["amr_wb_symbols"] == ["AudioAMRAMRWBDec_main"]


@pytest.mark.parametrize(
    "source",
    [
        "void AudioAMRSpeech_Decode_Frame(void) {}\n",
        "void AudioAMRAMRWBDec_main(void) {}\n",
        (
            "void AudioAMRSpeech_Decode_Frame(void) {}\n"
            "void AudioAMRAMRWBDec_main(void) {}\n"
            'const char banner[] = "3GPP AMR-WB Floating-point Speech Decoder";\n'
        ),
    ],
)
def test_banner_or_linked_api_fragments_are_not_release_proof(tmp_path, source):
    assert extract_amr_wb_version(_compile(tmp_path, source)) == []


def test_amr_wb_is_contained_inside_the_vendor_audio_container(tmp_path):
    data = _compile(
        tmp_path,
        "void AudioAMRSpeech_Decode_Frame(void) {}\n"
        "void AudioAMRAMRWBDec_main(void) {}\n"
        'const char banner[] = "3GPP AMR-WB Floating-point Speech Decoder, '
        'v6.0.0, Dec 14, 2004";\n'
        "const char *get_banner(void) { return banner; }\n",
    )

    components = BinaryInventory().extract(
        data,
        "libnormal_audio.so",
        "/lib/libnormal_audio.so",
    )

    assert components[0].resolved_version == ""
    assert any(
        component.name == "3GPP AMR-WB decoder" and component.resolved_version == "6.0.0"
        for component in components
    )
    amr_wb = next(component for component in components if component.name == "3GPP AMR-WB decoder")
    assert {
        "name": "firmware:vulnerability:query",
        "value": "not-queryable-no-canonical-osv-package",
    } in amr_wb.properties
