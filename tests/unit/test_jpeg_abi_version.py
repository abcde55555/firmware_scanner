"""IJG JPEG release proof comes from a documented ABI guard, not a name guess."""

import json
import shutil
import subprocess

import pytest

from firmware_scanner.extraction.binary_inventory import BinaryInventory
from firmware_scanner.extraction.jpeg_abi_version import extract_jpeg_abi_evidence


def _compile(tmp_path, abi: int) -> bytes:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is required for the JPEG ABI fixture")
    source = tmp_path / "jpeg.c"
    output = tmp_path / "libjpeg.so"
    source.write_text(
        "void jpeg_read_header(void) {}\n"
        f"void jpeg_CreateDecompress(void *p, int version, unsigned long size) {{\n"
        f"  if (version != {abi}) {{ *(volatile int *)p = version; }}\n"
        f"  if (size != 480) {{ *(volatile int *)p = (int)size; }}\n"
        "}\n"
    )
    subprocess.run(
        [compiler, "-shared", "-fPIC", "-O2", str(source), "-o", str(output)],
        check=True,
        capture_output=True,
    )
    return output.read_bytes()


def _compile_with_banner(tmp_path, banner: str) -> bytes:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is required for the JPEG ABI fixture")
    source = tmp_path / "jpeg-turbo.c"
    output = tmp_path / "libjpeg-turbo.so"
    source.write_text(
        "void jpeg_read_header(void) {}\n"
        "void jpeg_CreateDecompress(void *p, int version, unsigned long size) {\n"
        "  if (version != 62) { *(volatile int *)p = version; }\n"
        "  if (size != 480) { *(volatile int *)p = (int)size; }\n"
        "}\n"
        f'const char banner[] = "{banner}";\n'
        "const char *get_banner(void) { return banner; }\n"
    )
    subprocess.run(
        [compiler, "-shared", "-fPIC", "-O2", str(source), "-o", str(output)],
        check=True,
        capture_output=True,
    )
    return output.read_bytes()


def test_ijg_6b_abi_guard_is_a_release_proof(tmp_path):
    data = _compile(tmp_path, 62)

    hit = extract_jpeg_abi_evidence(data)

    assert hit is not None
    assert hit.abi_version == 62
    evidence = json.loads(hit.evidence)
    assert evidence["probe"] == "ijg-jpeg-abi-guard-v1"
    assert evidence["abi_version"] == 62
    assert evidence["guard_file_offset"] >= evidence["function_file_offset"]
    assert evidence["release_semantics"] == "abi-compatibility-not-implementation-release"
    assert evidence["source"].endswith("/android-4.4.4_r2/jpeglib.h")


def test_other_jpeg_abi_versions_are_not_guessed_as_6b(tmp_path):
    assert extract_jpeg_abi_evidence(_compile(tmp_path, 80)) is None


def test_libjpeg_turbo_keeps_ijg_6_abi_without_becoming_ijg_6b(tmp_path):
    data = _compile_with_banner(tmp_path, "libjpeg-turbo version 2.1.5.1")
    assert extract_jpeg_abi_evidence(data) is None


def test_jpeg_abi_guard_is_kept_as_interface_evidence_not_a_release(tmp_path):
    data = _compile(tmp_path, 62)

    component = BinaryInventory().extract(
        data,
        "libjpeg.so",
        "/lib/libjpeg.so",
    )[0]

    assert component.name == "libjpeg.so"
    assert component.resolved_version == ""
    assert {
        "name": "firmware:jpeg:abi-version",
        "value": "62",
    } in component.properties
