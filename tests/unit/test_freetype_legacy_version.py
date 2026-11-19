"""Read-only version proof for legacy ARM FreeType libraries."""

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from firmware_scanner.extraction.binary_inventory import BinaryInventory


@pytest.fixture(scope="module")
def allwinner_freetype(tmp_path_factory):
    image = os.environ.get("FREETYPE_ALLWINNER_SYSTEM_IMAGE")
    if not image:
        pytest.skip("set FREETYPE_ALLWINNER_SYSTEM_IMAGE to run the legacy FreeType control")
    image_path = Path(image)
    if not image_path.is_file():
        pytest.skip(f"legacy FreeType system image is unavailable: {image_path}")
    debugfs = shutil.which("debugfs")
    if not debugfs:
        pytest.skip("debugfs is required for the read-only legacy FreeType control")

    output = tmp_path_factory.mktemp("allwinner-freetype") / "libft2.so"
    result = subprocess.run(
        [debugfs, "-R", f"dump /lib/libft2.so {output}", str(image_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode or not output.is_file():
        pytest.skip(f"/lib/libft2.so is absent from {image_path}")
    data = output.read_bytes()
    assert hashlib.sha256(data).hexdigest() == (
        "f652c2ffb3409fc54a98e0d0335f120de53d32392fbbcc2b207dd93e50f5643f"
    )
    return data


def test_legacy_arm_freetype_version_is_attributed_from_paired_library_apis(
    allwinner_freetype,
):
    component = BinaryInventory().extract(
        allwinner_freetype,
        "libft2.so",
        "/lib/libft2.so",
    )[0]

    assert component.resolved_version == "2.4.12"
    assert any(
        prop["name"] == "firmware:version:resolution-state" and prop["value"] == "exact"
        for prop in component.properties
    )
    assert any(
        "FT_Library_Version" in version.evidence and "FT_New_Library" in version.evidence
        for version in component.versions
    )


def test_legacy_freetype_rejects_a_field_overwrite_after_initialization(
    allwinner_freetype,
):
    original = bytes.fromhex("0210a0e30420a0e30c30a0e30100a0e30e0085e9bc0085e5005087e5e4ffffea")
    mutated = allwinner_freetype.replace(
        original,
        original[:-4] + bytes.fromhex("0c4085e5"),
        1,
    )
    assert mutated != allwinner_freetype

    component = BinaryInventory().extract(
        mutated,
        "libft2.so",
        "/lib/libft2.so",
    )[0]

    assert component.resolved_version == ""
