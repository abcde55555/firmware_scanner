"""User-visible Rust estimates retain nearby candidates and component ownership."""

from __future__ import annotations

import json
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from firmware_scanner.extraction.rust_version_estimate import RustVersionEstimator


def _index(tmp_path):
    sites = [
        {"file": "src/lib.rs", "line": line, "column": 7, "kind": "compiled-panic"}
        for line in (12, 13, 14)
    ]
    release = lambda version: {
        "version": version,
        "source": f"https://static.crates.io/crates/ryu/ryu-{version}.crate",
        "source_sha256": "a" * 64,
        "sites": sites,
    }
    document = {
        "schema_version": 1,
        "families": [
            {
                "crate": "ryu",
                "prior_version": "1.0.20",
                "prior_source": "https://android.googlesource.com/platform/external/rust/android-crates-io/+/c991cad10330f37e93d82926bd6dae7f4f6647f6/crates/ryu/Cargo.toml",
                "releases": [release("1.0.19"), release("1.0.20")],
            }
        ],
    }
    path = tmp_path / "index.json"
    path.write_text(json.dumps(document))
    return path


def _locations(crate="ryu"):
    return [
        {
            "crate": crate,
            "source_file": "src/lib.rs",
            "line": line,
            "column": 7,
            "code_references": [{"vaddr": "0x1000"}],
            "corroborated_calls": [{"symbol": "core panic"}],
        }
        for line in (12, 13, 14)
    ]


def test_same_code_releases_produce_estimate_and_retain_all_candidates(tmp_path):
    estimate = RustVersionEstimator(_index(tmp_path)).estimate_locations(_locations(), "ryu")
    assert estimate.version == "1.0.20"
    assert estimate.candidates == ("1.0.19", "1.0.20")
    assert estimate.kind == "estimated-release"
    assert estimate.matched_sites == 3
    assert estimate.selection == "reference-source-prior-within-candidates"


def test_dependency_positions_cannot_version_the_host(tmp_path):
    estimator = RustVersionEstimator(_index(tmp_path))
    assert estimator.estimate_locations(_locations("other-crate"), "ryu") is None


def test_repeated_one_site_is_insufficient_independent_evidence(tmp_path):
    estimator = RustVersionEstimator(_index(tmp_path))
    assert estimator.estimate_locations([_locations()[0]] * 20, "ryu") is None


def test_unreferenced_source_strings_are_insufficient(tmp_path):
    rows = _locations()
    for row in rows:
        row["corroborated_calls"] = []
    assert RustVersionEstimator(_index(tmp_path)).estimate_locations(rows, "ryu") is None


def test_same_positions_across_minor_lines_remain_unresolved(tmp_path):
    path = _index(tmp_path)
    document = json.loads(path.read_text())
    document["families"][0]["releases"][0]["version"] = "1.1.0"
    path.write_text(json.dumps(document))
    assert RustVersionEstimator(path).estimate_locations(_locations(), "ryu") is None


def _elf(tmp_path):
    cc = shutil.which("cc")
    if not cc:
        pytest.skip("host assembler/linker required; the fixture is never executed")
    path = "external/rust/android-crates-io/crates/ryu/src/lib.rs"
    callee = "_RNvNtCs8_4core9panicking18panic_bounds_check"
    text = ".text\n"
    for number in (12, 13, 14):
        text += (
            f".global function_{number}\n.type function_{number},@function\nfunction_{number}:\n"
            f"lea .Lloc{number}(%rip),%rdx\ncall *{callee}@GOTPCREL(%rip)\nret\n"
            f".size function_{number},.-function_{number}\n"
        )
    text += f'.section .rodata\n.Lpath: .ascii "{path}"\n.section .data.rel.ro\n'
    for number in (12, 13, 14):
        text += f".balign 8\n.Lloc{number}: .quad .Lpath\n.quad {len(path)}\n.long {number},7\n"
    text += '.section .note.GNU-stack,"",@progbits\n'
    source, binary = tmp_path / "fixture.S", tmp_path / "fixture.so"
    source.write_text(text)
    subprocess.run(
        [cc, "-shared", "-nostdlib", "-Wl,-z,relro", str(source), "-o", str(binary)],
        check=True,
        capture_output=True,
    )
    return binary.read_bytes()


def test_inventory_exports_estimate_with_candidates_and_original_location(tmp_path):
    from firmware_scanner.extraction.binary_inventory import BinaryInventory
    from firmware_scanner.sbom.cyclonedx import CycloneDXGenerator

    inventory = BinaryInventory()
    inventory._rust_estimator = RustVersionEstimator(_index(tmp_path))
    result = inventory.extract(_elf(tmp_path), "libryu.dylib.so", "/system/lib64/libryu.dylib.so")
    host = next(row for row in result if row.name == "libryu.dylib.so")
    assert host.resolved_version == "1.0.20"
    properties = {row["name"]: row["value"] for row in host.properties}
    assert properties["firmware:version:kind"] == "estimated-release"
    assert json.loads(properties["firmware:version:candidates"]) == ["1.0.19", "1.0.20"]
    assert properties["firmware:evidence:location"] == "/system/lib64/libryu.dylib.so"
    assert any(row.method.value == "version_estimate" for row in host.versions)
    sbom = CycloneDXGenerator().generate([host], "firmware.img", "a" * 64)
    exported = sbom["components"][0]
    assert exported["version"] == "1.0.20"
    assert any(
        row["name"] == "firmware:version:kind" and row["value"] == "estimated-release"
        for row in exported["properties"]
    )


@pytest.mark.parametrize("observed", [("1.0.21",), ("1.0.21", "1.0.22")])
def test_inventory_preserves_observed_releases_and_conflicts(tmp_path, monkeypatch, observed):
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    inventory = BinaryInventory()
    hits = [
        SimpleNamespace(
            name="libryu.dylib.so",
            version=version,
            confidence=0.95,
            evidence=f"own release {version}",
            source="https://example.org/release",
        )
        for version in observed
    ]
    monkeypatch.setattr(inventory._reference, "match", lambda *_args, **_kwargs: hits)

    def unexpected_estimate(*_):
        pytest.fail("an estimate must not replace an observed release or explicit conflict")

    monkeypatch.setattr(inventory._rust_estimator, "estimate", unexpected_estimate)
    host = inventory.extract(_elf(tmp_path), "libryu.dylib.so", "/lib/libryu.dylib.so")[0]

    assert host.resolved_version == (observed[0] if len(observed) == 1 else "")
    assert not any(prop.get("value") == "estimated-release" for prop in host.properties)
