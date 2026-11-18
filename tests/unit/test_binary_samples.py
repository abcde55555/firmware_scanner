import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from firmware_scanner.extraction.binary_samples import BinarySampleMatcher


@pytest.fixture(scope="module")
def compiled_elfs(tmp_path_factory):
    compiler = shutil.which("gcc") or shutil.which("cc")
    if not compiler:
        pytest.fail("a C compiler is required to build real ELF fixtures")
    tmp_path = tmp_path_factory.mktemp("compiled-elfs")
    paths = {}
    for name, body in {
        "alpha": "int alpha_value(void) { return 17; }\n",
        "beta": "int beta_value(void) { return 29; }\n",
    }.items():
        source = tmp_path / f"{name}.c"
        output = tmp_path / f"{name}.so"
        source.write_text(body, encoding="utf-8")
        subprocess.run(
            [compiler, "-shared", "-fPIC", "-Wl,--build-id=none", "-o", str(output), str(source)],
            check=True,
            capture_output=True,
        )
        paths[name] = output
    return {name: path.read_bytes() for name, path in paths.items()}


def sample(component_name, release, data, **overrides):
    record = {
        "name": component_name,
        "version": release,
        "sha256": hashlib.sha256(data).hexdigest(),
        "source": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
        "upstream_source": "https://www.kernel.org/",
        "artifact_path": f"lib/{component_name}.so",
        "architecture": "x86_64",
        "version_kind": "release",
    }
    record.update(overrides)
    return record


def write_index(path: Path, samples):
    path.write_text(json.dumps({"schema_version": 1, "samples": samples}), encoding="utf-8")
    return path


def test_exact_full_file_match_returns_untruncated_version_and_all_provenance(tmp_path, compiled_elfs):
    data = compiled_elfs["alpha"]
    row = sample("libalpha", "v1.2.3-4-gabc1234", data, version_kind="commit")
    matcher = BinarySampleMatcher(write_index(tmp_path / "index.json", [row]))

    matches = matcher.match(data)

    assert len(matches) == 1
    assert matches[0].name == "libalpha"
    assert matches[0].version == "v1.2.3-4-gabc1234"
    evidence = json.loads(matches[0].evidence)
    assert evidence["method"] == "whole_file_sha256"
    assert evidence["sha256"] == row["sha256"]
    assert evidence["provenance"] == [{
        "source": row["source"],
        "upstream_source": row["upstream_source"],
        "artifact_path": row["artifact_path"],
        "architecture": "x86_64",
        "version_kind": "commit",
    }]


def test_changed_byte_does_not_match_a_whole_file_sample(tmp_path, compiled_elfs):
    data = compiled_elfs["alpha"]
    matcher = BinarySampleMatcher(write_index(tmp_path / "index.json", [sample("libalpha", "1.0", data)]))
    modified = data[:-1] + bytes([data[-1] ^ 1])

    assert matcher.match(modified) == []
    assert matcher.candidates(modified) == []


def test_same_name_and_hash_with_multiple_versions_is_ambiguous(tmp_path, compiled_elfs):
    data = compiled_elfs["alpha"]
    matcher = BinarySampleMatcher(write_index(tmp_path / "index.json", [
        sample("libalpha", "1.0.0", data),
        sample("libalpha", "1.1.0", data, artifact_path="rebuild/libalpha.so"),
    ]))

    assert matcher.match(data) == []
    assert [candidate["version"] for candidate in matcher.candidates(data)] == ["1.0.0", "1.1.0"]


def test_same_bytes_can_support_separate_provenanced_component_identities(tmp_path, compiled_elfs):
    data = compiled_elfs["alpha"]
    matcher = BinarySampleMatcher(write_index(tmp_path / "index.json", [
        sample("libalpha", "1.0.0", data),
        sample("vendor-alpha", "2.0.0", data, artifact_path="vendor/libalpha.so"),
    ]))

    assert [(match.name, match.version) for match in matcher.match(data)] == [
        ("libalpha", "1.0.0"),
        ("vendor-alpha", "2.0.0"),
    ]


def test_single_version_match_retains_provenance_from_every_matching_record(tmp_path, compiled_elfs):
    data = compiled_elfs["alpha"]
    first = sample("libalpha", "1.0.0", data)
    second = sample(
        "libalpha", "1.0.0", data, artifact_path="release/libalpha.so",
        source="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git?build=release",
    )
    matcher = BinarySampleMatcher(write_index(tmp_path / "index.json", [first, second]))

    matches = matcher.match(data)

    assert len(matches) == 1
    evidence = json.loads(matches[0].evidence)
    assert len(evidence["provenance"]) == 2
    assert {item["artifact_path"] for item in evidence["provenance"]} == {
        "lib/libalpha.so",
        "release/libalpha.so",
    }


def test_default_missing_catalog_is_empty_and_never_fabricates_a_match(compiled_elfs):
    matcher = BinarySampleMatcher()

    assert matcher.match(compiled_elfs["alpha"]) == []
    assert matcher.candidates(compiled_elfs["alpha"]) == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"source": "http://insecure.invalid/source"},
        {"source": "https://example.com/placeholder"},
        {"upstream_source": "https://example.org/demo"},
        {"sha256": "abc123"},
        {"name": ""},
        {"version": " "},
        {"artifact_path": "../../outside.so"},
    ],
)
def test_invalid_or_placeholder_provenance_is_rejected_at_import(tmp_path, compiled_elfs, overrides):
    row = sample("libalpha", "1.0", compiled_elfs["alpha"], **overrides)
    path = write_index(tmp_path / "index.json", [row])

    with pytest.raises(ValueError):
        BinarySampleMatcher(path)


@pytest.mark.parametrize(
    "payload",
    [
        {"schema_version": 2, "samples": []},
        {"schema_version": 1, "samples": {}},
        {"schema_version": 1, "samples": [{"name": "incomplete"}]},
    ],
)
def test_malformed_catalog_schema_raises_value_error(tmp_path, payload):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError):
        BinarySampleMatcher(path)


def test_malformed_json_and_missing_explicit_path_raise_value_error(tmp_path):
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{broken", encoding="utf-8")

    with pytest.raises(ValueError):
        BinarySampleMatcher(malformed)
    with pytest.raises(ValueError):
        BinarySampleMatcher(tmp_path / "missing.json")
