import hashlib
import json

import pytest

from firmware_scanner.core.rules_manifest import (
    build_rule_lock,
    verify_builtin_rule_lock,
    verify_rule_lock,
)


def test_rule_lock_verifies_all_declared_files(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    rules = data / "rules.json"
    rules.write_text('{"rules": []}\n')
    digest = hashlib.sha256(rules.read_bytes()).hexdigest()
    lock = data / "rules.lock.json"
    lock.write_text(json.dumps({
        "schema_version": 1,
        "release": "2026.11.19.1",
        "files": [{
            "path": "rules.json",
            "sha256": digest,
            "kind": "binary-reference",
        }],
    }))

    verified = verify_rule_lock(lock, data)

    assert verified["release"] == "2026.11.19.1"
    assert verified["files"][0]["path"] == "rules.json"
    assert len(verified["lock_sha256"]) == 64


def test_rule_lock_rejects_changed_rule_content(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    rules = data / "rules.json"
    rules.write_text('{"rules": ["old"]}\n')
    digest = hashlib.sha256(rules.read_bytes()).hexdigest()
    lock = data / "rules.lock.json"
    lock.write_text(json.dumps({
        "schema_version": 1,
        "release": "test",
        "files": [{
            "path": "rules.json",
            "sha256": digest,
            "kind": "binary-reference",
        }],
    }))
    rules.write_text('{"rules": ["changed"]}\n')

    with pytest.raises(ValueError, match="rule pack hash mismatch"):
        verify_rule_lock(lock, data)


def test_rule_lock_rejects_path_traversal(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    lock = data / "rules.lock.json"
    lock.write_text(json.dumps({
        "schema_version": 1,
        "release": "test",
        "files": [{
            "path": "../outside.json",
            "sha256": "0" * 64,
            "kind": "binary-reference",
        }],
    }))

    with pytest.raises(ValueError, match="invalid rule pack path"):
        verify_rule_lock(lock, data)


def test_builtin_rule_lock_covers_version_management_inputs():
    verified = verify_builtin_rule_lock()
    paths = {entry["path"] for entry in verified["files"]}
    assert {
        "binary_reference.json",
        "emba_rules.json",
        "provenance/android_source_project_rules.json",
        "provenance/source-version-pins.json",
        "database_packs/blintdb-v4-arm64.json",
        "database_packs/nsrl-rds-2026.03.1-android-minimal.json",
    }.issubset(paths)


def test_build_rule_lock_is_deterministic_and_excludes_the_lock_itself(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "b.json").write_text("{}\n")
    (data / "a.json").write_text("{}\n")
    (data / "rules.lock.json").write_text("{}\n")

    first = build_rule_lock(data, "release-1")
    second = build_rule_lock(data, "release-1")

    assert first == second
    assert [item["path"] for item in first["files"]] == ["a.json", "b.json"]
    assert first["release"] == "release-1"
