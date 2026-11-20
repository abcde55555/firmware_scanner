from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "experiments/version_coverage/build_rust_ast_index.py"


def _module():
    spec = importlib.util.spec_from_file_location("build_rust_ast_index", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_indexes_macro_call_index_and_arithmetic_ast_positions(monkeypatch):
    mod = _module()
    monkeypatch.setenv("PYTHONPATH", "")
    source = (
        'fn f(v: Vec<i32>, i: usize) {\n'
        '    let _ = v[i] + v.len();\n'
        '    let _ = v.get(i).unwrap();\n'
        '    let _ = v.get(i).expect("missing");\n'
        '    let _ = i + 1; assert!(i < v.len()); assert_eq!(i, 2);\n'
        '    panic!("failure");\n'
        '}\n'
    )

    sites = mod.index_source("src/lib.rs", source.encode())
    actual = {(row["line"], row["kind"]) for row in sites}
    assert {
        (2, "index_expression"),
        (2, "arithmetic_add"),
        (3, "unwrap_call"),
        (4, "expect_call"),
        (5, "assert_macro"),
        (5, "assert_eq_macro"),
        (5, "arithmetic_add"),
        (6, "panic_macro"),
    } <= actual
    assert all(row["file"] == "src/lib.rs" and row["line"] >= 1 and row["column"] >= 1 for row in sites)


def test_columns_are_one_based_unicode_character_columns():
    mod = _module()
    sites = mod.index_source("src/lib.rs", 'fn f() { let _ = "雪"; panic!("x"); }'.encode())
    panic_site = next(row for row in sites if row["kind"] == "panic_macro")
    assert panic_site["line"] == 1
    assert panic_site["column"] == len('fn f() { let _ = "雪"; ') + 1


def test_keeps_valid_ast_sites_in_syntactically_invalid_source():
    mod = _module()
    source = b"fn f() { panic!(\"still located\"); let broken = ; }"
    sites = mod.index_source("src/broken.rs", source)
    assert any(row["kind"] == "panic_macro" and row["file"] == "src/broken.rs" for row in sites)
    assert mod.parse_source(source)[1] is True


def test_source_parse_budget_is_checked_before_parsing(monkeypatch):
    mod = _module()
    monkeypatch.setattr(mod, "MAX_SOURCE_BYTES", 8, raising=False)
    with pytest.raises(ValueError, match="budget"):
        mod.index_source("src/lib.rs", b"fn excessive() {}")


@pytest.mark.parametrize("path", ["../escape.rs", "/absolute.rs", "src\\escape.rs", "src/lib.txt", ""])
def test_rejects_source_paths_outside_canonical_rust_file_boundary(path):
    with pytest.raises(ValueError):
        _module().validate_source_file(path)


def test_accepts_only_normalized_relative_rust_source_paths():
    assert _module().validate_source_file("src/net/socket.rs") == "src/net/socket.rs"


def test_eligibility_requires_both_binary_reference_and_corroborated_call(tmp_path):
    mod = _module()
    locations = tmp_path / "locations.json"
    locations.write_text(json.dumps({"rows": [{"locations": [
        {"crate": "kept_crate", "source_file": "src/lib.rs", "code_references": [1], "corroborated_calls": [1]},
        {"crate": "reference_only", "source_file": "src/lib.rs", "code_references": [1], "corroborated_calls": []},
        {"crate": "call_only", "source_file": "src/lib.rs", "code_references": [], "corroborated_calls": [1]},
    ]}]}))
    assert mod.eligible_locations(locations) == {"kept_crate": {"src/lib.rs"}}


def test_build_index_emits_runtime_schema_and_verified_source_hashes(tmp_path):
    mod = _module()
    source = b'fn f() { panic!("reference"); }\n'
    source_path = tmp_path / "sources" / "pkg_name" / "1.2.3" / "src" / "lib.rs"
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(source)
    digest = hashlib.sha256(source).hexdigest()
    archive_path = tmp_path / ".cache" / "crates" / "pkg-name-1.2.3.crate"
    archive_path.parent.mkdir(parents=True)
    with tarfile.open(archive_path, "w:gz") as archive:
        member = tarfile.TarInfo("pkg-name-1.2.3/src/lib.rs")
        member.size = len(source)
        archive.addfile(member, io.BytesIO(source))
    archive_digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    corpus = tmp_path / "corpus.json"
    corpus.write_text(json.dumps({"crates": [{
        "crate_path": "pkg_name",
        "package_name": "pkg-name",
        "declared_version": "1.2.3",
        "manifest": {"url": "https://android.googlesource.com/manifest"},
        "pinned_files": {},
        "errors": [],
        "versions": [{
            "version": "1.2.3",
            "archive_url": "https://static.crates.io/crates/pkg-name/pkg-name-1.2.3.crate",
            "archive_sha256": archive_digest,
            "index_checksum": archive_digest,
            "files": {"src/lib.rs": {"path": "sources/pkg_name/1.2.3/src/lib.rs", "sha256": digest}},
            "missing_files": [],
            "errors": [],
        }],
    }]}))
    output = tmp_path / "index.json"

    result = mod.build_index(corpus, output)
    release = result["families"][0]["releases"][0]
    assert result["schema_version"] == 1
    assert result["families"][0]["crate"] == "pkg-name"
    assert result["families"][0]["prior_version"] == "1.2.3"
    assert result["families"][0]["prior_source"] == "https://android.googlesource.com/manifest"
    assert release["source"] == "https://static.crates.io/crates/pkg-name/pkg-name-1.2.3.crate"
    assert release["source_sha256"] == archive_digest
    assert release["source_file_hashes"] == {"src/lib.rs": digest}
    assert {"file", "line", "column", "kind"} <= release["sites"][0].keys()
    assert result["grammar"]["runtime"]["version"]
    assert result["grammar"]["grammar"]["sha256"]
    assert json.loads(output.read_text()) == result
