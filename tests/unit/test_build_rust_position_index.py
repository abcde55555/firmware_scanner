import pytest

from experiments.version_coverage.build_rust_position_index import merge_indices


def _index(kind, checksum="a" * 64):
    return {"schema_version": 1, "families": [{"crate": "some-crate", "prior_version": "1.2.3",
            "prior_source": "https://example.org/Cargo.toml", "releases": [{"version": "1.2.3",
            "source": "https://static.crates.io/crates/some-crate/some-crate-1.2.3.crate",
            "source_sha256": checksum,
            "sites": [{"file": "src/lib.rs", "line": 12, "column": 7, "kind": kind}]}]}]}


def test_combines_compiled_and_ast_references_without_losing_their_methods():
    result = merge_indices(_index("compiled-panic"), _index("index_expression"))
    assert len(result["families"]) == 1
    releases = result["families"][0]["releases"]
    assert len(releases) == 1
    assert {site["kind"] for site in releases[0]["sites"]} == {"compiled-panic", "index_expression"}


def test_cannot_combine_two_sources_for_the_same_release():
    with pytest.raises(ValueError, match="source"):
        merge_indices(_index("compiled-panic"), _index("index_expression", "b" * 64))
