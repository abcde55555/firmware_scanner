import importlib
import sqlite3

import pytest

from experiments.version_coverage.blint_db_probe import (
    defined_elf_symbols,
    eligible_observations,
    merged_coverage,
    missing_ranges,
    query_symbol_candidates,
    validate_schema,
)


def make_db(path):
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE SchemaMeta (key TEXT, value TEXT);
        INSERT INTO SchemaMeta VALUES ('schema_version', '3');
        CREATE TABLE Projects (project_id INTEGER, name TEXT, purl TEXT,
                               ecosystem TEXT, metadata_json TEXT,
                               source_sbom_json TEXT);
        CREATE TABLE Builds (build_id INTEGER, project_id INTEGER,
                             target_arch TEXT, target_triplet TEXT,
                             metadata_json TEXT);
        CREATE TABLE Binaries (binary_id INTEGER, build_id INTEGER, name TEXT,
                               sha256 TEXT, metadata_json TEXT);
        CREATE TABLE Symbols (binary_id INTEGER, name TEXT, raw_name TEXT,
                              symbol_version TEXT, is_exported INTEGER);
        INSERT INTO Projects VALUES (1, 'libdemo', 'pkg:generic/libdemo@1.0',
                                    'meson', '{}', '{}');
        INSERT INTO Builds VALUES (1, 1, 'arm64', 'aarch64-linux-gnu', '{}');
        INSERT INTO Binaries VALUES (1, 1, 'libdemo.so', 'abc', '{}');
        INSERT INTO Symbols VALUES (1, 'demo_init', NULL, NULL, 1);
        """
    )
    connection.commit()
    connection.close()


def test_exact_match_ranks_by_distinct_symbol_and_returns_all_release_candidates(tmp_path):
    path = tmp_path / "blint.db"
    make_db(path)
    with sqlite3.connect(path) as connection:
        schema = validate_schema(connection)
        found = query_symbol_candidates(connection, {"demo_init", "absent"})
    assert schema["schema_version"] == "3"
    assert found[0]["project_name"] == "libdemo"
    assert found[0]["matched_symbols"] == 1
    assert found[0]["version_candidates"] == ["pkg:generic/libdemo@1.0"]


def test_ambiguous_releases_are_preserved_as_multiple_candidates(tmp_path):
    path = tmp_path / "ambiguous.db"
    make_db(path)
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO Projects VALUES (2, 'libdemo', 'pkg:generic/libdemo@2.0', 'meson', '{}', '{}')")
        connection.execute("INSERT INTO Builds VALUES (2, 2, 'arm64', 'aarch64-linux-gnu', '{}')")
        connection.execute("INSERT INTO Binaries VALUES (2, 2, 'libdemo.so', 'def', '{}')")
        connection.execute("INSERT INTO Symbols VALUES (2, 'demo_init', NULL, NULL, 1)")
        found = query_symbol_candidates(connection, {"demo_init"})
    assert len(found) == 2
    assert {item["version_candidates"][0] for item in found} == {
        "pkg:generic/libdemo@1.0", "pkg:generic/libdemo@2.0"
    }


def test_schema_mismatch_is_rejected_instead_of_silently_returning_no_hits(tmp_path):
    path = tmp_path / "wrong.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE unrelated (value TEXT)")
    with pytest.raises(ValueError, match="required blint-db tables"):
        validate_schema(connection)


def test_defined_symbol_extraction_excludes_dependency_imports(monkeypatch):
    class Symbol:
        def __init__(self, name, section):
            self.name = name
            self.values = {"st_shndx": section}

        def __getitem__(self, key):
            return self.values[key]

    section_type = type("SymbolTableSection", (), {
        "iter_symbols": lambda self: iter([
            Symbol("defined_api", 7), Symbol("libc_import", "SHN_UNDEF")
        ])
    })

    class FakeELF:
        def __init__(self, _stream):
            pass

        def iter_sections(self):
            return [section_type(), type("DynamicSection", (), {
                "iter_symbols": lambda self: (_ for _ in ()).throw(AssertionError("must be skipped"))
            })()]

    elf_module = importlib.import_module("elftools.elf.elffile")
    monkeypatch.setattr(elf_module, "ELFFile", FakeELF)
    assert defined_elf_symbols(b"ELF fixture") == {"defined_api"}


def test_unknown_host_claim_is_not_excluded_by_versioned_dependency_claim(tmp_path):
    scan = tmp_path / "scan" / "system"
    scan.mkdir(parents=True)
    (scan / "input.json").write_text('{"path":"/tmp/system.img"}')
    (scan / "file-observations.json").write_text(
        '[{"location":"/system/lib/libhost.so","filename":"libhost.so",'
        '"sha256":"abc","claims":[{"name":"libhost.so","version":"",'
        '"versions":[{"version":""}]},{"name":"embedded-dep","version":"3.2",'
        '"versions":[{"version":"3.2"}]}]}]'
    )
    rows = eligible_observations([scan / "file-observations.json"])
    assert len(rows) == 1
    assert rows[0]["location"] == "/system/lib/libhost.so"


def test_resumable_chunks_only_download_true_coverage_gaps():
    coverage = merged_coverage([(8, 20), (0, 12), (28, 40), (36, 48)], 40)
    assert coverage == [(0, 20), (28, 40)]
    assert missing_ranges(coverage, 40) == [(20, 28)]


def test_coverage_is_clipped_to_declared_layer_size():
    coverage = merged_coverage([(0, 32), (24, 64)], 40)
    assert coverage == [(0, 40)]
    assert missing_ranges(coverage, 40) == []
