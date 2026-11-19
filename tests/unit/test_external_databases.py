import hashlib
import json
import sqlite3

import pytest

from firmware_scanner.cli.app import (
    _external_database_enricher,
    _validate_external_databases,
)
from firmware_scanner.core.config import AnalysisConfig
from firmware_scanner.databases import manifest as manifest_module
from firmware_scanner.databases.blintdb import BLintDatabase
from firmware_scanner.databases.enricher import DatabaseEnricher
from firmware_scanner.databases.manifest import DatabaseManifest, packaged_manifests
from firmware_scanner.databases.nsrl import NSRLDatabase
from firmware_scanner.extraction.binary_inventory import BinaryInventory
from firmware_scanner.extraction.models import Component
from firmware_scanner.extraction.smart_analyzer import SmartSectionAnalyzer


def manifest(kind: str, digest: str = "0" * 64) -> DatabaseManifest:
    return DatabaseManifest.from_dict({
        "schema_version": 1,
        "kind": kind,
        "name": kind,
        "release": "test",
        "database_sha256": digest,
        "database_bytes": 1,
        "database_schema_version": "3" if kind == "blintdb" else "RDSv3",
        "source_url": "https://example.invalid/database",
        "license": "test",
        "architecture": "all",
    })


def make_nsrl(path):
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE FILE (
            sha256 TEXT, sha1 TEXT, md5 TEXT, crc32 TEXT,
            file_name TEXT, file_size INTEGER, package_id INTEGER
        );
        CREATE TABLE PKG (
            package_id INTEGER, name TEXT, version TEXT,
            operating_system_id INTEGER, manufacturer_id INTEGER,
            language TEXT, application_type TEXT
        );
        CREATE INDEX file_sha256 ON FILE(sha256);
        INSERT INTO PKG VALUES (1, 'Example Android Image', '16', 1, 1, '', '');
        INSERT INTO FILE VALUES (
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'cccccccccccccccccccccccccccccccc',
            'dddddddd',
            'libexact.so', 1234, 1
        );
        """
    )
    connection.commit()
    connection.close()


def make_blint(path):
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE SchemaMeta (key TEXT, value TEXT);
        CREATE TABLE Projects (project_id INTEGER, name TEXT, purl TEXT);
        CREATE TABLE Builds (build_id INTEGER, project_id INTEGER, target_arch TEXT);
        CREATE TABLE Binaries (binary_id INTEGER, build_id INTEGER, name TEXT);
        CREATE TABLE Symbols (
            binary_id INTEGER, source TEXT, name TEXT, is_imported INTEGER
        );
        CREATE TABLE Dependencies (
            binary_id INTEGER, source TEXT, name TEXT, version TEXT, purl TEXT
        );
        CREATE INDEX symbols_name ON Symbols(name);
        INSERT INTO SchemaMeta VALUES ('schema_version', '3');
        INSERT INTO Projects VALUES (1, 'libdemo', 'pkg:conan/libdemo@1.2.3');
        INSERT INTO Builds VALUES (1, 1, 'arm64');
        INSERT INTO Binaries VALUES (1, 1, 'libdemo.so');
        INSERT INTO Dependencies VALUES (
            1, 'import_dependencies',
            '/tmp/blint/host/libdemo/1.2.3/shared-release/aarch64/lib/libdemo.so',
            '', 'pkg:conan/libdemo@1.2.3'
        );
        """
    )
    for index in range(35):
        connection.execute(
            "INSERT INTO Symbols VALUES (1, 'dynamic_symbols', ?, 0)",
            (f"demo_identity_{index}",),
        )
    connection.commit()
    connection.close()


def test_packaged_database_manifests_are_complete():
    manifests = packaged_manifests()
    assert {item.kind for item in manifests} == {"blintdb", "nsrl"}
    assert all(len(item.database_sha256) == 64 for item in manifests)


def test_nsrl_exact_lookup_keeps_distribution_semantics(tmp_path):
    path = tmp_path / "nsrl.db"
    make_nsrl(path)
    database = NSRLDatabase(path, manifest("nsrl"), verify_hash=False)
    rows = database.lookup("a" * 64, 1234)
    assert rows[0]["file_name"] == "libexact.so"
    assert rows[0]["package_name"] == "Example Android Image"
    assert rows[0]["version_semantics"] == "distribution-package-not-upstream-library"


def test_nsrl_reuses_one_read_only_connection_for_repeated_lookups(tmp_path, monkeypatch):
    path = tmp_path / "nsrl.db"
    make_nsrl(path)
    database = NSRLDatabase(path, manifest("nsrl"), verify_hash=False)
    assert database.lookup("a" * 64, 1234)

    def unexpected_reconnect(_path, **_kwargs):
        raise AssertionError("NSRL lookup opened a new SQLite connection")

    monkeypatch.setattr(sqlite3, "connect", unexpected_reconnect)
    try:
        assert database.lookup("a" * 64, 1234)
    finally:
        database.close()


def test_blintdb_returns_reference_candidate_without_promoting_version(tmp_path, monkeypatch):
    path = tmp_path / "blint.db"
    make_blint(path)
    database = BLintDatabase(path, manifest("blintdb"), verify_hash=False)
    monkeypatch.setattr(
        database,
        "_symbol_sources",
        lambda _data: {
            "dynamic_symbols": {f"demo_identity_{index}" for index in range(35)}
        },
    )
    candidates = database.candidates(b"ELF", "host.so")
    assert candidates[0]["unique_component_versions"] == [{
        "name": "libdemo",
        "version": "1.2.3",
    }]
    assert candidates[0]["version_semantics"] == "reference-build-candidate-not-target-version"


def test_blintdb_reuses_one_read_only_connection_for_repeated_queries(tmp_path, monkeypatch):
    path = tmp_path / "blint.db"
    make_blint(path)
    database = BLintDatabase(path, manifest("blintdb"), verify_hash=False)
    monkeypatch.setattr(
        database,
        "_symbol_sources",
        lambda _data: {
            "dynamic_symbols": {f"demo_identity_{index}" for index in range(35)}
        },
    )
    assert database.candidates(b"ELF", "libdemo.so")
    original_connect = sqlite3.connect

    def unexpected_reconnect(*_args, **_kwargs):
        raise AssertionError("BLintDB query opened a new SQLite connection")

    monkeypatch.setattr(sqlite3, "connect", unexpected_reconnect)
    try:
        assert database.candidates(b"ELF", "libdemo.so")
    finally:
        monkeypatch.setattr(sqlite3, "connect", original_connect)
        database.close()


def test_blintdb_filename_match_requires_informative_symbols(tmp_path, monkeypatch):
    path = tmp_path / "blint.db"
    make_blint(path)
    database = BLintDatabase(path, manifest("blintdb"), verify_hash=False)
    monkeypatch.setattr(
        database,
        "_symbol_sources",
        lambda _data: {
            "dynamic_symbols": {f"demo_identity_{index}" for index in range(35)}
        },
    )
    monkeypatch.setattr(
        database,
        "_low_information",
        lambda _connection, sources: {
            (source, name)
            for source, names in sources.items()
            for name in names
        },
    )
    assert database.candidates(b"ELF", "libdemo.so") == []


def test_enricher_adds_evidence_properties_but_never_resolved_version(tmp_path, monkeypatch):
    nsrl_path = tmp_path / "nsrl.db"
    blint_path = tmp_path / "blint.db"
    make_nsrl(nsrl_path)
    make_blint(blint_path)
    nsrl = NSRLDatabase(nsrl_path, manifest("nsrl"), verify_hash=False)
    blint = BLintDatabase(blint_path, manifest("blintdb"), verify_hash=False)
    monkeypatch.setattr(
        blint,
        "_symbol_sources",
        lambda _data: {
            "dynamic_symbols": {f"demo_identity_{index}" for index in range(35)}
        },
    )
    component = Component(name="host.so")
    enricher = DatabaseEnricher(blint=blint, nsrl=nsrl)
    enricher.enrich(
        component,
        b"\x7fELF" + b"\0" * 10 + b"x" * 1234,
        "host.so",
        "/system/lib64/host.so",
    )
    assert component.resolved_version == ""
    assert any(item["name"] == "firmware:blintdb:candidates" for item in component.properties)
    assert enricher.stats.blint_candidate_files == 1
    assert enricher.stats.nsrl_queried_files == 1


def test_enricher_queries_blint_identity_even_when_target_version_is_known(
    tmp_path,
    monkeypatch,
):
    blint_path = tmp_path / "blint.db"
    make_blint(blint_path)
    blint = BLintDatabase(blint_path, manifest("blintdb"), verify_hash=False)
    monkeypatch.setattr(
        blint,
        "_symbol_sources",
        lambda _data: {
            "dynamic_symbols": {f"demo_identity_{index}" for index in range(35)}
        },
    )
    component = Component(
        name="libdemo.so",
        resolved_version="1.0.0",
        properties=[{
            "name": "firmware:version:resolution-state",
            "value": "exact",
        }],
    )
    enricher = DatabaseEnricher(blint=blint)

    enricher.enrich(
        component,
        b"\x7fELF" + b"\0" * 10,
        "libdemo.so",
        "/lib/libdemo.so",
    )

    assert component.resolved_version == "1.0.0"
    assert any(item["name"] == "firmware:blintdb:candidates" for item in component.properties)


def test_enricher_reconciles_blint_identity_without_overwriting_target_version(
    tmp_path,
    monkeypatch,
):
    blint_path = tmp_path / "blint.db"
    make_blint(blint_path)
    blint = BLintDatabase(blint_path, manifest("blintdb"), verify_hash=False)
    monkeypatch.setattr(
        blint,
        "_symbol_sources",
        lambda _data: {
            "dynamic_symbols": {f"demo_identity_{index}" for index in range(35)}
        },
    )
    component = Component(name="libdemo.so")
    enricher = DatabaseEnricher(blint=blint)
    enricher.enrich(
        component,
        b"\x7fELF" + b"\0" * 10,
        "libdemo.so",
        "/lib/libdemo.so",
    )
    component.resolved_version = "1.0.0"
    component.properties.append({
        "name": "firmware:version:resolution-state",
        "value": "exact",
    })

    enricher.reconcile([component])

    properties = {item["name"]: item["value"] for item in component.properties}
    assert component.resolved_version == "1.0.0"
    assert json.loads(properties["firmware:blintdb:identity-confirmed"]) == {
        "projects": ["libdemo"],
        "components": ["libdemo"],
    }
    comparison = json.loads(properties["firmware:blintdb:reference-version-comparison"])
    assert comparison["target_version"] == "1.0.0"
    assert comparison["reference_versions"] == ["1.2.3"]
    assert comparison["decision"] == "diagnostic-only-no-version-overwrite"
    assert enricher.stats.blint_identity_confirmations == 1
    assert enricher.stats.blint_reference_version_mismatches == 1


def test_blint_identity_records_a_matching_component_from_an_aggregate_project(
    tmp_path,
    monkeypatch,
):
    blint_path = tmp_path / "blint.db"
    make_blint(blint_path)
    connection = sqlite3.connect(blint_path)
    connection.execute(
        "UPDATE Projects SET name='aggregate', purl='pkg:conan/aggregate@9.0'"
    )
    connection.commit()
    connection.close()
    blint = BLintDatabase(blint_path, manifest("blintdb"), verify_hash=False)
    monkeypatch.setattr(
        blint,
        "_symbol_sources",
        lambda _data: {
            "dynamic_symbols": {f"demo_identity_{index}" for index in range(35)}
        },
    )
    component = Component(name="libdemo.so")
    enricher = DatabaseEnricher(blint=blint)
    enricher.enrich(
        component,
        b"\x7fELF" + b"\0" * 10,
        "libdemo.so",
        "/lib/libdemo.so",
    )

    enricher.reconcile([component])

    properties = {item["name"]: item["value"] for item in component.properties}
    assert json.loads(properties["firmware:blintdb:identity-confirmed"]) == {
        "projects": [],
        "components": ["libdemo"],
    }


def test_enricher_paths_accept_cli_string_values(tmp_path, monkeypatch):
    nsrl_path = tmp_path / "nsrl.db"
    make_nsrl(nsrl_path)
    compatible = DatabaseManifest.from_dict({
        "schema_version": 1,
        "kind": "nsrl",
        "name": "small",
        "release": "test",
        "database_sha256": "0" * 64,
        "database_bytes": nsrl_path.stat().st_size,
        "database_schema_version": "RDSv3",
        "source_url": "https://example.invalid/database",
        "license": "test",
        "architecture": "all",
    })
    monkeypatch.setattr(manifest_module, "packaged_manifests", lambda: [compatible])
    enricher = DatabaseEnricher.from_paths(
        nsrl_path=str(nsrl_path),
        verify_hash=False,
    )
    try:
        assert enricher.nsrl is not None
    finally:
        enricher.close()


def test_database_hash_verification_is_cached_by_immutable_file_metadata(tmp_path, monkeypatch):
    database = tmp_path / "database.db"
    database.write_bytes(b"verified database")
    digest = hashlib.sha256(database.read_bytes()).hexdigest()
    verified = DatabaseManifest.from_dict({
        "schema_version": 1,
        "kind": "nsrl",
        "name": "small",
        "release": "test",
        "database_sha256": digest,
        "database_bytes": database.stat().st_size,
        "database_schema_version": "RDSv3",
        "source_url": "https://example.invalid/database",
        "license": "test",
        "architecture": "all",
    })
    monkeypatch.setattr(manifest_module, "packaged_manifests", lambda: [verified])
    calls = []
    original = manifest_module._sha256
    monkeypatch.setattr(
        manifest_module,
        "_sha256",
        lambda path: calls.append(path) or original(path),
    )
    cache = tmp_path / "verification-cache.json"
    first = manifest_module.load_database_manifest("nsrl", database, cache_path=cache)
    second = manifest_module.load_database_manifest("nsrl", database, cache_path=cache)
    assert first == second == verified
    assert len(calls) == 1


def test_database_integrity_verification_can_be_skipped_without_reading_file(
    tmp_path,
    monkeypatch,
):
    database = tmp_path / "database.db"
    database.write_bytes(b"database")
    compatible = DatabaseManifest.from_dict({
        "schema_version": 1,
        "kind": "nsrl",
        "name": "small",
        "release": "test",
        "database_sha256": "0" * 64,
        "database_bytes": database.stat().st_size,
        "database_schema_version": "RDSv3",
        "source_url": "https://example.invalid/database",
        "license": "test",
        "architecture": "all",
    })
    monkeypatch.setattr(manifest_module, "packaged_manifests", lambda: [compatible])

    def unexpected_hash_read(_path):
        raise AssertionError("integrity-disabled manifest selection read the database")

    monkeypatch.setattr(manifest_module, "_sha256", unexpected_hash_read)

    selected = manifest_module.load_database_manifest(
        "nsrl",
        database,
        verify_hash=False,
    )

    assert selected == compatible


def test_binary_inventory_reuses_content_evidence_at_a_new_location(monkeypatch):
    calls = []

    class Enricher:
        def __init__(self):
            from firmware_scanner.databases.enricher import DatabaseStats

            self.stats = DatabaseStats()

        def enrich(self, component, data, filename, location):
            calls.append(location)
            component.properties.extend([
                {"name": "firmware:evidence:container", "value": location},
                {"name": "test:content-evidence", "value": "cached"},
            ])

    inventory = BinaryInventory(database_enricher=Enricher())
    monkeypatch.setattr(inventory._deep, "extract", lambda _filename, _data: None)
    raw = b"\x7fELF" + b"\0" * 60 + b"libcache-demo version 1.2.3\0"

    first = inventory.extract(raw, "libcache-demo.so", "/first/libcache-demo.so")
    first[0].properties.append({"name": "test:mutation", "value": "leaked"})
    first[0].resolved_version = "mutated"
    second = inventory.extract(raw, "libcache-demo.so", "/second/libcache-demo.so")

    assert calls == ["/first/libcache-demo.so"]
    assert inventory.analysis_stats["content_cache_hits"] == 1
    assert second[0].resolved_version != "mutated"
    assert "/first/" not in second[0].description
    assert all(
        "/first/" not in version.evidence
        for version in second[0].versions
    )
    assert not any(
        item["name"] == "test:mutation"
        for item in second[0].properties
    )
    assert {
        item["value"]
        for item in second[0].properties
        if item["name"] == "firmware:evidence:location"
    } == {"/second/libcache-demo.so"}
    assert {
        item["value"]
        for item in second[0].properties
        if item["name"] == "firmware:evidence:container"
    } == {"/second/libcache-demo.so"}


def test_smart_section_analyzer_passes_external_database_evidence_for_generic_firmware(
    monkeypatch,
):
    calls = []

    class Enricher:
        def __init__(self):
            from firmware_scanner.databases.enricher import DatabaseStats

            self.stats = DatabaseStats()

        def enrich(self, component, data, filename, location):
            calls.append((filename, location))
            component.properties.append({
                "name": "firmware:nsrl:file-matched",
                "value": "true",
            })

    analyzer = SmartSectionAnalyzer(database_enricher=Enricher())
    monkeypatch.setattr(
        analyzer._get_binary_inventory()._deep,
        "extract",
        lambda _filename, _data: None,
    )
    components = analyzer.analyze_section(
        "/usr/lib/libgeneric.so",
        b"\x7fELF" + b"\0" * 60 + b"generic payload\0",
    )

    assert calls == [("libgeneric.so", "/usr/lib/libgeneric.so")]
    assert any(
        prop["name"] == "firmware:nsrl:file-matched"
        for component in components
        for prop in component.properties
    )
    assert analyzer.analysis_stats["content_cache_entries"] == 1
    assert analyzer.database_stats["files_queried"] == 0


def test_external_database_validation_failure_is_not_silently_ignored(monkeypatch):
    def rejected(**_kwargs):
        raise ValueError("database schema mismatch")

    monkeypatch.setattr(
        "firmware_scanner.databases.DatabaseEnricher.from_paths",
        rejected,
    )
    config = AnalysisConfig(nsrl_db_path="/database/nsrl.db")
    with pytest.raises(RuntimeError, match="database schema mismatch"):
        _validate_external_databases(config)


def test_json_report_exposes_generic_database_and_cache_stats(tmp_path):
    from firmware_scanner.cli.app import _output_json_report
    from firmware_scanner.core.context import AnalysisContext

    context = AnalysisContext(
        firmware_path=tmp_path / "firmware.bin",
        metadata={
            "database_stats": {"files_queried": 7},
            "analysis_stats": {"content_cache_hits": 3},
            "family_provenance_stats": {"versions_inherited": 1},
            "provenance_stats": {"notice_license_attribution": {"components_licensed": 2}},
            "license_stats": {"licensed_components": 2, "total_components": 3},
            "rules": {
                "release": "builtin-test",
                "lock_sha256": "c" * 64,
            },
        },
    )
    output = tmp_path / "analysis.json"
    _output_json_report(context, output)
    report = json.loads(output.read_text())
    assert report["database_stats"] == {"files_queried": 7}
    assert report["analysis_stats"] == {"content_cache_hits": 3}
    assert report["family_provenance_stats"] == {"versions_inherited": 1}
    assert report["provenance_stats"] == {
        "notice_license_attribution": {"components_licensed": 2}
    }
    assert report["license_stats"] == {
        "licensed_components": 2,
        "total_components": 3,
    }
    assert report["rules"]["release"] == "builtin-test"


def test_generic_database_context_closes_connection_after_exception(monkeypatch):
    closed = []

    class Enricher:
        def close(self):
            closed.append(True)

    monkeypatch.setattr(
        "firmware_scanner.cli.app._create_external_database_enricher",
        lambda _config: Enricher(),
    )
    with pytest.raises(ValueError, match="scan failed"):
        with _external_database_enricher(AnalysisConfig()):
            raise ValueError("scan failed")
    assert closed == [True]
