"""Conservative symbol attribution against a pinned BLintDB SQLite database."""

from __future__ import annotations

import re
import sqlite3
import struct
from collections import defaultdict
from pathlib import Path

from .manifest import DatabaseManifest

_MECHANICAL_SYMBOL_RE = re.compile(
    r"^_*(?:__mh_[a-z]+_header|OUTLINED_FUNCTION_\d+|main|start|init|fini"
    r"|_GLOBAL__sub_I_.*|sub_[0-9a-fA-F]+|\$[atdx](?:\.\d+)?)$",
    re.IGNORECASE,
)
_CONAN_DEPLOY_PATH_RE = re.compile(
    r"/host/(?P<name>[^/]+)/(?P<version>[^/]+)/(?P<configuration>[^/]+)/"
    r"(?P<triplet>[^/]+)/(?P<relative>.+)$"
)


def normalize_binary_name(value: str | None) -> str:
    if not value:
        return ""
    name = Path(value).name.lower()
    for suffix in (".dylib", ".dll", ".so", ".a", ".lib", ".exe"):
        name = name.removesuffix(suffix)
    name = name.removeprefix("lib").split(".")[0]
    return "".join(character for character in name if character.isalnum())


class BLintDatabase:
    def __init__(
        self,
        path: Path,
        manifest: DatabaseManifest,
        *,
        verify_hash: bool = True,
        integrity_verified: bool | None = None,
    ):
        if manifest.kind != "blintdb":
            raise ValueError("BLintDatabase requires a blintdb manifest")
        if verify_hash:
            from .manifest import load_database_manifest

            verified = load_database_manifest("blintdb", path)
            if verified.database_sha256 != manifest.database_sha256:
                raise ValueError("BLintDB manifest changed during verification")
        self.path = path
        self.manifest = manifest
        self.integrity_verified = (
            bool(verify_hash) if integrity_verified is None else bool(integrity_verified)
        )
        self._connection = self._connect()
        required = {"SchemaMeta", "Projects", "Builds", "Binaries", "Symbols"}
        tables = {
            row[0]
            for row in self._connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if not required.issubset(tables):
            self.close()
            raise ValueError("BLintDB lacks required lookup tables")
        schema_meta = dict(self._connection.execute("SELECT key,value FROM SchemaMeta"))
        actual_schema = str(schema_meta.get("schema_version", ""))
        if actual_schema != manifest.database_schema_version:
            self.close()
            raise ValueError(
                f"BLintDB schema mismatch: got {actual_schema}, "
                f"expected {manifest.database_schema_version}"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path.resolve().as_uri() + "?mode=ro&immutable=1",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA temp_store=FILE")
        connection.execute("PRAGMA cache_size=-65536")
        return connection

    @staticmethod
    def _symbol_sources(data: bytes) -> dict[str, set[str]]:
        sources: dict[str, set[str]] = defaultdict(set)
        if len(data) < 52 or data[:4] != b"\x7fELF":
            return sources
        elf_class, encoding = data[4], data[5]
        if elf_class not in (1, 2) or encoding not in (1, 2):
            return sources
        endian = "<" if encoding == 1 else ">"
        try:
            if elf_class == 2:
                if len(data) < 64:
                    return sources
                section_offset = struct.unpack_from(endian + "Q", data, 40)[0]
                entry_size, section_count = struct.unpack_from(endian + "HH", data, 58)
                section_format = endian + "IIQQQQIIQQ"
                symbol_format = endian + "IBBHQQ"
                minimum_section_size, minimum_symbol_size = 64, 24
            else:
                section_offset = struct.unpack_from(endian + "I", data, 32)[0]
                entry_size, section_count = struct.unpack_from(endian + "HH", data, 46)
                section_format = endian + "IIIIIIIIII"
                symbol_format = endian + "IIIBBH"
                minimum_section_size, minimum_symbol_size = 40, 16
            if (
                entry_size < minimum_section_size
                or section_count == 0
                or section_offset + entry_size * section_count > len(data)
            ):
                return sources
            sections = [
                struct.unpack_from(section_format, data, section_offset + index * entry_size)
                for index in range(section_count)
            ]
        except struct.error:
            return sources

        for section in sections:
            section_type = section[1]
            if section_type not in (2, 11):
                continue
            source = "dynamic_symbols" if section_type == 11 else "symtab_symbols"
            symbol_offset, symbol_table_size = section[4], section[5]
            strings_index, symbol_entry_size = section[6], section[9]
            if strings_index >= len(sections) or symbol_entry_size < minimum_symbol_size:
                continue
            string_section = sections[strings_index]
            strings_offset, strings_size = string_section[4], string_section[5]
            if symbol_offset + symbol_table_size > len(data) or strings_offset + strings_size > len(
                data
            ):
                continue
            strings = data[strings_offset : strings_offset + strings_size]
            for position in range(
                symbol_offset,
                symbol_offset + symbol_table_size - minimum_symbol_size + 1,
                symbol_entry_size,
            ):
                try:
                    symbol = struct.unpack_from(symbol_format, data, position)
                except struct.error:
                    continue
                name_offset = symbol[0]
                section_index = symbol[3] if elf_class == 2 else symbol[5]
                if not name_offset or section_index == 0 or name_offset >= len(strings):
                    continue
                end = strings.find(b"\0", name_offset)
                if end <= name_offset:
                    continue
                name = strings[name_offset:end].decode("utf-8", errors="replace")
                if _MECHANICAL_SYMBOL_RE.match(name):
                    continue
                sources[source].add(name)
        return sources

    def candidates(self, data: bytes, filename: str) -> list[dict]:
        try:
            sources = self._symbol_sources(data)
        except (ValueError, TypeError, OSError, UnicodeError):
            return []
        if not sources:
            return []
        all_names = sorted({name for names in sources.values() for name in names})
        target_name = normalize_binary_name(filename)
        connection = self._connection
        low_information = self._low_information(connection, sources)
        matched: dict[int, dict] = {}
        for source, names in sources.items():
            for start in range(0, len(names), 350):
                batch = sorted(names)[start : start + 350]
                placeholders = ",".join("?" for _ in batch)
                rows = connection.execute(
                    "SELECT DISTINCT s.binary_id,s.name,b.name AS binary_name,"
                    "p.name AS project_name,p.purl,bu.target_arch "
                    "FROM Symbols s JOIN Binaries b ON b.binary_id=s.binary_id "
                    "JOIN Builds bu ON bu.build_id=b.build_id "
                    "JOIN Projects p ON p.project_id=bu.project_id "
                    f"WHERE s.source=? AND s.name IN ({placeholders}) "
                    "AND (s.is_imported=0 OR s.is_imported IS NULL)",
                    [source, *batch],
                )
                for row in rows:
                    item = matched.setdefault(
                        int(row["binary_id"]),
                        {
                            "binary_name": row["binary_name"],
                            "project_name": row["project_name"],
                            "project_purl": row["purl"],
                            "target_arch": row["target_arch"],
                            "symbols": set(),
                            "identity": set(),
                        },
                    )
                    item["symbols"].add(str(row["name"]))
                    if (source, str(row["name"])) not in low_information:
                        item["identity"].add(str(row["name"]))
            qualified = []
            total_symbols = max(1, len(all_names))
            for binary_id, item in matched.items():
                identity_count = len(item["identity"])
                name_match = normalize_binary_name(item["binary_name"]) == target_name
                coverage = identity_count / total_symbols
                if not (
                    (name_match and identity_count >= 5)
                    or (identity_count >= 30 and coverage >= 0.10)
                ):
                    continue
                dependencies = self._dependency_versions(connection, binary_id, item["binary_name"])
                versions = {(entry["name"], entry["version"]) for entry in dependencies}
                qualified.append(
                    {
                        "project_name": item["project_name"],
                        "project_purl": item["project_purl"],
                        "reference_binary": item["binary_name"],
                        "target_arch": item["target_arch"],
                        "binary_name_match": name_match,
                        "identity_symbol_count": identity_count,
                        "target_symbol_coverage": round(coverage, 6),
                        "components": dependencies,
                        "unique_component_versions": [
                            {"name": name, "version": version} for name, version in sorted(versions)
                        ],
                        "version_semantics": "reference-build-candidate-not-target-version",
                    }
                )
        return sorted(
            qualified,
            key=lambda row: (
                not row["binary_name_match"],
                -row["identity_symbol_count"],
                row["project_name"],
            ),
        )[:5]

    def close(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            connection.close()
            self._connection = None

    @staticmethod
    def _low_information(
        connection: sqlite3.Connection,
        sources: dict[str, set[str]],
    ) -> set[tuple[str, str]]:
        result: set[tuple[str, str]] = set()
        for source, names in sources.items():
            ordered = sorted(names)
            for start in range(0, len(ordered), 350):
                batch = ordered[start : start + 350]
                placeholders = ",".join("?" for _ in batch)
                rows = connection.execute(
                    "SELECT s.name FROM Symbols s "
                    "JOIN Binaries b ON b.binary_id=s.binary_id "
                    "JOIN Builds bu ON bu.build_id=b.build_id "
                    "JOIN Projects p ON p.project_id=bu.project_id "
                    f"WHERE s.source=? AND s.name IN ({placeholders}) "
                    "GROUP BY s.name HAVING COUNT(DISTINCT p.name)>=2",
                    [source, *batch],
                )
                result.update((source, str(row[0])) for row in rows)
        return result

    @staticmethod
    def _dependency_versions(
        connection: sqlite3.Connection,
        binary_id: int,
        binary_name: str,
    ) -> list[dict]:
        result = []
        if "Dependencies" not in {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }:
            return result
        rows = connection.execute(
            "SELECT name,version,purl FROM Dependencies "
            "WHERE binary_id=? AND source='import_dependencies'",
            (binary_id,),
        )
        for row in rows:
            match = _CONAN_DEPLOY_PATH_RE.search(str(row["name"]))
            if not match:
                continue
            item = match.groupdict()
            if Path(item["relative"]).name != Path(binary_name).name:
                continue
            result.append(
                {
                    "name": item["name"],
                    "version": item["version"],
                    "configuration": item["configuration"],
                    "triplet": item["triplet"],
                    "purl": row["purl"],
                }
            )
        return result
