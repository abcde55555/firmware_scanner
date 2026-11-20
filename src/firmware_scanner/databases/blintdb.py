"""Conservative symbol attribution against a pinned BLintDB SQLite database."""

from __future__ import annotations

import hashlib
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
_ELF_VERSION_SUFFIX_RE = re.compile(r"@@?([A-Za-z0-9._]+)$")
_IMPORT_ORIGIN_RE = re.compile(
    r"^[\w.\-/]+(?:\.dll|\.dylib|\.so|\.tbd|[A-Za-z]\w*\.[A-Za-z])::"
)
_IMPORT_DECORATIONS = ("__imp_", "_imp_", "__hilt_", "real@")


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
        binary_columns = {
            str(row["name"])
            for row in self._connection.execute("PRAGMA table_info(Binaries)")
        }
        self.import_hash_supported = {"import_hash", "machine_type"}.issubset(
            binary_columns
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
        sources, _imports = BLintDatabase._symbol_evidence(data)
        return sources

    @staticmethod
    def _symbol_evidence(data: bytes) -> tuple[dict[str, set[str]], set[str]]:
        sources: dict[str, set[str]] = defaultdict(set)
        imports: set[str] = set()
        if len(data) < 52 or data[:4] != b"\x7fELF":
            return sources, imports
        elf_class, encoding = data[4], data[5]
        if elf_class not in (1, 2) or encoding not in (1, 2):
            return sources, imports
        endian = "<" if encoding == 1 else ">"
        try:
            if elf_class == 2:
                if len(data) < 64:
                    return sources, imports
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
                return sources, imports
            sections = [
                struct.unpack_from(section_format, data, section_offset + index * entry_size)
                for index in range(section_count)
            ]
        except struct.error:
            return sources, imports

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
                if section_index == 0:
                    imports.add(name)
                    continue
                if _MECHANICAL_SYMBOL_RE.match(name):
                    continue
                sources[source].add(name)
        return sources, imports

    @staticmethod
    def _elf_machine(data: bytes) -> str:
        if len(data) < 20 or data[:4] != b"\x7fELF":
            return ""
        endian = "little" if data[5] == 1 else "big"
        return {
            3: "X86",
            8: "MIPS",
            20: "PPC",
            21: "PPC64",
            40: "ARM",
            62: "X86_64",
            183: "AARCH64",
            243: "RISCV",
        }.get(int.from_bytes(data[18:20], endian), "")

    @staticmethod
    def _normalize_import_name(name: str) -> str:
        value = name.strip()
        if len(value) <= 1024:
            value = _IMPORT_ORIGIN_RE.sub("", value)
        value = _ELF_VERSION_SUFFIX_RE.sub("", value)
        for decoration in _IMPORT_DECORATIONS:
            if value.startswith(decoration):
                value = value[len(decoration) :]
                break
        return value.lstrip("_").lower()

    @classmethod
    def _import_hash(cls, import_names: set[str]) -> tuple[str, int]:
        normalized = {
            normalized
            for name in import_names
            if (normalized := cls._normalize_import_name(name))
        }
        if not normalized:
            return "", 0
        payload = "\n".join(sorted(normalized))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16], len(normalized)

    def candidates(self, data: bytes, filename: str) -> list[dict]:
        try:
            sources, imports = self._symbol_evidence(data)
        except (ValueError, TypeError, OSError, UnicodeError):
            return []
        if not sources and not imports:
            return []
        all_names = sorted({name for names in sources.values() for name in names})
        target_name = normalize_binary_name(filename)
        connection = self._connection
        matched: dict[int, dict] = {}
        matched_symbol_pairs: set[tuple[str, str]] = set()
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
                            "match_methods": set(),
                        },
                    )
                    item["symbols"].add(str(row["name"]))
                    item.setdefault("symbol_sources", defaultdict(set))[source].add(
                        str(row["name"])
                    )
                    matched_symbol_pairs.add((source, str(row["name"])))
                    item["identity"].add(str(row["name"]))
                    item["match_methods"].add("symbols")
        import_hash, imported_symbol_count = self._import_hash(imports)
        if self.import_hash_supported and import_hash and imported_symbol_count >= 5:
            self._merge_import_hash_candidates(
                connection,
                matched,
                import_hash=import_hash,
                imported_symbol_count=imported_symbol_count,
                target_machine=self._elf_machine(data),
            )
        if matched_symbol_pairs:
            matched_sources: dict[str, set[str]] = defaultdict(set)
            for source, name in matched_symbol_pairs:
                matched_sources[source].add(name)
            low_information = self._low_information(connection, matched_sources)
            for item in matched.values():
                low_names = {
                    name
                    for source, names in item.get("symbol_sources", {}).items()
                    for name in names
                    if (source, name) in low_information
                }
                item["identity"].difference_update(low_names)
                if not item["identity"]:
                    item["match_methods"].discard("symbols")
        qualified = []
        total_symbols = max(1, len(all_names))
        for binary_id, item in matched.items():
            identity_count = len(item["identity"])
            name_match = normalize_binary_name(item["binary_name"]) == target_name
            coverage = identity_count / total_symbols
            if not (
                (name_match and identity_count >= 5)
                or (identity_count >= 30 and coverage >= 0.10)
                or (
                    "import_hash" in item["match_methods"]
                    and (name_match or item.get("import_candidate_unique"))
                )
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
                    "match_methods": sorted(item["match_methods"]),
                    "import_hash": item.get("import_hash", ""),
                    "imported_symbol_count": item.get("imported_symbol_count", 0),
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

    @staticmethod
    def _merge_import_hash_candidates(
        connection: sqlite3.Connection,
        matched: dict[int, dict],
        *,
        import_hash: str,
        imported_symbol_count: int,
        target_machine: str,
    ) -> None:
        if not target_machine:
            return
        rows = connection.execute(
            "SELECT b.binary_id,b.name,b.machine_type,bu.target_arch,"
            "p.name AS project_name,p.purl "
            "FROM Binaries b JOIN Builds bu ON bu.build_id=b.build_id "
            "JOIN Projects p ON p.project_id=bu.project_id "
            "WHERE b.import_hash=? "
            "AND (b.machine_type=? OR b.machine_type='' OR b.machine_type IS NULL) "
            "ORDER BY p.name,b.name LIMIT 11",
            (import_hash, target_machine),
        ).fetchall()
        projects = {str(row["project_name"]) for row in rows}
        if not rows or len(rows) > 10 or len(projects) > 3:
            return
        for rank, row in enumerate(rows, start=1):
            item = matched.setdefault(
                int(row["binary_id"]),
                {
                    "binary_name": row["name"],
                    "project_name": row["project_name"],
                    "project_purl": row["purl"],
                    "target_arch": row["target_arch"] or row["machine_type"],
                    "symbols": set(),
                    "identity": set(),
                    "match_methods": set(),
                },
            )
            item["match_methods"].add("import_hash")
            item["import_hash"] = import_hash
            item["imported_symbol_count"] = imported_symbol_count
            item.setdefault("import_candidate_rank", rank)
            item["import_candidate_unique"] = len(rows) == 1

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
