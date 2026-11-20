"""Apply Blint's symbol-only attribution gates to a raw BLintDB probe.

The raw probe intentionally keeps every symbol hit. This stage mirrors the
consumer's current safety rules, then resolves a matched reference binary to
the dependency name and version encoded in its Conan deploy path.
"""
from __future__ import annotations

import argparse
import io
import json
import mmap
import re
import sqlite3
from collections import defaultdict
from pathlib import Path

from elftools.elf.elffile import ELFFile

MECHANICAL_SYMBOL_RE = re.compile(
    r"^_*(?:__mh_[a-z]+_header|OUTLINED_FUNCTION_\d+|main|start|init|fini"
    r"|_GLOBAL__sub_I_.*|sub_[0-9a-fA-F]+|\$[atdx](?:\.\d+)?)$",
    re.IGNORECASE,
)
CONAN_DEPLOY_PATH_RE = re.compile(
    r"/host/(?P<name>[^/]+)/(?P<version>[^/]+)/(?P<configuration>[^/]+)/"
    r"(?P<triplet>[^/]+)/(?P<relative>.+)$"
)
TLS_PROVIDER_NAMES = {"libcrypto.so", "libssl.so"}


def normalize_binary_name(value: str | None) -> str:
    if not value:
        return ""
    name = Path(str(value)).name.lower()
    for suffix in (".dylib", ".dll", ".so", ".a", ".lib", ".exe"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    name = name.removeprefix("lib")
    name = name.split(".")[0]
    return "".join(character for character in name if character.isalnum())


def dependency_from_conan_path(value: str) -> dict | None:
    match = CONAN_DEPLOY_PATH_RE.search(value)
    if not match:
        return None
    item = match.groupdict()
    item["binary_name"] = Path(item["relative"]).name
    return item


def elf_dynamic_symbol_names(data: bytes) -> set[str]:
    elf = ELFFile(io.BytesIO(data))
    dynamic = elf.get_section_by_name(".dynsym")
    if dynamic is None:
        return set()
    return {
        symbol.name
        for symbol in dynamic.iter_symbols()
        if symbol.name and symbol["st_shndx"] != "SHN_UNDEF"
    }


def low_information_names(connection: sqlite3.Connection, names: set[str]) -> set[str]:
    result: set[str] = set()
    ordered = sorted(names)
    for start in range(0, len(ordered), 400):
        batch = ordered[start:start + 400]
        placeholders = ",".join("?" for _ in batch)
        rows = connection.execute(
            "SELECT s.name FROM Symbols s "
            "JOIN Binaries b ON b.binary_id=s.binary_id "
            "JOIN Builds bu ON bu.build_id=b.build_id "
            "JOIN Projects p ON p.project_id=bu.project_id "
            f"WHERE s.name IN ({placeholders}) "
            "GROUP BY s.name HAVING COUNT(DISTINCT p.name) >= 2",
            batch,
        )
        result.update(str(row[0]) for row in rows)
    return result


def dependency_candidates(
    connection: sqlite3.Connection, binary_ids: set[int]
) -> dict[int, list[dict]]:
    result: dict[int, list[dict]] = defaultdict(list)
    ordered = sorted(binary_ids)
    for start in range(0, len(ordered), 400):
        batch = ordered[start:start + 400]
        placeholders = ",".join("?" for _ in batch)
        rows = connection.execute(
            "SELECT DISTINCT binary_id,name,version,purl FROM Dependencies "
            f"WHERE binary_id IN ({placeholders}) AND source='import_dependencies'",
            batch,
        )
        for binary_id, name, version, purl in rows:
            parsed = dependency_from_conan_path(str(name))
            if parsed is not None:
                parsed.update({"declared_version": version, "purl": purl})
                result[int(binary_id)].append(parsed)
    return result


def defined_candidate_pairs(
    connection: sqlite3.Connection,
    binary_ids: set[int],
    symbol_names: set[str],
) -> set[tuple[int, str]]:
    """Return queried target names that the reference binary actually defines."""
    connection.execute("PRAGMA temp_store=FILE")
    connection.execute("CREATE TEMP TABLE candidate_binaries(binary_id INTEGER PRIMARY KEY)")
    connection.executemany(
        "INSERT INTO candidate_binaries(binary_id) VALUES(?)",
        [(binary_id,) for binary_id in binary_ids],
    )
    result: set[tuple[int, str]] = set()
    ordered = sorted(symbol_names)
    for start in range(0, len(ordered), 400):
        batch = ordered[start:start + 400]
        placeholders = ",".join("?" for _ in batch)
        rows = connection.execute(
            "SELECT DISTINCT s.binary_id,s.name FROM Symbols s "
            "JOIN candidate_binaries c ON c.binary_id=s.binary_id "
            f"WHERE s.name IN ({placeholders}) "
            "AND (s.is_imported=0 OR s.is_imported IS NULL)",
            batch,
        )
        result.update((int(binary_id), str(name)) for binary_id, name in rows)
    return result


def identity_symbols(symbols: set[str], low_information: set[str]) -> set[str]:
    return {
        name
        for name in symbols
        if name not in low_information and not MECHANICAL_SYMBOL_RE.match(name)
    }


def gate_row(
    row: dict,
    *,
    connection: sqlite3.Connection,
    low_information: set[str],
    dependency_map: dict[int, list[dict]],
    defined_pairs: set[tuple[int, str]],
    dynamic_symbols: set[str],
) -> dict:
    target_name = normalize_binary_name(row["location"])
    projects: dict[str, dict] = {}
    for candidate in row.get("candidates", []):
        project = projects.setdefault(candidate["project_name"], {
            "project_name": candidate["project_name"],
            "project_purls": set(),
            "symbols": set(),
            "binaries": [],
        })
        if candidate.get("purl"):
            project["project_purls"].add(candidate["purl"])
        candidate_defined = {
            name for name in candidate.get("symbol_evidence", [])
            if (int(candidate["binary_id"]), name) in defined_pairs
        }
        project["symbols"].update(candidate_defined)
        project["binaries"].append(candidate | {"defined_symbols": sorted(candidate_defined)})

    name_matches = []
    identity_matches = []
    for project_name, project in projects.items():
        chosen = {
            name for name in project["symbols"] if not MECHANICAL_SYMBOL_RE.match(name)
        }
        identity = identity_symbols(project["symbols"], low_information)
        project["chosen_symbols"] = chosen
        project["identity_symbols"] = identity
        project["matched_defined_symbols"] = {
            candidate["binary_id"]: len(identity_symbols(
                set(candidate["defined_symbols"]), low_information
            ))
            for candidate in project["binaries"]
        }
        binary_name_match = any(
            normalize_binary_name(candidate["binary_name"]) == target_name
            and len({
                name for name in candidate["defined_symbols"]
                if not MECHANICAL_SYMBOL_RE.match(name)
            }) >= 5
            for candidate in project["binaries"]
        )
        target_bound_identity_match = any(
            len(identity_symbols(set(candidate["defined_symbols"]), low_information)) >= 30
            and (
                len(identity_symbols(set(candidate["defined_symbols"]), low_information))
                / max(1, int(row.get("defined_symbol_count") or 1))
            ) >= 0.10
            for candidate in project["binaries"]
        )
        if binary_name_match:
            name_matches.append(project_name)
        elif target_bound_identity_match:
            identity_matches.append(project_name)

    # Blint keeps nameless identity matches only when no filename-backed
    # project was found. This suppresses unrelated static-link symbol piles.
    kept_names = name_matches or identity_matches
    kept: list[dict] = []
    for project_name in sorted(set(kept_names)):
        project = projects[project_name]
        if (
            project_name == "openssl"
            and Path(row["location"]).name in TLS_PROVIDER_NAMES
            and not any(name.startswith(("OSSL_", "ossl_")) for name in dynamic_symbols)
        ):
            continue
        selected_binaries = [
            binary for binary in project["binaries"]
            if (
                normalize_binary_name(binary["binary_name"]) == target_name
                and len({
                    name for name in binary["defined_symbols"]
                    if not MECHANICAL_SYMBOL_RE.match(name)
                }) >= 5
                if project_name in name_matches
                else (
                    len(identity_symbols(
                        set(binary.get("defined_symbols", [])), low_information
                    )) >= 30
                    and (
                        len(identity_symbols(
                            set(binary.get("defined_symbols", [])), low_information
                        ))
                        / max(1, int(row.get("defined_symbol_count") or 1))
                    ) >= 0.10
                )
            )
        ]
        versions = set()
        components = []
        for binary in selected_binaries:
            for dependency in dependency_map.get(int(binary["binary_id"]), []):
                if dependency["binary_name"] != Path(str(binary["binary_name"])).name:
                    continue
                key = (dependency["name"], dependency["version"])
                versions.add(key)
                components.append({
                    "name": dependency["name"],
                    "version": dependency["version"],
                    "configuration": dependency["configuration"],
                    "triplet": dependency["triplet"],
                    "reference_binary": binary["binary_name"],
                })
        if (
            Path(row["location"]).name in TLS_PROVIDER_NAMES
            and components
            and {component["name"] for component in components} == {"openssl"}
            and not any(name.startswith(("OSSL_", "ossl_")) for name in dynamic_symbols)
        ):
            continue
        kept.append({
            "project": project_name,
            "project_purls": sorted(project["project_purls"]),
            "binary_name_match": project_name in name_matches,
            "chosen_symbol_count": len(project["chosen_symbols"]),
            "identity_symbol_count": len(project["identity_symbols"]),
            "identity_symbols": sorted(project["identity_symbols"])[:30],
            "selected_reference_binaries": sorted({
                binary["binary_name"] for binary in selected_binaries
            }),
            "candidate_target_coverage": {
                str(binary["binary_id"]): round(
                    project["matched_defined_symbols"][binary["binary_id"]]
                    / max(1, int(row.get("defined_symbol_count") or 1)),
                    6,
                )
                for binary in selected_binaries
            },
            "components": components,
            "unique_component_versions": [
                {"name": name, "version": version} for name, version in sorted(versions)
            ],
        })
    return {
        "location": row["location"],
        "corpus": row["corpus"],
        "image": row["image"],
        "observation_sha256": row["observation_sha256"],
        "defined_symbol_count": row.get("defined_symbol_count"),
        "target_binary_name": Path(row["location"]).name,
        "matches": kept,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw_probe", type=Path)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    raw = json.loads(args.raw_probe.read_text())
    connection = sqlite3.connect(
        args.database.resolve().as_uri() + "?mode=ro&immutable=1", uri=True
    )
    all_symbols = {
        symbol
        for row in raw["rows"]
        for candidate in row.get("candidates", [])
        for symbol in candidate.get("symbol_evidence", [])
    }
    low_information = low_information_names(connection, all_symbols)
    binary_ids = {
        int(candidate["binary_id"])
        for row in raw["rows"]
        for candidate in row.get("candidates", [])
    }
    dependencies = dependency_candidates(connection, binary_ids)
    defined_pairs = defined_candidate_pairs(connection, binary_ids, all_symbols)

    image_handles = {}
    image_maps = {}
    from firmware_scanner.android.ext4_reader import Ext4Reader

    gated = []
    try:
        for row in raw["rows"]:
            image = row["image"]
            if image not in image_handles:
                source = open(image, "rb")  # noqa: SIM115 - closed in finally
                mapped = mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ)
                image_handles[image] = source
                image_maps[image] = (mapped, Ext4Reader(mapped))
            mapped, filesystem = image_maps[image]
            data = filesystem.read_file(row["location"], max_size=128 * 1024 * 1024)
            dynamic_symbols = elf_dynamic_symbol_names(data)
            gated.append(gate_row(
                row,
                connection=connection,
                low_information=low_information,
                dependency_map=dependencies,
                defined_pairs=defined_pairs,
                dynamic_symbols=dynamic_symbols,
            ))
    finally:
        connection.close()
        for mapped, _filesystem in image_maps.values():
            mapped.close()
        for source in image_handles.values():
            source.close()

    summary = {
        "raw_probe": str(args.raw_probe),
        "database": str(args.database),
        "targets": len(gated),
        "targets_with_identity": sum(bool(row["matches"]) for row in gated),
        "targets_with_binary_name_match": sum(
            any(match["binary_name_match"] for match in row["matches"]) for row in gated
        ),
        "targets_with_unique_component_version": sum(
            any(len(match["unique_component_versions"]) == 1 for match in row["matches"])
            for row in gated
        ),
        "targets_with_ambiguous_component_version": sum(
            any(len(match["unique_component_versions"]) > 1 for match in row["matches"])
            for row in gated
        ),
        "low_information_symbol_count": len(low_information),
        "defined_candidate_symbol_pairs": len(defined_pairs),
        "scope": (
            "Blint symbol-only gates; no function hashes or callgraph; "
            "version comes only from a unique Conan deploy path"
        ),
        "rows": gated,
    }
    args.output.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({key: value for key, value in summary.items() if key != "rows"}, indent=2))


if __name__ == "__main__":
    main()
