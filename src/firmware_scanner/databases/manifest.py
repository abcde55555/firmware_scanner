"""Integrity and compatibility checks for external reference databases."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path


@dataclass(frozen=True)
class DatabaseManifest:
    schema_version: int
    kind: str
    name: str
    release: str
    database_sha256: str
    database_bytes: int
    database_schema_version: str
    source_url: str
    license: str
    architecture: str
    properties: dict

    @classmethod
    def from_dict(cls, payload: dict) -> DatabaseManifest:
        required = {
            "schema_version",
            "kind",
            "name",
            "release",
            "database_sha256",
            "database_bytes",
            "database_schema_version",
            "source_url",
            "license",
            "architecture",
        }
        missing = sorted(required - set(payload))
        if missing:
            raise ValueError(f"database manifest missing fields: {', '.join(missing)}")
        digest = str(payload["database_sha256"]).lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("database manifest sha256 is invalid")
        if payload["kind"] not in {"blintdb", "nsrl"}:
            raise ValueError(f"unsupported database kind: {payload['kind']}")
        if int(payload["schema_version"]) != 1:
            raise ValueError(f"unsupported database manifest schema: {payload['schema_version']}")
        return cls(
            schema_version=int(payload["schema_version"]),
            kind=str(payload["kind"]),
            name=str(payload["name"]),
            release=str(payload["release"]),
            database_sha256=digest,
            database_bytes=int(payload["database_bytes"]),
            database_schema_version=str(payload["database_schema_version"]),
            source_url=str(payload["source_url"]),
            license=str(payload["license"]),
            architecture=str(payload["architecture"]),
            properties=dict(payload.get("properties") or {}),
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(16 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _default_cache_path() -> Path:
    root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return root / "firmware-scanner" / "database-verification.json"


def _read_cache(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _write_cache(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def packaged_manifests() -> list[DatabaseManifest]:
    root = files("firmware_scanner.data").joinpath("database_packs")
    result = []
    for entry in sorted(root.iterdir(), key=lambda item: item.name):
        if entry.name.endswith(".json"):
            result.append(DatabaseManifest.from_dict(json.loads(entry.read_text())))
    return result


def load_database_manifest(
    kind: str,
    database: Path,
    *,
    cache_path: Path | None = None,
    verify_hash: bool = True,
) -> DatabaseManifest:
    """Select a packaged manifest by size and optionally verify its SHA-256."""
    if not database.is_file():
        raise FileNotFoundError(database)
    size = database.stat().st_size
    candidates = [
        manifest
        for manifest in packaged_manifests()
        if manifest.kind == kind and manifest.database_bytes == size
    ]
    if not candidates:
        raise ValueError(
            f"no packaged integrity manifest matches {kind} database size {size}: {database}"
        )
    if not verify_hash:
        if len(candidates) != 1:
            raise ValueError(
                f"multiple packaged integrity manifests match {kind} database size "
                f"{size}; SHA-256 verification is required to disambiguate"
            )
        return candidates[0]
    stat = database.stat()
    cache_file = cache_path or _default_cache_path()
    cache = _read_cache(cache_file)
    cache_key = str(database.resolve())
    cached = cache.get(cache_key, {})
    digest = ""
    if (
        cached.get("kind") == kind
        and cached.get("size") == stat.st_size
        and cached.get("mtime_ns") == stat.st_mtime_ns
        and cached.get("ctime_ns") == stat.st_ctime_ns
        and cached.get("inode") == stat.st_ino
    ):
        digest = str(cached.get("sha256", "")).lower()
    if not digest:
        digest = _sha256(database)
        cache[cache_key] = {
            "kind": kind,
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "ctime_ns": stat.st_ctime_ns,
            "inode": stat.st_ino,
            "sha256": digest,
        }
        _write_cache(cache_file, cache)
    for manifest in candidates:
        if manifest.database_sha256 == digest:
            return manifest
    expected = ", ".join(manifest.database_sha256 for manifest in candidates)
    raise ValueError(
        f"{kind} database SHA-256 mismatch: got {digest}, expected one of {expected}"
    )
