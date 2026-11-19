"""Integrity verification for packaged rule and provenance data."""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path, PurePosixPath


def _sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def _rule_kind(relative: str) -> str:
    if relative.startswith("database_packs/"):
        return "database-manifest"
    if relative.startswith("provenance/"):
        return "provenance-pack"
    if relative.startswith("signatures/"):
        return "signature-pack"
    if relative.startswith("cve/"):
        return "offline-advisory-pack"
    if relative in {"binary_reference.json", "emba_rules.json"}:
        return "binary-rule-pack"
    if relative == "binary_samples.json":
        return "binary-sample-pack"
    if relative == "rust_version_positions.json":
        return "rust-version-pack"
    return "data-pack"


def build_rule_lock(data_root: Path, release: str) -> dict:
    """Build a deterministic lock for all JSON data below ``data_root``."""
    release = release.strip()
    if not release:
        raise ValueError("rule lock release must not be empty")
    files = []
    for path in sorted(data_root.rglob("*.json")):
        relative = path.relative_to(data_root).as_posix()
        if relative == "rules.lock.json":
            continue
        files.append({
            "path": relative,
            "sha256": _sha256(path.read_bytes()),
            "kind": _rule_kind(relative),
        })
    return {
        "schema_version": 1,
        "release": release,
        "files": files,
    }


def verify_rule_lock(
    lock_path: Path,
    data_root: Traversable | Path,
) -> dict:
    """Verify a rule lock and every file referenced by it."""
    try:
        lock_bytes = lock_path.read_bytes()
        payload = json.loads(lock_bytes)
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"cannot read rule lock: {exc}") from exc
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported rule lock schema")
    release = str(payload.get("release", "")).strip()
    entries = payload.get("files")
    if not release or not isinstance(entries, list) or not entries:
        raise ValueError("rule lock requires a release and files")

    seen = set()
    verified_files = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("invalid rule lock entry")
        relative = str(entry.get("path", "")).replace("\\", "/")
        parsed = PurePosixPath(relative)
        if (
            not relative
            or parsed.is_absolute()
            or ".." in parsed.parts
            or relative in seen
        ):
            raise ValueError(f"invalid rule pack path: {relative!r}")
        seen.add(relative)
        expected = str(entry.get("sha256", "")).lower()
        if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
            raise ValueError(f"invalid rule pack sha256 for {relative}")
        candidate = data_root.joinpath(*parsed.parts)
        if not candidate.is_file():
            raise ValueError(f"rule pack file is missing: {relative}")
        digest = _sha256(candidate.read_bytes())
        if digest != expected:
            raise ValueError(
                f"rule pack hash mismatch for {relative}: got {digest}, expected {expected}"
            )
        verified_files.append({
            "path": relative,
            "sha256": digest,
            "kind": str(entry.get("kind", "")),
        })
    return {
        "schema_version": 1,
        "release": release,
        "lock_sha256": _sha256(lock_bytes),
        "files": verified_files,
    }


def verify_builtin_rule_lock() -> dict:
    """Verify the rules bundled in the installed firmware-scanner wheel."""
    root = files("firmware_scanner.data")
    lock_path = root.joinpath("rules.lock.json")
    if not lock_path.is_file():
        raise ValueError("built-in rule lock is missing")
    # Traversable and pathlib.Path share the required read/is_file interface,
    # but mypy cannot express that structural compatibility here.
    return verify_rule_lock(lock_path, root)  # type: ignore[arg-type]
