"""Exact whole-file matching against a provenance-bearing binary sample index.

Only a SHA-256 match over the complete input bytes can produce a version claim.
Section hashes and partial binary fingerprints are deliberately not considered.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from importlib.resources import files
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

from .static_version import StaticVersionMatch

_SCHEMA_VERSION = 1
_FIELDS = {
    "name",
    "version",
    "sha256",
    "source",
    "upstream_source",
    "artifact_path",
    "architecture",
    "version_kind",
}
_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
_PLACEHOLDER_WORDS = {"demo", "dummy", "example", "fake", "fixture", "illustrative", "placeholder"}
_PLACEHOLDER_HOSTS = {"example.com", "example.org", "example.net", "example.invalid", "invalid", "localhost"}


def _is_placeholder(value: str) -> bool:
    words = re.findall(r"[a-z]+", value.casefold())
    return any(word in _PLACEHOLDER_WORDS for word in words)


def _validate_https_url(value: Any, field: str, sample_index: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or _is_placeholder(value):
        raise ValueError(f"samples[{sample_index}].{field} must be a real HTTPS provenance URL")
    parsed = urlsplit(value)
    host = (parsed.hostname or "").casefold().rstrip(".")
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or host in _PLACEHOLDER_HOSTS
        or host.endswith(".invalid")
    ):
        raise ValueError(f"samples[{sample_index}].{field} must be a real HTTPS provenance URL")
    return value


def _validate_artifact_path(value: Any, sample_index: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        or "\\" in value
        or _is_placeholder(value)
    ):
        raise ValueError(f"samples[{sample_index}].artifact_path must be a safe relative path")
    posix_path = PurePosixPath(value)
    if posix_path.is_absolute() or PureWindowsPath(value).is_absolute() or any(
        part in {"", ".", ".."} for part in value.split("/")
    ):
        raise ValueError(f"samples[{sample_index}].artifact_path must be a safe relative path")
    return value


def _validate_sample(record: Any, index: int) -> dict[str, str]:
    if not isinstance(record, dict) or set(record) != _FIELDS:
        raise ValueError(f"samples[{index}] must contain exactly: {', '.join(sorted(_FIELDS))}")
    validated: dict[str, str] = {}
    for field in ("name", "version", "architecture", "version_kind"):
        value = record.get(field)
        if not isinstance(value, str) or not value or value != value.strip() or _is_placeholder(value):
            raise ValueError(f"samples[{index}].{field} must be a non-placeholder string")
        validated[field] = value

    digest = record.get("sha256")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ValueError(f"samples[{index}].sha256 must contain exactly 64 hexadecimal characters")
    validated["sha256"] = digest.lower()
    validated["source"] = _validate_https_url(record.get("source"), "source", index)
    validated["upstream_source"] = _validate_https_url(
        record.get("upstream_source"), "upstream_source", index
    )
    validated["artifact_path"] = _validate_artifact_path(record.get("artifact_path"), index)
    return validated


class BinarySampleMatcher:
    """Match complete byte strings to validated, source-backed sample records."""

    def __init__(self, index_path: Path | str | None = None):
        if index_path is None:
            default_path = files("firmware_scanner.data").joinpath("binary_samples.json")
            if not default_path.is_file():
                records: Any = []
                document: Any = {"schema_version": _SCHEMA_VERSION, "samples": records}
            else:
                try:
                    document = json.loads(default_path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                    raise ValueError(f"Invalid bundled binary sample index: {exc}") from exc
        else:
            path = Path(index_path)
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"Invalid binary sample index at {path}: {exc}") from exc

        if (
            not isinstance(document, dict)
            or type(document.get("schema_version")) is not int
            or document.get("schema_version") != _SCHEMA_VERSION
            or not isinstance(document.get("samples"), list)
        ):
            raise ValueError("Binary sample index must use schema_version 1 and contain a samples list")

        self._by_digest: dict[str, list[dict[str, str]]] = defaultdict(list)
        for index, item in enumerate(document["samples"]):
            sample = _validate_sample(item, index)
            if sample not in self._by_digest[sample["sha256"]]:
                self._by_digest[sample["sha256"]].append(sample)
        for digest in self._by_digest:
            self._by_digest[digest].sort(
                key=lambda item: (
                    item["name"].casefold(), item["version"], item["artifact_path"], item["source"]
                )
            )

    def candidates(self, data: bytes) -> list[dict[str, str]]:
        """Return every provenance record for an exact full-file SHA-256 match."""
        if not isinstance(data, bytes) or not data:
            return []
        digest = hashlib.sha256(data).hexdigest()
        return [dict(sample) for sample in self._by_digest.get(digest, ())]

    def match(self, data: bytes) -> list[StaticVersionMatch]:
        """Return exact claims only where each component name has one indexed version."""
        candidates = self.candidates(data)
        grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
        for sample in candidates:
            grouped[sample["name"].casefold()].append(sample)

        matches: list[StaticVersionMatch] = []
        for records in grouped.values():
            versions = {sample["version"] for sample in records}
            if len(versions) != 1:
                continue
            first = records[0]
            evidence = json.dumps(
                {
                    "method": "whole_file_sha256",
                    "sha256": first["sha256"],
                    "provenance": [
                        {
                            "source": sample["source"],
                            "upstream_source": sample["upstream_source"],
                            "artifact_path": sample["artifact_path"],
                            "architecture": sample["architecture"],
                            "version_kind": sample["version_kind"],
                        }
                        for sample in records
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            matches.append(StaticVersionMatch(first["name"], first["version"], evidence, 1.0))
        return sorted(matches, key=lambda match: (match.name.casefold(), match.name, match.version))
