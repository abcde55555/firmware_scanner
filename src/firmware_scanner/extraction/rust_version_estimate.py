"""Usable Rust release estimates from owned positions and finite public references.

Nearby candidates and the selection rule remain attached. A reference source
prior is a tie-breaker, not a claim that the scanned file used that checkout.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from .rust_locations import extract_locations


def _key(crate):
    return crate.replace("_", "-")


def _version(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise ValueError("reference version must be a stable Rust release")
    return tuple(map(int, value.split(".")))


def _source(value):
    if not isinstance(value, str):
        raise TypeError("reference source must be an HTTPS URL")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("reference source must be an HTTPS URL")
    return value


@dataclass(frozen=True)
class RustVersionEstimate:
    crate: str
    version: str
    candidates: tuple[str, ...]
    matched_sites: int
    target_sites: int
    support: float
    selection: str
    evidence: str
    kind: str = "estimated-release"


class RustVersionEstimator:
    def __init__(self, index_path: Path | str | None = None):
        path = Path(index_path) if index_path is not None else files("firmware_scanner.data").joinpath(
            "rust_version_positions.json")
        if path.is_file():
            with path.open("rb") as handle:
                raw = handle.read(32 * 1024 * 1024 + 1)
        else:
            raw = b'{"schema_version":1,"families":[]}'
        if len(raw) > 32 * 1024 * 1024:
            raise ValueError("Rust reference index exceeds read budget")
        document = json.loads(raw)
        if document.get("schema_version") != 1 or not isinstance(document.get("families"), list):
            raise ValueError("unsupported Rust reference index")
        if len(document["families"]) > 256:
            raise ValueError("too many Rust reference families")
        self._families = {}
        self._index_sha256 = hashlib.sha256(raw).hexdigest()
        total_sites = 0
        for family in document["families"]:
            crate = family["crate"]
            if not isinstance(crate, str) or not re.fullmatch(r"[a-z0-9_-]+", crate):
                raise ValueError("invalid Rust reference crate")
            key = _key(crate)
            if key in self._families:
                raise ValueError("duplicate Rust reference family")
            releases = {}
            for release in family["releases"]:
                version = release["version"]
                _version(version)
                if version in releases:
                    raise ValueError("duplicate Rust reference release")
                _source(release["source"])
                if not re.fullmatch(r"[a-f0-9]{64}", release["source_sha256"]):
                    raise ValueError("invalid Rust source checksum")
                sites = set()
                for site in release["sites"]:
                    file = site["file"]
                    if (not isinstance(file, str) or not file.endswith(".rs") or "\\" in file
                            or PurePosixPath(file).is_absolute() or any(
                                part in ("", ".", "..") for part in file.split("/"))):
                        raise ValueError("invalid Rust source path")
                    line, column = site["line"], site["column"]
                    if type(line) is not int or type(column) is not int or not (
                            0 < line < 1_000_000 and 0 < column < 1_000_000):
                        raise ValueError("invalid Rust source coordinate")
                    sites.add((file, line, column))
                    total_sites += 1
                    if total_sites > 1_000_000:
                        raise ValueError("Rust source-position budget exceeded")
                releases[version] = (sites, release)
                if len(releases) > 128:
                    raise ValueError("too many Rust reference releases")
            prior = family.get("prior_version", "")
            if prior:
                _version(prior)
                _source(family["prior_source"])
            self._families[key] = (family, releases)

    def estimate(self, data: bytes, filename: str) -> RustVersionEstimate | None:
        match = re.fullmatch(r"lib([A-Za-z0-9_-]+)\.dylib\.so", filename)
        if not match or _key(match[1]) not in self._families:
            return None
        if b"external/rust/android-crates-io/crates/" not in data:
            return None
        return self.estimate_locations(extract_locations(data)["locations"], match[1])

    def estimate_locations(self, locations, crate) -> RustVersionEstimate | None:
        entry = self._families.get(_key(crate))
        if entry is None:
            return None
        family, releases = entry
        observed = {(row["source_file"], row["line"], row["column"])
                    for row in locations if _key(row["crate"]) == _key(crate)
                    and row.get("code_references") and row.get("corroborated_calls")}
        if len(observed) < 3:
            return None
        ranked = []
        for version, (sites, reference) in releases.items():
            lines = {(file, line) for file, line, _ in sites}
            exact = observed & sites
            line_hits = sum((file, line) in lines for file, line, _ in observed)
            support = (len(exact) + line_hits) / (2 * len(observed))
            if len(exact) >= 3 and support >= .5:
                ranked.append((support, len(exact), version, reference))
        if not ranked:
            return None
        ranked.sort(key=lambda row: (row[0], row[1], _version(row[2])), reverse=True)
        best = ranked[0]
        candidates = tuple(sorted((row[2] for row in ranked if best[0] - row[0] <= .02), key=_version))
        if len({_version(version)[:2] for version in candidates}) != 1:
            return None
        prior = family.get("prior_version")
        version = prior if prior in candidates else candidates[len(candidates) // 2]
        selection = ("reference-source-prior-within-candidates" if prior in candidates else
                     "middle-of-nearby-candidate-releases")
        selected = next(row for row in ranked if row[2] == version)
        evidence = {"method": "owned-rust-source-positions", "version_kind": "estimated-release",
                    "crate": family["crate"], "selected_version": version,
                    "candidate_versions": candidates, "selection": selection,
                    "reference_prior_source": family.get("prior_source", ""),
                    "matched_sites": selected[1], "target_sites": len(observed),
                    "support_fraction": selected[0], "score_kind": "feature-support-not-calibrated-accuracy",
                    "reference_source": selected[3]["source"],
                    "reference_source_sha256": selected[3]["source_sha256"],
                    "reference_site_kinds": sorted({site.get("kind", "unspecified")
                                                    for site in selected[3]["sites"]}),
                    "index_sha256": self._index_sha256,
                    "matched_positions": [list(site) for site in sorted(observed & releases[version][0])[:32]],
                    "limitations": "finite references; vendor patches and unindexed releases may differ"}
        return RustVersionEstimate(family["crate"], version, candidates, selected[1], len(observed),
                                   selected[0], selection, json.dumps(evidence, sort_keys=True))
