#!/usr/bin/env python3
"""Evaluate version coverage against an immutable set of component observations."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_LOCATION_RE = re.compile(r"(?<![A-Za-z0-9:/])/(?!/)(?:[^\s\"'<>;,|]+)")
_URL_RE = re.compile(r"https?://[^\s\"'<>;,|]+", re.IGNORECASE)
_SOURCE_FILE_RE = re.compile(r"\b(?:build\.prop|AndroidManifest\.xml)\b", re.IGNORECASE)
_UNKNOWN = {"", "unknown", "n/a", "na", "none", "null", "unavailable", "unanalysed", "unanalyzed",
            "detected", "detected (version unknown)"}
_CONFLICT = {"conflict", "ambiguous", "multiple", "various"}
_RANGE_RE = re.compile(
    r"(?:>=|<=|>|<|~|\^|\*|\|\||\bto\b|\s[-–—]\s|\d\s*,\s*\d|"
    r"(?:^|[.+-])x(?:[.+-]|$))",
    re.IGNORECASE,
)


def _normalized(value: Any) -> str:
    return " ".join(str(value or "").casefold().split())


def _identity(record: dict[str, Any]) -> str:
    """Identity intentionally excludes version and location so they can evolve."""
    return "|".join(
        _normalized(record.get(field))
        for field in ("component_type", "name", "vendor")
    )


def _clean_location(value: str) -> str:
    value = value.strip().replace("\\", "/").rstrip(".).,;:")  # noqa: B005 -- a set of punctuation
    value = re.sub(r"/+", "/", value)
    return value.rstrip("/")


def _locations(record: dict[str, Any]) -> list[str]:
    locations: set[str] = set()

    def add_text(value: Any, direct: bool = False) -> None:
        if not isinstance(value, str) or not value.strip():
            return
        searchable = _URL_RE.sub(" ", value)
        matches = _LOCATION_RE.findall(searchable)
        matches.extend(_SOURCE_FILE_RE.findall(searchable))
        if direct and not matches and not _URL_RE.search(value):
            matches = [value]
        for match in matches:
            cleaned = _clean_location(match)
            if cleaned:
                locations.add(cleaned)

    def add_location_value(value: Any) -> None:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith(("[", "{")):
                try:
                    decoded = json.loads(stripped)
                except (json.JSONDecodeError, TypeError):
                    decoded = value
                if decoded is not value:
                    add_location_value(decoded)
                    return
            add_text(value, direct=True)
        elif isinstance(value, list):
            for item in value:
                add_location_value(item)
        elif isinstance(value, dict):
            for item in value.values():
                add_location_value(item)

    def visit_properties(value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                visit_properties(item)
        elif isinstance(value, dict):
            property_name = value.get("name", value.get("key", ""))
            if str(property_name).casefold() == "firmware:evidence:location":
                add_location_value(value.get("value"))
            for key, item in value.items():
                if str(key).casefold() == "firmware:evidence:location":
                    add_location_value(item)
                elif key not in {"value", "name", "key"}:
                    visit_properties(item)

    for key in ("location", "locations", "source_location", "source_locations", "evidence"):
        value = record.get(key)
        if isinstance(value, list):
            for item in value:
                add_text(item, direct=key != "evidence")
        else:
            add_text(value, direct=key != "evidence")
    add_text(record.get("description"))
    visit_properties(record.get("properties"))
    versions = record.get("versions", [])
    if isinstance(versions, list):
        for version in versions:
            if isinstance(version, dict):
                add_text(version.get("evidence"))
                add_text(version.get("location"), direct=True)
                add_text(version.get("locations"), direct=True)
    return sorted(locations)


def observation_key(record: dict[str, Any]) -> str:
    """Return a stable, explicit key suitable for a verified-version mapping."""
    payload = json.dumps(
        [_identity(record), _locations(record)], ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _version(record: dict[str, Any]) -> str:
    if "resolved_version" not in record:
        versions = record.get("versions", [])
        candidates = {
            str(item.get("version", "")).strip()
            for item in versions
            if isinstance(item, dict)
        } if isinstance(versions, list) else set()
        if len(candidates) != 1:
            return ""
        value = candidates.pop()
    else:
        value = record.get("resolved_version")
    return str(value or "").strip()


def _version_kind(value: str) -> str:
    normalized = value.strip().casefold()
    if normalized in _UNKNOWN or normalized in _CONFLICT:
        return "unknown"
    if _RANGE_RE.search(normalized):
        return "range"
    return "exact"


def _resolution_state(record: dict[str, Any]) -> str:
    properties = record.get("properties", [])
    if not isinstance(properties, list):
        return ""
    return next((
        str(prop.get("value", ""))
        for prop in properties
        if isinstance(prop, dict)
        and prop.get("name") == "firmware:version:resolution-state"
    ), "")


def _output_kind(record: dict[str, Any]) -> str:
    """A single selected estimate is usable without becoming an observed release."""
    value = _version(record)
    properties = record.get("properties", [])
    state = _resolution_state(record)
    if state == "estimated" or state.startswith("estimated-"):
        return "estimated"
    if state == "conflict-unresolved":
        return "unknown"
    kind = _version_kind(value)
    if kind != "exact":
        return kind
    if isinstance(properties, list) and any(
        isinstance(prop, dict) and prop.get("name") == "firmware:version:kind"
        and prop.get("value") == "estimated-release" for prop in properties
    ):
        return "estimated"
    versions = record.get("versions", [])
    if isinstance(versions, list) and any(
        isinstance(item, dict) and item.get("method") == "version_estimate"
        and item.get("version") == value for item in versions
    ):
        return "estimated"
    return kind


def _adjacent_estimate(record: dict[str, Any], expected: str | None) -> bool:
    if expected is None or _output_kind(record) != "estimated":
        return False
    values = [_version(record), expected]
    if not all(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value) for value in values):
        return False
    actual, target = [tuple(map(int, value.split("."))) for value in values]
    return actual[:2] == target[:2] and abs(actual[2] - target[2]) == 1


def _native(record: dict[str, Any]) -> bool:
    return (
        record.get("component_type") == "library"
        and "native library" in str(record.get("description", "")).lower()
    )


def _taxonomy(record: dict[str, Any]) -> str:
    properties = record.get("properties", [])
    if not isinstance(properties, list):
        return ""
    return next((
        str(prop.get("value", ""))
        for prop in properties
        if isinstance(prop, dict)
        and prop.get("name") == "firmware:taxonomy"
        and prop.get("value")
    ), "")


def _input_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _deduplicate(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, tuple[str, ...]], list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault((_identity(record), tuple(_locations(record))), []).append(record)
    unique: list[dict[str, Any]] = []
    for group_key in sorted(grouped):
        copies = grouped[group_key]
        copies = sorted(
            copies,
            key=lambda record: json.dumps(record, sort_keys=True, ensure_ascii=False, default=str),
        )
        record_versions = [_version(record) for record in copies]
        has_conflict_marker = any(version.casefold() in _CONFLICT for version in record_versions)
        claims = {
            version for version in record_versions
            if _version_kind(version) != "unknown"
        }
        if len(claims) == 1 and not has_conflict_marker:
            claim = next(iter(claims))
            # Keep an exact/range claim when all remaining copies are unknown or agree.
            agreeing = [record for record in copies if _version(record) == claim]
            source = next((record for record in agreeing if _output_kind(record) == "exact"), agreeing[0])
            unique.append(dict(source))
        elif not claims and not has_conflict_marker:
            unique.append(dict(copies[0]))
        else:
            merged = dict(copies[0])
            merged["resolved_version"] = ""
            merged["versions"] = [{"version": version} for version in sorted(claims)]
            unique.append(merged)
    return unique


def _match(baseline: list[dict[str, Any]], current: list[dict[str, Any]]) -> dict[int, int]:
    """Match every baseline row even when one BOM row merged several paths."""
    edges: list[tuple[int, str, int, int]] = []
    for bi, base in enumerate(baseline):
        base_locations = set(_locations(base))
        if not base_locations:
            continue
        for ci, candidate in enumerate(current):
            if _identity(base) != _identity(candidate):
                continue
            shared = base_locations & set(_locations(candidate))
            if shared:
                edges.append((-len(shared), observation_key(base), bi, ci))
    used_base: set[int] = set()
    matches: dict[int, int] = {}
    for _, _, bi, ci in sorted(edges):
        if bi not in used_base:
            matches[bi] = ci
            used_base.add(bi)
    return matches


def _metrics(indices: list[int], baseline: list[dict[str, Any]], current: list[dict[str, Any]],
             matches: dict[int, int], verified_by_index: dict[int, str]) -> dict[str, Any]:
    exact = estimated = unknown = ranges = independently_verified = correct = errors = adjacent = 0
    estimated_by_state: Counter[str] = Counter()
    for bi in indices:
        ci = matches.get(bi)
        if ci is None:
            continue
        output_version = _version(current[ci])
        kind = _output_kind(current[ci])
        if kind == "exact":
            exact += 1
        elif kind == "estimated":
            estimated += 1
            estimated_by_state[_resolution_state(current[ci]) or "unspecified-estimate"] += 1
        elif kind == "range":
            ranges += 1
        else:
            unknown += 1
        expected = verified_by_index.get(bi)
        if expected is not None:
            independently_verified += 1
            if kind in ("exact", "estimated") and output_version == expected:
                correct += 1
            elif kind in ("exact", "estimated"):
                errors += 1
            adjacent += _adjacent_estimate(current[ci], expected)
    denominator = len(indices)
    ratio = correct / denominator if denominator else 0.0
    return {
        "baseline": denominator,
        "matched": sum(index in matches for index in indices),
        "uncovered": denominator - sum(index in matches for index in indices),
        "exact_versions": exact,
        "estimated_versions": estimated,
        "estimated_by_state": dict(sorted(estimated_by_state.items())),
        "usable_versions": exact + estimated,
        "usable_coverage": (exact + estimated) / denominator if denominator else 0.0,
        "usable_target_50_percent": ("NOT_APPLICABLE" if not denominator else
                                     "MET" if (exact + estimated) / denominator >= .5 else "NOT_MET"),
        "unknown": unknown,
        "ranges": ranges,
        "independently_verified": independently_verified,
        "correct": correct,
        "errors": errors,
        "adjacent_estimates": adjacent,
        "accepted_verified": correct + adjacent,
        "correct_coverage": ratio,
        "target_50_percent": "NOT_APPLICABLE" if not denominator else ("MET" if ratio >= 0.5 else "NOT_MET"),
    }


def evaluate(baseline: list[dict], current: list[dict], verified: dict) -> dict:
    """Compare current output with every fixed baseline observation.

    ``verified`` maps ``observation_key(record)`` to an independently established,
    exact expected version. The 50% gate is the fraction of the frozen cohort that
    is independently confirmed correct; populated version fields alone do not pass.
    """
    baseline_hash = _input_hash(baseline)
    current_hash = _input_hash(current)
    baseline = [record for record in baseline if isinstance(record, dict)]
    current = _deduplicate([record for record in current if isinstance(record, dict)])
    if not isinstance(verified, dict):
        raise TypeError("verified must map observation keys to expected version strings")

    key_indices: dict[str, list[int]] = {}
    for index, record in enumerate(baseline):
        key_indices.setdefault(observation_key(record), []).append(index)
    verified_by_index: dict[int, str] = {}
    warnings: list[str] = []
    for key, expected_value in verified.items():
        matching_indices = key_indices.get(str(key))
        expected = str(expected_value).strip()
        if not matching_indices:
            warnings.append(f"verification key does not identify a baseline observation: {key}")
            continue
        if _version_kind(expected) != "exact":
            warnings.append(f"verification value is not an exact version for key: {key}")
            continue
        for index in matching_indices:
            verified_by_index[index] = expected

    matches = _match(baseline, current)
    native_indices = [i for i, record in enumerate(baseline) if _native(record)]
    fixed_indices = list(range(len(baseline)))
    taxonomy_indices: dict[str, list[int]] = {}
    for bi, ci in matches.items():
        taxonomy = _taxonomy(current[ci])
        if taxonomy:
            taxonomy_indices.setdefault(taxonomy, []).append(bi)
    observations = []
    for bi, record in enumerate(baseline):
        ci = matches.get(bi)
        output = current[ci] if ci is not None else None
        output_version = _version(output) if output is not None else ""
        kind = _output_kind(output) if output is not None else "unknown"
        expected = verified_by_index.get(bi)
        observations.append({
            "observation_key": observation_key(record),
            "identity": _identity(record),
            "locations": _locations(record),
            "native": _native(record),
            "matched": output is not None,
            "version": output_version if output is not None else None,
            "version_kind": kind if output is not None else None,
            "verified_version": expected,
            "correct": expected is not None and kind in ("exact", "estimated") and output_version == expected,
            "error": expected is not None and kind in ("exact", "estimated") and output_version != expected,
            "adjacent_estimate": output is not None and _adjacent_estimate(output, expected),
        })

    matched_current = set(matches.values())
    unmatched_current = [record for index, record in enumerate(current) if index not in matched_current]
    new_records = [record for record in unmatched_current if _locations(record)]
    unlocated_unmatched = len(unmatched_current) - len(new_records)
    methods: Counter[str] = Counter()
    for record in current:
        versions = record.get("versions", [])
        if isinstance(versions, list):
            methods.update(
                str(item["method"])
                for item in versions
                if isinstance(item, dict) and item.get("method")
            )
    return {
        "schema_version": 1,
        "target_percent": 50,
        "input_sha256": {"baseline": baseline_hash, "current": current_hash},
        "baseline_commit": None,
        "evidence_types": dict(sorted(methods.items())),
        "fixed": {
            "all": _metrics(fixed_indices, baseline, current, matches, verified_by_index),
            "native": _metrics(native_indices, baseline, current, matches, verified_by_index),
            "by_taxonomy": {
                taxonomy: _metrics(
                    sorted(indices),
                    baseline,
                    current,
                    matches,
                    verified_by_index,
                )
                for taxonomy, indices in sorted(taxonomy_indices.items())
            },
            "observations": observations,
        },
        "new": {"records": len(new_records), "unlocated_unmatched": unlocated_unmatched, "observations": [
            {"identity": _identity(record), "locations": _locations(record), "version": _version(record)}
            for record in new_records
        ]},
        "verification_warnings": warnings,
    }


def _load_records(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and isinstance(value.get("components"), list):
        return value["components"]
    raise ValueError(f"{path} must contain a record list or an object with a components list")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path, help="baseline JSON list or system_analysis.json")
    parser.add_argument("current", type=Path, help="current JSON list or system_analysis.json")
    parser.add_argument("--verified", type=Path, help="JSON object mapping observation keys to exact versions")
    parser.add_argument("--baseline-commit", help="commit that produced the fixed baseline, if known")
    args = parser.parse_args(argv)
    verified = json.loads(args.verified.read_text(encoding="utf-8")) if args.verified else {}
    result = evaluate(_load_records(args.baseline), _load_records(args.current), verified)
    result["baseline_commit"] = args.baseline_commit
    result["input_files_sha256"] = {
        "baseline": hashlib.sha256(args.baseline.read_bytes()).hexdigest(),
        "current": hashlib.sha256(args.current.read_bytes()).hexdigest(),
    }
    json.dump(result, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
