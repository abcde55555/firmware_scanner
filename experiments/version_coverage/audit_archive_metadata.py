#!/usr/bin/env python3
"""Independently verify archive metadata declarations in an ext4 image.

This script reads only APK/JAR ZIP metadata members referenced by a component
analysis JSON. It does not invoke or load native code from the image.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

MAX_METADATA_BYTES = 64 * 1024
ANDROIDX_MEMBER = re.compile(r"^META-INF/androidx\.([^_]+)_(.+)\.version$")
MAVEN_MEMBER = re.compile(
    r"^META-INF/maven/([^/]+)/([^/]+)/pom\.properties$"
)
PURL = re.compile(r"^pkg:maven/([^/]+)/([^@]+)@(.+)$")


def properties_from_text(text: str) -> dict[str, str]:
    """Parse the simple key=value subset used by Maven pom.properties."""
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        match = re.match(r"^([^:=\s]+)\s*[:=]\s*(.*)$", line)
        if match:
            values[match.group(1)] = match.group(2).strip()
    return values


def inspect_declaration(kind: str, member: str, raw: bytes) -> dict[str, Any]:
    text = raw.decode("utf-8", errors="replace")
    result: dict[str, Any] = {
        "raw_text": text,
        "declared_group": None,
        "declared_artifact": None,
        "declared_version": None,
        "parse_status": "unrecognized_metadata",
    }
    if kind == "androidx-version-file":
        match = ANDROIDX_MEMBER.fullmatch(member)
        if not match:
            return result
        group_suffix, artifact = match.groups()
        version_text = text.strip()
        if version_text.startswith("version="):
            version_text = version_text[len("version="):].strip()
        if version_text and "\n" not in version_text and "\r" not in version_text:
            result.update({
                "declared_group": f"androidx.{group_suffix}",
                "declared_artifact": artifact,
                "declared_version": version_text,
                "parse_status": "parsed",
            })
        return result

    if kind == "maven-pom-properties":
        match = MAVEN_MEMBER.fullmatch(member)
        props = properties_from_text(text)
        if not match:
            return result
        path_group, path_artifact = match.groups()
        result.update({
            "declared_group": props.get("groupId"),
            "declared_artifact": props.get("artifactId"),
            "declared_version": props.get("version"),
            "path_group": path_group,
            "path_artifact": path_artifact,
        })
        if all(result[key] for key in (
            "declared_group", "declared_artifact", "declared_version"
        )):
            result["parse_status"] = "parsed"
        return result
    return result


def locations_for(component: dict[str, Any]) -> list[str]:
    return list(dict.fromkeys(
        str(prop.get("value", ""))
        for prop in component.get("properties", [])
        if prop.get("name") == "firmware:evidence:location"
        and "!/" in str(prop.get("value", ""))
    ))


def compare_one(
    component: dict[str, Any], kind: str, location: str,
    filesystem: Any, archive_cache: dict[str, zipfile.ZipFile | Exception],
    member_cache: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    archive_path, member = location.rsplit("!/", 1)
    result: dict[str, Any] = {
        "component_name": component.get("name"),
        "reported_purl": component.get("purl"),
        "reported_version": component.get("resolved_version"),
        "metadata_kind": kind,
        "evidence_location": location,
        "archive_path": archive_path,
        "member_path": member,
        "declaration_status": "failed",
        "failure_reason": None,
        "actual_byte_version_proven": False,
    }
    if Path(archive_path).suffix.lower() not in {".apk", ".jar"}:
        result["failure_reason"] = "evidence container is not an APK/JAR path"
        result["warning"] = result["failure_reason"]
        return result

    cache_key = (archive_path, member)
    if cache_key not in member_cache:
        try:
            archive = archive_cache.get(archive_path)
            if archive is None:
                archive = zipfile.ZipFile(
                    _FilesystemArchive(filesystem, archive_path), mode="r"
                )
                archive_cache[archive_path] = archive
            if isinstance(archive, Exception):
                raise archive
            info = archive.getinfo(member)
            if info.file_size > MAX_METADATA_BYTES:
                raise ValueError(
                    f"metadata member exceeds {MAX_METADATA_BYTES} byte limit"
                )
            with archive.open(info, "r") as stream:
                raw = stream.read(MAX_METADATA_BYTES + 1)
            if len(raw) > MAX_METADATA_BYTES:
                raise ValueError(
                    f"metadata member exceeds {MAX_METADATA_BYTES} byte limit"
                )
            declaration = inspect_declaration(kind, member, raw)
            declaration["evidence_sha256"] = hashlib.sha256(raw).hexdigest()
            declaration["evidence_size"] = len(raw)
            member_cache[cache_key] = declaration
        # A corrupt or unsupported archive at one location must not stop other checks.
        except Exception as exc:  # noqa: BLE001
            if archive_path not in archive_cache:
                archive_cache[archive_path] = exc
            member_cache[cache_key] = {
                "parse_status": "read_error",
                "failure_reason": f"{type(exc).__name__}: {exc}",
                "raw_text": None,
                "evidence_sha256": None,
                "evidence_size": None,
            }

    declaration = member_cache[cache_key]
    result.update(declaration)
    if declaration.get("parse_status") != "parsed":
        result["failure_reason"] = declaration.get(
            "failure_reason", declaration.get("parse_status")
        )
        result["warning"] = result["failure_reason"]
        return result

    purl_match = PURL.fullmatch(str(component.get("purl") or ""))
    if not purl_match:
        result["failure_reason"] = "reported purl is not a versioned Maven coordinate"
        result["warning"] = result["failure_reason"]
        return result
    purl_group, purl_artifact, purl_version = purl_match.groups()
    result["purl_group"] = purl_group
    result["purl_artifact"] = purl_artifact
    result["purl_version"] = purl_version
    checks = {
        "coordinate_group_matches": declaration.get("declared_group") == purl_group,
        "coordinate_artifact_matches": declaration.get("declared_artifact") == purl_artifact,
        "declared_version_matches_purl": declaration.get("declared_version") == purl_version,
        "declared_version_matches_component": (
            declaration.get("declared_version") == str(component.get("resolved_version") or "")
        ),
    }
    if kind == "maven-pom-properties":
        checks.update({
            "declared_group_matches_member_path": (
                declaration.get("declared_group") == declaration.get("path_group")
            ),
            "declared_artifact_matches_member_path": (
                declaration.get("declared_artifact") == declaration.get("path_artifact")
            ),
            "member_path_group_matches_purl": declaration.get("path_group") == purl_group,
            "member_path_artifact_matches_purl": declaration.get("path_artifact") == purl_artifact,
        })
    result.update(checks)
    if all(checks.values()):
        result["declaration_status"] = "declaration_consistent"
        result["failure_reason"] = None
    else:
        result["declaration_status"] = "declaration_mismatch"
        result["failure_reason"] = "one or more coordinate/version comparisons failed"
        result["warning"] = result["failure_reason"]
    return result


class _FilesystemArchive:
    """Small file-like adapter around the repository's read-only archive reader."""
    def __new__(cls, filesystem: Any, path: str):
        from firmware_scanner.android.archive_reader import FilesystemFile
        return FilesystemFile(filesystem, path)


def audit(image_path: Path, analysis_path: Path) -> dict[str, Any]:
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    components = analysis.get("components", [])
    candidates: list[tuple[dict[str, Any], str, list[str]]] = []
    for component in components:
        kind = next((
            str(prop.get("value"))
            for prop in component.get("properties", [])
            if prop.get("name") == "firmware:metadata_kind"
        ), None)
        if kind not in {"androidx-version-file", "maven-pom-properties"}:
            continue
        candidates.append((component, kind, locations_for(component)))

    if not candidates:
        raise ValueError("analysis contains no supported archive-metadata components")

    from firmware_scanner.android.ext4_reader import Ext4Reader

    entries: list[dict[str, Any]] = []
    archive_cache: dict[str, zipfile.ZipFile | Exception] = {}
    member_cache: dict[tuple[str, str], dict[str, Any]] = {}
    with image_path.open("rb") as image_file, mmap.mmap(
        image_file.fileno(), length=0, access=mmap.ACCESS_READ
    ) as image:
        filesystem = Ext4Reader(image)
        if not filesystem.is_valid():
            raise ValueError(f"input image is not a supported ext4 image: {image_path}")
        try:
            for component, kind, locations in candidates:
                if not locations:
                    entries.append({
                        "component_name": component.get("name"),
                        "reported_purl": component.get("purl"),
                        "reported_version": component.get("resolved_version"),
                        "metadata_kind": kind,
                        "evidence_location": None,
                        "declaration_status": "failed",
                        "failure_reason": "no archive-member evidence location",
                        "warning": "no archive-member evidence location",
                        "actual_byte_version_proven": False,
                    })
                    continue
                for location in locations:
                    entries.append(compare_one(
                        component, kind, location, filesystem,
                        archive_cache, member_cache,
                    ))
        finally:
            for archive in archive_cache.values():
                if isinstance(archive, zipfile.ZipFile):
                    archive.close()

    status_counts = Counter(entry["declaration_status"] for entry in entries)
    kind_counts = Counter(entry["metadata_kind"] for entry in entries)
    consistent = status_counts.get("declaration_consistent", 0)
    failed = len(entries) - consistent
    unique_member_locations = {
        (entry.get("archive_path"), entry.get("member_path"))
        for entry in entries
        if entry.get("archive_path") and entry.get("member_path")
    }
    return {
        "schema": "independent-archive-metadata-audit/v1",
        "image": str(image_path),
        "analysis": str(analysis_path),
        "method": {
            "filesystem": "read-only Ext4Reader over a read-only mmap",
            "archive_access": "FilesystemFile random access; ZIP central directory and selected metadata members only",
            "independent_parser": "local AndroidX version-file and Maven properties parsing; product extraction functions are not used",
            "max_uncompressed_metadata_member_bytes": MAX_METADATA_BYTES,
            "target_code_execution": False,
            "actual_byte_version_proven_by_metadata": False,
        },
        "summary": {
            "candidate_components": len(candidates),
            "components_with_metadata_locations": sum(bool(locs) for _, _, locs in candidates),
            "component_location_checks": len(entries),
            "unique_zip_member_locations": len(unique_member_locations),
            "evidence_checks": len(entries),
            "declaration_consistent": consistent,
            "failed_or_mismatched": failed,
            "failure_count_includes": ["read errors", "missing or unparseable metadata", "coordinate/version mismatches"],
            "actual_byte_version_proven": 0,
            "status_counts": dict(status_counts),
            "metadata_kind_check_counts": dict(kind_counts),
            "warning_count": sum("warning" in entry for entry in entries),
        },
        "warnings": [
            {
                "component_name": entry.get("component_name"),
                "evidence_location": entry.get("evidence_location"),
                "warning": entry["warning"],
            }
            for entry in entries if "warning" in entry
        ],
        "limitations": [
            "A matching declaration proves only that the referenced archive contains metadata declaring the reported coordinates and version.",
            "Metadata can be stale, copied, or inconsistent with compiled classes; no DEX/JAR class implementation or native ELF was inspected.",
            "No overall product accuracy rate is inferred from this targeted evidence audit.",
            "ZIP members larger than 64 KiB are rejected without expanding them.",
        ],
        "checks": entries,
    }


def markdown_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Archive metadata evidence audit",
        "",
        f"- Image: `{report['image']}`",
        f"- Analysis: `{report['analysis']}`",
        f"- Candidate components: {summary['candidate_components']}",
        f"- Component × evidence-location checks: {summary['component_location_checks']}",
        f"- Unique ZIP member locations: {summary['unique_zip_member_locations']}",
        f"- Declaration consistent: {summary['declaration_consistent']}",
        f"- Failed or mismatched: {summary['failed_or_mismatched']}",
        f"- Warnings: {summary['warning_count']}",
        f"- Actual byte version proven: {summary['actual_byte_version_proven']}",
        "",
        "## Method and interpretation",
        "",
        "The audit independently opened the APK/JAR referenced by each metadata evidence location and read the ZIP member directly. Each readable member is limited to 64 KiB and records its uncompressed SHA-256 and original decoded text. AndroidX coordinates are taken from the version-member path; Maven coordinates and version are read from `pom.properties` and its path.",
        "",
        "`declaration_consistent` means the archive declaration, Maven purl, and component version fields agree. It does not prove the compiled code has that version. The audit does not claim an overall accuracy rate.",
        "",
        "## Results by metadata kind",
        "",
        "| Kind | Evidence checks | Consistent | Failed/mismatched |",
        "|---|---:|---:|---:|",
    ]
    for kind, count in sorted(summary["metadata_kind_check_counts"].items()):
        consistent = sum(
            1 for check in report["checks"]
            if check.get("metadata_kind") == kind
            and check.get("declaration_status") == "declaration_consistent"
        )
        lines.append(f"| `{kind}` | {count} | {consistent} | {count - consistent} |")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.extend([
        "",
        "Per-location evidence, hashes, raw metadata, comparisons, and failure reasons are in the JSON report alongside this file.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="read-only ext4 image")
    parser.add_argument("analysis", type=Path, help="system_analysis.json to audit")
    parser.add_argument("output", type=Path, help="output .json or .md report path")
    args = parser.parse_args()
    try:
        report = audit(args.image, args.analysis)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if args.output.suffix.lower() == ".md":
            args.output.write_text(markdown_report(report), encoding="utf-8")
        else:
            args.output.write_text(
                json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        print(json.dumps(report["summary"], ensure_ascii=False, sort_keys=True))
        return 1 if report["summary"]["failed_or_mismatched"] else 0
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, zipfile.BadZipFile) as exc:
        print(f"audit failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
