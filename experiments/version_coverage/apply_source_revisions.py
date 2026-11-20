"""Attach AOSP manifest build revisions to conservatively attributed ELF records."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from experiments.version_coverage.evaluate import _identity, _locations, observation_key

_APEX_PATH_RE = re.compile(r"(/system/apex/[^/]+\.apex)(?:!|$)")
_APK_PATH_RE = re.compile(r"([^!\s]+\.apk)(?:!|$)")


def _component_locations(component: dict) -> list[str]:
    locations = list(_locations(component))
    for prop in component.get("properties", []):
        if isinstance(prop, dict) and prop.get("name") == "firmware:evidence:location":
            value = prop.get("value")
            if isinstance(value, str):
                locations.append(value)
    return sorted(set(locations))


def apply_revisions(
    analysis: dict,
    frozen_candidates: dict,
    source_manifest: dict,
) -> tuple[dict, dict]:
    manifest = {
        row["path"]: row
        for row in source_manifest.get("projects", [])
        if row.get("path") and row.get("revision")
    }
    candidates = {
        row["observation_key"]: row
        for row in frozen_candidates.get("observations", [])
        if len(row.get("source_candidates", [])) == 1
    }
    candidates_by_identity: dict[str, list[dict]] = {}
    for candidate in candidates.values():
        candidates_by_identity.setdefault(candidate["identity"], []).append(candidate)
    applied = []
    skipped = []
    package_versions = {}
    for package in analysis.get("components", []):
        if not package.get("resolved_version"):
            continue
        for location in _component_locations(package):
            if location.endswith((".apex", ".apk")):
                package_versions[location] = str(package["resolved_version"])
    for component in analysis.get("components", []):
        key = observation_key(component)
        candidate = candidates.get(key)
        if candidate is None:
            component_locations = set(_locations(component))
            compatible = [
                item for item in candidates_by_identity.get(_identity(component), [])
                if set(item.get("locations", [])) <= component_locations
            ]
            sources = {
                (
                    item["source_candidates"][0]["project_path"],
                    item["source_candidates"][0]["declared_commit"],
                )
                for item in compatible
            }
            if len(sources) == 1:
                candidate = compatible[0]
        if candidate is None:
            continue
        if component.get("resolved_version"):
            skipped.append({
                "observation_key": key,
                "name": component.get("name"),
                "reason": "existing-version",
                "existing_version": component["resolved_version"],
            })
            continue
        source = candidate["source_candidates"][0]
        project_path = source["project_path"]
        project = manifest.get(project_path)
        if project is None or not project.get("revision"):
            skipped.append({
                "observation_key": key,
                "name": component.get("name"),
                "reason": "manifest-project-or-revision-missing",
                "project_path": project_path,
            })
            continue
        revision = str(project["revision"])
        version = f"git:{revision}"
        component["resolved_version"] = version
        component.setdefault("versions", []).append({
            "version": version,
            "confidence": 0.68,
            "method": "version_estimate",
            "evidence": (
                f"IMAGE NOTICE maps {component.get('name')} to {project_path}; "
                f"internal manifest pins {project.get('name')} at {revision}"
            ),
            "version_type": "git-revision",
        })
        properties = component.setdefault("properties", [])
        for name, value in (
            ("firmware:version:kind", "estimated-source-revision"),
            ("firmware:source:project", project_path),
            ("firmware:source:repository", str(project.get("name") or "")),
            ("firmware:source:revision", revision),
            ("firmware:source:revision-confidence", "0.68"),
            ("firmware:evidence:source", "image NOTICE plus internal manifest"),
        ):
            if not any(
                isinstance(item, dict) and item.get("name") == name
                for item in properties
            ):
                properties.append({"name": name, "value": value})
        applied.append({
            "observation_key": key,
            "name": component.get("name"),
            "locations": candidate.get("locations", []),
            "version": version,
            "project_path": project_path,
            "project_repository": project.get("name"),
            "revision": revision,
        })
    package_applied = []
    for component in analysis.get("components", []):
        if component.get("resolved_version") or "native library" not in str(
            component.get("description", "")
        ).lower():
            continue
        locations = _component_locations(component)
        apex_parents = sorted({
            match.group(1) for location in locations
            if (match := _APEX_PATH_RE.search(location))
        })
        apk_parents = sorted({
            match.group(1) for location in locations
            if (match := _APK_PATH_RE.search(location))
        })
        parents = apex_parents or apk_parents
        versions = {
            package_versions[parent] for parent in parents if parent in package_versions
        }
        if not parents or len(versions) != 1:
            continue
        version = versions.pop()
        parent_kind = "APEX" if apex_parents else "APK"
        component["resolved_version"] = version
        component.setdefault("versions", []).append({
            "version": version,
            "confidence": 0.72,
            "method": "version_estimate",
            "evidence": (
                f"Containing {parent_kind} package version for native library "
                f"{component.get('name')}; this is parent-package provenance"
            ),
            "version_type": f"android-{parent_kind.lower()}-version-code",
        })
        properties = component.setdefault("properties", [])
        for name, value in (
            ("firmware:version:kind", f"estimated-{parent_kind.lower()}-package-version"),
            ("firmware:container:type", parent_kind.lower()),
            ("firmware:container:locations", json.dumps(parents, ensure_ascii=False)),
            ("firmware:version:scope", "parent-package-not-upstream-library"),
        ):
            if not any(
                isinstance(item, dict) and item.get("name") == name
                for item in properties
            ):
                properties.append({"name": name, "value": value})
        package_applied.append({
            "name": component.get("name"),
            "version": version,
            "parent_type": parent_kind,
            "parents": parents,
        })
    return analysis, {
        "candidate_observations": len(candidates),
        "applied": len(applied),
        "parent_package_versions_applied": len(package_applied),
        "skipped": len(skipped),
        "applied_rows": applied,
        "parent_package_rows": package_applied,
        "skipped_rows": skipped,
        "attribution": (
            "Build revisions identify the image's pinned AOSP source project. "
            "They are not upstream library release versions."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analysis", type=Path)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--output-analysis", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    analysis = json.loads(args.analysis.read_text())
    candidates = json.loads(args.candidates.read_text())
    source_manifest = json.loads(args.source_manifest.read_text())
    updated, report = apply_revisions(analysis, candidates, source_manifest)
    args.output_analysis.write_text(json.dumps(updated, ensure_ascii=False, indent=2) + "\n")
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if not key.endswith("_rows")}, indent=2))


if __name__ == "__main__":
    main()
