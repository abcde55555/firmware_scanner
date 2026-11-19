"""Android source and parent-package provenance for otherwise unversioned ELFs."""

from __future__ import annotations

import gzip
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict

from ..extraction.models import Component, ExtractionMethod, VersionConfidence

_APEX_PATH_RE = re.compile(r"(/[^!\s]+\.(?:apex|capex))!")
_APK_PATH_RE = re.compile(r"(/[^!\s]+\.apk)!")
_NATIVE_MARKER = "native library"


def _normalise_notice_path(value: str) -> str:
    path = value.strip()
    if path.startswith("//"):
        path = path[1:]
    return path if path.startswith("/") else "/" + path


def parse_notice_attributions(data: bytes) -> dict[str, set[str]]:
    """Return trusted build file-to-project labels from Android NOTICE XML."""
    if data.startswith(b"\x1f\x8b"):
        data = gzip.decompress(data)
    root = ET.fromstring(data)
    result: dict[str, set[str]] = {}
    for item in root.findall(".//file-name"):
        label = (item.get("lib") or "").strip()
        file_name = (item.text or "").strip()
        if not label or label.casefold() == "android" or not file_name:
            continue
        result.setdefault(_normalise_notice_path(file_name), set()).add(label)
    return result


def _locations(component: Component) -> list[str]:
    result = {
        str(prop["value"])
        for prop in component.properties
        if prop.get("name") == "firmware:evidence:location" and prop.get("value")
    }
    return sorted(result)


def _binary_sha256(component: Component) -> str:
    return next(
        (
            str(prop.get("value", "")).lower()
            for prop in component.properties
            if prop.get("name") == "firmware:binary:sha256"
        ),
        "",
    )


def _version_kind(component: Component) -> str:
    return next(
        (
            str(prop.get("value", ""))
            for prop in component.properties
            if prop.get("name") == "firmware:version:kind"
        ),
        "",
    )


def _manifest_by_path(source_manifest: dict | None) -> dict[str, dict]:
    grouped: dict[str, list[dict]] = {}
    for project in (source_manifest or {}).get("projects", []):
        path, revision = project.get("path"), project.get("revision")
        if path and revision:
            grouped.setdefault(str(path), []).append(project)
    result = {}
    for path, projects in grouped.items():
        revisions = {str(project["revision"]) for project in projects}
        if len(revisions) == 1:
            result[path] = projects[0]
    return result


def source_manifest_matches_image(source_manifest: dict | None, image_sha256: str | None) -> bool:
    """Require an explicit manifest to identify exactly the scanned image."""
    if not source_manifest or not image_sha256:
        return False
    declared = str(source_manifest.get("image_sha256", "")).strip()
    return bool(declared) and declared.casefold() == image_sha256.casefold()


def _append_unique(properties: list[dict], name: str, value: str) -> None:
    item = {"name": name, "value": value}
    if item not in properties:
        properties.append(item)


def _apply_source_revision(
    component: Component,
    labels: set[str],
    manifest: dict[str, dict],
    source_project_rules: list[dict],
) -> dict | None:
    candidates = [manifest[label] for label in sorted(labels) if label in manifest]
    rule_evidence = ""
    confidence = 0.68
    if not candidates:
        for rule in source_project_rules:
            try:
                matched = re.search(str(rule.get("pattern", "")), component.name)
            except re.error:
                continue
            if not matched:
                continue
            project = manifest.get(str(rule.get("project_path", "")))
            if project is None:
                continue
            candidates = [project]
            confidence = min(0.9, max(0.0, float(rule.get("confidence", 0.68))))
            rule_evidence = str(rule.get("evidence", "SONAME source-project rule"))
            break
    revisions = {str(project["revision"]) for project in candidates}
    if len(revisions) != 1:
        return None
    project = candidates[0]
    revision = str(project["revision"])
    version = f"git:{revision}"
    component.resolved_version = version
    component.versions = [version for version in component.versions if version.version]
    component.versions.append(
        VersionConfidence(
            version=version,
            confidence=confidence,
            method=ExtractionMethod.VERSION_ESTIMATE,
            evidence=(
                f"{rule_evidence or 'NOTICE maps ' + component.name + ' to ' + str(project['path'])}; "
                f"the image source manifest pins {project.get('name', project['path'])} "
                f"at {revision}"
            ),
        )
    )
    _append_unique(component.properties, "firmware:version:kind", "estimated-source-revision")
    _append_unique(component.properties, "firmware:source:project", str(project["path"]))
    _append_unique(component.properties, "firmware:source:repository", str(project.get("name", "")))
    _append_unique(component.properties, "firmware:source:revision", revision)
    _append_unique(component.properties, "firmware:version:scope", "source-project-build-revision")
    return {
        "name": component.name,
        "locations": _locations(component),
        "version": version,
        "project_path": project["path"],
        "revision": revision,
    }


def _parent_version(component: Component, package_versions: dict[str, str]) -> dict | None:
    locations = _locations(component)
    for regex, parent_type in ((_APEX_PATH_RE, "apex"), (_APK_PATH_RE, "apk")):
        parents = sorted(
            {match.group(1) for location in locations if (match := regex.search(location))}
        )
        if not parents:
            continue
        versions = {package_versions[parent] for parent in parents if parent in package_versions}
        if len(versions) != 1 or any(parent not in package_versions for parent in parents):
            return None
        version = versions.pop()
        component.resolved_version = version
        component.versions = [item for item in component.versions if item.version]
        component.versions.append(
            VersionConfidence(
                version=version,
                confidence=0.72,
                method=ExtractionMethod.VERSION_ESTIMATE,
                evidence=(
                    f"Containing {parent_type.upper()} package version for native library "
                    f"{component.name}; this is parent-package provenance"
                ),
            )
        )
        _append_unique(
            component.properties,
            "firmware:version:kind",
            f"estimated-{parent_type}-package-version",
        )
        _append_unique(component.properties, "firmware:container:type", parent_type)
        _append_unique(
            component.properties,
            "firmware:container:locations",
            json.dumps(parents, ensure_ascii=False, sort_keys=True),
        )
        _append_unique(
            component.properties,
            "firmware:version:scope",
            "parent-package-not-upstream-library",
        )
        return {
            "name": component.name,
            "version": version,
            "parent_type": parent_type,
            "parents": parents,
        }
    return None


def apply_android_provenance(
    components: list[Component],
    *,
    notice_attributions: dict[str, set[str]] | None = None,
    source_manifest: dict | None = None,
    source_project_rules: list[dict] | None = None,
) -> dict:
    """Add explicit AOSP source revisions first and parent package versions second."""
    notice_attributions = notice_attributions or {}
    source_project_rules = source_project_rules or []
    manifest = _manifest_by_path(source_manifest)
    package_versions = {}
    for component in components:
        if not component.resolved_version:
            continue
        for location in _locations(component):
            if location.endswith((".apex", ".capex", ".apk")):
                package_versions[location] = component.resolved_version

    source_rows = []
    parent_rows = []
    for component in components:
        if component.resolved_version or _NATIVE_MARKER not in component.description.lower():
            continue
        labels = {
            label
            for location in _locations(component)
            for label in notice_attributions.get(location, ())
        }
        row = _apply_source_revision(component, labels, manifest, source_project_rules)
        if row is not None:
            source_rows.append(row)
            continue
        row = _parent_version(component, package_versions)
        if row is not None:
            parent_rows.append(row)

    by_hash: dict[str, list[Component]] = defaultdict(list)
    for component in components:
        digest = _binary_sha256(component)
        if digest and _NATIVE_MARKER in component.description.lower():
            by_hash[digest].append(component)
    propagated_rows = []
    inherited_properties = {
        "firmware:source:project",
        "firmware:source:repository",
        "firmware:source:revision",
        "firmware:container:type",
        "firmware:container:locations",
        "firmware:version:scope",
    }
    for digest, equal_binaries in by_hash.items():
        donors = [
            component
            for component in equal_binaries
            if component.resolved_version and _version_kind(component).startswith("estimated-")
        ]
        versions = {component.resolved_version for component in donors}
        if len(versions) != 1:
            continue
        donor = donors[0]
        version = donor.resolved_version
        for component in equal_binaries:
            if component.resolved_version:
                continue
            component.resolved_version = version
            component.versions.append(
                VersionConfidence(
                    version=version,
                    confidence=0.72,
                    method=ExtractionMethod.VERSION_ESTIMATE,
                    evidence=(
                        f"Byte-identical ELF sha256={digest} inherits provenance from "
                        f"{'; '.join(_locations(donor))}"
                    ),
                )
            )
            for prop in donor.properties:
                if prop.get("name") in inherited_properties:
                    _append_unique(component.properties, prop["name"], str(prop["value"]))
            _append_unique(
                component.properties,
                "firmware:evidence:inherited-from-container-sha256",
                digest,
            )
            propagated_rows.append(
                {
                    "name": component.name,
                    "locations": _locations(component),
                    "version": version,
                    "sha256": digest,
                    "donor_locations": _locations(donor),
                }
            )
    return {
        "source_revisions_applied": len(source_rows),
        "parent_package_versions_applied": len(parent_rows),
        "byte_identical_provenance_propagated": len(propagated_rows),
        "source_rows": source_rows,
        "parent_package_rows": parent_rows,
        "propagated_rows": propagated_rows,
        "scope": (
            "AOSP build revisions and parent package versions are provenance estimates, "
            "not upstream library releases"
        ),
    }
