"""Android source and parent-package provenance for otherwise unversioned ELFs."""

from __future__ import annotations

import gzip
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from urllib.parse import quote

from ..extraction.models import Component, ExtractionMethod, VersionConfidence

_APEX_PATH_RE = re.compile(r"(/[^!\s]+\.(?:apex|capex))!")
_APK_PATH_RE = re.compile(r"(/[^!\s]+\.apk)!")
_NATIVE_MARKER = "native library"
_EXECUTABLE_MARKER = "elf executable"


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


def _source_path_projects(component: Component) -> set[str]:
    return {
        str(prop.get("value", ""))
        for prop in component.properties
        if prop.get("name") == "firmware:source:path-project" and prop.get("value")
    }


def _source_path_evidence(component: Component) -> dict[str, dict]:
    evidence = {}
    for prop in component.properties:
        if prop.get("name") != "firmware:source:path-evidence":
            continue
        try:
            item = json.loads(str(prop.get("value", "")))
        except (TypeError, ValueError):
            continue
        if (
            isinstance(item, dict)
            and item.get("project")
            and item.get("source_path")
            and isinstance(item.get("file_offset"), int)
        ):
            evidence.setdefault(str(item["project"]), item)
    return evidence


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


def _set_property(component: Component, name: str, value: str) -> None:
    component.properties = [prop for prop in component.properties if prop.get("name") != name]
    component.properties.append({"name": name, "value": value})


def classify_source_project(project_path: str) -> str:
    """Classify explicitly attributed AOSP/vendor source paths conservatively."""
    path = project_path.strip().strip("/").casefold()
    if path.startswith("vendor/"):
        if "/opensource/" in f"/{path}/" or "/open-source/" in f"/{path}/":
            return "vendor-open-source"
        return "vendor-proprietary"
    if path.startswith("external/"):
        return "third-party-oss"
    if path.startswith(
        (
            "frameworks/",
            "system/",
            "hardware/",
            "packages/modules/",
            "art/",
            "bionic/",
            "build/",
            "libnativehelper/",
        )
    ):
        return "platform-first-party"
    return "unknown"


def apply_component_taxonomy(components: list[Component]) -> None:
    """Add taxonomy only where a source project or ecosystem PURL is explicit."""
    external_schemes = {
        "cargo",
        "cocoapods",
        "composer",
        "conan",
        "gem",
        "golang",
        "github",
        "gitlab",
        "maven",
        "npm",
        "nuget",
        "pypi",
        "swift",
    }
    for component in components:
        if any(prop.get("name") == "firmware:taxonomy" for prop in component.properties):
            continue
        if any(
            prop.get("name") == "firmware:blintdb:identity-confirmed" and prop.get("value")
            for prop in component.properties
        ):
            _append_unique(component.properties, "firmware:taxonomy", "third-party-oss")
            _append_unique(
                component.properties,
                "firmware:taxonomy:evidence",
                "blintdb-confirmed-identity",
            )
            continue
        purl = component.purl.casefold()
        if any(purl.startswith(f"pkg:{scheme}/") for scheme in external_schemes):
            _append_unique(component.properties, "firmware:taxonomy", "third-party-oss")
            _append_unique(
                component.properties,
                "firmware:taxonomy:evidence",
                "external-ecosystem-purl",
            )


@lru_cache(maxsize=1)
def load_source_version_pins() -> tuple[dict, ...]:
    pins: list[dict] = []
    keys = set()
    for file_name in (
        "source-version-pins.json",
        "source-subproject-version-pins.json",
    ):
        path = files("firmware_scanner.data").joinpath("provenance", file_name)
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1:
            raise ValueError("Unsupported source version pin schema")
        for item in payload.get("pins", []):
            project_path = str(item.get("project_path", "")).strip()
            revision = str(item.get("revision", "")).strip()
            version = str(item.get("version", "")).strip()
            source_url = str(item.get("source_url", "")).strip()
            authority = str(item.get("authority", "")).strip()
            subpath_prefix = str(item.get("subpath_prefix", "")).strip().strip("/")
            ecosystem = str(item.get("ecosystem", "")).strip()
            package_name = str(item.get("package_name", "")).strip()
            aliases = item.get("component_aliases", [])
            if not project_path or len(revision) != 40 or not version:
                raise ValueError("Invalid source version pin")
            if not source_url.startswith("https://") or not authority:
                raise ValueError("Source version pins require HTTPS provenance")
            if subpath_prefix and (
                subpath_prefix.startswith("/") or ".." in subpath_prefix.split("/")
            ):
                raise ValueError("Invalid source version pin subpath")
            if ecosystem and ecosystem != "cargo":
                raise ValueError(f"Unsupported source version ecosystem: {ecosystem}")
            if ecosystem == "cargo" and not package_name:
                raise ValueError("Cargo source pins require a package name")
            if not isinstance(aliases, list) or not all(
                isinstance(alias, str) and alias.strip() for alias in aliases
            ):
                raise ValueError("Invalid source version component aliases")
            key = (project_path, revision, subpath_prefix)
            if key in keys:
                raise ValueError(
                    f"Duplicate source version pin: {project_path}@{revision}/{subpath_prefix}"
                )
            keys.add(key)
            pins.append(
                {
                    "project_path": project_path,
                    "revision": revision,
                    "version": version,
                    "source_url": source_url,
                    "authority": authority,
                    "subpath_prefix": subpath_prefix,
                    "ecosystem": ecosystem,
                    "package_name": package_name,
                    "component_aliases": [alias.strip() for alias in aliases],
                }
            )
    return tuple(pins)


def _source_component_key(value: str, *, strip_lib_prefix: bool) -> str:
    name = Path(value).name.casefold()
    changed = True
    while changed:
        changed = False
        for suffix in (".dylib", ".so", ".dll"):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
                changed = True
    if strip_lib_prefix:
        name = name.removeprefix("lib")
    return "".join(character for character in name if character.isalnum())


def _source_version_pin(
    project: dict,
    component_name: str,
    source_paths: set[str],
) -> dict | None:
    project_path = str(project.get("path", ""))
    revision = str(project.get("revision", ""))
    candidates = [
        pin
        for pin in load_source_version_pins()
        if pin["project_path"] == project_path and pin["revision"] == revision
    ]
    subprojects = [pin for pin in candidates if pin["subpath_prefix"]]
    if subprojects:
        component_key = _source_component_key(
            component_name,
            strip_lib_prefix=True,
        )
        name_matches = [
            pin
            for pin in subprojects
            if any(
                _source_component_key(value, strip_lib_prefix=False) == component_key
                for value in (
                    Path(pin["subpath_prefix"]).name,
                    pin["package_name"],
                    *pin["component_aliases"],
                )
            )
        ]
        if len(name_matches) == 1:
            return name_matches[0]
        path_matches = sorted(
            (
                pin
                for pin in subprojects
                if any(
                    path.startswith(f"{project_path}/{pin['subpath_prefix']}/")
                    for path in source_paths
                )
            ),
            key=lambda pin: len(pin["subpath_prefix"]),
            reverse=True,
        )
        if path_matches:
            return path_matches[0]
    top_level = [pin for pin in candidates if not pin["subpath_prefix"]]
    return top_level[0] if len(top_level) == 1 else None


def _apply_source_revision(
    component: Component,
    labels: set[str],
    manifest: dict[str, dict],
    source_project_rules: list[dict],
) -> dict | None:
    candidates = [manifest[label] for label in sorted(labels) if label in manifest]
    rule_evidence = ""
    confidence = 0.68
    source_path_projects = _source_path_projects(component)
    source_path_evidence = _source_path_evidence(component)
    if not candidates and source_path_projects:
        for rule in source_project_rules:
            project_path = str(rule.get("project_path", ""))
            if project_path not in source_path_projects:
                continue
            try:
                matched = re.search(str(rule.get("pattern", "")), component.name)
            except re.error:
                continue
            if not matched:
                continue
            project = manifest.get(project_path)
            if project is None:
                continue
            candidates = [project]
            confidence = min(0.94, max(0.78, float(rule.get("confidence", 0.78))))
            marker = source_path_evidence.get(project_path, {})
            rule_evidence = str(rule.get("evidence", "SONAME source-project rule")) + (
                f"; binary embeds {marker.get('source_path')!r} at file offset "
                f"0x{int(marker.get('file_offset', 0)):x}"
                if marker
                else f"; binary embeds a source path under {project_path}"
            )
            break
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
    pin = _source_version_pin(
        project,
        component.name,
        {str(item.get("source_path", "")) for item in source_path_evidence.values()},
    )
    version = pin["version"] if pin else f"git:{revision}"
    component.resolved_version = version
    component.versions = [version for version in component.versions if version.version]
    component.versions.append(
        VersionConfidence(
            version=version,
            confidence=max(confidence, 0.97) if pin else confidence,
            method=ExtractionMethod.BUILD_METADATA if pin else ExtractionMethod.VERSION_ESTIMATE,
            evidence=(
                (
                    f"{rule_evidence or 'NOTICE maps ' + component.name + ' to ' + str(project['path'])}; "
                    f"the pinned source revision declares release {version} via "
                    f"{pin['authority']} at {pin['source_url']}"
                )
                if pin
                else (
                    f"{rule_evidence or 'NOTICE maps ' + component.name + ' to ' + str(project['path'])}; "
                    f"the image source manifest pins {project.get('name', project['path'])} "
                    f"at {revision}"
                )
            ),
        )
    )
    _append_unique(
        component.properties,
        "firmware:version:kind",
        "source-declared-release" if pin else "estimated-source-revision",
    )
    _append_unique(component.properties, "firmware:source:project", str(project["path"]))
    _append_unique(component.properties, "firmware:source:repository", str(project.get("name", "")))
    _append_unique(component.properties, "firmware:source:revision", revision)
    if pin and pin["subpath_prefix"]:
        _append_unique(
            component.properties,
            "firmware:source:subproject",
            pin["subpath_prefix"],
        )
    if pin and pin["ecosystem"] == "cargo":
        component.purl = (
            f"pkg:cargo/{quote(pin['package_name'], safe='._-')}"
            f"@{quote(pin['version'], safe='._-+')}"
        )
        _append_unique(
            component.properties,
            "firmware:upstream:component",
            pin["package_name"],
        )
        _append_unique(
            component.properties,
            "firmware:upstream:purl",
            component.purl,
        )
    taxonomy = classify_source_project(str(project["path"]))
    if taxonomy != "unknown":
        _append_unique(component.properties, "firmware:taxonomy", taxonomy)
        _append_unique(
            component.properties,
            "firmware:taxonomy:evidence",
            "source-project-path",
        )
    if pin:
        _append_unique(component.properties, "firmware:source:version-authority", pin["authority"])
        _append_unique(component.properties, "firmware:source:version-evidence", pin["source_url"])
    _append_unique(
        component.properties,
        "firmware:version:scope",
        (
            "source-subproject-declared-release"
            if pin and pin["subpath_prefix"]
            else "source-project-declared-release"
            if pin
            else "source-project-build-revision"
        ),
    )
    _set_property(
        component,
        "firmware:version:resolution-state",
        "exact" if pin else "estimated-source-revision",
    )
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
                    f"Containing {parent_type.upper()} package version for binary "
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
            (
                "parent-package-not-upstream-library"
                if _NATIVE_MARKER in component.description.lower()
                else "parent-package-not-upstream-component"
            ),
        )
        _set_property(component, "firmware:version:resolution-state", "estimated-parent-package")
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
        description = component.description.lower()
        is_library = _NATIVE_MARKER in description
        is_executable = _EXECUTABLE_MARKER in description
        if component.resolved_version or not (is_library or is_executable):
            continue
        labels = {
            label
            for location in _locations(component)
            for label in notice_attributions.get(location, ())
        }
        if is_library:
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
        description = component.description.lower()
        if digest and (_NATIVE_MARKER in description or _EXECUTABLE_MARKER in description):
            by_hash[digest].append(component)
    propagated_rows = []
    inherited_properties = {
        "firmware:source:project",
        "firmware:source:repository",
        "firmware:source:revision",
        "firmware:container:type",
        "firmware:container:locations",
        "firmware:version:scope",
        "firmware:version:resolution-state",
        "firmware:taxonomy",
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
                    _set_property(component, prop["name"], str(prop["value"]))
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
    apply_component_taxonomy(components)
    return {
        "source_revisions_applied": len(source_rows),
        "source_versions_applied": sum(
            row["version"].startswith("git:") is False for row in source_rows
        ),
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
