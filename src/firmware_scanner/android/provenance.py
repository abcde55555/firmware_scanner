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

from ..extraction.binary_inventory import identity_key
from ..extraction.models import Component, ExtractionMethod, VersionConfidence

_APEX_PATH_RE = re.compile(r"(/[^!\s]+\.(?:apex|capex))!")
_APK_PATH_RE = re.compile(r"(/[^!\s]+\.apk)!")
_FRAMEWORK_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:/system)?/framework(?:/|$)",
    re.IGNORECASE,
)
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
        source_evidence = {
            str(prop.get("value", "")).strip()
            for prop in component.properties
            if prop.get("name") == "firmware:evidence:source"
            and str(prop.get("value", "")).startswith("https://")
        }
        if source_evidence and not source_evidence.issubset(
            {"https://github.com/e-m-b-a/emba"}
        ):
            _append_unique(component.properties, "firmware:taxonomy", "third-party-oss")
            _append_unique(
                component.properties,
                "firmware:taxonomy:evidence",
                "upstream-source-evidence",
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
    existing_version = component.resolved_version
    existing_state = next(
        (
            str(prop.get("value", ""))
            for prop in component.properties
            if prop.get("name") == "firmware:version:resolution-state"
        ),
        "",
    )
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
    if existing_version:
        if (
            existing_state != "exact"
            or pin is None
            or not _pinned_version_extends(existing_version, str(pin["version"]))
        ):
            return None
    elif pin is None:
        version = f"git:{revision}"
    component.resolved_version = version
    if not existing_version:
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


def _pinned_version_extends(base: str, pinned: str) -> bool:
    """Allow a source pin to complete a proven base release, never replace it."""
    if pinned == base or not pinned.startswith(base):
        return False
    suffix = pinned[len(base) :]
    return bool(
        re.fullmatch(r"\d+(?:\.\d+)+", base)
        and suffix
        and suffix[0] in {".", "+", "-", "p"}
    )


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


def _platform_build_version(component: Component, baseline: str) -> dict | None:
    locations = _locations(component)
    framework_paths = [*locations, component.description]
    if (
        component.component_type != "framework"
        or not component.name.startswith("framework/")
        or not any(_FRAMEWORK_PATH_RE.search(path) for path in framework_paths)
    ):
        return None
    component.resolved_version = baseline
    component.purl = (
        f"{component.purl.split('@', 1)[0]}@{quote(baseline, safe='._-+')}"
        if component.purl
        else component.purl
    )
    component.versions = [item for item in component.versions if item.version]
    component.versions.append(
        VersionConfidence(
            version=baseline,
            confidence=0.74,
            method=ExtractionMethod.VERSION_ESTIMATE,
            evidence=(
                f"Android framework component {component.name} shares the "
                f"enclosing platform build baseline"
            ),
        )
    )
    _append_unique(
        component.properties,
        "firmware:version:kind",
        "estimated-android-platform-build",
    )
    _append_unique(component.properties, "firmware:container:type", "android-platform")
    _append_unique(
        component.properties,
        "firmware:version:scope",
        "platform-build-not-upstream-release",
    )
    _append_unique(component.properties, "firmware:taxonomy", "platform-first-party")
    _append_unique(
        component.properties,
        "firmware:taxonomy:evidence",
        "android-framework-archive",
    )
    _set_property(component, "firmware:version:resolution-state", "estimated-platform-build")
    return {
        "name": component.name,
        "version": baseline,
        "baseline_type": "android-platform-build",
    }


@lru_cache(maxsize=1)
def _android_release_estimate_projects() -> list[dict]:
    path = files("firmware_scanner.data").joinpath(
        "provenance",
        "android-release-project-estimates.json",
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported Android release-project estimate schema")
    return list(payload.get("releases", []))


def _component_identities(component: Component) -> set[str]:
    return {
        str(prop.get("value", "")).casefold()
        for prop in component.properties
        if prop.get("name") == "firmware:identity" and prop.get("value")
    }


def _embedded_source_prefixes(component: Component) -> dict[str, dict]:
    evidence: dict[str, dict] = {}
    for prop in component.properties:
        if prop.get("name") != "firmware:source:path-prefix-evidence":
            continue
        try:
            item = json.loads(str(prop.get("value", "")))
        except (TypeError, ValueError):
            continue
        if not (
            isinstance(item, dict)
            and isinstance(item.get("project_path"), str)
            and isinstance(item.get("source_path"), str)
            and isinstance(item.get("file_offset"), int)
        ):
            continue
        evidence.setdefault(item["project_path"], item)
    return evidence


def _contained_release_component(
    component: Component,
    *,
    rule: dict,
    evidence: dict,
) -> Component:
    version = str(rule["version"])
    name = str(rule["component_name"])
    source_path = str(evidence["source_path"])
    source_offset = int(evidence["file_offset"])
    location = next(iter(_locations(component)), component.name)
    contained = Component(
        name=name,
        vendor=str(rule.get("vendor", "")),
        resolved_version=version,
        component_type="library",
        purl=(
            f"pkg:generic/{quote(name, safe='._-')}"
            f"@{quote(version, safe='._-+')}"
        ),
        description=(
            f"Embedded component inferred from source-path evidence in {component.name}"
        ),
        versions=[
            VersionConfidence(
                version=version,
                confidence=0.8,
                method=ExtractionMethod.VERSION_ESTIMATE,
                evidence=(
                    f"{component.name} embeds {source_path!r} at file offset "
                    f"0x{source_offset:x}; AOSP tag {rule['aosp_tag']} declares "
                    f"{version} in {rule.get('version_authority', 'its source tree')} "
                    f"at {rule.get('source_url', '')}. This is source provenance, "
                    "not a version string emitted by the target binary."
                ),
            )
        ],
        properties=[
            {"name": "firmware:evidence:location", "value": location},
            {"name": "firmware:evidence:container", "value": component.name},
            {"name": "firmware:relationship", "value": "contains-evidence-for"},
            {"name": "firmware:version:kind", "value": "estimated-android-source-release"},
            {
                "name": "firmware:version:resolution-state",
                "value": "estimated-aosp-release",
            },
            {
                "name": "firmware:version:scope",
                "value": "aosp-source-path-derived-not-binary-self-version",
            },
            {"name": "firmware:source:project", "value": str(rule["project_path"])},
            {"name": "firmware:source:aosp-tag", "value": str(rule["aosp_tag"])},
            {
                "name": "firmware:source:embedded-path",
                "value": source_path,
            },
            {
                "name": "firmware:source:embedded-path-offset",
                "value": f"0x{source_offset:x}",
            },
            {
                "name": "firmware:source:version-authority",
                "value": str(rule.get("version_authority", "")),
            },
            {
                "name": "firmware:source:version-evidence",
                "value": str(rule.get("source_url", "")),
            },
        ],
    )
    taxonomy = classify_source_project(str(rule["project_path"]))
    if taxonomy != "unknown":
        contained.properties.extend(
            [
                {"name": "firmware:taxonomy", "value": taxonomy},
                {"name": "firmware:taxonomy:evidence", "value": "source-project-path"},
            ]
        )
    return contained


def _android_release_project_versions(
    components: list[Component],
    *,
    android_version: str,
    android_build_id: str,
) -> list[dict]:
    if not android_version or not android_build_id:
        return []
    rules = []
    for release in _android_release_estimate_projects():
        if str(release.get("android_version", "")) != android_version:
            continue
        if android_build_id not in {str(value) for value in release.get("build_ids", [])}:
            continue
        rules.extend(
            {
                **project,
                "aosp_tag": str(release.get("aosp_tag", "")),
            }
            for project in release.get("projects", [])
        )
    contained_identities: dict[str, set[str]] = defaultdict(set)
    for component in components:
        identities = _component_identities(component)
        if identities and any(
            prop.get("name") == "firmware:relationship"
            and prop.get("value") == "contains-evidence-for"
            for prop in component.properties
        ):
            for location in _locations(component):
                contained_identities[location].update(identities)
    rows = []
    existing_components = {
        (
            identity_key(component.name),
            tuple(_locations(component)),
        )
        for component in components
    }
    contained_components: list[Component] = []
    for component in components:
        source_prefixes = _embedded_source_prefixes(component)
        identities = set(_component_identities(component))
        for location in _locations(component):
            identities.update(contained_identities.get(location, ()))
        filename = Path(component.name).name.casefold()
        for rule in rules:
            rule_identities = {str(identity).casefold() for identity in rule.get("identities", [])}
            filename_patterns = [
                str(value).casefold() for value in rule.get("filename_patterns", [])
            ]
            required_properties = {
                str(name): str(value) for name, value in rule.get("required_properties", {}).items()
            }
            component_properties = {
                str(prop.get("name", "")): str(prop.get("value", ""))
                for prop in component.properties
            }
            if any(
                component_properties.get(name) != value
                for name, value in required_properties.items()
            ):
                continue
            project_evidence = source_prefixes.get(str(rule["project_path"]))
            if project_evidence is not None and bool(rule.get("embedded_source_version")):
                pair = (
                    identity_key(str(rule["component_name"])),
                    tuple(_locations(component)),
                )
                if pair not in existing_components:
                    contained = _contained_release_component(
                        component,
                        rule=rule,
                        evidence=project_evidence,
                    )
                    contained_components.append(contained)
                    existing_components.add(pair)
                    rows.append(
                        {
                            "name": str(rule["component_name"]),
                            "version": str(rule["version"]),
                            "project_path": rule["project_path"],
                            "aosp_tag": rule["aosp_tag"],
                            "source_url": rule.get("source_url", ""),
                            "source_path": project_evidence["source_path"],
                            "container": component.name,
                        }
                    )
                continue
            if component.resolved_version or any(
                prop.get("name") == "firmware:version:conflict"
                for prop in component.properties
            ):
                continue
            if (
                not identities.intersection(rule_identities)
                and not bool(rule.get("filename_only"))
            ):
                continue
            if filename_patterns:
                if rule.get("filename_match") == "exact":
                    if filename not in filename_patterns:
                        continue
                elif not any(pattern in filename for pattern in filename_patterns):
                    continue
            version = str(rule.get("version", ""))
            if not version:
                continue
            component.resolved_version = version
            component.purl = f"pkg:generic/{quote(rule['component_name'], safe='._-')}@{quote(version, safe='._-+')}"
            component.versions = [item for item in component.versions if item.version]
            component.versions.append(
                VersionConfidence(
                    version=version,
                    confidence=0.78,
                    method=ExtractionMethod.VERSION_ESTIMATE,
                    evidence=(
                        f"The binary has the confirmed {rule['component_name']} identity for "
                        f"Android {android_version} build {android_build_id}; the pinned AOSP "
                        f"tag {rule['aosp_tag']} declares {version}. This estimate is not a "
                        "binary-embedded version and may not reflect vendor patches."
                    ),
                )
            )
            _append_unique(
                component.properties,
                "firmware:version:kind",
                "estimated-android-source-release",
            )
            _set_property(
                component,
                "firmware:version:resolution-state",
                "estimated-aosp-release",
            )
            _set_property(
                component,
                "firmware:version:scope",
                "aosp-release-derived-not-binary-self-version",
            )
            _append_unique(
                component.properties,
                "firmware:source:project",
                str(rule["project_path"]),
            )
            _append_unique(
                component.properties,
                "firmware:source:aosp-tag",
                str(rule["aosp_tag"]),
            )
            _append_unique(
                component.properties,
                "firmware:source:version-authority",
                str(rule.get("version_authority", "")),
            )
            _append_unique(
                component.properties,
                "firmware:source:version-evidence",
                str(rule.get("source_url", "")),
            )
            taxonomy = classify_source_project(str(rule["project_path"]))
            if taxonomy != "unknown":
                _append_unique(component.properties, "firmware:taxonomy", taxonomy)
                _append_unique(
                    component.properties,
                    "firmware:taxonomy:evidence",
                    "source-project-path",
                )
            rows.append(
                {
                    "name": component.name,
                    "version": version,
                    "project_path": rule["project_path"],
                    "aosp_tag": rule["aosp_tag"],
                    "source_url": rule.get("source_url", ""),
                }
            )
            break
    components.extend(contained_components)
    return rows


def apply_android_provenance(
    components: list[Component],
    *,
    notice_attributions: dict[str, set[str]] | None = None,
    source_manifest: dict | None = None,
    source_project_rules: list[dict] | None = None,
    platform_baseline: str = "",
    android_version: str = "",
    android_build_id: str = "",
) -> dict:
    """Add scoped source, platform-build and parent-package provenance."""
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

    source_path_properties = {
        "firmware:source:path-prefix-evidence",
        "firmware:source:path-project",
        "firmware:source:path-evidence",
    }
    source_properties_by_location: dict[str, list[dict]] = defaultdict(list)
    for component in components:
        inherited = [
            prop
            for prop in component.properties
            if prop.get("name") in source_path_properties
        ]
        if not inherited:
            continue
        for location in _locations(component):
            source_properties_by_location[location].extend(inherited)
    for component in components:
        if not any(
            prop.get("name") == "firmware:relationship"
            and prop.get("value") == "contains-evidence-for"
            for prop in component.properties
        ):
            continue
        for location in _locations(component):
            for prop in source_properties_by_location.get(location, ()):
                if prop not in component.properties:
                    component.properties.append(dict(prop))

    source_rows = []
    parent_rows = []
    platform_rows = []
    for component in components:
        description = component.description.lower()
        is_library = _NATIVE_MARKER in description
        is_executable = _EXECUTABLE_MARKER in description
        labels = {
            label
            for location in _locations(component)
            for label in notice_attributions.get(location, ())
        }
        if component.resolved_version:
            if is_library:
                row = _apply_source_revision(component, labels, manifest, source_project_rules)
                if row is not None:
                    source_rows.append(row)
            continue
        if platform_baseline:
            row = _platform_build_version(component, platform_baseline)
            if row is not None:
                platform_rows.append(row)
                continue
        if not (is_library or is_executable):
            continue
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
    release_rows = _android_release_project_versions(
        components,
        android_version=android_version,
        android_build_id=android_build_id,
    )
    apply_component_taxonomy(components)
    return {
        "source_revisions_applied": len(source_rows),
        "source_versions_applied": sum(
            row["version"].startswith("git:") is False for row in source_rows
        ),
        "parent_package_versions_applied": len(parent_rows),
        "platform_build_versions_applied": len(platform_rows),
        "aosp_release_versions_applied": len(release_rows),
        "byte_identical_provenance_propagated": len(propagated_rows),
        "source_rows": source_rows,
        "parent_package_rows": parent_rows,
        "platform_build_rows": platform_rows,
        "aosp_release_rows": release_rows,
        "propagated_rows": propagated_rows,
        "scope": (
            "AOSP build revisions, platform builds and parent package versions are "
            "provenance estimates, not upstream library releases"
        ),
    }
