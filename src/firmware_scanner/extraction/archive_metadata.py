"""Extract dependency releases explicitly recorded in archive metadata."""

import re
import zipfile
import zlib
import xml.etree.ElementTree as ET

from ..android.notice_licenses import detect_license_text
from .models import Component, ExtractionMethod, VersionConfidence

_MAX_ENTRIES = 200_000
_MAX_METADATA_ENTRIES = 2048
_MAX_TOTAL_METADATA_BYTES = 8 * 1024 * 1024
_MAX_METADATA_BYTES = 64 * 1024
_MAX_COORDINATE_LENGTH = 256
_MAX_VERSION_LENGTH = 128

_MAVEN_METADATA_PATH = re.compile(
    r"^META-INF/maven/(?P<group>[A-Za-z0-9_.-]+)/(?P<artifact>[A-Za-z0-9_.-]+)/pom\.properties$"
)
_MAVEN_POM_XML_PATH = re.compile(
    r"^META-INF/maven/(?P<group>[A-Za-z0-9_.-]+)/(?P<artifact>[A-Za-z0-9_.-]+)/pom\.xml$"
)
_ANDROIDX_VERSION_PATH = re.compile(
    r"^META-INF/(?P<coordinate>androidx\.[A-Za-z0-9.-]+_[A-Za-z0-9.-]+)\.version$"
)
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]*$")


def _valid_coordinate(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= _MAX_COORDINATE_LENGTH
        and all(char.isalnum() or char in "._-" for char in value)
        and not value.startswith((".", "-", "_"))
        and not value.endswith((".", "-", "_"))
    )


def _valid_version(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= _MAX_VERSION_LENGTH
        and _VERSION.fullmatch(value) is not None
        and value.casefold() not in {"unknown", "unspecified", "none", "null", "detected", "latest"}
        and not value.startswith("${")
    )


def _read_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes | None:
    """Read a small metadata member without trusting its declared or inflated size."""
    if info.file_size > _MAX_METADATA_BYTES:
        return None
    try:
        with archive.open(info) as member:
            content = member.read(_MAX_METADATA_BYTES + 1)
        if len(content) > _MAX_METADATA_BYTES:
            return None
        return content
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, zlib.error, EOFError):
        return None


def _parse_maven_properties(content: bytes) -> dict[str, str] | None:
    try:
        text = content.decode("ISO-8859-1")
    except UnicodeDecodeError:
        return None

    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        if "=" not in line:
            return None
        key, value = line.split("=", 1)
        key = key.strip()
        if key in {"groupId", "artifactId", "version"}:
            if key in values:
                return None
            values[key] = value.strip()
    return values


def _xml_text(element: ET.Element, name: str) -> str:
    for child in element:
        if child.tag.rsplit("}", 1)[-1] == name:
            return (child.text or "").strip()
    return ""


def _parse_maven_pom_xml(content: bytes) -> tuple[str, str, str, list[str]] | None:
    try:
        root = ET.fromstring(content)
    except (ET.ParseError, ValueError):
        return None
    group = _xml_text(root, "groupId")
    artifact = _xml_text(root, "artifactId")
    version = _xml_text(root, "version")
    if not group or not artifact or not version:
        return None
    license_parts: list[str] = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "license":
            continue
        license_parts.extend(
            value for name in ("name", "url") if (value := _xml_text(element, name))
        )
    licenses = sorted(detect_license_text(" ".join(license_parts)))
    return group, artifact, version, licenses


def _component(
    name: str,
    group: str,
    artifact: str,
    version: str,
    location: str,
    entry_name: str,
    metadata_kind: str,
) -> Component:
    evidence = f"{location}!/{entry_name} ({metadata_kind})"
    return Component(
        name=name,
        component_type="library",
        resolved_version=version,
        purl=f"pkg:maven/{group}/{artifact}@{version}",
        description=f"Dependency version recorded in {location}",
        properties=[
            {"name": "firmware:metadata_kind", "value": metadata_kind},
            {"name": "firmware:evidence:location", "value": f"{location}!/{entry_name}"},
            {"name": "firmware:evidence:container", "value": location},
        ],
        versions=[
            VersionConfidence(
                version=version,
                confidence=0.98,
                method=ExtractionMethod.MANIFEST_BINARY,
                evidence=evidence,
            )
        ],
    )


def extract_archive_metadata(
    archive: zipfile.ZipFile, location: str, warnings: list[str] | None = None
) -> list[Component]:
    """Extract Maven and AndroidX dependency versions from a ZIP/APK/JAR archive.

    Only complete, explicit metadata is accepted. Oversized, malformed, ambiguous,
    records are ignored. Conflicts retain identity and claims but no resolved
    version. Budgets count metadata reads separately from ordinary resource names.
    """
    records: dict[str, list[Component]] = {}
    try:
        infos = archive.infolist()
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile):
        return []

    def warn(message):
        if warnings is not None:
            warnings.append(f"{message}: {location}")

    if len(infos) > _MAX_ENTRIES:
        warn("Archive member-name scan budget reached")
    metadata_count = metadata_bytes = 0
    for info in infos[:_MAX_ENTRIES]:
        name = info.filename
        maven_match = _MAVEN_METADATA_PATH.fullmatch(name)
        pom_xml_match = _MAVEN_POM_XML_PATH.fullmatch(name)
        androidx_match = _ANDROIDX_VERSION_PATH.fullmatch(name)
        if not maven_match and not pom_xml_match and not androidx_match:
            continue
        if metadata_count >= _MAX_METADATA_ENTRIES:
            warn("Archive dependency metadata scan budget reached")
            break
        metadata_count += 1
        if info.file_size > _MAX_METADATA_BYTES:
            warn(f"Dependency metadata exceeds entry size limit {name}")
            continue
        if metadata_bytes + info.file_size > _MAX_TOTAL_METADATA_BYTES:
            warn("Archive dependency metadata scan budget reached")
            break
        content = _read_entry(archive, info)
        if content is None:
            warn(f"Cannot read bounded dependency metadata {name}")
            continue
        metadata_bytes += len(content)

        licenses: list[str] = []
        if maven_match:
            path_group = maven_match.group("group")
            path_artifact = maven_match.group("artifact")
            props = _parse_maven_properties(content)
            if not props:
                continue
            group = props.get("groupId", "")
            artifact = props.get("artifactId", "")
            version = props.get("version", "")
            if (
                group != path_group
                or artifact != path_artifact
                or not _valid_coordinate(group)
                or not _valid_coordinate(artifact)
                or not _valid_version(version)
            ):
                continue
            metadata_kind = "maven-pom-properties"
        elif pom_xml_match:
            path_group = pom_xml_match.group("group")
            path_artifact = pom_xml_match.group("artifact")
            parsed = _parse_maven_pom_xml(content)
            if not parsed:
                continue
            group, artifact, version, licenses = parsed
            if (
                group != path_group
                or artifact != path_artifact
                or not _valid_coordinate(group)
                or not _valid_coordinate(artifact)
                or not _valid_version(version)
            ):
                continue
            metadata_kind = "maven-pom-xml"
        else:
            # AndroidX filenames use androidx.<group>_<artifact>.version.
            coordinate = androidx_match.group("coordinate")[len("androidx.") :]
            group_tail, artifact = coordinate.rsplit("_", 1)
            group = f"androidx.{group_tail}"
            try:
                version = content.decode("ascii").strip()
            except UnicodeDecodeError:
                continue
            if (
                not group_tail
                or "_" in artifact
                or not _valid_coordinate(group)
                or not _valid_coordinate(artifact)
                or not _valid_version(version)
            ):
                continue
            metadata_kind = "androidx-version-file"

        key = f"{group}:{artifact}"
        component = _component(
            name=key,
            group=group,
            artifact=artifact,
            version=version,
            location=location,
            entry_name=name,
            metadata_kind=metadata_kind,
        )
        if licenses:
            component.licenses = licenses
            component.properties.extend(
                [
                    {
                        "name": "firmware:license:evidence",
                        "value": f"{location}!/{name}",
                    },
                    {
                        "name": "firmware:license:match-confidence",
                        "value": "0.95",
                    },
                ]
            )
        records.setdefault(key, []).append(component)

    result: list[Component] = []
    for candidates in records.values():
        versions = {candidate.resolved_version for candidate in candidates}
        component = candidates[0]
        component.licenses = sorted(
            {license for candidate in candidates for license in candidate.licenses}
        )
        if len(versions) != 1:
            component.resolved_version = ""
            component.purl = component.purl.rsplit("@", 1)[0]
            component.versions = [item for candidate in candidates for item in candidate.versions]
            component.properties.append(
                {"name": "firmware:version:conflict", "value": ", ".join(sorted(versions))}
            )
            warn(f"Conflicting dependency versions for {component.name}")
        result.append(component)
    return result
