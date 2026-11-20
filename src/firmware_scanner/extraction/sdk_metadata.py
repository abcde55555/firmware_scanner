"""Extract explicit SDK releases recorded in root-level APK properties files."""

import re
import zipfile
import zlib

from .models import Component, ExtractionMethod, VersionConfidence

_MAX_ENTRIES = 200_000
_MAX_METADATA_ENTRIES = 2048
_MAX_TOTAL_METADATA_BYTES = 8 * 1024 * 1024
_MAX_METADATA_BYTES = 16 * 1024
_ARTIFACT = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}$")

# These artifact families have stable, public Maven group ownership.
_GROUP_PREFIXES = (
    ("firebase-", "com.google.firebase"),
    ("play-services-", "com.google.android.gms"),
    ("transport-", "com.google.android.datatransport"),
)
_EXACT_GROUPS = {
    "review": "com.google.android.play",
    "review-ktx": "com.google.android.play",
    "user-messaging-platform": "com.google.android.ump",
}
_PLACEHOLDER_VERSIONS = {
    "unknown", "unspecified", "latest", "latest.release", "latest.integration",
    "detected", "none", "null", "n/a", "na",
}


def _group_for(artifact: str) -> str | None:
    if artifact in _EXACT_GROUPS:
        return _EXACT_GROUPS[artifact]
    for prefix, group in _GROUP_PREFIXES:
        if artifact.startswith(prefix):
            return group
    return None


def _parse_properties(content: bytes, artifact: str) -> str | None:
    """Accept only the SDK-owned three-field identity/version record."""
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError:
        return None

    wanted = {"version", "client", f"{artifact}_client"}
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        if "=" not in line:
            return None
        key, value = (part.strip() for part in line.split("=", 1))
        if key in values:
            return None
        values[key] = value

    version = values.get("version", "")
    if (set(values) != wanted or values.get("client") != artifact
            or values.get(f"{artifact}_client") != version
            or not _VERSION.fullmatch(version)
            or version.lower() in _PLACEHOLDER_VERSIONS
            or version.lower().startswith("latest.")
            or version.endswith(".+")):
        return None
    return version


def _read_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes | None:
    if info.file_size > _MAX_METADATA_BYTES:
        return None
    try:
        with archive.open(info) as member:
            content = member.read(_MAX_METADATA_BYTES + 1)
        return content if len(content) <= _MAX_METADATA_BYTES else None
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, zlib.error, EOFError):
        return None


def _component(artifact: str, version: str, location: str,
               entry_name: str) -> Component:
    group = _group_for(artifact)
    assert group is not None
    identity = f"{group}:{artifact}"
    group_path = group.replace(".", "/")
    artifact_url = (
        f"https://dl.google.com/dl/android/maven2/{group_path}/{artifact}/"
        f"{version}/{artifact}-{version}.aar"
    )
    pom_url = (
        f"https://dl.google.com/dl/android/maven2/{group_path}/{artifact}/"
        f"{version}/{artifact}-{version}.pom"
    )
    evidence = (
        f"{location}!/{entry_name} (version={version}; "
        f"client={artifact}; {artifact}_client={version})"
    )
    return Component(
        name=identity,
        component_type="library",
        resolved_version=version,
        purl=f"pkg:maven/{group}/{artifact}@{version}",
        description=f"SDK release recorded in {location}",
        properties=[
            {"name": "firmware:metadata_kind", "value": "sdk-artifact-properties"},
            {"name": "firmware:evidence:location", "value": f"{location}!/{entry_name}"},
            {"name": "firmware:evidence:container", "value": location},
            {"name": "firmware:metadata_provenance", "value": (
                f"{artifact_url}; {pom_url}; "
                "https://developer.android.com/build/remote-repositories"
            )},
        ],
        versions=[VersionConfidence(
            version=version,
            confidence=0.98,
            method=ExtractionMethod.MANIFEST_BINARY,
            evidence=evidence,
        )],
    )


def extract_sdk_metadata(archive: zipfile.ZipFile, location: str,
                         warnings: list[str] | None = None) -> list[Component]:
    """Extract SDK releases from exact root-level ``<artifact>.properties`` entries.

    A record is accepted only when ``version``, ``client`` and
    ``<artifact>_client`` are present once and agree. Generic build metadata,
    compiler metadata, nested properties, and artifacts without known Maven
    group ownership are ignored. Conflicting releases retain claims without a
    resolved version.
    """
    try:
        infos = archive.infolist()
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile):
        return []

    def warn(message: str) -> None:
        if warnings is not None:
            warnings.append(f"{message}: {location}")

    if len(infos) > _MAX_ENTRIES:
        warn("SDK metadata archive member scan budget reached")
    records: dict[str, list[Component]] = {}
    metadata_count = metadata_bytes = 0
    for info in infos[:_MAX_ENTRIES]:
        # The root location and artifact-derived keys are part of the identity.
        if "/" in info.filename or not info.filename.endswith(".properties"):
            continue
        artifact = info.filename[:-len(".properties")]
        if not _ARTIFACT.fullmatch(artifact) or _group_for(artifact) is None:
            continue
        if metadata_count >= _MAX_METADATA_ENTRIES:
            warn("SDK metadata scan budget reached")
            break
        metadata_count += 1
        if info.file_size > _MAX_METADATA_BYTES:
            warn(f"Cannot read bounded SDK metadata {info.filename}")
            continue
        if metadata_bytes + info.file_size > _MAX_TOTAL_METADATA_BYTES:
            warn("SDK metadata scan budget reached")
            break
        content = _read_entry(archive, info)
        if content is None:
            warn(f"Cannot read bounded SDK metadata {info.filename}")
            continue
        metadata_bytes += len(content)
        version = _parse_properties(content, artifact)
        if version is None:
            continue
        component = _component(artifact, version, location, info.filename)
        records.setdefault(component.name, []).append(component)

    result: list[Component] = []
    for identity, candidates in records.items():
        versions = {candidate.resolved_version for candidate in candidates}
        component = candidates[0]
        if len(versions) > 1:
            component.resolved_version = ""
            component.purl = component.purl.rsplit("@", 1)[0]
            component.versions = [claim for candidate in candidates for claim in candidate.versions]
            component.properties.append({
                "name": "firmware:version:conflict",
                "value": ", ".join(sorted(versions)),
            })
            warn(f"Conflicting SDK metadata for {identity}")
        result.append(component)
    return result
