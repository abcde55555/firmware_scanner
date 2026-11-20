#!/usr/bin/env python3
"""Build the bundled exact-hash sample index from pinned public Maven artifacts.

This is an offline-capable importer after references have been downloaded. It
never runs or extracts an artifact; ZIP members are read as bounded byte strings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = Path(__file__).with_name("reference_sources.json")
DEFAULT_REFERENCES = ROOT / "reports/version-coverage-50-20261118/references"
DEFAULT_OUTPUT = ROOT / "src/firmware_scanner/data/binary_samples.json"
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_POM_BYTES = 2 * 1024 * 1024
_HEX = re.compile(r"[0-9a-f]{64}\Z")


def _safe_member_path(name: str) -> tuple[str, ...]:
    if not name or "\x00" in name or "\\" in name:
        raise ValueError(f"unsafe archive member path: {name!r}")
    path = PurePosixPath(name)
    parts = tuple(name.split("/"))
    if (
        path.is_absolute()
        or PureWindowsPath(name).is_absolute()
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError(f"unsafe archive member path: {name!r}")
    return parts


def _pom_coordinates(pom_bytes: bytes) -> tuple[str, str, str]:
    if len(pom_bytes) > MAX_POM_BYTES:
        raise ValueError("POM exceeds the 2 MiB limit")
    if b"<!DOCTYPE" in pom_bytes.upper() or b"<!ENTITY" in pom_bytes.upper():
        raise ValueError("POM declarations are not accepted")
    try:
        root = ElementTree.fromstring(pom_bytes)
    except ElementTree.ParseError as exc:
        raise ValueError(f"invalid companion POM XML: {exc}") from exc

    def direct_text(tag: str) -> str:
        for child in root:
            if child.tag.rsplit("}", 1)[-1] == tag and child.text:
                return child.text.strip()
        return ""

    return direct_text("groupId"), direct_text("artifactId"), direct_text("version")


def _pom_relocation_target(pom_bytes: bytes) -> dict[str, str] | None:
    root = ElementTree.fromstring(pom_bytes)
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "relocation":
            continue
        target = {
            child.tag.rsplit("}", 1)[-1]: (child.text or "").strip()
            for child in element
            if child.tag.rsplit("}", 1)[-1] in {"groupId", "artifactId", "version"}
        }
        return {key: value for key, value in target.items() if value}
    return None


def parse_aar(
    aar_bytes: bytes,
    pom_bytes: bytes,
    *,
    expected_group: str,
    expected_artifact: str,
    version: str,
    artifact_url: str,
    upstream_source: str,
    version_kind: str,
) -> list[dict[str, str]]:
    """Validate the matching POM and return one schema-1 record per ELF JNI .so."""
    coordinates = _pom_coordinates(pom_bytes)
    expected = (expected_group, expected_artifact, version)
    if coordinates != expected:
        raise ValueError(f"POM coordinates {coordinates!r} do not match expected {expected!r}")
    if _pom_relocation_target(pom_bytes) is not None:
        raise ValueError("POM declares Maven relocation; no sample is attributed to the relocated coordinate")
    _https_url(artifact_url)
    _https_url(upstream_source)
    if len(aar_bytes) > MAX_ARCHIVE_BYTES:
        raise ValueError("AAR exceeds the 128 MiB compressed archive limit")

    try:
        from io import BytesIO

        archive_context = zipfile.ZipFile(BytesIO(aar_bytes), "r")
    except (zipfile.BadZipFile, OSError) as exc:
        raise ValueError(f"invalid AAR ZIP: {exc}") from exc

    records: list[dict[str, str]] = []
    names: set[str] = set()
    actual_member_total = 0
    with archive_context as archive:
        infos = archive.infolist()
        declared_total = sum(info.file_size for info in infos if not info.is_dir())
        if declared_total > MAX_ARCHIVE_TOTAL_BYTES:
            raise ValueError("AAR exceeds the 256 MiB total uncompressed member limit")
        for info in infos:
            parts = _safe_member_path(info.filename.rstrip("/") if info.is_dir() else info.filename)
            if info.filename in names:
                raise ValueError(f"duplicate archive member path: {info.filename!r}")
            names.add(info.filename)
            if info.is_dir():
                continue
            mode = info.external_attr >> 16
            if mode & 0o170000 == 0o120000:
                raise ValueError(f"symbolic link archive member is not accepted: {info.filename!r}")
            if info.file_size > MAX_MEMBER_BYTES:
                raise ValueError(f"archive member exceeds the 64 MiB limit: {info.filename!r}")
            if len(parts) != 3 or parts[0] != "jni" or not parts[2].endswith(".so"):
                continue
            payload_buffer = bytearray()
            try:
                with archive.open(info, "r") as member:
                    while chunk := member.read(64 * 1024):
                        payload_buffer.extend(chunk)
                        actual_member_total += len(chunk)
                        if len(payload_buffer) > MAX_MEMBER_BYTES:
                            raise ValueError(f"archive member exceeds the 64 MiB limit: {info.filename!r}")
                        if actual_member_total > MAX_ARCHIVE_TOTAL_BYTES:
                            raise ValueError("AAR exceeds the 256 MiB total uncompressed member limit")
            except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
                raise ValueError(f"cannot read archive member {info.filename!r}: {exc}") from exc
            payload = bytes(payload_buffer)
            if len(payload) != info.file_size:
                raise ValueError(f"archive member size mismatch: {info.filename!r}")
            if not payload.startswith(b"\x7fELF"):
                continue
            records.append({
                "name": parts[2],
                "version": version,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "source": artifact_url,
                "upstream_source": upstream_source,
                "artifact_path": info.filename,
                "architecture": parts[1],
                "version_kind": version_kind,
            })
    return records


def _read_config(path: Path) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("reference source config must use schema_version 1")
    sources = document.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("reference source config must contain a non-empty sources list")
    return sources


def _https_url(url: str) -> str:
    if not url.startswith("https://"):
        raise ValueError(f"reference URL must use HTTPS: {url!r}")
    return url


def _download(url: str, target: Path, limit: int) -> dict[str, Any]:
    """Download one reference file with a strict byte cap and return its manifest row."""
    request = urllib.request.Request(url, headers={"User-Agent": "firmware-scanner-sample-index/1"})
    digest = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            final_url = response.geturl()
            _https_url(final_url)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as output:
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > limit:
                        raise ValueError(f"download exceeds {limit} byte limit: {url}")
                    digest.update(chunk)
                    output.write(chunk)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return {"url": url, "path": target.name, "size": size, "sha256": digest.hexdigest()}


def _artifact_urls(source: dict[str, Any], version: str) -> tuple[str, str]:
    group_path = str(source["group"]).replace(".", "/")
    artifact = str(source["artifact"])
    base_url = _https_url(str(source["repository_base_url"]).rstrip("/"))
    directory = f"{base_url}/{group_path}/{artifact}/{version}"
    stem = f"{artifact}-{version}"
    return f"{directory}/{stem}.aar", f"{directory}/{stem}.pom"


def build_index(config_path: Path, references_dir: Path) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Fetch pinned references sequentially and build the complete record list."""
    sources = _read_config(config_path)
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "artifacts": [],
        "warnings": [],
        "errors": [],
    }
    samples: list[dict[str, str]] = []
    total_archive_bytes = 0
    references_dir.mkdir(parents=True, exist_ok=True)

    for source in sources:
        for version in source["versions"]:
            aar_url, pom_url = _artifact_urls(source, version)
            stem = f"{source['artifact']}-{version}"
            aar_path = references_dir / f"{stem}.aar"
            pom_path = references_dir / f"{stem}.pom"
            try:
                pom_row = _download(pom_url, pom_path, MAX_POM_BYTES)
                manifest["artifacts"].append(pom_row)
                pom_bytes = pom_path.read_bytes()
                coordinates = _pom_coordinates(pom_bytes)
                expected = (source["group"], source["artifact"], version)
                if coordinates != expected:
                    raise ValueError(f"POM coordinates {coordinates!r} do not match expected {expected!r}")
                relocation = _pom_relocation_target(pom_bytes)
                if relocation is not None:
                    manifest["warnings"].append({
                        "coordinate": f"{source['group']}:{source['artifact']}:{version}",
                        "pom_url": pom_url,
                        "warning": "POM declares Maven relocation; no sample is attributed to the old coordinate",
                        "relocated_to": relocation,
                    })
                    continue
                if total_archive_bytes >= MAX_ARCHIVE_TOTAL_BYTES:
                    raise ValueError("run exceeds the 256 MiB cumulative downloaded AAR limit")
                remaining = MAX_ARCHIVE_TOTAL_BYTES - total_archive_bytes
                aar_row = _download(aar_url, aar_path, min(MAX_ARCHIVE_BYTES, remaining))
                manifest["artifacts"].append(aar_row)
                total_archive_bytes += aar_row["size"]
                records = parse_aar(
                    aar_path.read_bytes(),
                    pom_bytes,
                    expected_group=source["group"],
                    expected_artifact=source["artifact"],
                    version=version,
                    artifact_url=aar_url,
                    upstream_source=source["upstream_source"],
                    version_kind=source.get("version_kinds", {}).get(version, "artifact-release"),
                )
                samples.extend(records)
            except (OSError, ValueError, urllib.error.URLError, TimeoutError) as exc:
                manifest["errors"].append({
                    "coordinate": f"{source['group']}:{source['artifact']}:{version}",
                    "url": aar_url,
                    "error": f"{type(exc).__name__}: {exc}",
                })

    return samples, manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--references-dir", type=Path, default=DEFAULT_REFERENCES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        samples, manifest = build_index(args.config, args.references_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"cannot build sample index: {exc}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"schema_version": 1, "samples": samples}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest["sample_count"] = len(samples)
    manifest["distinct_sha256_count"] = len({sample["sha256"] for sample in samples})
    manifest_path = args.references_dir / "checksum-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(samples)} samples ({manifest['distinct_sha256_count']} distinct SHA-256 values) to {args.output}")
    print(
        f"wrote checksum manifest to {manifest_path}; recorded "
        f"{len(manifest['warnings'])} warnings and {len(manifest['errors'])} artifact errors"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
