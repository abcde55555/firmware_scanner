"""Conservative package-level license evidence from APK and JAR archives."""

from __future__ import annotations

import re
import zipfile
import zlib
from dataclasses import dataclass

from .notice_licenses import detect_license_text

_PACKAGE_LICENSE_PATH = re.compile(
    r"^(?:META-INF/)?(?:LICENSE|LICENCE|NOTICE)(?:[._-][^/]*)?$",
    re.IGNORECASE,
)
_MAX_LICENSE_BYTES = 64 * 1024
_MAX_LICENSE_ENTRIES = 16
_MAX_TOTAL_LICENSE_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ArchiveLicenseEvidence:
    licenses: tuple[str, ...] = ()
    files: tuple[str, ...] = ()


def _decode_license_text(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-16", "iso-8859-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return ""


def extract_package_license_evidence(
    archive: zipfile.ZipFile,
    location: str,
) -> ArchiveLicenseEvidence:
    """Return package-level SPDX evidence from explicitly named license files."""
    licenses: set[str] = set()
    files: list[str] = []
    total = 0
    count = 0
    for info in archive.infolist():
        if not _PACKAGE_LICENSE_PATH.fullmatch(info.filename):
            continue
        if count >= _MAX_LICENSE_ENTRIES or info.file_size > _MAX_LICENSE_BYTES:
            continue
        if total + info.file_size > _MAX_TOTAL_LICENSE_BYTES:
            break
        count += 1
        try:
            with archive.open(info) as member:
                data = member.read(_MAX_LICENSE_BYTES + 1)
        except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, zlib.error, EOFError):
            continue
        if len(data) > _MAX_LICENSE_BYTES:
            continue
        total += len(data)
        detected = detect_license_text(_decode_license_text(data))
        if not detected:
            continue
        licenses.update(detected)
        files.append(f"{location}!/{info.filename}")
    return ArchiveLicenseEvidence(
        licenses=tuple(sorted(licenses)),
        files=tuple(files),
    )
