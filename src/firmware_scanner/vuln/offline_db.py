"""Offline CVE database for firmware vulnerability scanning without internet."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass
class OfflineCVE:
    """A CVE entry from the offline database."""

    id: str
    severity: str
    cvss: float
    summary: str
    affected_versions: str


_ALIASES: dict[str, str] = {
    "libcurl": "curl",
    "openssl-fips": "openssl",
    "libopenssl": "openssl",
    "arm-mbed-tls": "mbedtls",
    "mbed-tls": "mbedtls",
    "mbed tls": "mbedtls",
    "freertos-kernel": "freertos",
    "amazon-freertos": "freertos",
    "lwip-2": "lwip",
    "wolf-ssl": "wolfssl",
    "u-boot-spl": "u-boot",
}


@lru_cache(maxsize=1)
def _load_db() -> dict[str, list[dict]]:
    """Load the offline CVE database."""
    db_path = Path(__file__).parent.parent / "data" / "cve" / "offline_db.json"
    if not db_path.exists():
        return {}
    return json.loads(db_path.read_text(encoding="utf-8"))


def _normalize_name(name: str) -> str:
    """Normalize component name for CVE lookup."""
    lower = name.lower().strip()
    if lower.startswith("lib") and lower[3:] in _load_db():
        return lower[3:]
    return _ALIASES.get(lower, lower)


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse version string to comparable tuple."""
    match = re.match(r"(\d+(?:\.\d+)*)", version_str)
    if not match:
        return (0,)
    return tuple(int(x) for x in match.group(1).split("."))


def _is_affected(version: str, spec: str) -> bool:
    """Check if version matches affected specification."""
    if not version or not spec:
        return False
    parsed = _parse_version(version)
    if parsed == (0,):
        return False
    for constraint in spec.split(","):
        constraint = constraint.strip()
        if constraint.startswith("<="):
            target = _parse_version(constraint[2:])
            if target != (0,) and parsed <= target:
                return True
        elif constraint.startswith("<"):
            target = _parse_version(constraint[1:])
            if target != (0,) and parsed < target:
                return True
    return False


def scan_offline(component_name: str, version: str) -> list[OfflineCVE]:
    """Scan a component against the offline CVE database."""
    db = _load_db()
    normalized = _normalize_name(component_name)
    if normalized not in db:
        return []
    return [
        OfflineCVE(
            id=entry["id"],
            severity=entry["severity"],
            cvss=entry["cvss"],
            summary=entry["summary"],
            affected_versions=entry["affected"],
        )
        for entry in db[normalized]
        if _is_affected(version, entry.get("affected", ""))
    ]


def scan_components_offline(
    components: list[dict[str, str]],
) -> dict[str, list[OfflineCVE]]:
    """Scan multiple components against offline CVE database."""
    results: dict[str, list[OfflineCVE]] = {}
    for comp in components:
        name = comp.get("name", "")
        version = comp.get("version", "")
        if name and version:
            cves = scan_offline(name, version)
            if cves:
                results[name] = cves
    return results
