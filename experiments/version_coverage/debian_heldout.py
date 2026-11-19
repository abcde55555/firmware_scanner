#!/usr/bin/env python3
"""Evaluate BinaryInventory against Debian package metadata as held-out truth."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON_LIB = Path("/usr/lib/x86_64-linux-gnu")


@dataclass(frozen=True)
class CatalogItem:
    package: str
    library: str
    aliases: tuple[str, ...]


CATALOG = (
    CatalogItem("zlib1g", "libz.so.1", ("zlib", "libz")),
    CatalogItem("libpng16-16t64", "libpng16.so.16", ("png", "libpng")),
    CatalogItem("libexpat1", "libexpat.so.1", ("expat", "libexpat")),
    CatalogItem("libpcre2-8-0", "libpcre2-8.so.0", ("pcre2", "libpcre2-8")),
    CatalogItem("libssl3t64", "libcrypto.so.3", ("openssl", "libcrypto", "libssl")),
    CatalogItem("libcurl4t64", "libcurl.so.4", ("curl", "libcurl")),
    CatalogItem("libsqlite3-0", "libsqlite3.so.0", ("sqlite", "sqlite3", "libsqlite3")),
    CatalogItem("liblz4-1", "liblz4.so.1", ("lz4", "liblz4")),
    CatalogItem("libzstd1", "libzstd.so.1", ("zstd", "libzstd")),
    CatalogItem("libbrotli1", "libbrotlidec.so.1", ("brotli", "libbrotlidec")),
    CatalogItem("libjpeg62-turbo", "libjpeg.so.62", ("jpeg", "libjpeg", "libjpeg-turbo")),
    CatalogItem("libtiff6", "libtiff.so.6", ("tiff", "libtiff")),
    CatalogItem("libwebp7", "libwebp.so.7", ("webp", "libwebp")),
    CatalogItem("libfreetype6", "libfreetype.so.6", ("freetype", "libfreetype", "ft2")),
    CatalogItem("libharfbuzz0b", "libharfbuzz.so.0", ("harfbuzz", "libharfbuzz")),
    CatalogItem("libarchive13t64", "libarchive.so.13", ("archive", "libarchive")),
    CatalogItem("libcapstone5", "libcapstone.so.5", ("capstone", "libcapstone")),
    CatalogItem("libpcap0.8t64", "libpcap.so.0.8", ("pcap", "libpcap")),
    CatalogItem("libuv1t64", "libuv.so.1", ("uv", "libuv")),
    CatalogItem("libssh2-1t64", "libssh2.so.1", ("ssh2", "libssh2")),
    CatalogItem("libjson-c5", "libjson-c.so.5", ("jsonc", "json-c", "libjson-c")),
)

_OVERRIDES = {
    "libevent-2.1-7t64": "2.1.12-stable",
    "libjpeg62-turbo": "3.1.3",
    "libmagic1t64": "5.46",
    "zlib1g": "1.3.1",
}


def normalize_upstream_version(package: str, package_version: str) -> str:
    """Strip Debian epoch/revision metadata with explicit non-trivial overrides."""
    if package in _OVERRIDES:
        return _OVERRIDES[package]
    value = package_version.split(":", 1)[-1]
    stable = re.match(r"(\d+\.\d+\.\d+-(?:stable|beta|alpha))", value)
    if stable:
        return stable.group(1)
    if "-" in value:
        value = value.rsplit("-", 1)[0]
    value = re.split(r"(?:\+|~)", value, maxsplit=1)[0]
    return value.removeprefix("v")


def package_version(package: str) -> str:
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", package],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def package_library(package: str, soname: str) -> Path | None:
    result = subprocess.run(
        ["dpkg-query", "-L", package],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        return None
    for line in result.stdout.splitlines():
        if Path(line).name == soname and Path(line).exists():
            return Path(line).resolve()
    fallback = COMMON_LIB / soname
    return fallback.resolve() if fallback.exists() else None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _state(component) -> str:
    return next((
        str(prop.get("value", ""))
        for prop in component.properties
        if prop.get("name") == "firmware:version:resolution-state"
    ), "")


def evaluate_library(
    inventory,
    path: Path,
    item: CatalogItem,
    expected_version: str,
) -> dict:
    from firmware_scanner.extraction.binary_inventory import identity_key

    components = inventory.extract(path.read_bytes(), item.library, str(path))
    aliases = {identity_key(alias) for alias in item.aliases}
    candidates = [
        component
        for component in components
        if identity_key(component.name) in aliases
    ]
    versions = [
        {
            "name": component.name,
            "version": component.resolved_version,
            "state": _state(component),
        }
        for component in candidates
    ]
    exact = next((
        component
        for component in candidates
        if component.resolved_version == expected_version
        and _state(component) == "exact"
    ), None)
    estimated = next((
        component
        for component in candidates
        if component.resolved_version and _state(component) == "estimated"
    ), None)
    wrong = next((
        component
        for component in candidates
        if component.resolved_version
        and _state(component) == "exact"
        and component.resolved_version != expected_version
    ), None)
    return {
        "package": item.package,
        "library": item.library,
        "source_path": str(path),
        "sha256": _sha256(path),
        "expected_version": expected_version,
        "catalog_identity_matched": bool(candidates),
        "versions": versions,
        "outcome": (
            "exact" if exact else
            "estimated" if estimated else
            "wrong" if wrong else
            "unknown"
        ),
    }


def _metrics(records: list[dict]) -> dict:
    counts = {
        outcome: sum(record["outcome"] == outcome for record in records)
        for outcome in ("exact", "estimated", "wrong", "unknown")
    }
    total = len(records)
    recognized = sum(record["catalog_identity_matched"] for record in records)
    usable = counts["exact"] + counts["estimated"]
    return {
        "total": total,
        "catalog_identity_matched": recognized,
        "catalog_identity_match_rate": recognized / total if total else 0.0,
        **counts,
        "usable_versions": usable,
        "usable_coverage": usable / total if total else 0.0,
        "exact_coverage": counts["exact"] / total if total else 0.0,
        "precision_among_version_claims": (
            counts["exact"] / (counts["exact"] + counts["wrong"])
            if counts["exact"] + counts["wrong"] else 0.0
        ),
    }


def run(output: Path) -> dict:
    from firmware_scanner import __version__
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    output.mkdir(parents=True, exist_ok=True)
    stripped_dir = output / "stripped"
    stripped_dir.mkdir(exist_ok=True)
    records = []
    skipped = []
    inventory = BinaryInventory()
    for item in CATALOG:
        version = package_version(item.package)
        path = package_library(item.package, item.library)
        if not version or path is None:
            skipped.append({"package": item.package, "library": item.library})
            continue
        expected = normalize_upstream_version(item.package, version)
        stripped = stripped_dir / path.name
        shutil.copy2(path, stripped)
        result = subprocess.run(
            ["strip", "--strip-all", str(stripped)],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            skipped.append({
                "package": item.package,
                "library": item.library,
                "error": f"strip failed: {result.stderr.strip()}",
            })
            continue
        record = evaluate_library(inventory, stripped, item, expected)
        record["package_version"] = version
        records.append(record)

    report = {
        "schema_version": 1,
        "scanner_version": __version__,
        "method": (
            "Debian package metadata is truth; one explicitly mapped upstream library per "
            "package; copied and strip --strip-all; static scan only; no target execution. "
            "Catalog identity matching is based on explicit filename/component aliases and "
            "is not an independent identity-precision claim."
        ),
        "catalog": [asdict(item) for item in CATALOG],
        "records": records,
        "skipped": skipped,
        "metrics": _metrics(records),
    }
    report["report_sha256"] = hashlib.sha256(
        json.dumps(report, sort_keys=True).encode()
    ).hexdigest()
    path = output / "heldout-report.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "reports/heldout-debian-20261119",
    )
    args = parser.parse_args()
    report = run(args.output)
    print(json.dumps({
        "output": str(args.output),
        "scanner_version": report["scanner_version"],
        "metrics": report["metrics"],
        "skipped": len(report["skipped"]),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
