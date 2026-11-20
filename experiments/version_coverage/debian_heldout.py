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
    CatalogItem("libogg0", "libogg.so.0", ("ogg", "libogg")),
    CatalogItem("libvorbis0a", "libvorbis.so.0", ("vorbis", "libvorbis")),
    CatalogItem("libvorbisenc2", "libvorbisenc.so.2", ("vorbis", "libvorbisenc")),
    CatalogItem("libflac14", "libFLAC.so.14", ("flac", "libflac")),
    CatalogItem("libsndfile1", "libsndfile.so.1", ("sndfile", "libsndfile")),
    CatalogItem("libopus0", "libopus.so.0", ("opus", "libopus")),
    CatalogItem("libspeex1", "libspeex.so.1", ("speex", "libspeex")),
    CatalogItem("libsamplerate0", "libsamplerate.so.0", ("samplerate", "libsamplerate")),
    CatalogItem("libsoxr0", "libsoxr.so.0", ("soxr", "libsoxr")),
    CatalogItem("libexif12", "libexif.so.12", ("exif", "libexif")),
    CatalogItem("libbpf1", "libbpf.so.1", ("bpf", "libbpf")),
    CatalogItem("libyaml-0-2", "libyaml-0.so.2", ("yaml", "libyaml")),
    CatalogItem("liblzo2-2", "liblzo2.so.2", ("lzo2", "liblzo2")),
    CatalogItem("libdeflate0", "libdeflate.so.0", ("deflate", "libdeflate")),
    CatalogItem("libsnappy1v5", "libsnappy.so.1", ("snappy", "libsnappy")),
    CatalogItem("libzip5", "libzip.so.5", ("zip", "libzip")),
    CatalogItem("libjxl0.11", "libjxl.so.0.11", ("jxl", "libjxl")),
    CatalogItem("libavif16", "libavif.so.16", ("avif", "libavif")),
    CatalogItem("libheif1", "libheif.so.1", ("heif", "libheif")),
    CatalogItem("libdav1d7", "libdav1d.so.7", ("dav1d", "libdav1d")),
    CatalogItem("libaom3", "libaom.so.3", ("aom", "libaom")),
    CatalogItem("libopenjp2-7", "libopenjp2.so.7", ("openjp2", "openjpeg")),
    CatalogItem("libtasn1-6", "libtasn1.so.6", ("tasn1", "libtasn1")),
    CatalogItem("libnettle8t64", "libnettle.so.8", ("nettle", "libnettle")),
    CatalogItem("libhogweed6t64", "libhogweed.so.6", ("hogweed", "libhogweed")),
    CatalogItem("libgmp10", "libgmp.so.10", ("gmp", "libgmp")),
    CatalogItem("libdbus-1-3", "libdbus-1.so.3", ("dbus", "libdbus")),
    CatalogItem("libsystemd0", "libsystemd.so.0", ("systemd", "libsystemd")),
    CatalogItem("libudev1", "libudev.so.1", ("udev", "libudev")),
    CatalogItem("libnghttp2-14", "libnghttp2.so.14", ("nghttp2", "libnghttp2")),
    CatalogItem("libnghttp3-9", "libnghttp3.so.9", ("nghttp3", "libnghttp3")),
    CatalogItem("libngtcp2-16", "libngtcp2.so.16", ("ngtcp2", "libngtcp2")),
    CatalogItem("libssh-4", "libssh.so.4", ("ssh", "libssh")),
)

INDEPENDENT_CATALOG = (
    CatalogItem("libpango-1.0-0", "libpango-1.0.so.0", ("pango", "libpango")),
    CatalogItem("libcairo2", "libcairo.so.2", ("cairo", "libcairo")),
    CatalogItem("libpixman-1-0", "libpixman-1.so.0", ("pixman", "libpixman")),
    CatalogItem(
        "libgdk-pixbuf-2.0-0",
        "libgdk_pixbuf-2.0.so.0",
        ("gdkpixbuf20", "gdk-pixbuf"),
    ),
    CatalogItem("libgraphite2-3", "libgraphite2.so.3", ("graphite2", "libgraphite2")),
    CatalogItem("libkrb5-3", "libkrb5.so.3", ("krb5", "libkrb5")),
    CatalogItem("libgssapi-krb5-2", "libgssapi_krb5.so.2", ("gssapi-krb5",)),
    CatalogItem("libldap2", "libldap.so.2", ("ldap", "libldap")),
    CatalogItem("libsasl2-2", "libsasl2.so.2", ("sasl2", "libsasl2")),
    CatalogItem("libp11-kit0", "libp11-kit.so.0", ("p11-kit", "libp11-kit")),
    CatalogItem("libgnutls30t64", "libgnutls.so.30", ("gnutls", "libgnutls")),
    CatalogItem("libunistring5", "libunistring.so.5", ("unistring", "libunistring")),
    CatalogItem("libidn2-0", "libidn2.so.0", ("idn2", "libidn2")),
    CatalogItem("libpsl5t64", "libpsl.so.5", ("psl", "libpsl")),
    CatalogItem("libgpg-error0", "libgpg-error.so.0", ("gpg-error", "libgpg-error")),
    CatalogItem("libgcrypt20", "libgcrypt.so.20", ("gcrypt", "libgcrypt")),
    CatalogItem("liblzma5", "liblzma.so.5", ("lzma", "xzutils")),
    CatalogItem("libbz2-1.0", "libbz2.so.1.0", ("bz2", "bzip2")),
    CatalogItem("libffi8", "libffi.so.8", ("ffi", "libffi")),
    CatalogItem("libseccomp2", "libseccomp.so.2", ("seccomp", "libseccomp")),
)

INDEPENDENT_2_CATALOG = (
    CatalogItem("libmagic1t64", "libmagic.so.1", ("magic", "libmagic")),
    CatalogItem("libcap2", "libcap.so.2", ("cap", "libcap")),
    CatalogItem("libattr1", "libattr.so.1", ("attr", "libattr")),
    CatalogItem("libacl1", "libacl.so.1", ("acl", "libacl")),
    CatalogItem("libltdl7", "libltdl.so.7", ("ltdl", "libltdl")),
    CatalogItem("libgpgme45", "libgpgme.so.45", ("gpgme", "libgpgme")),
    CatalogItem("libassuan9", "libassuan.so.9", ("assuan", "libassuan")),
    CatalogItem("libksba8", "libksba.so.8", ("ksba", "libksba")),
    CatalogItem("libnpth0t64", "libnpth.so.0", ("npth", "libnpth")),
    CatalogItem("libpopt0", "libpopt.so.0", ("popt", "libpopt")),
    CatalogItem("libaudit1", "libaudit.so.1", ("audit", "libaudit")),
    CatalogItem("libselinux1", "libselinux.so.1", ("selinux", "libselinux")),
    CatalogItem(
        "libdevmapper1.02.1",
        "libdevmapper.so.1.02.1",
        ("devmapper", "libdevmapper"),
    ),
    CatalogItem("libfuse3-4", "libfuse3.so.4", ("fuse3", "libfuse3")),
    CatalogItem("libapparmor1", "libapparmor.so.1", ("apparmor", "libapparmor")),
    CatalogItem("libgdbm6t64", "libgdbm.so.6", ("gdbm", "libgdbm")),
    CatalogItem("libreadline8t64", "libreadline.so.8", ("readline", "libreadline")),
    CatalogItem("libedit2", "libedit.so.2", ("edit", "libedit")),
    CatalogItem("liblcms2-2", "liblcms2.so.2", ("lcms2", "liblcms2")),
    CatalogItem("libidn12", "libidn.so.12", ("idn", "libidn")),
)

_OVERRIDES = {
    "libevent-2.1-7t64": "2.1.12-stable",
    "libjpeg62-turbo": "3.1.3",
    "libgmp10": "6.3.0",
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
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    cache = subprocess.run(
        ["apt-cache", "show", package],
        check=False,
        capture_output=True,
        text=True,
    )
    if cache.returncode == 0:
        match = re.search(r"^Version:\s*(\S+)", cache.stdout, re.MULTILINE)
        if match:
            return match.group(1)
    return ""


def package_library(
    package: str,
    soname: str,
    package_release: str,
    *,
    download_dir: Path | None = None,
    extract_dir: Path | None = None,
) -> tuple[Path | None, str]:
    result = subprocess.run(
        ["dpkg-query", "-L", package],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        result_lines = []
    else:
        result_lines = result.stdout.splitlines()
    for line in result_lines:
        if Path(line).name == soname and Path(line).exists():
            path = Path(line).resolve()
            if _path_owned_by_package(path, package):
                return path, "installed"
    fallback = COMMON_LIB / soname
    if fallback.exists() and _path_owned_by_package(fallback.resolve(), package):
        return fallback.resolve(), "installed"
    if download_dir is None or extract_dir is None:
        return None, "missing"

    download_dir.mkdir(parents=True, exist_ok=True)
    package_extract = extract_dir / package
    package_extract.mkdir(parents=True, exist_ok=True)
    download = subprocess.run(
        ["apt-get", "download", f"{package}={package_release}"],
        check=False,
        cwd=download_dir,
        capture_output=True,
        text=True,
    )
    if download.returncode:
        return None, "missing"
    existing = sorted(
        download_dir.glob(f"{package}_*.deb"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if existing:
        archive = existing[0]
        metadata = subprocess.run(
            ["dpkg-deb", "-f", str(archive), "Package", "Version"],
            check=False,
            capture_output=True,
            text=True,
        )
        if metadata.returncode:
            return None, "missing"
        values = dict(line.split(": ", 1) for line in metadata.stdout.splitlines() if ": " in line)
        if values.get("Package") != package or values.get("Version") != package_release:
            return None, "missing"
        subprocess.run(
            ["dpkg-deb", "-x", str(archive), str(package_extract)],
            check=False,
            capture_output=True,
            text=True,
        )
        for path in package_extract.rglob(soname):
            if path.is_file():
                return path.resolve(), "apt-download"
    return None, "missing"


def _path_owned_by_package(path: Path, package: str) -> bool:
    result = subprocess.run(
        ["dpkg-query", "-S", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        return False
    owners = {
        line.rsplit(": ", 1)[0].split(":", 1)[0].split(",")[0]
        for line in result.stdout.splitlines()
        if ": " in line
    }
    return package in owners


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _state(component) -> str:
    return next(
        (
            str(prop.get("value", ""))
            for prop in component.properties
            if prop.get("name") == "firmware:version:resolution-state"
        ),
        "",
    )


def evaluate_library(
    inventory,
    path: Path,
    item: CatalogItem,
    expected_version: str,
) -> dict:
    from firmware_scanner.extraction.binary_inventory import identity_key

    components = inventory.extract(path.read_bytes(), item.library, str(path))
    aliases = {identity_key(alias) for alias in item.aliases}
    candidates = [component for component in components if identity_key(component.name) in aliases]
    versions = [
        {
            "name": component.name,
            "version": component.resolved_version,
            "state": _state(component),
        }
        for component in candidates
    ]
    exact_versions = {
        component.resolved_version
        for component in candidates
        if component.resolved_version and _state(component) == "exact"
    }
    estimated_versions = {
        component.resolved_version
        for component in candidates
        if component.resolved_version and _state(component) == "estimated"
    }
    return {
        "package": item.package,
        "library": item.library,
        "source_path": str(path),
        "sha256": _sha256(path),
        "expected_version": expected_version,
        "catalog_identity_matched": bool(candidates),
        "versions": versions,
        "outcome": _classify_outcome(exact_versions, estimated_versions, expected_version),
    }


def _metrics(records: list[dict]) -> dict:
    counts = {
        outcome: sum(record["outcome"] == outcome for record in records)
        for outcome in (
            "exact",
            "estimated",
            "adjacent",
            "wrong",
            "wrong_estimate",
            "unknown",
        )
    }
    total = len(records)
    recognized = sum(record["catalog_identity_matched"] for record in records)
    usable = counts["exact"] + counts["estimated"] + counts["adjacent"]
    incorrect = counts["wrong"] + counts["wrong_estimate"]
    claimed = usable + incorrect
    return {
        "total": total,
        "catalog_identity_matched": recognized,
        "catalog_identity_match_rate": recognized / total if total else 0.0,
        **counts,
        "usable_versions": usable,
        "usable_coverage": usable / total if total else 0.0,
        "exact_coverage": counts["exact"] / total if total else 0.0,
        "precision_among_version_claims": (usable / claimed if claimed else 0.0),
    }


def _adjacent(actual: str, expected: str) -> bool:
    for pattern, prefix_length in (
        (r"(\d+)\.(\d+)", 1),
        (r"(\d+)\.(\d+)\.(\d+)", 2),
    ):
        actual_match = re.fullmatch(pattern, actual)
        expected_match = re.fullmatch(pattern, expected)
        if actual_match is None or expected_match is None:
            continue
        actual_parts = tuple(map(int, actual_match.groups()))
        expected_parts = tuple(map(int, expected_match.groups()))
        return (
            actual_parts[:prefix_length] == expected_parts[:prefix_length]
            and abs(actual_parts[-1] - expected_parts[-1]) == 1
        )
    return False


def _classify_outcome(
    exact_versions: set[str],
    estimated_versions: set[str],
    expected: str,
) -> str:
    if exact_versions:
        if expected in exact_versions and exact_versions == {expected}:
            return "exact"
        return "wrong"
    if expected in estimated_versions:
        return "estimated"
    if estimated_versions and all(_adjacent(version, expected) for version in estimated_versions):
        return "adjacent"
    if estimated_versions:
        return "wrong_estimate"
    return "unknown"


def run(output: Path, catalog=CATALOG) -> dict:
    from firmware_scanner import __version__
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    output.mkdir(parents=True, exist_ok=True)
    stripped_dir = output / "stripped"
    stripped_dir.mkdir(exist_ok=True)
    records = []
    skipped = []
    inventory = BinaryInventory()
    for item in catalog:
        version = package_version(item.package)
        path, acquisition = package_library(
            item.package,
            item.library,
            version,
            download_dir=output / "debs",
            extract_dir=output / "extracted",
        )
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
            skipped.append(
                {
                    "package": item.package,
                    "library": item.library,
                    "error": f"strip failed: {result.stderr.strip()}",
                }
            )
            continue
        record = evaluate_library(inventory, stripped, item, expected)
        record["package_version"] = version
        record["acquisition"] = acquisition
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
        "catalog": [asdict(item) for item in catalog],
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
    parser.add_argument(
        "--suite",
        choices=("development", "independent", "independent2"),
        default="development",
    )
    args = parser.parse_args()
    catalogs = {
        "development": CATALOG,
        "independent": INDEPENDENT_CATALOG,
        "independent2": INDEPENDENT_2_CATALOG,
    }
    catalog = catalogs[args.suite]
    report = run(args.output, catalog)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "scanner_version": report["scanner_version"],
                "metrics": report["metrics"],
                "skipped": len(report["skipped"]),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
