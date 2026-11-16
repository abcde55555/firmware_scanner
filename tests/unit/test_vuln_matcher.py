"""Unit tests for OSV vulnerability matcher and semver range evaluation."""

import pytest
from firmware_scanner.vuln.osv_client import (
    clean_version,
    is_version_affected,
    extract_canonical_id,
    OSVClient,
)
from firmware_scanner.vuln.matcher import VulnMatcher, _is_scannable
from firmware_scanner.extraction.models import Component


def test_clean_version():
    assert clean_version("3.40.1-2+deb12u2") == "3.40.1"
    assert clean_version("3.46.1-3") == "3.46.1"
    assert clean_version("1:1.6.44-1") == "1.6.44"
    assert clean_version("version-3.43.2") == "3.43.2"
    assert clean_version("v8.12.0") == "8.12.0"
    assert clean_version("") == ""


def test_extract_canonical_id():
    # Direct CVE ID
    assert extract_canonical_id({"id": "CVE-2024-0232"}) == "CVE-2024-0232"
    # Distro advisory with CVE embedded in ID
    assert extract_canonical_id({"id": "DEBIAN-CVE-2025-29087"}) == "CVE-2025-29087"
    assert extract_canonical_id({"id": "UBUNTU-CVE-2025-3277"}) == "CVE-2025-3277"
    # Upstream field
    assert extract_canonical_id({"id": "ECHO-186e-750f-440b", "upstream": ["CVE-2025-70873"]}) == "CVE-2025-70873"
    # Related field
    assert extract_canonical_id({"id": "SUSE-SU-2025:01455-1", "related": ["CVE-2025-29087"]}) == "CVE-2025-29087"


def test_is_version_affected_cve_2024_0232():
    # CVE-2024-0232 affected versions 3.43.0 and 3.43.1, fixed in 3.43.2
    vuln_cve_2024_0232 = {
        "id": "CVE-2024-0232",
        "affected": [{
            "package": {"name": "sqlite3"},
            "ranges": [{
                "type": "SEMVER",
                "events": [{"introduced": "0"}, {"fixed": "3.43.2"}]
            }],
            "versions": ["3.43.0", "3.43.1"]
        }]
    }

    # SQLite 3.44.5 is strictly newer than fixed version 3.43.2 -> NOT affected!
    assert is_version_affected("3.44.5", vuln_cve_2024_0232) is False

    # Versions < 3.43.2 -> ARE affected
    assert is_version_affected("3.43.1", vuln_cve_2024_0232) is True
    assert is_version_affected("3.42.0", vuln_cve_2024_0232) is True


def test_is_version_affected_distro_advisory():
    # Distro notice where fixed version in upstream is 3.42.0
    distro_vuln = {
        "id": "DEBIAN-CVE-2025-7458",
        "affected": [
            {
                "package": {"name": "sqlite3", "ecosystem": "Debian:12"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
            },
            {
                "package": {"name": "sqlite3", "ecosystem": "Debian:13"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.42.0-1"}]}]
            }
        ]
    }

    # Upstream 3.44.5 is >= 3.42.0 -> NOT affected!
    assert is_version_affected("3.44.5", distro_vuln) is False

    # Old version 3.40.1 < 3.42.0 -> affected
    assert is_version_affected("3.40.1", distro_vuln) is True


def test_is_scannable():
    # Regular upstream libraries with semver
    c1 = Component(name="libsqlite.so", resolved_version="3.44.5")
    assert _is_scannable(c1) is True

    c2 = Component(name="curl", resolved_version="8.12.0")
    assert _is_scannable(c2) is True

    # Milestone landmark floor with '+' -> skipped from fixed semver queries
    c3 = Component(name="sqlite3", resolved_version="3.24.0+")
    assert _is_scannable(c3) is False

    # Android HAL interfaces -> skipped
    c4 = Component(name="android.hardware.camera.device@3.2.so", resolved_version="3.2")
    assert _is_scannable(c4) is False


def test_cpe_synthesizer():
    from firmware_scanner.extraction.cpe_synthesizer import synthesize_cpe

    assert synthesize_cpe("libopenssl.so", "1.1.1w") == "cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*"
    assert synthesize_cpe("libcrypto.so.1.1", "1.1.1k") == "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"
    assert synthesize_cpe("libssl.so", "3.0.9") == "cpe:2.3:a:openssl:openssl:3.0.9:*:*:*:*:*:*:*"
    assert synthesize_cpe("libsqlite.so", "3.44.5") == "cpe:2.3:a:sqlite:sqlite:3.44.5:*:*:*:*:*:*:*"
    assert synthesize_cpe("curl", "8.12.0") == "cpe:2.3:a:haxx:curl:8.12.0:*:*:*:*:*:*:*"
    assert synthesize_cpe("libcrypto.so", "BoringSSL") == ""

