"""Unit tests for OSV vulnerability matcher and semver range evaluation."""

from firmware_scanner.extraction.models import Component
from firmware_scanner.vuln.cache import cache_key
from firmware_scanner.vuln.matcher import VulnMatcher, _is_scannable, _normalize_name
from firmware_scanner.vuln.osv_client import (
    OSVClient,
    clean_version,
    extract_canonical_id,
    is_version_affected,
)


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
    assert (
        extract_canonical_id({"id": "ECHO-186e-750f-440b", "upstream": ["CVE-2025-70873"]})
        == "CVE-2025-70873"
    )
    # Related field
    assert (
        extract_canonical_id({"id": "SUSE-SU-2025:01455-1", "related": ["CVE-2025-29087"]})
        == "CVE-2025-29087"
    )


def test_is_version_affected_cve_2024_0232():
    # CVE-2024-0232 affected versions 3.43.0 and 3.43.1, fixed in 3.43.2
    vuln_cve_2024_0232 = {
        "id": "CVE-2024-0232",
        "affected": [
            {
                "package": {"name": "sqlite3"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.43.2"}]}
                ],
                "versions": ["3.43.0", "3.43.1"],
            }
        ],
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
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            },
            {
                "package": {"name": "sqlite3", "ecosystem": "Debian:13"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.42.0-1"}]}
                ],
            },
        ],
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

    # CalVer version (e.g. 20260522) with purl -> scannable
    c5 = Component(
        name="json", resolved_version="20260522", purl="pkg:maven/org.json/json@20260522"
    )
    assert _is_scannable(c5) is True

    cargo_exact = Component(
        name="libandroid_logger.dylib.so",
        resolved_version="0.15.0",
        purl="pkg:cargo/android_logger@0.15.0",
        properties=[
            {
                "name": "firmware:version:resolution-state",
                "value": "exact",
            }
        ],
    )
    assert _is_scannable(cargo_exact) is True

    cargo_estimate = Component(
        name="libandroid_logger.dylib.so",
        resolved_version="git:c991cad10330f37e93d82926bd6dae7f4f6647f6",
        purl="pkg:generic/libandroid_logger.dylib.so",
        properties=[
            {
                "name": "firmware:version:resolution-state",
                "value": "estimated-source-revision",
            }
        ],
    )
    assert _is_scannable(cargo_estimate) is False


def test_is_scannable_rejects_every_non_exact_version_resolution_state():
    for state in (
        "estimated",
        "equivalence-class",
        "conflict-unresolved",
        "estimated-source-revision",
        "estimated-parent-package",
        "estimated-platform-build",
    ):
        component = Component(
            name="libsqlite.so",
            resolved_version="3.44.5",
            properties=[
                {
                    "name": "firmware:version:resolution-state",
                    "value": state,
                }
            ],
        )
        assert _is_scannable(component) is False

    exact = Component(
        name="libsqlite.so",
        resolved_version="3.44.5",
        properties=[
            {
                "name": "firmware:version:resolution-state",
                "value": "exact",
            }
        ],
    )
    assert _is_scannable(exact) is True


def test_is_scannable_does_not_query_android_lzma_sdk_as_xz_utils():
    component = Component(
        name="liblzma.so",
        resolved_version="24.09",
        properties=[
            {
                "name": "firmware:version:resolution-state",
                "value": "exact",
            },
            {
                "name": "firmware:source:project",
                "value": "external/lzma",
            },
        ],
    )
    assert _is_scannable(component) is False


def test_vuln_scan_uses_a_blint_confirmed_component_identity_for_osv_queries():
    component = Component(
        name="libft2.so",
        resolved_version="2.4.12",
        purl="pkg:generic/libft2.so@2.4.12",
        properties=[
            {
                "name": "firmware:version:resolution-state",
                "value": "exact",
            },
            {
                "name": "firmware:blintdb:identity-confirmed",
                "value": '{"components": ["freetype"], "projects": ["freetype"]}',
            },
        ],
    )
    queries = []

    class Client:
        def check_cache_freshness(self):
            return True, 0.0

        def query_with_cache(self, requested):
            queries.extend(requested)
            return [[] for _ in requested]

        def parse_vulns(self, *_args, **_kwargs):
            return []

    VulnMatcher(client=Client()).scan([component])

    assert queries == [
        {
            "name": "freetype",
            "version": "2.4.12",
            "ecosystem": "",
        }
    ]


def test_vuln_scan_does_not_query_platform_build_components():
    component = Component(
        name="framework/core",
        component_type="framework",
        resolved_version="16-BP2A.250805.005-1775195212",
        properties=[
            {
                "name": "firmware:version:resolution-state",
                "value": "estimated-platform-build",
            }
        ],
    )

    class Client:
        def __init__(self):
            self.queries = []

        def check_cache_freshness(self):
            raise AssertionError("platform build must be rejected before cache checks")

        def query_with_cache(self, requested):
            self.queries.extend(requested)
            return []

    client = Client()
    result = VulnMatcher(client=client).scan([component])

    assert result.total_components_scanned == 0
    assert result.results == []
    assert client.queries == []


def test_normalize_name_maps_expanded_native_library_families_to_osv_names():
    expected = {
        "libexif.so": "libexif",
        "libdrm.so": "libdrm",
        "libfuse.so": "libfuse",
        "libbpf.so": "libbpf",
        "libdav1d.so": "dav1d",
        "libyuv.so": "libyuv",
        "libheif.so": "libheif",
        "libavif.so": "libavif",
        "libjxl.so": "libjxl",
        "libzip.so": "libzip",
        "libtiff.so": "libtiff",
        "libjsoncpp.so": "jsoncpp",
        "libntfs-3g.so": "ntfs-3g",
        "libminijail.so": "minijail",
        "libperfetto.so": "perfetto",
        "libpiex.so": "piex",
        "libselinux.so": "selinux",
        "libtinyalsa.so": "tinyalsa",
    }
    assert {name: _normalize_name(name) for name in expected} == expected


def test_parse_vulns_discards_distro_advisories_for_unrelated_packages():
    advisory = {
        "id": "CVE-2021-47098",
        "summary": "kernel: Fix of 38 CVEs",
        "affected": [
            {
                "package": {
                    "name": "kernel",
                    "ecosystem": "TuxCare:AlmaLinux:9.2",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "5.14.0-1"}],
                    }
                ],
            }
        ],
    }
    parsed = OSVClient().parse_vulns(
        [advisory],
        comp_version="1.4",
        comp_name="libbpf.so",
    )
    assert parsed == []


def test_parse_vulns_keeps_only_affected_entries_for_the_target_package():
    advisory = {
        "id": "CVE-2020-12767",
        "summary": "libexif denial of service",
        "affected": [
            {
                "package": {"name": "kernel"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "9.9.9"}],
                    }
                ],
            },
            {
                "package": {"name": "libexif", "ecosystem": "Debian:12"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "0.6.22"}],
                    }
                ],
            },
        ],
    }
    parsed = OSVClient().parse_vulns(
        [advisory],
        comp_version="0.6.21",
        comp_name="libexif.so",
    )
    assert [item.id for item in parsed] == ["CVE-2020-12767"]
    assert "9.9.9" not in parsed[0].affected_versions


def test_parse_vulns_rejects_a_different_upstream_version_branch():
    advisory = {
        "id": "CVE-2022-3602",
        "summary": "OpenSSL buffer overrun",
        "affected": [
            {
                "package": {"name": "openssl", "ecosystem": "AlmaLinux:9"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "3.0.7"}],
                    }
                ],
            }
        ],
    }
    parsed = OSVClient().parse_vulns(
        [advisory],
        comp_version="1.0.1f",
        comp_name="OpenSSL",
    )
    assert parsed == []


def test_cache_key_includes_ecosystem_and_prevents_cross_ecosystem_reuse():
    assert cache_key(name="openssl", version="1.0.1f", ecosystem="") != cache_key(
        name="openssl",
        version="1.0.1f",
        ecosystem="Alpine:v3.20",
    )


def test_is_version_affected_multi_branch():
    # Advisory that has multiple branches: 5.3.x (fixed in 5.3.39), 6.1.x (fixed in 6.1.21), 6.2.x (fixed in 6.2.19)
    multi_branch_vuln = {
        "id": "GHSA-test-multi-branch",
        "affected": [
            {
                "package": {"name": "spring-webflux", "ecosystem": "Maven"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "5.3.0"}, {"fixed": "5.3.39"}]}
                ],
            },
            {
                "package": {"name": "spring-webflux", "ecosystem": "Maven"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "6.1.0"}, {"fixed": "6.1.21"}]}
                ],
            },
            {
                "package": {"name": "spring-webflux", "ecosystem": "Maven"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "6.2.0"}, {"fixed": "6.2.19"}]}
                ],
            },
        ],
    }

    # 6.2.14 is affected (in [6.2.0, 6.2.19))
    assert is_version_affected("6.2.14", multi_branch_vuln) is True
    # 6.2.20 is fixed
    assert is_version_affected("6.2.20", multi_branch_vuln) is False
    # 6.1.10 is affected
    assert is_version_affected("6.1.10", multi_branch_vuln) is True
    # 6.1.22 is fixed
    assert is_version_affected("6.1.22", multi_branch_vuln) is False


def test_cpe_synthesizer():
    from firmware_scanner.extraction.cpe_synthesizer import synthesize_cpe

    assert (
        synthesize_cpe("libopenssl.so", "1.1.1w")
        == "cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*"
    )
    assert (
        synthesize_cpe("libcrypto.so.1.1", "1.1.1k")
        == "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"
    )
    assert synthesize_cpe("libssl.so", "3.0.9") == "cpe:2.3:a:openssl:openssl:3.0.9:*:*:*:*:*:*:*"
    assert (
        synthesize_cpe("libsqlite.so", "3.44.5") == "cpe:2.3:a:sqlite:sqlite:3.44.5:*:*:*:*:*:*:*"
    )
    assert synthesize_cpe("curl", "8.12.0") == "cpe:2.3:a:haxx:curl:8.12.0:*:*:*:*:*:*:*"
    assert (
        synthesize_cpe("libmbedtls.so", "2.28.8") == "cpe:2.3:a:arm:mbed_tls:2.28.8:*:*:*:*:*:*:*"
    )
    assert synthesize_cpe("dnsmasq", "2.86") == "cpe:2.3:a:thekelleys:dnsmasq:2.86:*:*:*:*:*:*:*"
    assert (
        synthesize_cpe("dropbear", "2022.83")
        == "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2022.83:*:*:*:*:*:*:*"
    )
    assert synthesize_cpe("bluez", "5.66") == "cpe:2.3:a:bluez:bluez:5.66:*:*:*:*:*:*:*"
    assert (
        synthesize_cpe("libprotobuf.so", "3.19.4")
        == "cpe:2.3:a:google:protobuf:3.19.4:*:*:*:*:*:*:*"
    )
    assert synthesize_cpe("toybox", "0.8.12") == "cpe:2.3:a:landley:toybox:0.8.12:*:*:*:*:*:*:*"
    assert synthesize_cpe("libcrypto.so", "BoringSSL") == ""


def test_component_cpe_synthesis_uses_confirmed_upstream_identity():
    from firmware_scanner.extraction.cpe_synthesizer import synthesize_component_cpe

    component = Component(
        name="libft2.so",
        resolved_version="2.4.12",
        properties=[
            {
                "name": "firmware:blintdb:identity-confirmed",
                "value": '{"components": ["freetype"], "projects": ["freetype"]}',
            }
        ],
    )

    assert synthesize_component_cpe(component) == (
        "cpe:2.3:a:freetype:freetype:2.4.12:*:*:*:*:*:*:*"
    )
