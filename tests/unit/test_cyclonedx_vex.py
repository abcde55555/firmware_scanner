"""Unit tests for CycloneDX 1.6 VEX and CPE synthesizer."""

import json

from firmware_scanner.extraction.cpe_synthesizer import synthesize_cpe
from firmware_scanner.vuln.models import (
    ComponentVulnResult,
    Severity,
    Vulnerability,
    VulnReference,
    VulnScanResult,
)
from firmware_scanner.vuln.report_vex import generate_cyclonedx_vex


def test_cpe_synthesizer_catalog():
    """Verify Gangmu catalog CPE mappings."""
    # libcurl -> cpe:2.3:a:haxx:curl
    assert synthesize_cpe("libcurl.so", "8.12.0") == "cpe:2.3:a:haxx:curl:8.12.0:*:*:*:*:*:*:*"
    assert synthesize_cpe("curl", "8.12.0") == "cpe:2.3:a:haxx:curl:8.12.0:*:*:*:*:*:*:*"

    # libsqlite.so -> cpe:2.3:a:sqlite:sqlite
    assert synthesize_cpe("libsqlite.so", "3.43.2") == "cpe:2.3:a:sqlite:sqlite:3.43.2:*:*:*:*:*:*:*"

    # libssl.so -> cpe:2.3:a:openssl:openssl
    assert synthesize_cpe("libssl.so", "1.1.1w") == "cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*"

    # protobuf -> cpe:2.3:a:google:protobuf
    assert synthesize_cpe("libprotobuf-cpp-full.so", "3.21.13") == "cpe:2.3:a:google:protobuf:3.21.13:*:*:*:*:*:*:*"

    # harfbuzz -> cpe:2.3:a:harfbuzz_project:harfbuzz
    assert synthesize_cpe("libharfbuzz_ng.so", "2.9.0") == "cpe:2.3:a:harfbuzz_project:harfbuzz:2.9.0:*:*:*:*:*:*:*"


def test_cyclonedx_vex_generation():
    """Verify CycloneDX 1.6 VEX generation with vulnerabilities section."""
    result = VulnScanResult(
        firmware_path="/test/path/firmware.img",
        firmware_sha256="1234567890abcdef",
        total_components_scanned=2,
        total_vulnerabilities=1,
        high_count=1,
        results=[
            ComponentVulnResult(
                component_name="curl",
                component_version="8.12.0",
                purl="pkg:generic/curl@8.12.0",
                cpe="cpe:2.3:a:haxx:curl:8.12.0:*:*:*:*:*:*:*",
                vulnerabilities=[
                    Vulnerability(
                        id="CVE-2024-9999",
                        summary="Buffer overflow in curl",
                        severity=Severity.HIGH,
                        cvss_score=8.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        affected_versions="< 8.13.0",
                        fixed_version="8.13.0",
                        references=[VulnReference(url="https://curl.se/docs/CVE-2024-9999.html", type="advisory")],
                    )
                ]
            )
        ]
    )

    vex_json = generate_cyclonedx_vex(result)
    data = json.loads(vex_json)

    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.6"
    assert "components" in data
    assert len(data["components"]) == 1
    assert data["components"][0]["name"] == "curl"

    assert "vulnerabilities" in data
    assert len(data["vulnerabilities"]) == 1
    v = data["vulnerabilities"][0]
    assert v["id"] == "CVE-2024-9999"
    assert v["source"]["name"] == "NVD"
    assert v["ratings"][0]["score"] == 8.5
    assert v["ratings"][0]["severity"] == "high"
    assert v["ratings"][0]["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert v["analysis"]["state"] == "exploitable"
    assert v["affects"][0]["ref"] == "pkg:generic/curl@8.12.0"


def test_cyclonedx_vex_merges_duplicate_ids_and_keeps_all_affected_refs():
    vulnerability = Vulnerability(
        id="CVE-2024-9999",
        summary="Shared vulnerability",
        severity=Severity.HIGH,
        cvss_score=8.5,
    )
    result = VulnScanResult(
        firmware_path="/test/path/firmware.img",
        firmware_sha256="1234567890abcdef",
        results=[
            ComponentVulnResult(
                component_name="curl",
                component_version="8.12.0",
                purl="pkg:generic/curl@8.12.0",
                vulnerabilities=[vulnerability],
            ),
            ComponentVulnResult(
                component_name="curl",
                component_version="8.12.0",
                purl="pkg:generic/curl-copy@8.12.0",
                vulnerabilities=[vulnerability],
            ),
        ],
    )
    data = json.loads(generate_cyclonedx_vex(result))
    assert len(data["vulnerabilities"]) == 1
    assert {
        item["ref"] for item in data["vulnerabilities"][0]["affects"]
    } == {
        "pkg:generic/curl@8.12.0",
        "pkg:generic/curl-copy@8.12.0",
    }
