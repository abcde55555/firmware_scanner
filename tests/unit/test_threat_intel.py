"""Unit tests for Threat Intelligence Engine and Multi-Source Vulnerability Enrichment."""

import json
from firmware_scanner.vuln.models import Vulnerability, ComponentVulnResult, VulnScanResult, Severity
from firmware_scanner.vuln.threat_intel import (
    is_cisa_kev,
    get_cisa_kev_info,
    get_epss_score,
    get_cnvd_cnnvd_ids,
    determine_vex_status,
)
from firmware_scanner.vuln.matcher import VulnMatcher
from firmware_scanner.vuln.report_vex import generate_cyclonedx_vex
from firmware_scanner.vuln.report_html import generate_vuln_html
from firmware_scanner.extraction.models import Component


def test_cisa_kev_lookup():
    assert is_cisa_kev("CVE-2021-44228") is True
    assert is_cisa_kev("cve-2022-22965") is True
    assert is_cisa_kev("CVE-1999-9999") is False

    info = get_cisa_kev_info("CVE-2021-44228")
    assert info is not None
    assert "Log4Shell" in info["notes"]
    assert "due_date" in info


def test_epss_scoring():
    # Known high-impact CVE
    score, percentile = get_epss_score("CVE-2021-44228")
    assert score > 0.90
    assert percentile > 0.99

    # Heuristic for KEV CVE not in explicit score table
    score_kev, perc_kev = get_epss_score("CVE-2020-14882")
    assert score_kev >= 0.70

    # Heuristic for critical non-KEV CVE
    score_crit, _ = get_epss_score("CVE-2099-0001", cvss_score=9.8)
    assert score_crit == 0.35

    # Heuristic for low non-KEV CVE
    score_low, _ = get_epss_score("CVE-2099-0002", cvss_score=2.1)
    assert score_low == 0.01


def test_cnvd_cnnvd_mapping():
    # Known exact mapping
    cnvd, cnnvd = get_cnvd_cnnvd_ids("CVE-2021-44228")
    assert cnvd == "CNVD-2021-95914"
    assert cnnvd == "CNNVD-202112-799"

    # Algorithmic fallback
    cnvd_fall, cnnvd_fall = get_cnvd_cnnvd_ids("CVE-2024-98765")
    assert cnvd_fall == "CNVD-2024-98765"
    assert "CNNVD-2024" in cnnvd_fall


def test_vex_status_determination():
    # KEV -> P0 Immediate
    state, just, prio = determine_vex_status("CVE-2021-44228", "critical", cvss_score=10.0)
    assert state == "exploitable"
    assert prio == "P0 - Immediate"

    # High severity non-KEV -> P1 High
    state, just, prio = determine_vex_status("CVE-2099-0003", "high", cvss_score=8.1)
    assert state == "exploitable"
    assert prio == "P1 - High"

    # Medium -> P2 Moderate
    state, just, prio = determine_vex_status("CVE-2099-0004", "medium", cvss_score=5.3)
    assert state == "in_triage"
    assert prio == "P2 - Moderate"

    # Low -> P3 Low
    state, just, prio = determine_vex_status("CVE-2099-0005", "low", cvss_score=2.0)
    assert state == "in_triage"
    assert prio == "P3 - Low"


def test_cyclonedx_vex_and_html_report_threat_intel():
    v1 = Vulnerability(
        id="CVE-2021-44228",
        summary="Log4Shell vulnerability",
        severity=Severity.CRITICAL,
        cvss_score=10.0,
        is_cisa_kev=True,
        epss_score=0.97531,
        epss_percentile=0.99990,
        cnvd_id="CNVD-2021-95914",
        cnnvd_id="CNNVD-202112-799",
    )
    v2 = Vulnerability(
        id="CVE-2023-1111",
        summary="Minor info leak",
        severity=Severity.LOW,
        cvss_score=3.1,
    )
    
    comp_res = ComponentVulnResult(
        component_name="log4j-core",
        component_version="2.14.1",
        vulnerabilities=[v1, v2],
    )
    scan_res = VulnScanResult(
        firmware_path="/tmp/firmware.bin",
        total_components_scanned=1,
        total_vulnerabilities=2,
        critical_count=1,
        low_count=1,
        cisa_kev_count=1,
        high_epss_count=1,
        results=[comp_res],
    )

    # 1. CycloneDX VEX validation
    vex_json_str = generate_cyclonedx_vex(scan_res)
    vex_data = json.loads(vex_json_str)
    assert "vulnerabilities" in vex_data
    vex_vuln = next(v for v in vex_data["vulnerabilities"] if v["id"] == "CVE-2021-44228")
    assert vex_vuln["analysis"]["state"] == "exploitable"
    props = {p["name"]: p["value"] for p in vex_vuln.get("properties", [])}
    assert props["cisa:kev"] == "true"
    assert "epss:score" in props
    assert props["cnvd:id"] == "CNVD-2021-95914"

    # 2. HTML report validation
    html_out = generate_vuln_html(scan_res)
    assert "CISA KEV" in html_out
    assert "High EPSS" in html_out
    assert "CNVD-2021-95914" in html_out
