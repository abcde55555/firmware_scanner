"""Unit tests for BinaryHashMatcher and LicenseCompliance."""

import hashlib
import struct
import pytest
from pathlib import Path

from firmware_scanner.core.context import AnalysisContext
from firmware_scanner.extraction.models import Component, VersionConfidence, ExtractionMethod
from firmware_scanner.extraction.hash_matcher import BinaryHashMatcher, KNOWN_BINARY_HASHES
from firmware_scanner.sbom.license_compliance import (
    normalize_license,
    classify_license,
    audit_firmware_licenses,
    LicenseRiskCategory,
    ComplianceSeverity,
)
from firmware_scanner.sbom.cyclonedx import CycloneDXGenerator
from firmware_scanner.sbom.html_report import generate_html_report


def test_hash_matcher_full_binary():
    matcher = BinaryHashMatcher()
    busybox_hash = "a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef"
    
    # Custom test data
    custom_data = b"X" * 128
    custom_hash = hashlib.sha256(custom_data).hexdigest()
    custom_matcher = BinaryHashMatcher({
        custom_hash: ("custom_tool", "2.1.0", "VendorX", "application", "pkg:generic/custom@2.1.0", "cpe:2.3:a:vendor:custom:2.1.0:*:*:*:*:*:*:*", ["Apache-2.0"])
    })
    
    comp = custom_matcher.match_binary(custom_data, "bin/custom_tool")
    assert comp is not None
    assert comp.name == "custom_tool"
    assert comp.resolved_version == "2.1.0"
    assert comp.licenses == ["Apache-2.0"]
    assert comp.versions[0].confidence == 1.0
    assert comp.versions[0].method == ExtractionMethod.SIGNATURE_HASH


def test_hash_matcher_elf_section():
    # Build minimal 64-bit ELF binary with .text section
    # ELF header (64 bytes)
    # Section header table offset: 64
    endian = "<"
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    e_type = 2 # ET_EXEC
    e_machine = 62 # x86-64
    e_version = 1
    e_entry = 0x400000
    e_phoff = 0
    e_shoff = 128 # section headers start at byte 128
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 0
    e_phnum = 0
    e_shentsize = 64
    e_shnum = 3 # null, .shstrtab, .text
    e_shstrndx = 1 # .shstrtab is section 1

    elf_hdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident, e_type, e_machine, e_version, e_entry,
        e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize,
        e_phnum, e_shentsize, e_shnum, e_shstrndx
    )

    # Shstrtab strings: \0.shstrtab\0.text\0
    shstrtab_data = b"\x00.shstrtab\x00.text\x00"
    shstrtab_offset = 320
    shstrtab_size = len(shstrtab_data)

    text_data = b"EMBEDDED_CODE_SECTION_CONTENT_12345"
    text_offset = 320 + shstrtab_size
    text_size = len(text_data)

    text_hash = hashlib.sha256(text_data).hexdigest()

    # Section 0: NULL
    sh_null = b"\x00" * 64
    # Section 1: .shstrtab (name index 1)
    sh_strtab = struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, shstrtab_offset, shstrtab_size, 0, 0, 1, 0)
    # Section 2: .text (name index 11)
    sh_text = struct.pack("<IIQQQQIIQQ", 11, 1, 6, 0x401000, text_offset, text_size, 0, 0, 16, 0)

    binary_data = (
        elf_hdr +
        b"\x00" * (128 - len(elf_hdr)) +
        sh_null + sh_strtab + sh_text +
        b"\x00" * (320 - (128 + 64 * 3)) +
        shstrtab_data +
        text_data
    )

    matcher = BinaryHashMatcher({
        text_hash: ("busybox", "1.36.1", "BusyBox", "application", "pkg:generic/busybox@1.36.1", "cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*", ["GPL-2.0-only"])
    })

    comp = matcher.match_binary(binary_data, "bin/busybox")
    # Matching one section cannot establish the complete binary's release.
    assert comp is None


def test_license_normalization():
    assert normalize_license("gplv2") == "GPL-2.0-only"
    assert normalize_license("GPL 2.0 or later") == "GPL-2.0-or-later"
    assert normalize_license("Apache 2.0") == "Apache-2.0"
    assert normalize_license("MIT License") == "MIT"
    assert normalize_license("new bsd") == "BSD-3-Clause"
    assert normalize_license("AGPL-3.0") == "AGPL-3.0-only"


def test_license_classification():
    assert classify_license("MIT") == LicenseRiskCategory.PERMISSIVE
    assert classify_license("Apache-2.0") == LicenseRiskCategory.PERMISSIVE
    assert classify_license("FTL") == LicenseRiskCategory.PERMISSIVE
    assert classify_license("LGPL-2.1-only") == LicenseRiskCategory.WEAK_COPYLEFT
    assert classify_license("GPL-2.0-only") == LicenseRiskCategory.STRONG_COPYLEFT
    assert classify_license("AGPL-3.0-only") == LicenseRiskCategory.NETWORK_COPYLEFT
    assert classify_license("Proprietary") == LicenseRiskCategory.COMMERCIAL


def test_license_audit_conflicts():
    # Case 1: Permissive only -> Compliant
    c1 = Component(name="curl", licenses=["MIT"])
    c2 = Component(name="zlib", licenses=["Zlib"])
    report = audit_firmware_licenses([c1, c2])
    assert report.is_compliant is True
    assert len(report.compliance_issues) == 0

    # Case 2: AGPL detected -> Non-compliant / High warning
    c3 = Component(name="network-daemon", licenses=["AGPL-3.0-only"])
    report = audit_firmware_licenses([c1, c3])
    assert report.is_compliant is False
    assert any(i.title == "AGPL-3.0 Network Copyleft Obligation" for i in report.compliance_issues)

    # Case 3: GPL-3.0 and Proprietary -> Critical Copyleft Contamination
    c4 = Component(name="gpl3-tool", licenses=["GPL-3.0-only"])
    c5 = Component(name="vendor-firmware-core", licenses=["Proprietary"])
    report = audit_firmware_licenses([c4, c5])
    assert report.is_compliant is False
    assert any(i.severity == ComplianceSeverity.CRITICAL for i in report.compliance_issues)


def test_license_audit_is_incomplete_when_components_lack_licenses():
    licensed = Component(name="curl", licenses=["MIT"])
    unknown = Component(name="vendor-library")

    report = audit_firmware_licenses([licensed, unknown])

    assert report.unlicensed_components == 1
    assert report.status == "incomplete"
    assert report.is_compliant is False

    bom = CycloneDXGenerator().generate(
        components=[licensed, unknown],
        firmware_path="/tmp/firmware.bin",
        firmware_hash_sha256="a" * 64,
    )
    properties = {
        item["name"]: item["value"]
        for item in bom["metadata"]["properties"]
    }
    assert properties["compliance:license:status"] == "incomplete"


def test_license_audit_exports_final_coverage_statistics():
    licensed = Component(name="curl", licenses=["MIT"])
    unknown = Component(name="vendor-library")

    stats = audit_firmware_licenses([licensed, unknown]).as_dict()

    assert stats == {
        "total_components": 2,
        "licensed_components": 1,
        "unlicensed_components": 1,
        "coverage": 0.5,
        "status": "incomplete",
        "licenses_found": {"MIT": 1},
        "risk_summary": {"Permissive": 1},
    }


def test_cyclonedx_and_html_report_license_integration(tmp_path):
    c1 = Component(name="busybox", resolved_version="1.35.0", licenses=["gplv2"])
    c2 = Component(name="proprietary-app", resolved_version="1.0.0", licenses=["commercial"])
    
    # CycloneDX
    cdx_gen = CycloneDXGenerator()
    bom = cdx_gen.generate(
        components=[c1, c2],
        firmware_path="/tmp/firmware.bin",
        firmware_hash_sha256="abc1234",
    )
    # Check normalized licenses in CycloneDX
    busybox_cdx = next(c for c in bom["components"] if c["name"] == "busybox")
    assert busybox_cdx["licenses"][0]["license"]["id"] == "GPL-2.0-only"
    
    # Check compliance property in metadata
    meta_props = {p["name"]: p["value"] for p in bom["metadata"].get("properties", [])}
    assert "compliance:license:status" in meta_props

    # HTML Report
    ctx = AnalysisContext(firmware_path=Path("/tmp/firmware.bin"))
    ctx.components = [c1, c2]
    ctx.file_hash_sha256 = "abc1234"
    html_out = generate_html_report(ctx)
    assert "License Compliance &amp; Audit" in html_out or "License Compliance & Audit" in html_out
    assert "GPL-2.0-only" in html_out or "gplv2" in html_out
