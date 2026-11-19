"""Unit tests for SBOM generators (CycloneDX 1.6 and SPDX 3.0.1)."""

import json
from pathlib import Path

from firmware_scanner.core.context import AnalysisContext
from firmware_scanner.extraction.models import Component, VersionConfidence, ExtractionMethod
from firmware_scanner.sbom.cyclonedx import CycloneDXGenerator
from firmware_scanner.sbom.spdx3 import SPDX3Generator
from firmware_scanner.sbom.generator import SBOMGenerator
from firmware_scanner.vuln.sbom_parser import is_sbom_file, parse_sbom_to_components


def _create_sample_context() -> AnalysisContext:
    comp1 = Component(
        name="busybox",
        vendor="BusyBox",
        resolved_version="1.35.0",
        component_type="application",
        purl="pkg:generic/busybox@1.35.0",
        cpe="cpe:2.3:a:busybox:busybox:1.35.0:*:*:*:*:*:*:*",
        licenses=["GPL-2.0-only"],
        description="BusyBox utilities",
    )
    comp1.versions.append(VersionConfidence(
        version="1.35.0",
        confidence=0.9,
        method=ExtractionMethod.STRING_PATTERN,
        evidence="BusyBox v1.35.0 multi-call binary",
    ))

    comp2 = Component(
        name="libsqlite.so",
        vendor="SQLite",
        resolved_version="3.40.1",
        component_type="library",
        purl="pkg:generic/libsqlite.so@3.40.1",
    )

    context = AnalysisContext(
        firmware_path=Path("/tmp/sample_firmware.img"),
        file_hash_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_hash_md5="d41d8cd98f00b204e9800998ecf8427e",
        detected_rtos="Linux",
        components=[comp1, comp2],
    )
    return context


def test_cyclonedx_1_6_generation():
    """Verify CycloneDX 1.6 SBOM format compliance."""
    context = _create_sample_context()
    gen = CycloneDXGenerator()
    data = gen.generate(
        components=context.components,
        firmware_path=str(context.firmware_path),
        firmware_hash_sha256=context.file_hash_sha256,
        firmware_hash_md5=context.file_hash_md5,
        detected_rtos=context.detected_rtos,
    )

    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.6"
    assert "urn:uuid:" in data["serialNumber"]
    assert {"name", "version", "type"}.isdisjoint(data["metadata"])
    assert data["metadata"]["component"]["type"] == "firmware"
    assert len(data["components"]) == 2
    assert data["components"][0]["name"] == "busybox"
    assert data["components"][0]["version"] == "1.35.0"
    assert data["components"][0]["purl"] == "pkg:generic/busybox@1.35.0"


def test_cyclonedx_dependencies_only_emit_unambiguous_declared_needed_edges():
    generator = CycloneDXGenerator()
    provider = Component(
        name="libz.so",
        resolved_version="1.3.1",
        purl="pkg:generic/libz.so@1.3.1",
        properties=[{"name": "firmware:elf:soname", "value": "libz.so.1"}],
    )
    consumer = Component(
        name="tool",
        resolved_version="1.0",
        purl="pkg:generic/tool@1.0",
        properties=[{"name": "firmware:elf:needed", "value": "libz.so.1"}],
    )
    bom = generator.generate(
        [consumer, provider],
        firmware_path="firmware.img",
        firmware_hash_sha256="a" * 64,
    )
    assert bom["dependencies"] == [{
        "ref": "pkg:generic/tool@1.0",
        "dependsOn": ["pkg:generic/libz.so@1.3.1"],
    }]


def test_cyclonedx_omits_dependency_when_soname_has_multiple_providers():
    generator = CycloneDXGenerator()
    providers = [
        Component(
            name=f"libz-{index}.so",
            resolved_version="1.3.1",
            purl=f"pkg:generic/libz-{index}.so@1.3.1",
            properties=[{"name": "firmware:elf:soname", "value": "libz.so.1"}],
        )
        for index in range(2)
    ]
    consumer = Component(
        name="tool",
        resolved_version="1.0",
        purl="pkg:generic/tool@1.0",
        properties=[{"name": "firmware:elf:needed", "value": "libz.so.1"}],
    )
    bom = generator.generate(
        [consumer, *providers],
        firmware_path="firmware.img",
        firmware_hash_sha256="a" * 64,
    )
    assert "dependencies" not in bom


def test_cyclonedx_merges_duplicate_consumer_refs_into_one_dependency():
    generator = CycloneDXGenerator()
    provider = Component(
        name="libz.so",
        resolved_version="1.3.1",
        purl="pkg:generic/libz.so@1.3.1",
        properties=[{"name": "firmware:elf:soname", "value": "libz.so.1"}],
    )
    consumers = [
        Component(
            name="tool",
            resolved_version="1.0",
            purl="pkg:generic/tool@1.0",
            properties=[{"name": "firmware:elf:needed", "value": "libz.so.1"}],
        )
        for _ in range(2)
    ]
    bom = generator.generate(
        [*consumers, provider],
        firmware_path="firmware.img",
        firmware_hash_sha256="a" * 64,
    )
    assert bom["dependencies"] == [{
        "ref": "pkg:generic/tool@1.0",
        "dependsOn": ["pkg:generic/libz.so@1.3.1"],
    }]


def test_cyclonedx_records_scan_analysis_stats_as_metadata():
    generator = CycloneDXGenerator()
    bom = generator.generate(
        [],
        firmware_path="firmware.img",
        firmware_hash_sha256="a" * 64,
        build_info={
            "analysis_stats": {
                "content_cache_hits": 12,
                "content_cache_entries": 40,
            },
        },
    )
    assert {
        "name": "firmware:analysis:stats",
        "value": '{"content_cache_entries": 40, "content_cache_hits": 12}',
    } in bom["metadata"]["properties"]


def test_spdx_3_0_1_generation():
    """Verify SPDX 3.0.1 JSON-LD SBOM format compliance."""
    context = _create_sample_context()
    gen = SPDX3Generator()
    data = gen.generate(
        components=context.components,
        firmware_path=str(context.firmware_path),
        firmware_hash_sha256=context.file_hash_sha256,
        firmware_hash_md5=context.file_hash_md5,
        detected_rtos=context.detected_rtos,
    )

    assert data["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
    assert "@graph" in data
    graph = data["@graph"]

    types = [elem.get("type") for elem in graph]
    assert "CreationInfo" in types
    assert "Tool" in types
    assert "SpdxDocument" in types
    assert "software_Package" in types
    assert "Relationship" in types

    creation_info = next(e for e in graph if e.get("type") == "CreationInfo")
    assert creation_info["specVersion"] == "3.0.1"

    spdx_doc = next(e for e in graph if e.get("type") == "SpdxDocument")
    assert "core" in spdx_doc["profileConformance"]
    assert "software" in spdx_doc["profileConformance"]

    packages = [e for e in graph if e.get("type") == "software_Package"]
    # 1 root firmware + 2 components
    assert len(packages) == 3
    busybox_pkg = next(p for p in packages if p.get("name") == "busybox")
    assert busybox_pkg["software_packageVersion"] == "1.35.0"
    assert busybox_pkg["software_packageUrl"] == "pkg:generic/busybox@1.35.0"

    relationships = [e for e in graph if e.get("type") == "Relationship"]
    assert any(r.get("relationshipType") == "describes" for r in relationships)
    assert any(r.get("relationshipType") == "contains" for r in relationships)


def test_sbom_parser_supports_cyclonedx_1_6_and_spdx_3_0_1(tmp_path):
    """Verify parser can ingest both CycloneDX 1.6 and SPDX 3.0.1 files."""
    context = _create_sample_context()
    sbom_gen = SBOMGenerator()

    # CycloneDX 1.6
    cdx_path = tmp_path / "test_cdx.json"
    cdx_path.write_text(sbom_gen.generate_cyclonedx(context), encoding="utf-8")
    assert is_sbom_file(cdx_path)
    cdx_comps, cdx_meta = parse_sbom_to_components(cdx_path)
    assert len(cdx_comps) == 2
    assert cdx_comps[0].name == "busybox"
    assert cdx_comps[0].resolved_version == "1.35.0"

    # SPDX 3.0.1
    spdx_path = tmp_path / "test_spdx.json"
    spdx_path.write_text(sbom_gen.generate_spdx(context), encoding="utf-8")
    assert is_sbom_file(spdx_path)
    spdx_comps, spdx_meta = parse_sbom_to_components(spdx_path)
    assert len(spdx_comps) == 2
    assert any(c.name == "busybox" and c.resolved_version == "1.35.0" for c in spdx_comps)
    assert any(c.name == "libsqlite.so" and c.resolved_version == "3.40.1" for c in spdx_comps)


def test_asrock_atv_sbom_metadata():
    """Verify that ATV-SBOM mandatory metadata fields and properties are generated."""
    context = _create_sample_context()
    gen = CycloneDXGenerator()
    data = gen.generate(
        components=context.components,
        firmware_path="/firmware/system.img",
        firmware_hash_sha256="abc12345",
        build_info={
            "chip_model": "x86_64",
            "build_date": "Fri Apr  3 05:46:52 UTC 2026",
            "build_id": "BP2A.250805.005",
            "target_product": "waydroid_tv_x86_64",
        },
        spec_version="1.5",
    )

    meta = data["metadata"]
    # 1. CycloneDX-compliant root component metadata
    assert {"name", "version", "type"}.isdisjoint(meta)
    assert meta["lifecycles"] == [{"phase": "build"}]
    assert meta["component"]["name"] == "waydroid_tv_x86_64"
    assert meta["component"]["version"] == "BP2A.250805.005"
    assert meta["component"]["type"] == "firmware"

    # 2. Mandatory ASRock properties
    props = {p["name"]: p["value"] for p in meta["properties"]}
    assert props["asrock:chip-model"] == "x86_64"
    assert props["asrock:build-date"] == "Fri Apr  3 05:46:52 UTC 2026"
    assert props["asrock:build-id"] == "BP2A.250805.005"
    assert props["asrock:target-product"] == "waydroid_tv_x86_64"

    # 3. Components have bom-ref and non-empty version in 1.5
    for c in data["components"]:
        assert "bom-ref" in c
        assert "version" in c and c["version"]

    # 4. Strict CycloneDX 1.5 root compliance: no illegal additionalProperties at root
    assert "name" not in data
    assert "type" not in data
    assert "lifecycles" not in data
    assert "properties" not in data

    # 5. Metadata component contains properties and bom-ref
    assert "bom-ref" in meta["component"]
    comp_props = {p["name"]: p["value"] for p in meta["component"]["properties"]}
    assert comp_props["asrock:chip-model"] == "x86_64"
    assert comp_props["asrock:target-product"] == "waydroid_tv_x86_64"

