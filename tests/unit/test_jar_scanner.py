"""Unit tests for JAR/WAR and Java archive component extraction."""

import io
import zipfile
import pytest

from firmware_scanner.extraction.smart_analyzer import SmartSectionAnalyzer
from firmware_scanner.extraction.models import Component
from firmware_scanner.sbom.cyclonedx import CycloneDXGenerator


def _create_mock_jar_with_pom_properties() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        pom_props = "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n"
        zf.writestr("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties", pom_props)
    return buf.getvalue()


def _create_mock_jar_with_manifest_mf() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        manifest = (
            "Manifest-Version: 1.0\n"
            "Implementation-Title: spring-web\n"
            "Implementation-Version: 5.3.18\n"
            "Bundle-SymbolicName: org.springframework.web\n"
        )
        zf.writestr("META-INF/MANIFEST.MF", manifest)
    return buf.getvalue()


def _create_mock_springboot_fat_jar() -> bytes:
    inner_jar = _create_mock_jar_with_pom_properties()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("BOOT-INF/lib/log4j-core-2.14.1.jar", inner_jar)
        manifest = "Manifest-Version: 1.0\nMain-Class: org.springframework.boot.loader.JarLauncher\n"
        zf.writestr("META-INF/MANIFEST.MF", manifest)
    return buf.getvalue()


def test_jar_pom_properties_extraction():
    data = _create_mock_jar_with_pom_properties()
    analyzer = SmartSectionAnalyzer()
    comps = analyzer.analyze_section("app/lib/log4j-core-2.14.1.jar", data)

    assert len(comps) == 1
    c = comps[0]
    assert c.name == "org.apache.logging.log4j:log4j-core"
    assert c.resolved_version == "2.14.1"
    assert c.purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def test_jar_manifest_mf_extraction():
    data = _create_mock_jar_with_manifest_mf()
    analyzer = SmartSectionAnalyzer()
    comps = analyzer.analyze_section("usr/share/java/spring-web.jar", data)

    assert len(comps) == 1
    c = comps[0]
    assert c.name == "spring-web"
    assert c.resolved_version == "5.3.18"
    assert "5.3.18" in c.purl


def test_springboot_fat_jar_nested_extraction():
    data = _create_mock_springboot_fat_jar()
    analyzer = SmartSectionAnalyzer()
    comps = analyzer.analyze_section("opt/backend/service.jar", data)

    assert any(c.name == "org.apache.logging.log4j:log4j-core" and c.resolved_version == "2.14.1" for c in comps)


def test_jar_filename_fallback():
    # Empty JAR without pom or manifest
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("dummy.txt", "dummy")
    data = buf.getvalue()

    analyzer = SmartSectionAnalyzer()
    comps = analyzer.analyze_section("opt/app/commons-io-2.8.0.jar", data)

    assert len(comps) == 1
    c = comps[0]
    assert c.name == "commons-io"
    assert c.resolved_version == "2.8.0"
    assert c.purl == "pkg:generic/commons-io@2.8.0"


def test_cyclonedx_maven_group_and_name_separation():
    comp = Component(
        name="org.apache.commons:commons-lang3",
        resolved_version="3.12.0",
        purl="pkg:maven/org.apache.commons/commons-lang3@3.12.0",
        component_type="library",
    )
    gen = CycloneDXGenerator()
    cdx = gen._component_to_cdx(comp)

    assert cdx["group"] == "org.apache.commons"
    assert cdx["name"] == "commons-lang3"
    assert cdx["version"] == "3.12.0"
    assert cdx["purl"] == "pkg:maven/org.apache.commons/commons-lang3@3.12.0"
