"""Tests for dependency versions recorded inside ZIP archives."""

import io
import zipfile
from collections.abc import Iterable

from firmware_scanner.extraction.archive_metadata import extract_archive_metadata


def _archive(entries: Iterable[tuple[str, str | bytes]]) -> zipfile.ZipFile:
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    data.seek(0)
    return zipfile.ZipFile(data)


def test_extracts_complete_maven_pom_properties_with_location_and_kind():
    with _archive([("META-INF/maven/com.example/widget/pom.properties",
                    "groupId=com.example\nartifactId=widget\nversion=2.4.1\n")]) as archive:
        components = extract_archive_metadata(archive, "/product/app/demo.apk")

    assert len(components) == 1
    component = components[0]
    assert component.name == "com.example:widget"
    assert component.resolved_version == "2.4.1"
    assert component.purl == "pkg:maven/com.example/widget@2.4.1"
    assert "pom.properties" in component.versions[0].evidence
    assert "/product/app/demo.apk" in component.versions[0].evidence
    assert {"name": "firmware:metadata_kind", "value": "maven-pom-properties"} in component.properties


def test_extracts_maven_pom_xml_coordinate_version_and_license():
    pom = """<?xml version="1.0" encoding="UTF-8"?>
    <project>
      <groupId>com.example</groupId>
      <artifactId>widget</artifactId>
      <version>2.4.1</version>
      <licenses>
        <license><name>Apache License, Version 2.0</name></license>
      </licenses>
    </project>
    """
    with _archive([
        ("META-INF/maven/com.example/widget/pom.xml", pom),
    ]) as archive:
        components = extract_archive_metadata(archive, "/product/app/demo.apk")

    assert len(components) == 1
    component = components[0]
    assert component.name == "com.example:widget"
    assert component.resolved_version == "2.4.1"
    assert component.licenses == ["Apache-2.0"]
    assert {
        "name": "firmware:metadata_kind",
        "value": "maven-pom-xml",
    } in component.properties
    assert any(
        prop["name"] == "firmware:license:evidence"
        and prop["value"].endswith(
            "/product/app/demo.apk!/META-INF/maven/com.example/widget/pom.xml"
        )
        for prop in component.properties
    )


def test_extracts_androidx_version_using_documented_group_artifact_filename():
    with _archive([("META-INF/androidx.core_core.version", "1.13.1\n")]) as archive:
        components = extract_archive_metadata(archive, "framework.jar")

    assert [(item.name, item.resolved_version) for item in components] == [
        ("androidx.core:core", "1.13.1")
    ]
    assert components[0].purl == "pkg:maven/androidx.core/core@1.13.1"
    assert "androidx.core_core.version" in components[0].versions[0].evidence
    assert {"name": "firmware:metadata_kind", "value": "androidx-version-file"} in components[0].properties


def test_ignores_incomplete_malformed_and_ambiguous_metadata():
    with _archive([
        ("META-INF/maven/com.example/missing-version/pom.properties",
         "groupId=com.example\nartifactId=missing-version\n"),
        ("META-INF/maven/com.example/bad/pom.properties",
         "groupId=com.example\nartifactId=bad\nversion=${revision}\n"),
        ("META-INF/maven/com.example/duplicate/pom.properties",
         "groupId=com.example\nartifactId=duplicate\nversion=1.0\nversion=2.0\n"),
        ("META-INF/maven/com.example/mismatched/pom.properties",
         "groupId=com.other\nartifactId=mismatched\nversion=1.0\n"),
        ("META-INF/androidx.invalid.version", "1.0\n"),
        ("META-INF/androidx.core_core.version", "1.0\n2.0\n"),
    ]) as archive:
        assert extract_archive_metadata(archive, "app.apk") == []


def test_deduplicates_identical_records_and_suppresses_conflicting_versions():
    with _archive([
        ("META-INF/maven/com.example/widget/pom.properties",
         "groupId=com.example\nartifactId=widget\nversion=1.0\n"),
        ("META-INF/maven/com.example/widget/pom.properties",
         "groupId=com.example\nartifactId=widget\nversion=1.0\n"),
        ("META-INF/androidx.core_core.version", "1.0\n"),
        ("META-INF/androidx.core_core.version", "1.0\n"),
    ]) as archive:
        same = extract_archive_metadata(archive, "app.apk")
    assert len(same) == 2

    with _archive([
        ("META-INF/maven/com.example/widget/pom.properties",
         "groupId=com.example\nartifactId=widget\nversion=1.0\n"),
        ("META-INF/maven/com.example/widget/pom.properties",
         "groupId=com.example\nartifactId=widget\nversion=2.0\n"),
        ("META-INF/androidx.core_core.version", "1.0\n"),
        ("META-INF/androidx.core_core.version", "2.0\n"),
    ]) as archive:
        conflicting = extract_archive_metadata(archive, "app.apk")
    assert len(conflicting) == 2
    assert all(not item.resolved_version for item in conflicting)
    assert all({value.version for value in item.versions} == {'1.0', '2.0'} for item in conflicting)


def test_skips_oversized_metadata_but_finds_metadata_after_many_resources():
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr(
            "META-INF/maven/com.example/huge/pom.properties",
            "groupId=com.example\nartifactId=huge\nversion=1.0\n" + "#" * 70_000,
        )
        for index in range(4100):
            archive.writestr(f"META-INF/other/{index}.txt", "ignored")
        archive.writestr(
            "META-INF/maven/com.example/late/pom.properties",
            "groupId=com.example\nartifactId=late\nversion=1.0\n",
        )
    data.seek(0)
    with zipfile.ZipFile(data) as archive:
        result = extract_archive_metadata(archive, "app.apk")
    assert [(item.name, item.resolved_version) for item in result] == [('com.example:late', '1.0')]


def test_does_not_treat_kotlin_module_or_google_build_properties_as_releases():
    with _archive([
        ("META-INF/main.kotlin_module", b"\x00\x01\x00\x03"),
        ("META-INF/com.google.android.material_material.version", "20250101\n"),
        ("META-INF/com.google.android.gms.version", "12451000\n"),
    ]) as archive:
        assert extract_archive_metadata(archive, "app.apk") == []


def test_oversized_entry_does_not_consume_total_read_budget():
    with _archive([
        ('META-INF/maven/com.example/huge/pom.properties', '#' * (9 * 1024 * 1024)),
        ('META-INF/maven/com.example/valid/pom.properties',
         'groupId=com.example\nartifactId=valid\nversion=1.2.3\n'),
        ('META-INF/maven/com.example/unknown/pom.properties',
         'groupId=com.example\nartifactId=unknown\nversion=unknown\n'),
    ]) as archive:
        result = extract_archive_metadata(archive, 'app.apk')
    assert [(c.name, c.resolved_version) for c in result] == [('com.example:valid', '1.2.3')]
