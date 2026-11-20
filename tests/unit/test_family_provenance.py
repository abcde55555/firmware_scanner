from firmware_scanner.extraction.family_provenance import apply_family_version_provenance
from firmware_scanner.extraction.models import Component, VersionConfidence


def component(name: str, version: str = "") -> Component:
    versions = []
    properties = []
    if version:
        versions = [
            VersionConfidence(
                version=version,
                confidence=0.94,
                method="disassembly",
                evidence="direct binary evidence",
            )
        ]
        properties = [
            {
                "name": "firmware:version:resolution-state",
                "value": "exact",
            }
        ]
    return Component(
        name=name,
        resolved_version=version,
        versions=versions,
        properties=properties,
    )


def test_shared_source_family_propagates_only_an_unambiguous_version():
    components = [
        component("libext2fs.so", "1.41.14"),
        component("libext2_blkid.so"),
        component("libext2_uuid.so"),
    ]

    stats = apply_family_version_provenance(components)

    assert stats["versions_inherited"] == 2
    assert components[1].resolved_version == "1.41.14"
    assert components[2].resolved_version == "1.41.14"
    assert all(
        any(
            prop["name"] == "firmware:version:resolution-state" and prop["value"] == "estimated"
            for prop in item.properties
        )
        for item in components[1:]
    )
    assert all(
        any(
            prop["name"] == "firmware:version:family" and prop["value"] == "e2fsprogs"
            for prop in item.properties
        )
        for item in components[1:]
    )


def test_conflicting_family_versions_do_not_propagate():
    components = [
        component("libicuuc.so", "51.x"),
        component("libicu.so", "52.x"),
        component("libicui18n.so"),
    ]

    stats = apply_family_version_provenance(components)

    assert stats["versions_inherited"] == 0
    assert components[2].resolved_version == ""
