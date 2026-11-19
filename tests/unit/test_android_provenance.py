import gzip

from firmware_scanner.android.provenance import (
    apply_android_provenance,
    parse_notice_attributions,
    source_manifest_matches_image,
)
from firmware_scanner.android.provenance import load_source_version_pins
from firmware_scanner.android.system_scanner import AndroidSystemScanner
from firmware_scanner.extraction.models import Component, VersionConfidence
from firmware_scanner.vuln.matcher import _is_scannable


def native(name: str, location: str) -> Component:
    return Component(
        name=name,
        resolved_version="",
        description=f"Native library at {location}",
        versions=[
            VersionConfidence(
                version="",
                confidence=0.5,
                evidence=f"ELF file at {location}; release version unknown",
            )
        ],
        properties=[{"name": "firmware:evidence:location", "value": location}],
    )


def test_notice_and_manifest_attach_aosp_build_revision():
    notice = gzip.compress(
        b'<licenses><file-name lib="frameworks/av">//system/lib/libcodec2.so</file-name></licenses>'
    )
    attributions = parse_notice_attributions(notice)
    component = native("libcodec2.so", "/system/lib/libcodec2.so")
    stats = apply_android_provenance(
        [component],
        notice_attributions=attributions,
        source_manifest={
            "projects": [
                {
                    "path": "frameworks/av",
                    "name": "LineageOS/android_frameworks_av",
                    "revision": "17db49fe6b4b3cca376fb943701f1224ed325f43",
                }
            ]
        },
    )
    assert stats["source_revisions_applied"] == 1
    assert component.resolved_version == "git:17db49fe6b4b3cca376fb943701f1224ed325f43"
    assert {
        "name": "firmware:version:kind",
        "value": "estimated-source-revision",
    } in component.properties
    assert {"name": "firmware:source:project", "value": "frameworks/av"} in component.properties


def test_unique_parent_apex_version_is_used_only_after_source_revision():
    parent = Component(
        name="com.example.module",
        component_type="application",
        resolved_version="360499999",
        properties=[
            {
                "name": "firmware:evidence:location",
                "value": "/system/apex/com.example.module.apex",
            }
        ],
    )
    library = native(
        "libmodule.so",
        "/system/apex/com.example.module.apex!/apex_payload.img/lib64/libmodule.so",
    )
    stats = apply_android_provenance([parent, library])
    assert stats["parent_package_versions_applied"] == 1
    assert library.resolved_version == "360499999"
    assert {
        "name": "firmware:version:scope",
        "value": "parent-package-not-upstream-library",
    } in library.properties


def test_conflicting_parent_versions_leave_library_unknown_and_not_vulnerability_scannable():
    parent_a = Component(
        name="a",
        component_type="application",
        resolved_version="1",
        properties=[
            {
                "name": "firmware:evidence:location",
                "value": "/system/apex/a.apex",
            }
        ],
    )
    parent_b = Component(
        name="b",
        component_type="application",
        resolved_version="2",
        properties=[
            {
                "name": "firmware:evidence:location",
                "value": "/system/apex/b.apex",
            }
        ],
    )
    library = native("libshared.so", "/system/lib64/libshared.so")
    library.properties.append(
        {
            "name": "firmware:evidence:location",
            "value": "/system/apex/a.apex!/apex_payload.img/lib64/libshared.so",
        }
    )
    library.properties.append(
        {
            "name": "firmware:evidence:location",
            "value": "/system/apex/b.apex!/apex_payload.img/lib64/libshared.so",
        }
    )
    apply_android_provenance([parent_a, parent_b, library])
    assert library.resolved_version == ""
    assert not _is_scannable(library)


def test_provenance_estimate_is_not_sent_to_osv():
    component = native("libcodec2.so", "/system/lib/libcodec2.so")
    component.resolved_version = "git:abc123"
    component.properties.append(
        {
            "name": "firmware:version:kind",
            "value": "estimated-source-revision",
        }
    )
    assert not _is_scannable(component)


def test_byte_identical_direct_copy_inherits_container_provenance():
    parent = Component(
        name="com.example.module",
        component_type="application",
        resolved_version="360499999",
        properties=[
            {
                "name": "firmware:evidence:location",
                "value": "/system/apex/com.example.module.apex",
            }
        ],
    )
    digest = "a" * 64
    apex_copy = native(
        "libshared.so",
        "/system/apex/com.example.module.apex!/apex_payload.img/lib64/libshared.so",
    )
    direct_copy = native("libshared.so", "/system/lib64/libshared.so")
    apex_copy.properties.append({"name": "firmware:binary:sha256", "value": digest})
    direct_copy.properties.append({"name": "firmware:binary:sha256", "value": digest})
    stats = apply_android_provenance([parent, apex_copy, direct_copy])
    assert stats["parent_package_versions_applied"] == 1
    assert stats["byte_identical_provenance_propagated"] == 1
    assert apex_copy.resolved_version == "360499999"
    assert direct_copy.resolved_version == "360499999"
    assert {
        "name": "firmware:evidence:inherited-from-container-sha256",
        "value": digest,
    } in direct_copy.properties


def test_same_name_with_different_hash_does_not_inherit_provenance():
    parent = Component(
        name="com.example.module",
        component_type="application",
        resolved_version="360499999",
        properties=[
            {
                "name": "firmware:evidence:location",
                "value": "/system/apex/com.example.module.apex",
            }
        ],
    )
    apex_copy = native(
        "libshared.so",
        "/system/apex/com.example.module.apex!/apex_payload.img/lib64/libshared.so",
    )
    direct_copy = native("libshared.so", "/system/lib64/libshared.so")
    apex_copy.properties.append({"name": "firmware:binary:sha256", "value": "a" * 64})
    direct_copy.properties.append({"name": "firmware:binary:sha256", "value": "b" * 64})
    apply_android_provenance([parent, apex_copy, direct_copy])
    assert apex_copy.resolved_version == "360499999"
    assert direct_copy.resolved_version == ""


def test_partially_resolved_parent_set_is_not_used():
    parent = Component(
        name="known",
        component_type="application",
        resolved_version="360499999",
        properties=[
            {
                "name": "firmware:evidence:location",
                "value": "/system/apex/known.apex",
            }
        ],
    )
    library = native(
        "libshared.so",
        "/system/apex/known.apex!/apex_payload.img/lib64/libshared.so",
    )
    library.properties.append(
        {
            "name": "firmware:evidence:location",
            "value": "/system/apex/missing.apex!/apex_payload.img/lib64/libshared.so",
        }
    )
    apply_android_provenance([parent, library])
    assert library.resolved_version == ""


def test_multiple_parents_with_the_same_version_are_accepted():
    parents = [
        Component(
            name=f"module-{index}",
            component_type="application",
            resolved_version="360499999",
            properties=[
                {
                    "name": "firmware:evidence:location",
                    "value": f"/system/apex/module-{index}.apex",
                }
            ],
        )
        for index in range(2)
    ]
    library = native(
        "libshared.so",
        "/system/apex/module-0.apex!/apex_payload.img/lib64/libshared.so",
    )
    library.properties.append(
        {
            "name": "firmware:evidence:location",
            "value": "/system/apex/module-1.apex!/apex_payload.img/lib64/libshared.so",
        }
    )
    apply_android_provenance([*parents, library])
    assert library.resolved_version == "360499999"


def test_explicit_source_manifest_requires_exact_image_hash():
    image_hash = "a" * 64
    assert source_manifest_matches_image({"image_sha256": image_hash}, image_hash)
    assert not source_manifest_matches_image({"projects": []}, image_hash)
    assert not source_manifest_matches_image({"image_sha256": "b" * 64}, image_hash)


def test_hal_namespace_rule_uses_declared_source_project_revision():
    component = native(
        "android.hardware.audio.core-V3-ndk.so",
        "/system/lib64/android.hardware.audio.core-V3-ndk.so",
    )
    stats = apply_android_provenance(
        [component],
        source_manifest={
            "projects": [
                {
                    "path": "hardware/interfaces",
                    "name": "LineageOS/android_hardware_interfaces",
                    "revision": "c" * 40,
                }
            ]
        },
        source_project_rules=[
            {
                "pattern": r"^android\.hardware\.",
                "project_path": "hardware/interfaces",
                "confidence": 0.72,
                "evidence": "HAL namespace",
            }
        ],
    )
    assert stats["source_revisions_applied"] == 1
    assert component.resolved_version == "git:" + "c" * 40
    assert {
        "name": "firmware:source:project",
        "value": "hardware/interfaces",
    } in component.properties


def test_unrelated_system_namespace_is_not_assigned_to_hardware_interfaces():
    component = native(
        "android.system.keystore2-V1-ndk.so",
        "/system/lib64/android.system.keystore2-V1-ndk.so",
    )
    apply_android_provenance(
        [component],
        source_manifest={
            "projects": [
                {
                    "path": "hardware/interfaces",
                    "name": "LineageOS/android_hardware_interfaces",
                    "revision": "c" * 40,
                }
            ]
        },
        source_project_rules=[
            {
                "pattern": r"^android\.hardware\.",
                "project_path": "hardware/interfaces",
            }
        ],
    )
    assert component.resolved_version == ""


def test_pinned_source_revision_supplies_declared_upstream_version():
    component = native("libft2.so", "/system/lib64/libft2.so")
    stats = apply_android_provenance(
        [component],
        source_manifest={
            "projects": [{
                "path": "external/freetype",
                "name": "platform/external/freetype",
                "revision": "d968d2541f7158e18ab22680bfa08a538019bf6a",
            }],
        },
        source_project_rules=[{
            "pattern": r"^libft2\.so$",
            "project_path": "external/freetype",
            "confidence": 0.86,
            "evidence": "FreeType SONAME fixture",
        }],
    )
    assert stats["source_versions_applied"] == 1
    assert component.resolved_version == "2.13.2"
    assert component.versions[-1].method.value == "build_metadata"
    assert {
        "name": "firmware:version:resolution-state",
        "value": "exact",
    } in component.properties
    assert {
        "name": "firmware:version:scope",
        "value": "source-project-declared-release",
    } in component.properties


def test_source_version_pin_does_not_apply_to_a_different_revision():
    component = native("libft2.so", "/system/lib64/libft2.so")
    apply_android_provenance(
        [component],
        source_manifest={
            "projects": [{
                "path": "external/freetype",
                "name": "platform/external/freetype",
                "revision": "f" * 40,
            }],
        },
        source_project_rules=[{
            "pattern": r"^libft2\.so$",
            "project_path": "external/freetype",
            "confidence": 0.86,
        }],
    )
    assert component.resolved_version == "git:" + "f" * 40


def test_source_version_pin_pack_is_immutable_and_complete():
    pins = load_source_version_pins()
    assert pins
    for pin in pins:
        assert pin["project_path"]
        assert len(pin["revision"]) == 40
        assert pin["version"]
        assert pin["source_url"].startswith("https://")


def test_source_project_rule_pack_covers_external_binary_families():
    rules = AndroidSystemScanner._load_source_project_rules()
    assert len(rules) >= 20
    freetype = next(
        rule for rule in rules
        if rule["project_path"] == "external/freetype"
    )
    assert __import__("re").search(freetype["pattern"], "libft2.so")


def test_exact_source_declared_release_can_generate_upstream_cpe():
    component = native("libz.so", "/system/lib/libz.so")
    component.resolved_version = "1.3.0.1-motley"
    component.versions = [
        VersionConfidence(
            version="1.3.0.1-motley",
            confidence=0.97,
            method="build_metadata",
            evidence="version from pinned source",
        )
    ]
    component.properties.extend([
        {
            "name": "firmware:version:resolution-state",
            "value": "exact",
        },
        {
            "name": "firmware:version:kind",
            "value": "source-declared-release",
        },
    ])
    assert AndroidSystemScanner._should_synthesize_upstream_cpe(component)


def test_estimated_source_revision_does_not_generate_upstream_cpe():
    component = native("libcodec2.so", "/system/lib/libcodec2.so")
    component.resolved_version = "git:" + "a" * 40
    component.properties.extend([
        {
            "name": "firmware:version:resolution-state",
            "value": "estimated-source-revision",
        },
        {
            "name": "firmware:version:kind",
            "value": "estimated-source-revision",
        },
    ])
    assert not AndroidSystemScanner._should_synthesize_upstream_cpe(component)
