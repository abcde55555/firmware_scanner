import gzip
import json

import pytest

from firmware_scanner.android.provenance import (
    _pinned_version_extends,
    apply_android_provenance,
    apply_component_taxonomy,
    classify_source_project,
    load_source_version_pins,
    parse_notice_attributions,
    source_manifest_matches_image,
)
from firmware_scanner.android.system_scanner import AndroidScanResult, AndroidSystemScanner
from firmware_scanner.extraction.binary_inventory import BinaryInventory
from firmware_scanner.extraction.models import Component, ExtractionMethod, VersionConfidence
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


def test_android_scanner_attaches_licenses_from_notice_html():
    notice = gzip.compress(b"""
    <tr><td class="same-license">
      <div class="file-list">/system/lib/libft2.so</div>
      <pre class="license-text">The FreeType Project LICENSE</pre>
    </td></tr>
    """)

    class Filesystem:
        def read_file(self, path, max_size=16 * 1024 * 1024):
            return notice if path == "/etc/NOTICE.html.gz" else None

    component = native("libft2.so", "/lib/libft2.so")
    result = AndroidScanResult(components=[component])
    stats = AndroidSystemScanner(Filesystem())._apply_android_provenance(result)

    assert component.licenses == ["FTL"]
    assert stats["notice_license_attribution"] == {
        "notice_files_matched": 1,
        "components_licensed": 1,
        "existing_licenses_preserved": 0,
    }


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


def test_unique_parent_apex_version_is_scoped_to_contained_executables():
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
    executable = Component(
        name="module_tool",
        component_type="application",
        resolved_version="",
        description=(
            "ELF executable at "
            "/system/apex/com.example.module.apex!/apex_payload.img/bin/module_tool"
        ),
        versions=[VersionConfidence(version="", confidence=0.5)],
        properties=[
            {
                "name": "firmware:evidence:location",
                "value": ("/system/apex/com.example.module.apex!/apex_payload.img/bin/module_tool"),
            }
        ],
    )

    stats = apply_android_provenance([parent, executable])

    assert stats["parent_package_versions_applied"] == 1
    assert executable.resolved_version == "360499999"
    assert {
        "name": "firmware:version:scope",
        "value": "parent-package-not-upstream-component",
    } in executable.properties
    assert {
        "name": "firmware:version:resolution-state",
        "value": "estimated-parent-package",
    } in executable.properties


def test_framework_components_use_a_scoped_platform_build_baseline():
    framework = Component(
        name="framework/core",
        component_type="framework",
        resolved_version="",
        description="Framework JAR at /framework/core.jar",
        versions=[VersionConfidence(version="", confidence=0.6)],
        properties=[],
    )

    stats = apply_android_provenance(
        [framework],
        platform_baseline="4.4.4-KTU84Q-20180511",
    )

    assert stats["platform_build_versions_applied"] == 1
    assert framework.resolved_version == "4.4.4-KTU84Q-20180511"
    assert {
        "name": "firmware:version:resolution-state",
        "value": "estimated-platform-build",
    } in framework.properties
    assert {
        "name": "firmware:version:scope",
        "value": "platform-build-not-upstream-release",
    } in framework.properties
    assert {
        "name": "firmware:taxonomy",
        "value": "platform-first-party",
    } in framework.properties


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/system/framework/core.jar", True),
        ("/framework/core.jar", True),
        ("/vendor/framework/core.jar", False),
        ("/product/framework/core.jar", False),
    ],
)
def test_platform_build_scope_accepts_only_system_or_partition_root_framework(
    path: str,
    expected: bool,
):
    framework = Component(
        name="framework/core",
        component_type="framework",
        resolved_version="",
        description=f"Framework JAR at {path}",
        versions=[VersionConfidence(version="", confidence=0.6)],
        properties=[],
    )

    stats = apply_android_provenance(
        [framework],
        platform_baseline="16-BP2A.250805.005-1775195212",
    )

    assert stats["platform_build_versions_applied"] == int(expected)
    assert bool(framework.resolved_version) is expected


def test_upstream_source_evidence_marks_third_party_oss_without_guessing():
    component = native("WebRTC AEC", "/lib/libwebrtc_audio_preprocessing.so")
    component.properties.append(
        {
            "name": "firmware:evidence:source",
            "value": (
                "https://android.googlesource.com/platform/external/webrtc/"
                "+/4b6dc1ec58105d17dc8c2f550124cc0621dc93b7/"
            ),
        }
    )
    emba_component = native("RuleOnly", "/lib/libunknown.so")
    emba_component.properties.append(
        {"name": "firmware:evidence:source", "value": "https://github.com/e-m-b-a/emba"}
    )

    apply_component_taxonomy([component, emba_component])

    assert {
        "name": "firmware:taxonomy",
        "value": "third-party-oss",
    } in component.properties
    assert not any(
        prop.get("name") == "firmware:taxonomy"
        for prop in emba_component.properties
    )


@pytest.mark.parametrize(
    ("component_name", "project_path", "base_version", "expected"),
    [
        ("libevent", "external/libevent", "", "2.1.12-stable"),
        ("OpenSSH", "external/openssh", "9.0", "9.0p1"),
        ("SpeexDSP", "external/speex", "", "1.2.1"),
        ("libyuv", "external/libyuv", "", "1883"),
    ],
)
def test_contained_component_inherits_host_source_path_and_uses_exact_pin(
    component_name,
    project_path,
    base_version,
    expected,
):
    pin = next(
        item
        for item in load_source_version_pins()
        if item["project_path"] == project_path
    )
    location = f"/system/bin/{component_name.lower()}"
    host = native("host-bin", location)
    host.properties.extend(
        [
            {"name": "firmware:source:path-project", "value": project_path},
            {
                "name": "firmware:source:path-evidence",
                "value": (
                    f'{{"project": "{project_path}", "source_path": '
                    f'"{project_path}/source.c", "file_offset": 16}}'
                ),
            },
        ]
    )
    contained = native(component_name, location)
    contained.resolved_version = base_version
    contained.properties.extend(
        [
            {"name": "firmware:evidence:container", "value": "host-bin"},
            {"name": "firmware:relationship", "value": "contains-evidence-for"},
            {"name": "firmware:identity", "value": component_name},
        ]
    )
    if base_version:
        contained.properties.append(
            {"name": "firmware:version:resolution-state", "value": "exact"}
        )

    stats = apply_android_provenance(
        [host, contained],
        source_manifest={
            "projects": [
                {
                    "path": project_path,
                    "name": f"test/{project_path}",
                    "revision": pin["revision"],
                }
            ]
        },
        source_project_rules=[
            {
                "pattern": f"^{component_name}$",
                "project_path": project_path,
                "confidence": 0.94,
                "evidence": "test exact source-path identity",
            }
        ],
    )

    assert contained.resolved_version == expected
    assert stats["source_versions_applied"] == 1
    assert {
        "name": "firmware:source:revision",
        "value": pin["revision"],
    } in contained.properties


def test_source_pin_does_not_replace_an_unrelated_exact_version():
    assert not _pinned_version_extends("9.0", "10.0p1")
    assert not _pinned_version_extends("9.0", "9.1p1")


def test_contained_identity_uses_location_filename_for_aosp_release_rule():
    location = "/lib/libvorbisidec.so"
    host = native("libvorbisidec.so", location)
    contained = native("Tremolo", location)
    contained.properties.extend(
        [
            {"name": "firmware:evidence:container", "value": "libvorbisidec.so"},
            {"name": "firmware:relationship", "value": "contains-evidence-for"},
            {"name": "firmware:identity", "value": "Tremolo"},
        ]
    )

    stats = apply_android_provenance(
        [host, contained],
        android_version="4.4.4",
        android_build_id="KTU84Q",
    )

    assert host.resolved_version == "0.07"
    assert contained.resolved_version == "0.07"
    assert stats["aosp_release_versions_applied"] == 2


def test_boringssl_revision_requires_an_embedded_source_path():
    revision = "ecc1358826150d6a1851c517c325b0e6c0e1b8be"
    component = native("libcrypto.so", "/system/lib64/libcrypto.so")
    component.properties.extend(
        [
            {"name": "firmware:source:path-project", "value": "external/boringssl"},
            {
                "name": "firmware:source:path-evidence",
                "value": json.dumps(
                    {
                        "project": "external/boringssl",
                        "source_path": "external/boringssl/src/crypto/err/err.c",
                        "file_offset": 128,
                    }
                ),
            },
        ]
    )
    rules = [
        {
            "pattern": r"^lib(?:crypto|ssl)\.so(?:\.[0-9]+)*$",
            "project_path": "external/boringssl",
            "confidence": 0.9,
            "require_source_path": True,
            "evidence": "test source-path-required BoringSSL identity",
        }
    ]
    manifest = {
        "projects": [
            {
                "path": "external/boringssl",
                "name": "platform/external/boringssl",
                "revision": revision,
            }
        ]
    }

    stats = apply_android_provenance(
        [component],
        source_manifest=manifest,
        source_project_rules=rules,
    )

    assert component.resolved_version == f"git:{revision}"
    assert stats["source_revisions_applied"] == 1
    assert stats["source_versions_applied"] == 0
    assert {
        "name": "firmware:version:resolution-state",
        "value": "estimated-source-revision",
    } in component.properties

    without_path = native("libcrypto.so", "/system/lib64/libcrypto.so")
    apply_android_provenance(
        [without_path],
        source_manifest=manifest,
        source_project_rules=rules,
    )
    assert without_path.resolved_version == ""

    wrong_path = native("libcrypto.so", "/system/lib64/libcrypto.so")
    wrong_path.properties.extend(
        [
            {"name": "firmware:source:path-project", "value": "external/openssl"},
            {
                "name": "firmware:source:path-evidence",
                "value": json.dumps(
                    {
                        "project": "external/openssl",
                        "source_path": "external/openssl/crypto/cryptlib.c",
                        "file_offset": 256,
                    }
                ),
            },
        ]
    )
    apply_android_provenance(
        [wrong_path],
        source_manifest={
            "projects": [
                *manifest["projects"],
                {
                    "path": "external/openssl",
                    "name": "platform/external/openssl",
                    "revision": "f" * 40,
                },
            ]
        },
        source_project_rules=rules,
    )
    assert wrong_path.resolved_version == ""

    incomplete_path = native("libcrypto.so", "/system/lib64/libcrypto.so")
    incomplete_path.properties.append(
        {"name": "firmware:source:path-project", "value": "external/boringssl"}
    )
    apply_android_provenance(
        [incomplete_path],
        source_manifest=manifest,
        source_project_rules=rules,
    )
    assert incomplete_path.resolved_version == ""


def test_perfetto_heapprofd_requires_matching_source_path_and_uses_release_pin():
    revision = "94a71474cc396db2b0fcff6755b8f2d3f7e304d0"
    component = native("heapprofd_client_api.so", "/system/lib64/heapprofd_client_api.so")
    component.properties.extend(
        [
            {"name": "firmware:source:path-project", "value": "external/perfetto"},
            {
                "name": "firmware:source:path-evidence",
                "value": json.dumps(
                    {
                        "project": "external/perfetto",
                        "source_path": (
                            "external/perfetto/src/profiling/memory/"
                            "malloc_interceptor_bionic_hooks.c"
                        ),
                        "file_offset": 5670,
                    }
                ),
            },
        ]
    )
    rules = [
        {
            "pattern": r"^heapprofd_client(?:_api)?\.so(?:\.[0-9]+)*$",
            "project_path": "external/perfetto",
            "confidence": 0.94,
            "require_source_path": True,
            "evidence": "test Perfetto heap profiling client source identity",
        }
    ]
    manifest = {
        "projects": [
            {
                "path": "external/perfetto",
                "name": "platform/external/perfetto",
                "revision": revision,
            }
        ]
    }

    stats = apply_android_provenance(
        [component],
        source_manifest=manifest,
        source_project_rules=rules,
    )

    assert component.resolved_version == "49.0"
    assert stats["source_versions_applied"] == 1
    assert {
        "name": "firmware:version:resolution-state",
        "value": "exact",
    } in component.properties

    without_path = native(
        "heapprofd_client_api.so",
        "/system/lib64/heapprofd_client_api.so",
    )
    apply_android_provenance(
        [without_path],
        source_manifest=manifest,
        source_project_rules=rules,
    )
    assert without_path.resolved_version == ""


@pytest.mark.parametrize(
    ("filename", "identity", "expected_version", "project_path"),
    [
        ("libexif.so", "libexif", "0.6.21", "external/libexif"),
        ("SpeexDSP", "SpeexDSP", "1.2beta3", "external/speex"),
        ("libstlport.so", "STLport", "5.0", "external/stlport"),
        ("libjhead.so", "Jhead", "2.87", "external/jhead"),
        ("libmdnssd.so", "mDNSResponder", "320.10.80", "external/mdnsresponder"),
    ],
)
def test_aosp_release_project_estimates_require_exact_build_and_identity(
    filename: str,
    identity: str,
    expected_version: str,
    project_path: str,
):
    component = native(filename, f"/lib/{filename}")
    component.properties.append({"name": "firmware:identity", "value": identity})

    stats = apply_android_provenance(
        [component],
        android_version="4.4.4",
        android_build_id="KTU84Q",
    )

    assert stats["aosp_release_versions_applied"] == 1
    assert component.resolved_version == expected_version
    assert {
        "name": "firmware:version:resolution-state",
        "value": "estimated-aosp-release",
    } in component.properties
    assert {
        "name": "firmware:source:project",
        "value": project_path,
    } in component.properties
    assert {
        "name": "firmware:source:aosp-tag",
        "value": "android-4.4.4_r2",
    } in component.properties
    assert {
        "name": "firmware:taxonomy",
        "value": "third-party-oss",
    } in component.properties


@pytest.mark.parametrize(
    ("filename", "identity", "revision", "project_path"),
    [
        (
            "libtinyalsa.so",
            "TinyALSA",
            "252af255884d55166115e09c74280aeeeeeb5553",
            "external/tinyalsa",
        ),
        (
            "libsonivox.so",
            "Sonivox",
            "ac263c249db97d9a1c19a1d5d5ca51e937411090",
            "external/sonivox",
        ),
    ],
)
def test_aosp_projects_without_release_versions_use_typed_source_revision(
    filename: str,
    identity: str,
    revision: str,
    project_path: str,
):
    component = native(filename, f"/lib/{filename}")
    component.properties.append({"name": "firmware:identity", "value": identity})

    stats = apply_android_provenance(
        [component],
        android_version="4.4.4",
        android_build_id="KTU84Q",
    )

    assert stats["aosp_release_versions_applied"] == 0
    assert stats["aosp_source_revisions_applied"] == 1
    assert component.resolved_version == f"git:{revision}"
    assert {
        "name": "firmware:version:resolution-state",
        "value": "estimated-aosp-source-revision",
    } in component.properties
    assert {
        "name": "firmware:version:kind",
        "value": "estimated-android-source-revision",
    } in component.properties
    assert {
        "name": "firmware:source:revision",
        "value": revision,
    } in component.properties
    assert {
        "name": "firmware:source:project",
        "value": project_path,
    } in component.properties


@pytest.mark.parametrize(
    ("filename", "expected_version", "project_path"),
    [
        ("libmtp.so", "1.0.1", "external/libmtp"),
        ("libvorbisidec.so", "0.07", "external/tremolo"),
        ("libwebviewchromium.so", "33.0.1750.166", "external/chromium_org"),
    ],
)
def test_aosp_filename_only_estimates_require_exact_build_and_soname(
    filename: str,
    expected_version: str,
    project_path: str,
):
    component = native(filename, f"/lib/{filename}")

    stats = apply_android_provenance(
        [component],
        android_version="4.4.4",
        android_build_id="KTU84Q",
    )

    assert stats["aosp_release_versions_applied"] == 1
    assert component.resolved_version == expected_version
    assert {
        "name": "firmware:version:resolution-state",
        "value": "estimated-aosp-release",
    } in component.properties
    assert {
        "name": "firmware:source:project",
        "value": project_path,
    } in component.properties
    assert {
        "name": "firmware:taxonomy",
        "value": "third-party-oss",
    } in component.properties


def test_aosp_filename_only_estimate_does_not_match_a_suffix_collision():
    component = native("vendor-libmtp.so", "/lib/vendor-libmtp.so")

    stats = apply_android_provenance(
        [component],
        android_version="4.4.4",
        android_build_id="KTU84Q",
    )

    assert stats["aosp_release_versions_applied"] == 0
    assert component.resolved_version == ""


def test_aosp_embedded_library_version_is_not_assigned_to_its_host_wrapper():
    component = native(
        "libstagefright_soft_vorbisdec.so",
        "/lib/libstagefright_soft_vorbisdec.so",
    )

    stats = apply_android_provenance(
        [component],
        android_version="4.4.4",
        android_build_id="KTU84Q",
    )

    assert stats["aosp_release_versions_applied"] == 0
    assert component.resolved_version == ""


def test_aosp_source_path_emits_a_separate_contained_release_component():
    host = native("libAppDataSearch.so", "/lib/libAppDataSearch.so")
    host.properties.append(
        {
            "name": "firmware:source:path-prefix-evidence",
            "value": json.dumps(
                {
                    "project_path": "external/protobuf",
                    "source_path": "external/protobuf/src/google/protobuf/message_lite.c",
                    "file_offset": 0x1234,
                }
            ),
        }
    )
    components = [host]

    stats = apply_android_provenance(
        components,
        android_version="4.4.4",
        android_build_id="KTU84Q",
    )

    assert stats["aosp_release_versions_applied"] == 1
    assert host.resolved_version == ""
    contained = next(component for component in components if component.name == "Protobuf")
    assert contained.resolved_version == "2.3.0"
    assert contained.purl == "pkg:generic/Protobuf@2.3.0"
    assert {
        "name": "firmware:relationship",
        "value": "contains-evidence-for",
    } in contained.properties
    assert {
        "name": "firmware:version:resolution-state",
        "value": "estimated-aosp-release",
    } in contained.properties
    assert contained.versions[0].method == ExtractionMethod.VERSION_ESTIMATE


def test_aosp_release_estimate_can_version_an_identified_resampler_host():
    host = native("libspeexresampler.so", "/lib/libspeexresampler.so")
    contained = native("SpeexDSP", "/lib/libspeexresampler.so")
    contained.properties.extend(
        [
            {"name": "firmware:identity", "value": "SpeexDSP"},
            {"name": "firmware:relationship", "value": "contains-evidence-for"},
        ]
    )

    stats = apply_android_provenance(
        [host, contained],
        android_version="4.4.4",
        android_build_id="KTU84Q",
    )

    assert stats["aosp_release_versions_applied"] == 2
    assert host.resolved_version == "1.2beta3"
    assert contained.resolved_version == "1.2beta3"


def test_jpeg_release_estimate_requires_the_observed_6b_compatibility_abi():
    component = native("libjpeg.so", "/lib/libjpeg.so")
    component.properties.extend(
        [
            {"name": "firmware:identity", "value": "libjpeg"},
            {"name": "firmware:jpeg:abi-version", "value": "62"},
        ]
    )

    stats = apply_android_provenance(
        [component],
        android_version="4.4.4",
        android_build_id="KTU84Q",
    )

    assert stats["aosp_release_versions_applied"] == 1
    assert component.resolved_version == "6b"
    assert {
        "name": "firmware:source:aosp-tag",
        "value": "android-4.4.4_r2",
    } in component.properties


def test_aosp_release_project_estimate_does_not_apply_to_unknown_build_id():
    component = native("libexif.so", "/lib/libexif.so")
    component.properties.append({"name": "firmware:identity", "value": "libexif"})

    stats = apply_android_provenance(
        [component],
        android_version="4.4.4",
        android_build_id="vendor-unknown",
    )

    assert stats["aosp_release_versions_applied"] == 0
    assert component.resolved_version == ""


def test_aosp_release_project_estimate_does_not_override_a_conflict():
    component = native("libexif.so", "/lib/libexif.so")
    component.properties.extend(
        [
            {"name": "firmware:identity", "value": "libexif"},
            {"name": "firmware:version:conflict", "value": "0.6.20, 0.6.21"},
        ]
    )

    stats = apply_android_provenance(
        [component],
        android_version="4.4.4",
        android_build_id="KTU84Q",
    )

    assert stats["aosp_release_versions_applied"] == 0
    assert component.resolved_version == ""


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


def test_embedded_source_path_must_agree_with_the_filename_rule():
    component = native("libopenssl.dylib.so", "/system/lib64/libopenssl.dylib.so")
    component.properties.append(
        {
            "name": "firmware:source:path-project",
            "value": "external/rust/crates/openssl",
        }
    )
    component.properties.append(
        {
            "name": "firmware:source:path-evidence",
            "value": (
                '{"file_offset": 4096, "project": "external/rust/crates/openssl", '
                '"source_path": "external/rust/crates/openssl/src/version.rs"}'
            ),
        }
    )
    stats = apply_android_provenance(
        [component],
        source_manifest={
            "projects": [
                {
                    "path": "external/rust/crates/openssl",
                    "name": "platform/external/rust/crates/openssl",
                    "revision": "e5ef6ef50b72972ad9d0ba582906f27f0b8ba06b",
                }
            ],
        },
        source_project_rules=[
            {
                "pattern": r"^libopenssl\.dylib\.so$",
                "project_path": "external/rust/crates/openssl",
                "confidence": 0.94,
                "evidence": "rust-openssl source files",
            }
        ],
    )

    assert stats["source_versions_applied"] == 1
    assert component.resolved_version == "0.10.64"
    assert {
        "name": "firmware:version:resolution-state",
        "value": "exact",
    } in component.properties
    assert {
        "name": "firmware:taxonomy",
        "value": "third-party-oss",
    } in component.properties
    assert "src/version.rs" in component.versions[-1].evidence
    assert "0x1000" in component.versions[-1].evidence


def test_openssh_manifest_revision_and_version_header_supply_release():
    component = native("libssh.so", "/product/lib64/libssh.so")
    component.properties.append(
        {
            "name": "firmware:source:path-project",
            "value": "external/openssh",
        }
    )
    stats = apply_android_provenance(
        [component],
        source_manifest={
            "projects": [
                {
                    "path": "external/openssh",
                    "name": "LineageOS/android_external_openssh",
                    "revision": "60ca88651d39f699932f63d41409facc18c5ad19",
                }
            ],
        },
        source_project_rules=[
            {
                "pattern": r"^(?:libssh\.so(?:\.[0-9]+)*|openssh)$",
                "project_path": "external/openssh",
                "confidence": 0.94,
            }
        ],
    )

    assert stats["source_versions_applied"] == 1
    assert component.resolved_version == "9.0p1"
    assert {
        "name": "firmware:source:version-authority",
        "value": "SSH_VERSION and SSH_PORTABLE",
    } in component.properties


def test_revision_pinned_rust_crate_resolves_its_own_cargo_release():
    component = native(
        "libandroid_logger.dylib.so",
        "/system/lib64/libandroid_logger.dylib.so",
    )
    component.properties.extend(
        [
            {
                "name": "firmware:source:path-project",
                "value": "external/rust/android-crates-io",
            },
            {
                "name": "firmware:source:path-evidence",
                "value": json.dumps(
                    {
                        "project": "external/rust/android-crates-io",
                        "source_path": (
                            "external/rust/android-crates-io/crates/android_logger/src/arrays.rs"
                        ),
                        "file_offset": 7178,
                    }
                ),
            },
        ]
    )
    apply_android_provenance(
        [component],
        notice_attributions={
            "/system/lib64/libandroid_logger.dylib.so": {
                "external/rust/android-crates-io",
            }
        },
        source_manifest={
            "projects": [
                {
                    "path": "external/rust/android-crates-io",
                    "name": "platform/external/rust/android-crates-io",
                    "revision": "c991cad10330f37e93d82926bd6dae7f4f6647f6",
                }
            ],
        },
        source_project_rules=[],
    )

    assert component.resolved_version == "0.15.0"
    assert component.purl == "pkg:cargo/android_logger@0.15.0"
    assert {
        "name": "firmware:version:resolution-state",
        "value": "exact",
    } in component.properties
    assert {
        "name": "firmware:source:subproject",
        "value": "crates/android_logger",
    } in component.properties
    assert {
        "name": "firmware:version:scope",
        "value": "source-subproject-declared-release",
    } in component.properties


def test_rust_crate_alias_resolves_without_embedded_source_path():
    component = native("libatomic_rust.dylib.so", "/system/lib64/libatomic_rust.dylib.so")
    apply_android_provenance(
        [component],
        notice_attributions={
            "/system/lib64/libatomic_rust.dylib.so": {
                "external/rust/android-crates-io",
            }
        },
        source_manifest={
            "projects": [
                {
                    "path": "external/rust/android-crates-io",
                    "revision": "c991cad10330f37e93d82926bd6dae7f4f6647f6",
                }
            ],
        },
        source_project_rules=[],
    )

    assert component.resolved_version == "0.6.0"
    assert component.purl == "pkg:cargo/atomic@0.6.0"


def test_unmapped_rust_wrapper_keeps_build_revision_instead_of_crate_version():
    component = native(
        "libvsprintf_wrapper.dylib.so",
        "/system/lib64/libvsprintf_wrapper.dylib.so",
    )
    apply_android_provenance(
        [component],
        notice_attributions={
            "/system/lib64/libvsprintf_wrapper.dylib.so": {
                "external/rust/android-crates-io",
            }
        },
        source_manifest={
            "projects": [
                {
                    "path": "external/rust/android-crates-io",
                    "revision": "c991cad10330f37e93d82926bd6dae7f4f6647f6",
                }
            ],
        },
        source_project_rules=[],
    )

    assert component.resolved_version == ("git:c991cad10330f37e93d82926bd6dae7f4f6647f6")
    assert not component.purl.startswith("pkg:cargo/")


@pytest.mark.parametrize(
    "component_name,source_path,package_name,version",
    [
        (
            "libnix.dylib.so",
            "external/rust/android-crates-io/crates/libc/src/unix/mod.rs",
            "nix",
            "0.29.0",
        ),
        (
            "librand_chacha.dylib.so",
            "external/rust/android-crates-io/crates/ppv-lite86/src/lib.rs",
            "rand_chacha",
            "0.3.1",
        ),
        (
            "liblibbpf_rs.dylib.so",
            "external/rust/android-crates-io/crates/vsprintf/src/lib.rs",
            "libbpf-rs",
            "0.24.8",
        ),
    ],
)
def test_dependency_source_path_does_not_override_the_owned_rust_crate(
    component_name,
    source_path,
    package_name,
    version,
):
    component = native(component_name, f"/system/lib64/{component_name}")
    component.properties.extend(
        [
            {
                "name": "firmware:source:path-project",
                "value": "external/rust/android-crates-io",
            },
            {
                "name": "firmware:source:path-evidence",
                "value": json.dumps(
                    {
                        "project": "external/rust/android-crates-io",
                        "source_path": source_path,
                        "file_offset": 4096,
                    }
                ),
            },
        ]
    )
    apply_android_provenance(
        [component],
        notice_attributions={
            f"/system/lib64/{component_name}": {
                "external/rust/android-crates-io",
            }
        },
        source_manifest={
            "projects": [
                {
                    "path": "external/rust/android-crates-io",
                    "revision": "c991cad10330f37e93d82926bd6dae7f4f6647f6",
                }
            ],
        },
        source_project_rules=[],
    )

    assert component.resolved_version == version
    assert component.purl == f"pkg:cargo/{package_name}@{version}"


def test_binary_inventory_records_only_manifest_source_paths():
    payload = (
        b"\x7fELF"
        + bytes(60)
        + b"\0external/rust/crates/openssl/src/version.rs\0"
        + b"unlisted/project/src/file.c\0"
    )
    component = BinaryInventory(
        source_manifest={
            "projects": [
                {"path": "external/rust/crates/openssl", "revision": "a" * 40},
                {"path": "external/rust/android-crates-io", "revision": "b" * 40},
            ],
        }
    ).extract(
        payload,
        "libopenssl.dylib.so",
        "/system/lib64/libopenssl.dylib.so",
    )[0]

    assert [
        prop["value"]
        for prop in component.properties
        if prop["name"] == "firmware:source:path-project"
    ] == ["external/rust/crates/openssl"]
    evidence = json.loads(
        next(
            prop["value"]
            for prop in component.properties
            if prop["name"] == "firmware:source:path-evidence"
        )
    )
    assert evidence == {
        "project": "external/rust/crates/openssl",
        "source_path": "external/rust/crates/openssl/src/version.rs",
        "file_offset": len(b"\x7fELF") + 60 + 1,
    }


def test_embedded_dependency_path_does_not_override_filename_rule():
    component = native("libunrelated.so", "/system/lib64/libunrelated.so")
    component.properties.extend(
        [
            {
                "name": "firmware:source:path-project",
                "value": "external/rust/crates/openssl",
            },
            {
                "name": "firmware:source:path-project",
                "value": "packages/modules/ConfigInfrastructure",
            },
        ]
    )
    apply_android_provenance(
        [component],
        source_manifest={
            "projects": [
                {
                    "path": "external/rust/crates/openssl",
                    "revision": "a" * 40,
                },
                {
                    "path": "packages/modules/ConfigInfrastructure",
                    "revision": "b" * 40,
                },
            ],
        },
        source_project_rules=[
            {
                "pattern": r"^libopenssl\.dylib\.so$",
                "project_path": "external/rust/crates/openssl",
            },
            {
                "pattern": r"^libaconfig_.*\.dylib\.so$",
                "project_path": "packages/modules/ConfigInfrastructure",
            },
        ],
    )

    assert component.resolved_version == ""


def test_adbd_helper_prefers_its_owner_over_an_embedded_logging_dependency():
    component = native("libadbd_fs.so", "/system/lib64/libadbd_fs.so")
    component.properties.append(
        {
            "name": "firmware:source:path-project",
            "value": "system/logging",
        }
    )
    apply_android_provenance(
        [component],
        source_manifest={
            "projects": [
                {"path": "system/logging", "revision": "a" * 40},
                {"path": "packages/modules/adb", "revision": "b" * 40},
            ],
        },
        source_project_rules=AndroidSystemScanner._load_source_project_rules(),
    )

    assert component.resolved_version == "git:" + "b" * 40
    assert {
        "name": "firmware:source:project",
        "value": "packages/modules/adb",
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
            "projects": [
                {
                    "path": "external/freetype",
                    "name": "platform/external/freetype",
                    "revision": "d968d2541f7158e18ab22680bfa08a538019bf6a",
                }
            ],
        },
        source_project_rules=[
            {
                "pattern": r"^libft2\.so$",
                "project_path": "external/freetype",
                "confidence": 0.86,
                "evidence": "FreeType SONAME fixture",
            }
        ],
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
            "projects": [
                {
                    "path": "external/freetype",
                    "name": "platform/external/freetype",
                    "revision": "f" * 40,
                }
            ],
        },
        source_project_rules=[
            {
                "pattern": r"^libft2\.so$",
                "project_path": "external/freetype",
                "confidence": 0.86,
            }
        ],
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
    by_project = {pin["project_path"]: pin for pin in pins if not pin["subpath_prefix"]}
    assert by_project["external/perfetto"]["version"] == "49.0"
    assert by_project["external/fsverity-utils"]["version"] == "1.6"
    assert by_project["external/piex"]["version"] == "0.27"
    rust_pins = [
        pin
        for pin in pins
        if pin["project_path"] == "external/rust/android-crates-io" and pin["subpath_prefix"]
    ]
    assert len(rust_pins) == 43
    assert all(pin["ecosystem"] == "cargo" for pin in rust_pins)


def test_source_project_rule_pack_covers_external_binary_families():
    rules = AndroidSystemScanner._load_source_project_rules()
    assert len(rules) >= 20
    freetype = next(rule for rule in rules if rule["project_path"] == "external/freetype")
    assert __import__("re").search(freetype["pattern"], "libft2.so")
    openssl = next(rule for rule in rules if rule["project_path"] == "external/rust/crates/openssl")
    assert __import__("re").search(openssl["pattern"], "libopenssl.dylib.so")


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
    component.properties.extend(
        [
            {
                "name": "firmware:version:resolution-state",
                "value": "exact",
            },
            {
                "name": "firmware:version:kind",
                "value": "source-declared-release",
            },
        ]
    )
    assert AndroidSystemScanner._should_synthesize_upstream_cpe(component)


def test_estimated_source_revision_does_not_generate_upstream_cpe():
    component = native("libcodec2.so", "/system/lib/libcodec2.so")
    component.resolved_version = "git:" + "a" * 40
    component.properties.extend(
        [
            {
                "name": "firmware:version:resolution-state",
                "value": "estimated-source-revision",
            },
            {
                "name": "firmware:version:kind",
                "value": "estimated-source-revision",
            },
        ]
    )
    assert not AndroidSystemScanner._should_synthesize_upstream_cpe(component)


@pytest.mark.parametrize(
    "project_path,taxonomy",
    [
        ("external/freetype", "third-party-oss"),
        ("frameworks/av", "platform-first-party"),
        ("hardware/interfaces", "platform-first-party"),
        ("vendor/qcom/opensource/power", "vendor-open-source"),
        ("vendor/qcom/proprietary/display", "vendor-proprietary"),
    ],
)
def test_source_project_taxonomy_is_explicit(project_path, taxonomy):
    assert classify_source_project(project_path) == taxonomy


def test_notice_provenance_records_platform_taxonomy():
    notice = gzip.compress(
        b'<licenses><file-name lib="frameworks/av">//system/lib/libcodec2.so</file-name></licenses>'
    )
    component = native("libcodec2.so", "/system/lib/libcodec2.so")
    apply_android_provenance(
        [component],
        notice_attributions=parse_notice_attributions(notice),
        source_manifest={
            "projects": [
                {
                    "path": "frameworks/av",
                    "name": "platform/frameworks/av",
                    "revision": "a" * 40,
                }
            ],
        },
    )
    assert {
        "name": "firmware:taxonomy",
        "value": "platform-first-party",
    } in component.properties
    assert {
        "name": "firmware:taxonomy:evidence",
        "value": "source-project-path",
    } in component.properties


def test_component_taxonomy_uses_external_ecosystem_purls():
    maven = Component(
        name="androidx.core:core",
        purl="pkg:maven/androidx.core/core@1.12.0",
    )
    cargo = Component(
        name="tokio",
        purl="pkg:cargo/tokio@1.44.0",
    )
    generic = Component(
        name="libvendor.so",
        purl="pkg:generic/libvendor.so@1.0",
    )
    apply_component_taxonomy([maven, cargo, generic])
    assert {
        "name": "firmware:taxonomy",
        "value": "third-party-oss",
    } in maven.properties
    assert {
        "name": "firmware:taxonomy",
        "value": "third-party-oss",
    } in cargo.properties
    assert not any(prop["name"] == "firmware:taxonomy" for prop in generic.properties)


def test_component_taxonomy_uses_confirmed_blint_identity():
    component = Component(
        name="libft2.so",
        properties=[
            {
                "name": "firmware:blintdb:identity-confirmed",
                "value": '{"components": ["freetype"], "projects": ["freetype"]}',
            }
        ],
    )

    apply_component_taxonomy([component])

    assert {
        "name": "firmware:taxonomy",
        "value": "third-party-oss",
    } in component.properties
    assert {
        "name": "firmware:taxonomy:evidence",
        "value": "blintdb-confirmed-identity",
    } in component.properties
