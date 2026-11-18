"""Tests for SDK version properties embedded at the root of APK archives."""

import io
import warnings
import zipfile

from firmware_scanner.extraction.sdk_metadata import extract_sdk_metadata


def _archive(entries):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    data.seek(0)
    return zipfile.ZipFile(data)


def test_extracts_google_and_firebase_release_with_full_archive_evidence():
    with _archive([
        ("play-services-base.properties",
         "version=18.1.0\nclient=play-services-base\nplay-services-base_client=18.1.0\n"),
        ("firebase-auth.properties",
         "version=24.0.1\nclient=firebase-auth\nfirebase-auth_client=24.0.1\n"),
    ]) as archive:
        components = extract_sdk_metadata(archive, "/product/app/sample.apk")

    assert {(item.name, item.resolved_version, item.purl) for item in components} == {
        ("com.google.android.gms:play-services-base", "18.1.0",
         "pkg:maven/com.google.android.gms/play-services-base@18.1.0"),
        ("com.google.firebase:firebase-auth", "24.0.1",
         "pkg:maven/com.google.firebase/firebase-auth@24.0.1"),
    }
    for component in components:
        evidence = component.versions[0].evidence
        assert "/product/app/sample.apk!/" in evidence
        assert component.resolved_version in evidence
        provenance = next(
            p["value"] for p in component.properties
            if p["name"] == "firmware:metadata_provenance"
        )
        artifact = component.name.rsplit(":", 1)[-1]
        assert f"/{artifact}/{component.resolved_version}/{artifact}-{component.resolved_version}.aar" in provenance
        assert f"/{artifact}/{component.resolved_version}/{artifact}-{component.resolved_version}.pom" in provenance


def test_ignores_malformed_mismatched_and_unowned_version_properties():
    with _archive([
        ("firebase-auth.properties",
         "version=24.0.1\nclient=firebase-auth\nfirebase-auth_client=24.0.0\n"),
        ("play-services-base.properties",
         "version=18.1.0\nclient=play-services-tasks\nplay-services-base_client=18.1.0\n"),
        ("kotlin-tooling-metadata.json", '{"compilerVersion":"2.0.0"}'),
        ("version.properties", "version=3.1.4\nclient=gradle\nversion_client=3.1.4\n"),
        ("firebase-messaging.properties",
         "version=24.0.1\nclient=firebase-messaging\n"
         "firebase-messaging_client=24.0.1\nhostversion=20261118\n"),
        ("META-INF/firebase-auth.properties",
         "version=24.0.1\nclient=firebase-auth\nfirebase-auth_client=24.0.1\n"),
    ]) as archive:
        assert extract_sdk_metadata(archive, "app.apk") == []


def test_conflicting_versions_keep_identity_but_do_not_resolve():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with _archive([
            ("firebase-auth.properties",
             "version=24.0.1\nclient=firebase-auth\nfirebase-auth_client=24.0.1\n"),
            ("firebase-auth.properties",
             "version=25.0.0\nclient=firebase-auth\nfirebase-auth_client=25.0.0\n"),
        ]) as archive:
            notices = []
            components = extract_sdk_metadata(archive, "app.apk", notices)

    assert len(components) == 1
    assert components[0].name == "com.google.firebase:firebase-auth"
    assert components[0].resolved_version == ""
    assert components[0].purl == "pkg:maven/com.google.firebase/firebase-auth"
    assert {claim.version for claim in components[0].versions} == {"24.0.1", "25.0.0"}
    assert any("Conflicting SDK metadata" in warning for warning in notices)


def test_rejects_duplicate_identity_fields_and_skips_oversized_entries():
    with _archive([
        ("firebase-auth.properties",
         "version=24.0.1\nversion=24.0.1\nclient=firebase-auth\nfirebase-auth_client=24.0.1\n"),
        ("play-services-base.properties",
         "version=18.1.0\nclient=play-services-base\nplay-services-base_client=18.1.0\n" + "#" * 17_000),
        ("private-sdk.properties",
         "version=4.5.6\nclient=private-sdk\nprivate-sdk_client=4.5.6\n"),
    ]) as archive:
        notices = []
        components = extract_sdk_metadata(archive, "app.apk", notices)

    assert components == []
    assert any("Cannot read bounded SDK metadata" in warning for warning in notices)


def test_rejects_unverified_artifact_names_and_placeholder_releases():
    with _archive([
        ("review-constructor.properties",
         "version=1.0\nclient=review-constructor\nreview-constructor_client=1.0\n"),
        ("user-messaging-platform-fork.properties",
         "version=1.0\nclient=user-messaging-platform-fork\n"
         "user-messaging-platform-fork_client=1.0\n"),
        ("firebase-auth.properties",
         "version=latest.release\nclient=firebase-auth\n"
         "firebase-auth_client=latest.release\n"),
        ("firebase-messaging.properties",
         "version=detected\nclient=firebase-messaging\n"
         "firebase-messaging_client=detected\n"),
        ("firebase-installations.properties",
         "version=unknown\nclient=firebase-installations\n"
         "firebase-installations_client=unknown\n"),
        ("firebase-components.properties",
         "version=unspecified\nclient=firebase-components\n"
         "firebase-components_client=unspecified\n"),
        ("play-services-tasks.properties",
         "version=18.+\nclient=play-services-tasks\n"
         "play-services-tasks_client=18.+\n"),
    ]) as archive:
        assert extract_sdk_metadata(archive, "app.apk") == []


def test_oversized_entry_does_not_hide_later_valid_sdk_metadata():
    with _archive([
        ("firebase-auth.properties", "#" * (9 * 1024 * 1024)),
        ("play-services-base.properties",
         "version=18.1.0\nclient=play-services-base\nplay-services-base_client=18.1.0\n"),
    ]) as archive:
        notices = []
        components = extract_sdk_metadata(archive, "app.apk", notices)

    assert [(component.name, component.resolved_version) for component in components] == [
        ("com.google.android.gms:play-services-base", "18.1.0")
    ]
    assert any("Cannot read bounded SDK metadata" in warning for warning in notices)
