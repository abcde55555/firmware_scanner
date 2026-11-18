import hashlib
import io
import zipfile

import pytest

from experiments.version_coverage.build_sample_index import parse_aar


def make_aar(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def make_pom(group="androidx.graphics", artifact="graphics-path", version="1.0.0"):
    return f"""<?xml version='1.0'?>
    <project><groupId>{group}</groupId><artifactId>{artifact}</artifactId>
    <version>{version}</version></project>""".encode()


def parse(
    aar,
    version="1.0.0",
    pom=None,
    group="androidx.graphics",
    artifact="graphics-path",
    upstream_source="https://developer.android.com/jetpack/androidx/releases/graphics",
    repository_base="https://dl.google.com/dl/android/maven2",
):
    return parse_aar(
        aar,
        pom or make_pom(version=version),
        expected_group=group,
        expected_artifact=artifact,
        version=version,
        artifact_url=f"{repository_base}/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.aar",
        upstream_source=upstream_source,
        version_kind="artifact-release",
    )


def test_imports_only_elf_shared_libraries_with_schema_provenance():
    elf = b"\x7fELFfixture-bytes"
    aar = make_aar({
        "jni/arm64-v8a/libgraphics_path.so": elf,
        "jni/armeabi-v7a/libgraphics_path.so": b"not an elf",
        "assets/readme.txt": b"ignored",
    })

    samples = parse(aar)

    assert samples == [{
        "name": "libgraphics_path.so",
        "version": "1.0.0",
        "sha256": hashlib.sha256(elf).hexdigest(),
        "source": "https://dl.google.com/dl/android/maven2/androidx/graphics/graphics-path/1.0.0/graphics-path-1.0.0.aar",
        "upstream_source": "https://developer.android.com/jetpack/androidx/releases/graphics",
        "artifact_path": "jni/arm64-v8a/libgraphics_path.so",
        "architecture": "arm64-v8a",
        "version_kind": "artifact-release",
    }]


def test_identical_full_file_bytes_keep_all_version_records():
    elf = b"\x7fELFsame-upstream-binary"
    aar = make_aar({"jni/x86_64/libtensorflowlite_jni.so": elf})

    samples = parse(
        aar, "2.10.0", make_pom("org.tensorflow", "tensorflow-lite", "2.10.0"),
        group="org.tensorflow", artifact="tensorflow-lite",
        upstream_source="https://github.com/tensorflow/tensorflow/releases",
        repository_base="https://repo.maven.apache.org/maven2",
    ) + parse(
        aar, "2.11.0", make_pom("org.tensorflow", "tensorflow-lite", "2.11.0"),
        group="org.tensorflow", artifact="tensorflow-lite",
        upstream_source="https://github.com/tensorflow/tensorflow/releases",
        repository_base="https://repo.maven.apache.org/maven2",
    )

    assert len(samples) == 2
    assert samples[0]["sha256"] == samples[1]["sha256"]
    assert {sample["version"] for sample in samples} == {"2.10.0", "2.11.0"}


def test_rejects_pom_coordinate_mismatch():
    aar = make_aar({"jni/arm64-v8a/libfoo.so": b"\x7fELFdata"})

    with pytest.raises(ValueError, match="POM coordinates"):
        parse(aar, pom=make_pom(version="1.0.1"))


def test_rejects_samples_attributed_to_a_relocated_coordinate():
    aar = make_aar({"jni/arm64-v8a/libtensorflowlite_jni.so": b"\x7fELFdata"})
    pom = b"""<project><groupId>org.tensorflow</groupId><artifactId>tensorflow-lite</artifactId>
    <version>2.17.0</version><distributionManagement><relocation>
    <groupId>com.google.ai.edge.litert</groupId><artifactId>litert</artifactId>
    <version>1.0.1</version></relocation></distributionManagement></project>"""

    with pytest.raises(ValueError, match="relocation"):
        parse(
            aar,
            "2.17.0",
            pom,
            group="org.tensorflow",
            artifact="tensorflow-lite",
            upstream_source="https://github.com/tensorflow/tensorflow/releases",
            repository_base="https://repo.maven.apache.org/maven2",
        )


def test_rejects_dangerous_archive_member_paths():
    aar = make_aar({"jni/../../outside/libfoo.so": b"\x7fELFdata"})

    with pytest.raises(ValueError, match="unsafe archive member path"):
        parse(aar)
