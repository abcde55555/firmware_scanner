import pytest


def extract_filename_release(filename):
    try:
        from firmware_scanner.extraction.filename_release import extract_filename_release
    except ImportError:
        pytest.fail("filename release parser has not been implemented")
    return extract_filename_release(filename)


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        (
            "libcronet.141.0.7340.3.so",
            ("libcronet", "141.0.7340.3"),
        ),
        (
            "/system/lib64/libmainlinecronet.133.0.6876.3.so",
            ("libmainlinecronet", "133.0.6876.3"),
        ),
        (
            "libchrome.1985.135.so",
            ("libchrome", "1985.135"),
        ),
        (
            "libexample-1.2.3.so",
            ("libexample", "1.2.3"),
        ),
        (
            "libexample_v2.4.0.so",
            ("libexample", "2.4.0"),
        ),
    ],
)
def test_extracts_release_when_filename_anchors_it_to_its_component(filename, expected):
    result = extract_filename_release(filename)

    assert result is not None
    component_name, release, evidence = result
    assert (component_name, release) == expected
    assert filename.rsplit("/", 1)[-1] in evidence


@pytest.mark.parametrize(
    "filename",
    [
        "libfoo.so.1.2.3",  # ABI SONAME version follows .so.
        "libstagefright_bufferpool@2.0.1.so",  # HIDL interface version
        "android.hardware.audio.common-V1-ndk.so",  # AIDL interface version
        "libexample_api34.so",  # Architecture/API level marker
        "libexample_api-1.2.3.so",  # API component's suffix is not its release
        "libsoftwinner-ril-4.4.so",  # Ambiguous short suffix, not a release claim
        "libexample.so",
        "libexample.1.2.3.so.4",
        "",
    ],
)
def test_rejects_abi_interface_api_and_non_release_suffixes(filename):
    assert extract_filename_release(filename) is None


def test_inventory_keeps_filename_release_on_its_host_and_dependency_version_separate():
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    data = b"\x7fELF" + b"\x00" * 256 + b"\x00Zstandard v1.5.6\x00"
    result = BinaryInventory().extract(data, "libcronet.141.0.7340.3.so", "/lib/libcronet.141.0.7340.3.so")
    host = next(component for component in result if component.name == "libcronet.141.0.7340.3.so")
    assert host.resolved_version == "141.0.7340.3"
    assert "filename release" in host.versions[-1].evidence
    dependency = next(component for component in result if component.name.lower() == "zstd")
    assert dependency.resolved_version == "1.5.6"


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("libelf-0.194.so", ("libelf", "0.194")),
        ("libcjson.so.1.7.19", ("libcjson", "1.7.19")),
        ("libfmt.so.10.1.0", ("libfmt", "10.1.0")),
        ("libhwy.so.1.3.0", ("libhwy", "1.3.0")),
        ("libjsoncpp.so.1.9.6", ("libjsoncpp", "1.9.6")),
        ("libpugixml.so.1.16", ("libpugixml", "1.16")),
        ("libspdlog.so.1.15.3", ("libspdlog", "1.15.3")),
        ("libtinyxml2.so.11.0.0", ("libtinyxml2", "11.0.0")),
        ("libyaml-cpp.so.0.8.0", ("libyaml-cpp", "0.8.0")),
    ],
)
def test_release_soname_allowlist_recovers_named_upstream_versions(
    filename,
    expected,
):
    result = extract_filename_release(filename)

    assert result is not None
    assert (result[0], result[1]) == expected
