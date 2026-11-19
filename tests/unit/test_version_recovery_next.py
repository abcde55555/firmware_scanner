"""Controls for release APIs and complete executable banners; never run targets."""

import shutil
import subprocess

import pytest

from firmware_scanner.extraction.binary_inventory import BinaryInventory, identity_key
from firmware_scanner.extraction.binary_reference import BinaryReferenceMatcher
from firmware_scanner.extraction.elf_deep_extractor import ELFDeepExtractor


@pytest.fixture
def shared_elf(tmp_path):
    cc = shutil.which("cc")
    if cc is None:
        pytest.skip("a C compiler is needed for static ELF controls")

    def compile_source(source, flags=()):
        path = tmp_path / "fixture.c"
        output = tmp_path / "fixture.so"
        path.write_text(source)
        subprocess.run(
            [cc, "-shared", "-fPIC", "-O2", *flags, str(path), "-o", str(output)],
            check=True,
            capture_output=True,
        )
        return output.read_bytes()

    return compile_source


@pytest.mark.parametrize(
    "name,version",
    [
        ("dhcpcd", "5.5.6"),
        ("hostapd", "2.0-devel-4.4.4_rtw_r10450.20140220"),
        ("hostapd_cli", "2.0-devel-4.4.4_rtw_r10450.20140220"),
        ("wpa_cli", "2.0-devel-4.4.4_rtw_r10450.20140220"),
        ("wpa_supplicant", "2.0-devel-4.4.4_rtw_r10450.20140220"),
    ],
)
def test_executable_banner_keeps_the_complete_own_version(name, version):
    prefix = "" if name == "dhcpcd" else "v"
    payload = b"\x7fELF" + bytes(60) + f"\0{name} {prefix}{version}\n".encode()
    components = BinaryInventory().extract(payload, name, f"/bin/{name}", "application")
    assert components[0].resolved_version == version


def test_deep_wpa_banner_does_not_truncate_the_vendor_branch():
    payload = b"\x7fELF" + bytes(60) + b"wpa_supplicant v2.0-devel-4.4.4_rtw_r10450.20140220\0"
    hit = ELFDeepExtractor().extract("wpa_supplicant", payload)
    assert hit.version == "2.0-devel-4.4.4_rtw_r10450.20140220"


@pytest.mark.parametrize("name", ["hostapd", "wpa_supplicant"])
@pytest.mark.parametrize("version", ["2.0-devel-gdeadbeef", "2.0-devel-4.4.4_rtw_r10450.20140220"])
def test_split_format_and_version_preserve_git_and_vendor_suffixes(name, version):
    payload = b"\x7fELF" + bytes(60) + f"{name} v%s\0{version}\0".encode()
    hit = ELFDeepExtractor().extract(name, payload)
    assert hit.version == version


@pytest.mark.parametrize("name", ["dhcpcd", "hostapd_cli", "wpa_cli", "wpa_supplicant"])
def test_command_filename_and_documented_examples_do_not_supply_a_release(name):
    assert BinaryReferenceMatcher().match(b"unrelated 5.5.6\0", name) == []
    payload = f"example: {name} v2.0\0".encode()
    assert not any(hit.name == name for hit in BinaryReferenceMatcher().match(payload, name))


@pytest.mark.parametrize(
    "filename,banner,version",
    [
        ("busybox-smp", b"BusyBox v1.20.0\0", "1.20.0"),
        ("pppd", b"pppd version %s\x002.4.3\0", "2.4.3"),
    ],
)
def test_owned_command_alias_uses_only_observed_same_family_evidence(filename, banner, version):
    payload = b"\x7fELF" + bytes(60) + banner
    components = BinaryInventory().extract(payload, filename, f"/bin/{filename}", "application")
    assert components[0].resolved_version == version
    empty = BinaryInventory().extract(
        b"\x7fELF" + bytes(60), filename, f"/bin/{filename}", "application"
    )
    assert empty[0].resolved_version == ""


def test_vpx_packed_api_and_full_string_agree_without_versioning_the_wrapper(shared_elf):
    data = shared_elf(
        "int vpx_codec_version(void) { return 0x010200; }\n"
        'const char *vpx_codec_version_str(void) { return "v1.2.0-5082-g58f7543"; }\n'
    )
    components = BinaryInventory().extract(data, "libvendor.so", "/lib/libvendor.so")
    assert components[0].resolved_version == ""
    vpx = next(c for c in components if c.name == "libvpx")
    assert vpx.resolved_version == "1.2.0-5082-g58f7543"
    assert {"name": "firmware:version:kind", "value": "development"} in vpx.properties


def test_vpx_disagreeing_defined_apis_remain_unresolved(shared_elf):
    data = shared_elf(
        "int vpx_codec_version(void) { return 0x010300; }\n"
        'const char *vpx_codec_version_str(void) { return "v1.2.0"; }\n'
    )
    vpx = next(
        c
        for c in BinaryInventory().extract(data, "libvpx.so", "/lib/libvpx.so")
        if c.name == "libvpx.so"
    )
    assert vpx.resolved_version == ""
    assert any(p["name"] == "firmware:version:conflict" for p in vpx.properties)


def test_libbpf_major_minor_string_remains_an_estimated_generation(shared_elf):
    data = shared_elf(
        'const char *libbpf_version_string(void) { return "v1.4"; }\n'
        "unsigned libbpf_major_version(void) { return 1; }\n"
        "unsigned libbpf_minor_version(void) { return 4; }\n"
    )
    component = BinaryInventory().extract(
        data,
        "libbpf.so",
        "/system/lib64/libbpf.so",
    )[0]
    assert component.resolved_version == "1.4.x"
    assert any(
        prop["name"] == "firmware:version:resolution-state"
        and prop["value"] == "estimated"
        for prop in component.properties
    )


def test_libyaml_abi_suffix_maps_to_yaml_identity():
    assert identity_key("libyaml-0.so.2") == "yaml"


@pytest.mark.parametrize(
    "function,component_name,version",
    [
        ("dav1d_version", "dav1d", "1.5.0"),
        ("opj_version", "OpenJPEG", "2.5.2"),
        ("heif_get_version", "libheif", "1.19.1"),
        ("avifVersion", "libavif", "1.2.0"),
    ],
)
def test_additional_defined_version_strings_are_attributed_by_api(
    shared_elf,
    function,
    component_name,
    version,
):
    data = shared_elf(
        f'const char *{function}(void) {{ return "{version}"; }}\n'
    )
    matches = BinaryInventory().extract(
        data,
        "libvendor.so",
        "/system/lib64/libvendor.so",
    )
    component = next(item for item in matches if item.name == component_name)
    assert component.resolved_version == version


@pytest.mark.parametrize(
    "function,component_name,string,version",
    [
        ("sf_version_string", "libsndfile", "libsndfile-1.2.2", "1.2.2"),
        (
            "src_get_version",
            "libsamplerate",
            "libsamplerate-0.2.2 (c) 2002-2008 Erik de Castro Lopo",
            "0.2.2",
        ),
        ("yaml_get_version_string", "libyaml", "0.2.5", "0.2.5"),
        ("lzo_version_string", "liblzo2", "2.10", "2.10"),
        ("zip_libzip_version", "libzip", "1.11.4", "1.11.4"),
        ("aom_codec_version_str", "libaom", "v3.13.1", "3.13.1"),
        ("pango_version_string", "Pango", "1.57.0", "1.57.0"),
        ("cairo_version_string", "Cairo", "1.18.4", "1.18.4"),
        ("pixman_version_string", "Pixman", "0.46.4", "0.46.4"),
        ("soxr_version", "libsoxr", "libsoxr-0.1.3", "0.1.3"),
        (
            "psl_get_version",
            "libpsl",
            "0.23.3 (+libidn2/2.3.8)",
            "0.23.3",
        ),
        ("lzma_version_string", "XZ Utils", "5.8.2", "5.8.2"),
        ("BZ2_bzlibVersion", "bzip2", "1.0.8, 13-Jul-2019", "1.0.8"),
        ("ffi_get_version", "libffi", "3.5.2", "3.5.2"),
    ],
)
def test_additional_owned_version_getters_accept_only_their_release_shape(
    shared_elf,
    function,
    component_name,
    string,
    version,
):
    data = shared_elf(f'const char *{function}(void) {{ return "{string}"; }}\n')
    component = next(
        item
        for item in BinaryInventory().extract(
            data,
            "libvendor.so",
            "/system/lib64/libvendor.so",
        )
        if item.name == component_name
    )
    assert component.resolved_version == version


def test_speex_wrapper_release_banner_is_attributed_to_speex():
    data = b"\x7fELF" + b"\0" * 60 + b"speex-1.2beta3\0"
    component = BinaryInventory().extract(
        data,
        "libspeexwrapper.so",
        "/lib/libspeexwrapper.so",
    )[0]
    assert component.name == "libspeexwrapper.so"
    assert component.resolved_version == "1.2beta3"


def test_pcre2_abi_suffix_and_release_date_banner_are_attributed():
    data = b"\x7fELF" + b"\0" * 60 + b"10.46 2025-08-27\0"

    component = BinaryInventory().extract(
        data,
        "libpcre2-8.so.0",
        "/lib/libpcre2-8.so.0",
    )[0]

    assert component.resolved_version == "10.46"


def test_libssh2_banner_is_attributed_to_the_host_library():
    data = b"\x7fELF" + b"\0" * 60 + b"SSH-2.0-libssh2_1.11.1\0"

    component = BinaryInventory().extract(
        data,
        "libssh2.so.1",
        "/lib/libssh2.so.1",
    )[0]

    assert component.resolved_version == "1.11.1"


def test_vpx_imports_and_runtime_values_are_not_release_proofs(shared_elf):
    data = shared_elf(
        "extern const char *vpx_codec_version_str(void);\n"
        "const char *(*getter)(void) = vpx_codec_version_str;\n"
        "volatile int n; int vpx_codec_version(void) { return n; }\n"
    )
    assert all(
        not c.resolved_version
        for c in BinaryInventory().extract(data, "libvpx.so", "/lib/libvpx.so")
    )


def test_vpx_function_name_next_to_unrelated_numbers_is_not_a_banner():
    assert (
        BinaryReferenceMatcher().match(b"vpx_codec_version_str diagnostic 9.9.9\0", "libvpx.so")
        == []
    )


def test_libevent_backend_message_identifies_library_without_versioning_neighbor_data():
    matches = BinaryReferenceMatcher().match(
        b"libevent using: %s\n\01.4.13-stable\0fcntl(O_NONBLOCK)\0", "libvendor.so"
    )
    assert [(hit.name, hit.version) for hit in matches] == [("libevent", "")]


def test_defined_libevent_getter_proves_the_complete_release(shared_elf):
    data = shared_elf('const char *event_get_version(void) { return "2.1.12-stable"; }')
    components = BinaryInventory().extract(data, "libevent.so", "/lib/libevent.so")
    assert components[0].resolved_version == "2.1.12-stable"
    imports = shared_elf(
        "extern const char *event_get_version(void); "
        "const char *(*getter)(void) = event_get_version;"
    )
    assert all(
        not c.resolved_version
        for c in BinaryInventory().extract(imports, "libevent.so", "/lib/libevent.so")
    )


def test_busybox_udhcp_vendor_class_is_applet_evidence_not_a_second_library():
    data = b"\x7fELF" + bytes(60) + b"BusyBox v1.20.0\0udhcp 1.20.0\0"
    components = BinaryInventory().extract(data, "busybox-smp", "/bin/busybox-smp", "application")
    assert [(c.name, c.resolved_version) for c in components] == [("busybox-smp", "1.20.0")]
    assert {"name": "firmware:busybox:applet", "value": "udhcp"} in components[0].properties


@pytest.mark.parametrize("version", ["0.9.9", "0.9.9-custom"])
def test_a_different_udhcp_version_is_not_silently_aliased_to_busybox(version):
    data = b"\x7fELF" + bytes(60) + f"BusyBox v1.20.0\0udhcp {version}\0".encode()
    components = BinaryInventory().extract(data, "busybox-smp", "/bin/busybox-smp", "application")
    assert any(c.name == "udhcp" and c.resolved_version == version for c in components)


def test_x86_32_vpx_keeps_full_string_suffix(shared_elf):
    data = shared_elf(
        "int vpx_codec_version(void) { return 0x010200; }\n"
        'const char *vpx_codec_version_str(void) { return "v1.2.0-5082-g58f7543"; }\n',
        flags=("-m32", "-nostdlib"),
    )
    vpx = next(
        c
        for c in BinaryInventory().extract(data, "libvpx.so", "/lib/libvpx.so")
        if c.name == "libvpx.so"
    )
    assert vpx.resolved_version == "1.2.0-5082-g58f7543"


@pytest.mark.parametrize("writable", [False, True])
def test_arm_getter_cannot_read_a_mutable_global_initial_value(writable):
    import struct

    from firmware_scanner.extraction.semantic_version import VERIFY, SemanticVersionExtractor
    from tests.unit.test_protobuf_version import _elf

    # ARM ldr r0,[pc,#4]; ldr r0,[r0]; bx lr; literal -> separate data segment.
    data = bytearray(
        _elf(bytes.fromhex("04009fe5000090e51eff2fe1") + struct.pack("<I", 0x10280), arm=True)[0]
    )
    data[0x601 : 0x601 + len(VERIFY)] = b"vpx_codec_version".ljust(len(VERIFY), b"\0")
    struct.pack_into("<I", data, 0x280, 0x010200)
    struct.pack_into("<H", data, 44, 2)
    data[52:84] = struct.pack("<8I", 1, 0, 0x10000, 0x10000, 0x200, 0x200, 5, 0x1000)
    data[84:116] = struct.pack(
        "<8I",
        1,
        0x200,
        0x10200,
        0x10200,
        len(data) - 0x200,
        len(data) - 0x200,
        6 if writable else 4,
        0x1000,
    )
    hits = SemanticVersionExtractor().extract(bytes(data))
    assert [(h.name, h.version) for h in hits] == ([] if writable else [("libvpx", "1.2.0")])


@pytest.mark.parametrize("version", ["1.20.0-custom", "1.20.0-gabcdef0"])
def test_busybox_applet_comparison_uses_the_complete_vendor_version(version):
    data = b"\x7fELF" + bytes(60) + f"BusyBox v{version}\0udhcp {version}\0".encode()
    components = BinaryInventory().extract(data, "busybox-smp", "/bin/busybox-smp", "application")
    assert [(c.name, c.resolved_version) for c in components] == [("busybox-smp", version)]
