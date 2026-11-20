"""Focused coverage for bounded, read-only native scanning inside APEX payloads."""

import io
import os
import shutil
import subprocess
import struct
import zipfile

import pytest


def _make_ext4_payload(tmp_path, *, size_mib=32, executable=False):
    """Create a small real ext4 image using the host's mke2fs utility."""
    mke2fs = shutil.which("mke2fs")
    binary = "/bin/true"
    if not mke2fs or not os.path.isfile(binary):
        pytest.skip("mke2fs and /bin/true are required for the real ext4 fixture")
    root = tmp_path / "root"
    (root / "apex" / "com.example.apex" / "lib64").mkdir(parents=True)
    with open(binary, "rb") as source:
        (root / "apex" / "com.example.apex" / "lib64" / "libfixture.so").write_bytes(source.read())
    if executable:
        (root / 'bin').mkdir()
        (root / 'bin' / 'tool').write_bytes((root / 'apex' / 'com.example.apex' / 'lib64' / 'libfixture.so').read_bytes())
    image = tmp_path / "payload.img"
    with image.open("wb") as output:
        output.truncate(size_mib * 1024 * 1024)
    subprocess.run(
        [mke2fs, "-q", "-F", "-t", "ext4", "-b", "4096", "-I", "256",
         "-O", "^64bit,^metadata_csum,^orphan_file", "-d", str(root), str(image)],
        check=True,
        capture_output=True,
    )
    return image.read_bytes()


def _apex(payload, *, name="apex_payload.img", extra=()):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, payload)
        for member, data in extra:
            archive.writestr(member, data)
    return output.getvalue()


def _component(name, version=""):
    from firmware_scanner.extraction.models import Component

    return Component(name=name, resolved_version=version, component_type="library")


class RecordingInventory:
    def __init__(self, version=""):
        self.calls = []
        self.version = version

    def extract(self, data, filename, location, component_type='library'):
        self.calls.append((data, filename, location))
        component = _component(filename, self.version)
        component.component_type = component_type
        return [component]


def test_scans_real_ext4_payload_and_attaches_nested_container_provenance(tmp_path):
    from firmware_scanner.android.apex_payload import scan_apex_payload

    apex_path = "/system/apex/com.example.apex"
    inventory = RecordingInventory(version="9.8.7")
    result = scan_apex_payload(_apex(_make_ext4_payload(tmp_path)), apex_path, inventory)

    assert result.analysed_files == 1
    assert len(inventory.calls) == 1
    _, filename, location = inventory.calls[0]
    assert filename == "libfixture.so"
    assert location == apex_path + "!/apex_payload.img/apex/com.example.apex/lib64/libfixture.so"
    assert result.components[0].resolved_version == "9.8.7"
    assert {prop["name"]: prop["value"] for prop in result.components[0].properties}[
        "firmware:evidence:container"
    ] == apex_path


def test_scans_compressed_apex_original_apex_without_losing_outer_location(tmp_path):
    from firmware_scanner.android.apex_payload import scan_apex_payload

    inner = _apex(_make_ext4_payload(tmp_path), name="apex_payload.img")
    compressed = _apex(b"", name="unused", extra=(("original_apex", inner),))
    inventory = RecordingInventory()

    result = scan_apex_payload(compressed, "/system/apex/com.example.capex", inventory)

    assert result.analysed_files == 1
    assert inventory.calls[0][2].startswith(
        "/system/apex/com.example.capex!/original_apex!/apex_payload.img/"
    )


def test_reports_corrupt_zip_and_unsupported_payload_filesystem():
    from firmware_scanner.android.apex_payload import scan_apex_payload

    corrupt = scan_apex_payload(b"PK\x03\x04truncated", "/bad.apex", RecordingInventory())
    unsupported = scan_apex_payload(_apex(b"not a filesystem"), "/unknown.apex", RecordingInventory())

    assert any("corrupt" in warning.lower() or "invalid" in warning.lower() for warning in corrupt.warnings)
    assert any("unsupported" in warning.lower() for warning in unsupported.warnings)


def test_reports_payload_crc_corruption_and_magic_only_truncated_filesystem():
    from firmware_scanner.android.apex_payload import scan_apex_payload

    valid_zip = bytearray(_apex(b"payload bytes", name="apex_payload.img"))
    central = valid_zip.find(b"PK\x01\x02")
    assert central >= 0
    valid_zip[central + 16] ^= 0x01  # change the declared CRC without changing payload data
    corrupt_payload = scan_apex_payload(bytes(valid_zip), "/crc.apex", RecordingInventory())

    # ext4 superblock magic alone must not make a truncated image look valid.
    truncated_fs = bytearray(2048)
    truncated_fs[1024 + 56:1024 + 58] = b"\x53\xef"
    truncated = scan_apex_payload(_apex(bytes(truncated_fs)), "/truncated.apex", RecordingInventory())

    assert any("corrupt" in warning.lower() for warning in corrupt_payload.warnings)
    assert any("truncated" in warning.lower() or "corrupt" in warning.lower() for warning in truncated.warnings)


def test_invalid_ext4_inode_group_metadata_does_not_abort_apex_scan():
    from firmware_scanner.android.apex_payload import scan_apex_payload
    payload = bytearray(4096)
    struct.pack_into('<H', payload, 1024 + 56, 0xef53)
    struct.pack_into('<I', payload, 1024, 16)
    struct.pack_into('<I', payload, 1024 + 4, 4)
    struct.pack_into('<I', payload, 1024 + 32, 8)
    # inodes_per_group remains zero in this malformed superblock.
    result = scan_apex_payload(_apex(bytes(payload)), '/malformed.apex', RecordingInventory())
    assert result.analysed_files == 0
    assert any('invalid' in warning.lower() or 'corrupt' in warning.lower() for warning in result.warnings)


def test_warns_for_duplicate_payload_member_and_scans_member_once():
    from firmware_scanner.android.apex_payload import scan_apex_payload

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("apex_payload.img", b"first")
        archive.writestr("apex_payload.img", b"second")

    result = scan_apex_payload(output.getvalue(), "/duplicate.apex", RecordingInventory())
    assert result.analysed_files == 0
    assert any("duplicate" in warning.lower() for warning in result.warnings)


def test_rejects_payload_above_512_mib_before_decompression():
    from firmware_scanner.android.apex_payload import scan_apex_payload

    # Forge only the ZIP metadata; the scanner must reject before reading/decompressing.
    apex = bytearray(_apex(b"tiny"))
    oversized = 512 * 1024 * 1024 + 1
    pos = 0
    while True:
        pos = apex.find(b"PK\x03\x04", pos)
        if pos < 0:
            break
        apex[pos + 22:pos + 26] = oversized.to_bytes(4, "little")
        pos += 4
    pos = apex.find(b"PK\x01\x02")
    assert pos >= 0
    apex[pos + 24:pos + 28] = oversized.to_bytes(4, "little")

    result = scan_apex_payload(bytes(apex), "/oversized.apex", RecordingInventory())

    assert result.analysed_files == 0
    assert any("512" in warning or "limit" in warning.lower() for warning in result.warnings)


def test_skips_and_warns_for_individual_elf_over_64_mib(tmp_path):
    from firmware_scanner.android.apex_payload import scan_apex_payload

    import firmware_scanner.android.apex_payload as apex_module

    class FakeReader:
        def __init__(self, data):
            self._data = data

        def is_valid(self):
            return True

        def walk(self, root="/", max_depth=10):
            yield "/", ["lib"], []
            yield "/lib", [], ["huge.so"]

        def file_size(self, path):
            return 64 * 1024 * 1024 + 1

        def read_file(self, path, max_size):
            if max_size == 4:
                return b"\x7fELF"
            raise AssertionError("oversized ELF must not be read")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(apex_module, "Ext4Reader", FakeReader, raising=False)
    inventory = RecordingInventory()
    try:
        result = scan_apex_payload(_apex(b"synthetic"), "/bounded.apex", inventory)
    finally:
        monkeypatch.undo()
    assert result.analysed_files == 0
    assert inventory.calls == []
    assert any("64" in warning or "size" in warning.lower() for warning in result.warnings)


def test_real_binary_inventory_accepts_payload_elf_without_module_version_fallback(tmp_path):
    from firmware_scanner.android.apex_payload import scan_apex_payload
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    result = scan_apex_payload(_apex(_make_ext4_payload(tmp_path)), "/system/apex/test.apex", BinaryInventory())

    assert result.analysed_files == 1
    assert result.components
    assert all(component.resolved_version != "apex-module-version" for component in result.components)


def test_payload_bin_elf_is_classified_as_an_application(tmp_path):
    from firmware_scanner.android.apex_payload import scan_apex_payload
    from firmware_scanner.extraction.binary_inventory import BinaryInventory
    result = scan_apex_payload(_apex(_make_ext4_payload(tmp_path, executable=True)), '/test.apex', BinaryInventory())
    tool = next(c for c in result.components if c.name == 'tool')
    assert tool.component_type == 'application'
    assert 'ELF executable' in tool.description


def test_android_system_scanner_includes_payload_libraries(tmp_path):
    from types import SimpleNamespace
    from firmware_scanner.android.system_scanner import AndroidSystemScanner

    data = _apex(_make_ext4_payload(tmp_path))
    class Filesystem:
        def exists(self, path):
            return path == '/system/apex'
        def list_directory(self, path):
            return [SimpleNamespace(name='com.example.apex')]
        def file_size(self, path):
            return len(data)
        def read_file(self, path, max_size):
            return data[:max_size]

    scanner = AndroidSystemScanner(Filesystem())
    inventory = RecordingInventory('9.8.7')
    scanner._binary_inventory = lambda: inventory
    result = scanner._scan_apex_modules()
    assert len(inventory.calls) == 1
    assert any(c.name == 'libfixture.so' and c.resolved_version == '9.8.7' for c in result)
    assert sum(c.component_type == 'application' for c in result) == 1


def test_full_scan_counts_apex_packages_separately_from_payload_executables(tmp_path):
    from types import SimpleNamespace
    from firmware_scanner.android.system_scanner import AndroidSystemScanner

    data = _apex(_make_ext4_payload(tmp_path, executable=True))

    class Filesystem:
        def is_valid(self):
            return True

        def exists(self, path):
            return path == '/system/apex'

        def list_directory(self, path):
            return [SimpleNamespace(name='com.example.apex')]

        def file_size(self, path):
            return len(data)

        def read_file(self, path, max_size):
            return data[:max_size]

    scanner = AndroidSystemScanner(Filesystem())
    scanner._binary_inventory = lambda: RecordingInventory()
    result = scanner.scan()
    assert any(c.name == 'tool' and c.component_type == 'application' for c in result.components)
    assert result.apex_count == 1


def test_corrupt_deflate_apex_manifest_does_not_abort_next_module():
    from types import SimpleNamespace
    from firmware_scanner.android.system_scanner import AndroidSystemScanner

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('AndroidManifest.xml', b'invalid manifest bytes')
    corrupt = bytearray(buffer.getvalue())
    name_size, extra_size = struct.unpack_from('<HH', corrupt, 26)
    corrupt[30 + name_size + extra_size] = 0x07  # reserved DEFLATE block type
    files = {'bad.apex': bytes(corrupt), 'good.apex': _apex(b'no filesystem')}

    class Filesystem:
        def exists(self, path):
            return path == '/system/apex'

        def list_directory(self, path):
            return [SimpleNamespace(name=name) for name in files]

        def file_size(self, path):
            return len(files[path.rsplit('/', 1)[-1]])

        def read_file(self, path, max_size):
            return files[path.rsplit('/', 1)[-1]][:max_size]

    scanner = AndroidSystemScanner(Filesystem())
    scanner._binary_inventory = lambda: RecordingInventory()
    components = scanner._scan_apex_modules()
    assert any(c.name == 'good' for c in components)
    assert any('Cannot parse APEX module manifest' in warning and 'bad.apex' in warning
               for warning in scanner._coverage_warnings)
