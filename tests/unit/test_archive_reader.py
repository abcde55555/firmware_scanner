"""Actual ZIP tail reads over a filesystem and ext4 range-reading regressions."""
import importlib
import importlib.util
import io
import shutil
import subprocess
import struct
import zipfile

import pytest

from firmware_scanner.android.ext4_reader import Ext4Reader


def _archive_reader_class():
    name = 'firmware_scanner.android.archive_reader'
    assert importlib.util.find_spec(name) is not None, 'seekable archive reader is missing'
    return importlib.import_module(name).FilesystemFile


@pytest.fixture
def ext4_files(tmp_path):
    mkfs = '/usr/sbin/mke2fs' if shutil.which('/usr/sbin/mke2fs') else shutil.which('mke2fs')
    if not mkfs:
        pytest.skip('mke2fs required for real ext4 range tests')
    root = tmp_path / 'root'
    root.mkdir()
    content = bytes(range(256)) * 4096
    (root / 'data.bin').write_bytes(content)
    with (root / 'hole.bin').open('wb') as handle:
        handle.write(b'HEAD')
        handle.seek(512 * 1024)
        handle.write(b'TAIL')
    z = io.BytesIO()
    with zipfile.ZipFile(z, 'w') as archive:
        archive.writestr('assets/filler', b'x' * 131072)
        archive.writestr('META-INF/maven/test/fixture/pom.properties', 'groupId=test\nartifactId=fixture\nversion=2.3.4\n')
    (root / 'fixture.apk').write_bytes(z.getvalue())
    image = tmp_path / 'test.ext4'
    subprocess.run([mkfs, '-q', '-F', '-t', 'ext4', '-b', '1024', '-d', str(root), str(image), '16384'], check=True, capture_output=True)
    return image.read_bytes(), content


def _range_reader(reader):
    method = getattr(reader, 'read_file_range', None)
    assert callable(method), 'ext4 random-access range reader is missing'
    return method


def test_ext4_range_matches_file_content_and_eof(ext4_files):
    image, content = ext4_files
    read = _range_reader(Ext4Reader(image))
    assert read('/data.bin', 990, 63) == content[990:1053]
    assert read('/data.bin', len(content)-7, 1024) == content[-7:]
    assert read('/data.bin', len(content)+100, 20) == b''
    assert read('/data.bin', 0, 0) == b''
    assert read('/missing', 0, 100) is None
    with pytest.raises(ValueError):
        read('/data.bin', -1, 100)
    with pytest.raises(ValueError):
        read('/data.bin', 0, -1)


def test_ext4_rejects_impossible_block_size_before_allocating():
    image = bytearray(2048)
    struct.pack_into('<H', image, 1024 + 56, 0xef53)
    struct.pack_into('<I', image, 1024 + 24, 64)
    assert not Ext4Reader(bytes(image)).is_valid()


def test_ext4_range_keeps_sparse_holes(ext4_files):
    image, _ = ext4_files
    read = _range_reader(Ext4Reader(image))
    assert read('/hole.bin', 0, 8) == b'HEAD' + b'\0' * 4
    assert read('/hole.bin', 512 * 1024 - 4, 8) == b'\0' * 4 + b'TAIL'


def test_ext4_range_does_not_materialize_file_prefix(ext4_files):
    image, content = ext4_files
    class TrackingImage:
        def __init__(self, data):
            self.data, self.largest_read = data, 0
        def __len__(self):
            return len(self.data)
        def __getitem__(self, key):
            if isinstance(key, slice):
                start, stop, step = key.indices(len(self.data))
                self.largest_read = max(self.largest_read, max(0, stop-start))
            return self.data[key]
    tracked = TrackingImage(image)
    read = _range_reader(Ext4Reader(tracked))
    assert read('/data.bin', 900000, 32) == content[900000:900032]
    assert tracked.largest_read <= 4096


def test_seekable_adapter_reads_real_zip_over_ext4(ext4_files):
    image, _ = ext4_files
    cls = _archive_reader_class()
    with cls(Ext4Reader(image), '/fixture.apk') as handle, zipfile.ZipFile(handle) as archive:
        data = archive.read('META-INF/maven/test/fixture/pom.properties')
        assert b'version=2.3.4' in data


def test_adapter_reads_archive_beyond_old_prefix_limit(tmp_path):
    cls = _archive_reader_class()
    path = tmp_path / 'large.apk'
    # A sparse archive tests the real central-directory offsets without 130 MiB of RAM.
    with path.open('wb') as handle:
        handle.seek(130 * 1024 * 1024)
        with zipfile.ZipFile(handle, 'w') as archive:
            archive.writestr('metadata.txt', b'component version 2.3.4')
    class RangeFilesystem:
        bytes_read = 0
        def file_size(self, name):
            return path.stat().st_size
        def read_file_range(self, name, offset, size):
            with path.open('rb') as handle:
                handle.seek(offset)
                data = handle.read(size)
            self.bytes_read += len(data)
            return data
        def read_file(self, *args, **kwargs):
            raise AssertionError('archive prefix must not be read')
    fs = RangeFilesystem()
    with cls(fs, '/large.apk') as handle, zipfile.ZipFile(handle) as archive:
        assert archive.read('metadata.txt') == b'component version 2.3.4'
    assert fs.bytes_read < 131072


def test_adapter_rejects_negative_seeks_and_closed_reads(ext4_files):
    image, _ = ext4_files
    cls = _archive_reader_class()
    handle = cls(Ext4Reader(image), '/data.bin')
    with pytest.raises(ValueError):
        handle.seek(-1)
    handle.close()
    with pytest.raises(ValueError):
        handle.read(1)


def test_android_scanner_reads_large_apk_metadata_without_prefix(tmp_path):
    from firmware_scanner.android.system_scanner import AndroidSystemScanner
    path = tmp_path / 'large.apk'
    with path.open('wb') as handle:
        handle.seek(130 * 1024 * 1024)
        with zipfile.ZipFile(handle, 'w') as archive:
            archive.writestr('META-INF/maven/test/fixture/pom.properties',
                             'groupId=test\nartifactId=fixture\nversion=2.3.4\n')
    class RangeFilesystem:
        bytes_read = 0
        def file_size(self, name):
            return path.stat().st_size
        def read_file_range(self, name, offset, size):
            with path.open('rb') as handle:
                handle.seek(offset)
                data = handle.read(size)
            self.bytes_read += len(data)
            return data
        def read_file(self, *args, **kwargs):
            raise AssertionError('large APK must use random-access reads')
    fs = RangeFilesystem()
    scanner = AndroidSystemScanner(fs)
    result = scanner._scan_single_apk('/large.apk')
    library = next((c for c in result if c.name == 'test:fixture'), None)
    assert library is not None
    assert library.resolved_version == '2.3.4'
    assert fs.bytes_read < 131072
    assert not any('128 MiB' in message for message in scanner._coverage_warnings)


def test_large_embedded_elf_uses_bounded_stream_reads(tmp_path):
    from firmware_scanner.android.system_scanner import AndroidSystemScanner
    path = tmp_path / 'large-native.apk'
    expected_size = 33 * 1024 * 1024 + 4
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        with archive.open('lib/x86_64/liblarge.so', 'w') as member:
            member.write(b'\x7fELF')
            for _ in range(33):
                member.write(bytes(1024 * 1024))
    scanner = AndroidSystemScanner(object())
    observed = []
    class Inventory:
        def extract(self, data, filename, location):
            observed.append((len(data), filename, location))
            return []
    scanner._binary_inventory = lambda: Inventory()
    with zipfile.ZipFile(path) as archive:
        original_open = archive.open
        class BoundedMember:
            def __init__(self, member): self.member = member
            def __enter__(self): return self
            def __exit__(self, *args): self.member.close()
            def read(self, size):
                assert 0 < size <= 1024 * 1024
                return self.member.read(size)
        archive.open = lambda *args, **kwargs: BoundedMember(original_open(*args, **kwargs))
        scanner._extract_embedded_native_libs(archive, '/large-native.apk')
    assert observed == [(expected_size, 'liblarge.so', '/large-native.apk!/lib/x86_64/liblarge.so')]
    assert not scanner._coverage_warnings


def test_corrupt_deflate_member_does_not_abort_other_native_libraries():
    from firmware_scanner.android.system_scanner import AndroidSystemScanner
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('lib/x86/libbroken.so', b'\x7fELF' + bytes(2048))
        archive.writestr('lib/x86/libpng.so', b'\x7fELF' + bytes(60) + b'libpng version 1.6.44\0')
    damaged = bytearray(data.getvalue())
    name_length, extra_length = struct.unpack_from('<HH', damaged, 26)
    damaged[30 + name_length + extra_length] = 0x07  # reserved DEFLATE block type
    scanner = AndroidSystemScanner(object())
    components = scanner._analyze_apk_data(bytes(damaged), '/corrupt.apk')
    assert any(c.name == 'libpng.so' and c.resolved_version == '1.6.44' for c in components)
    assert any('libbroken.so' in message for message in scanner._coverage_warnings)


@pytest.mark.parametrize('metadata_name', [
    'META-INF/maven/test/broken/pom.properties',
    'play-services-base.properties',
])
def test_corrupt_dependency_metadata_does_not_abort_apk_scan(metadata_name):
    from firmware_scanner.android.system_scanner import AndroidSystemScanner
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(metadata_name, b'broken metadata' * 30)
        archive.writestr('META-INF/maven/test/valid/pom.properties',
                         'groupId=test\nartifactId=valid\nversion=2.3.4\n')
    damaged = bytearray(data.getvalue())
    name_length, extra_length = struct.unpack_from('<HH', damaged, 26)
    damaged[30 + name_length + extra_length] = 0x07
    scanner = AndroidSystemScanner(object())
    result = scanner._analyze_apk_data(bytes(damaged), '/corrupt.apk')
    assert any(c.name == 'test:valid' and c.resolved_version == '2.3.4' for c in result)
    assert any(metadata_name in warning for warning in scanner._coverage_warnings)
