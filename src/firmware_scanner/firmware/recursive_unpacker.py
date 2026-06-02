"""Recursive firmware unpacker - extracts nested containers to maximum depth."""

import struct
from pathlib import Path
from dataclasses import dataclass, field
from ..extraction.models import FirmwareSection, UnpackResult


@dataclass
class UnpackedFile:
    """A file extracted from firmware at any depth level."""
    name: str           # Full path (e.g., "rootfs/usr/lib/libssl.so")
    data: bytes
    file_type: str      # "elf", "dex", "config", "binary", "text", "compressed", "container"
    depth: int          # 0 = top-level, 1 = inside first container, etc.
    parent: str = ""    # Parent container name


MAX_RECURSION_DEPTH = 4
MAX_TOTAL_FILES = 500
MAX_SINGLE_FILE_SIZE = 16 * 1024 * 1024  # 16MB


class RecursiveUnpacker:
    """Recursively unpacks firmware containers (ZIP, SquashFS, gzip, etc.)
    and catalogs all files found at every depth level."""

    def __init__(self, max_depth: int = MAX_RECURSION_DEPTH,
                 max_files: int = MAX_TOTAL_FILES,
                 max_file_size: int = MAX_SINGLE_FILE_SIZE):
        self._max_depth = max_depth
        self._max_files = max_files
        self._max_file_size = max_file_size
        self._files: list[UnpackedFile] = []

    def unpack(self, data: bytes, name: str, depth: int = 0) -> list[UnpackedFile]:
        """Recursively unpack data and return all discovered files."""
        if depth > self._max_depth or len(self._files) >= self._max_files:
            return self._files

        # Determine what this data is
        file_type = self._detect_type(data, name)

        # If it's a container, unpack it and recurse
        if file_type == "zip":
            self._unpack_zip(data, name, depth)
        elif file_type == "gzip":
            self._unpack_gzip(data, name, depth)
        elif file_type == "xz" or file_type == "lzma":
            self._unpack_lzma(data, name, depth)
        elif file_type == "squashfs":
            # SquashFS needs special handling - extract file list
            self._unpack_squashfs(data, name, depth)
        elif file_type == "cpio":
            self._unpack_cpio(data, name, depth)
        elif file_type == "uboot":
            self._unpack_uboot(data, name, depth)
        elif file_type == "android_sparse":
            self._unpack_android_sparse(data, name, depth)
        elif file_type == "ext4":
            self._unpack_ext4(data, name, depth)
        elif file_type == "erofs":
            self._unpack_erofs(data, name, depth)
        else:
            # For large binary blobs, scan for embedded containers
            if file_type == "binary" and len(data) > 65536:
                self._scan_for_embedded_containers(data, name, depth)
            elif len(data) > 16:
                self._files.append(UnpackedFile(
                    name=name,
                    data=data[:self._max_file_size],
                    file_type=file_type,
                    depth=depth,
                ))

        return self._files

    def _detect_type(self, data: bytes, name: str) -> str:
        """Detect file type from magic bytes and name."""
        if len(data) < 4:
            return "unknown"

        # Magic byte detection
        if data[:4] == b'\x7fELF':
            return "elf"
        if data[:2] == b'PK':
            return "zip"
        if data[:2] == b'\x1f\x8b':
            return "gzip"
        if data[:6] == b'\xfd7zXZ\x00':
            return "xz"
        if data[:3] == b'\x5d\x00\x00':
            return "lzma"
        if data[:4] == b'dex\n':
            return "dex"
        if data[:4] == b'hsqs' or data[:4] == b'sqsh':
            return "squashfs"
        if data[:6] == b'070701' or data[:6] == b'070702':
            return "cpio"
        if len(data) >= 4 and struct.unpack('>I', data[:4])[0] == 0x27051956:
            return "uboot"
        # Android sparse image
        if len(data) >= 4 and struct.unpack('<I', data[:4])[0] == 0xED26FF3A:
            return "android_sparse"
        # ext4 filesystem
        if len(data) >= 0x43A and data[0x438:0x43A] == b'\x53\xEF':
            return "ext4"
        # EROFS filesystem
        if len(data) >= 0x404 and struct.unpack_from('<I', data, 0x400)[0] == 0xE0F5E1E2:
            return "erofs"

        # Name-based detection
        lower = name.lower()
        if lower.endswith(('.so', '.elf', '.o', '.a', '.dylib')):
            return "elf"
        if lower.endswith(('.apk', '.zip', '.jar')):
            return "zip"
        if lower.endswith('.dex'):
            return "dex"
        if lower.endswith(('.h', '.c', '.cpp', '.cmake', '.py', '.rs')):
            return "source"
        if lower.endswith(('.yml', '.yaml', '.json', '.xml', '.properties', '.gradle', '.toml')):
            return "config"
        if lower.endswith(('.txt', '.md', '.rst', '.cfg', '.ini', '.conf')):
            return "text"
        if lower.endswith(('.bin', '.img', '.fw')):
            return "binary"
        if lower.endswith(('.gz', '.tgz')):
            return "gzip"
        if lower.endswith(('.xz', '.lzma')):
            return "xz"

        # Content heuristic
        try:
            data[:256].decode('utf-8')
            return "text"
        except Exception:
            return "binary"

    def _unpack_zip(self, data: bytes, parent_name: str, depth: int):
        """Unpack ZIP/APK archive."""
        import zipfile
        import io

        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            entries = sorted(zf.namelist(), key=lambda n: zf.getinfo(n).file_size, reverse=True)

            # Prioritize: manifests, configs, binaries, then others
            priority_files = []
            other_files = []
            for name in entries:
                try:
                    info = zf.getinfo(name)
                    if info.file_size == 0 or info.is_dir():
                        continue
                    lower = name.lower()
                    if any(kw in lower for kw in ['manifest', 'version', '.so', '.dex', 'package.json',
                                                    'build.gradle', '.properties', 'changelog', 'history']):
                        priority_files.append(name)
                    elif info.file_size > 100:
                        other_files.append(name)
                except Exception:
                    continue

            # Process priority files first, then others up to limit
            to_process = priority_files + other_files[:self._max_files - len(priority_files)]

            for name in to_process[:200]:  # Cap at 200 files per ZIP
                if len(self._files) >= self._max_files:
                    break
                try:
                    file_data = zf.read(name)
                    full_path = f"{parent_name}/{name}" if parent_name else name
                    self.unpack(file_data, full_path, depth + 1)
                except Exception:
                    continue
            zf.close()
        except Exception:
            pass

    def _unpack_gzip(self, data: bytes, parent_name: str, depth: int):
        """Decompress gzip data."""
        import gzip
        import zlib

        try:
            decompressed = gzip.decompress(data)
        except Exception:
            try:
                decompressed = zlib.decompress(data[10:], -15)
            except Exception:
                return

        inner_name = parent_name.replace('.gz', '').replace('.tgz', '.tar')
        self.unpack(decompressed, inner_name, depth + 1)

    def _unpack_lzma(self, data: bytes, parent_name: str, depth: int):
        """Decompress LZMA/XZ data."""
        import lzma

        try:
            decompressed = lzma.decompress(data)
            inner_name = parent_name.replace('.xz', '').replace('.lzma', '')
            self.unpack(decompressed, inner_name, depth + 1)
        except Exception:
            pass

    def _unpack_squashfs(self, data: bytes, parent_name: str, depth: int):
        """Extract files from SquashFS v4 filesystem using pure-Python reader."""
        from .squashfs_reader import SquashFSReader

        reader = SquashFSReader(data)
        if not reader.is_valid():
            self._scan_for_embedded_files(data, parent_name, depth)
            return

        root_entries = reader.list_directory('/')
        if not root_entries:
            # Can't read metadata (e.g. unsupported compression filters)
            # Try external unsquashfs tool as fallback
            if not self._try_external_unsquashfs(data, parent_name, depth):
                self._scan_for_embedded_files(data, parent_name, depth)
            return

        self._extract_from_squashfs(reader, parent_name, depth)

    def _try_external_unsquashfs(self, data: bytes, parent_name: str, depth: int) -> bool:
        """Try to extract SquashFS using external unsquashfs/sasquatch tool."""
        import shutil
        import tempfile
        import os

        tool = shutil.which("sasquatch") or shutil.which("unsquashfs")
        if not tool:
            return False

        try:
            tmp_dir = tempfile.mkdtemp(prefix="fwscan_sqfs_")
            sqfs_file = os.path.join(tmp_dir, "squashfs.img")
            out_dir = os.path.join(tmp_dir, "out")

            with open(sqfs_file, 'wb') as f:
                f.write(data)

            import subprocess
            result = subprocess.run(
                [tool, "-d", out_dir, "-f", "-n", sqfs_file],
                capture_output=True, timeout=60,
            )

            if result.returncode != 0 or not os.path.isdir(out_dir):
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return False

            # Walk extracted files and add interesting ones
            priority_dirs = {'bin', 'sbin', 'lib', 'etc', 'usr'}
            for root, dirs, files in os.walk(out_dir):
                if len(self._files) >= self._max_files:
                    break
                rel_root = os.path.relpath(root, out_dir).replace("\\", "/")
                top_dir = rel_root.split("/")[0] if rel_root != "." else ""

                # Skip low-value directories
                if top_dir and top_dir not in priority_dirs and top_dir != "usr":
                    continue

                for fname in files:
                    if len(self._files) >= self._max_files:
                        break
                    fpath = os.path.join(root, fname)
                    lower = fname.lower()

                    is_interesting = (
                        lower.endswith(('.so', '.elf', '.bin', '.conf', '.cfg',
                                        '.json', '.sh', '.lua', '.py'))
                        or '.so.' in lower
                        or 'version' in lower
                        or '.' not in fname
                        or '/bin/' in rel_root or '/sbin/' in rel_root
                    )
                    if not is_interesting:
                        continue

                    try:
                        stat = os.stat(fpath)
                        if stat.st_size < 16 or stat.st_size > self._max_file_size:
                            continue
                        file_data = open(fpath, 'rb').read(self._max_file_size)
                    except (OSError, IOError):
                        continue

                    file_type = self._detect_type(file_data, fname)
                    full_name = f"{parent_name}/{rel_root}/{fname}" if rel_root != "." else f"{parent_name}/{fname}"
                    self._files.append(UnpackedFile(
                        name=full_name,
                        data=file_data,
                        file_type=file_type,
                        depth=depth + 1,
                        parent=parent_name,
                    ))

            shutil.rmtree(tmp_dir, ignore_errors=True)
            return len(self._files) > 0
        except Exception:
            return False

    def _extract_from_squashfs(self, reader, parent_name: str, depth: int):
        """Walk a SquashFS filesystem reader and extract interesting files."""
        # Prioritize high-value directories for firmware analysis
        priority_dirs = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/lib', '/lib', '/etc']
        visited = set()

        for pdir in priority_dirs:
            if len(self._files) >= self._max_files:
                break
            entries = reader.list_directory(pdir)
            if not entries:
                continue
            visited.add(pdir)
            self._extract_matching_entries(reader, pdir, entries, parent_name, depth)

        # Then walk the rest
        for dir_path, entries in reader.walk("/", max_depth=4):
            if len(self._files) >= self._max_files:
                break
            if dir_path in visited:
                continue
            # Skip web assets and other low-value directories
            if any(seg in dir_path for seg in ('/img', '/css', '/js', '/font', '/icons')):
                continue
            visited.add(dir_path)
            self._extract_matching_entries(reader, dir_path, entries, parent_name, depth)

    def _extract_matching_entries(self, reader, dir_path: str, entries, parent_name: str, depth: int):
        """Extract files matching firmware analysis criteria from a directory."""
        for entry in entries:
            if len(self._files) >= self._max_files:
                break
            if not entry.is_file:
                continue

            file_path = f"{dir_path.rstrip('/')}/{entry.name}"
            full_name = f"{parent_name}{file_path}"
            lower = entry.name.lower()

            is_elf_candidate = (
                lower.endswith(('.so', '.elf', '.bin'))
                or any(lower.endswith(f'.so.{v}') for v in ('0', '1', '2'))
                or '.' not in entry.name
            )
            is_lib = '.so.' in lower
            is_config = lower.endswith(('.conf', '.cfg', '.ini', '.json', '.yaml', '.yml'))
            is_script = lower.endswith(('.sh', '.lua', '.py'))
            is_version_file = 'version' in lower or lower in (
                'openwrt_release', 'openwrt_version', 'banner',
            )
            in_bin_dir = any(seg in file_path for seg in ('/bin/', '/sbin/'))

            if not (is_elf_candidate or is_lib or is_config or is_script
                    or is_version_file or in_bin_dir):
                continue

            file_data = reader.read_file(file_path)
            if not file_data or len(file_data) < 16:
                continue

            file_type = self._detect_type(file_data, entry.name)
            self._files.append(UnpackedFile(
                name=full_name,
                data=file_data[:self._max_file_size],
                file_type=file_type,
                depth=depth + 1,
                parent=parent_name,
            ))

    def _unpack_cpio(self, data: bytes, parent_name: str, depth: int):
        """Parse CPIO archive (common in initramfs)."""
        offset = 0
        while offset < len(data) - 110 and len(self._files) < self._max_files:
            # newc format: "070701" header
            if data[offset:offset + 6] != b'070701' and data[offset:offset + 6] != b'070702':
                break

            try:
                # Parse CPIO header (110 bytes in newc format)
                namesize = int(data[offset + 94:offset + 102], 16)
                filesize = int(data[offset + 54:offset + 62], 16)

                # Align to 4 bytes
                name_offset = offset + 110
                name_end = name_offset + namesize
                name_padded = (name_end + 3) & ~3

                filename = data[name_offset:name_end - 1].decode('ascii', errors='ignore')

                data_offset = name_padded
                data_end = data_offset + filesize
                data_padded = (data_end + 3) & ~3

                if filename == 'TRAILER!!!' or filesize == 0:
                    offset = data_padded
                    continue

                if filesize > 0 and filesize < self._max_file_size:
                    file_data = data[data_offset:data_end]
                    full_path = f"{parent_name}/{filename}"
                    self.unpack(file_data, full_path, depth + 1)

                offset = data_padded
            except Exception:
                break

    def _unpack_uboot(self, data: bytes, parent_name: str, depth: int):
        """Handle U-Boot image."""
        if len(data) < 64:
            return

        try:
            comp_type = data[31]
            payload = data[64:]

            if comp_type == 1:  # gzip
                self._unpack_gzip(payload, f"{parent_name}/payload", depth + 1)
            elif comp_type == 3:  # lzma
                self._unpack_lzma(payload, f"{parent_name}/payload", depth + 1)
            else:
                self.unpack(payload, f"{parent_name}/payload", depth + 1)
        except Exception:
            pass

    def _scan_for_embedded_containers(self, data: bytes, parent_name: str, depth: int):
        """Scan a raw firmware blob for embedded filesystems/containers."""
        files_before = len(self._files)
        scan_limit = min(len(data), 32 * 1024 * 1024)

        # Scan for SquashFS magic
        offset = 0
        while offset < scan_limit - 4:
            pos = data.find(b'hsqs', offset)
            if pos == -1:
                pos = data.find(b'sqsh', offset)
            if pos == -1 or pos >= scan_limit:
                break
            # Verify it's a real superblock (check version)
            if pos + 30 <= len(data):
                ver_major = struct.unpack_from('<H', data, pos + 28)[0]
                if ver_major == 4:
                    sqfs_data = data[pos:]
                    self._unpack_squashfs(sqfs_data, f"{parent_name}/squashfs@{pos:#x}", depth + 1)
                    break
            offset = pos + 4

        # If SquashFS didn't yield results, try compressed streams
        if len(self._files) == files_before:
            pos = data.find(b'\x1f\x8b\x08', 0, scan_limit)
            if pos > 0 and pos < scan_limit:
                self._unpack_gzip(data[pos:], f"{parent_name}/gzip@{pos:#x}", depth + 1)

        if len(self._files) == files_before:
            pos = data.find(b'\xfd7zXZ\x00', 0, scan_limit)
            if pos > 0 and pos < scan_limit:
                self._unpack_lzma(data[pos:], f"{parent_name}/xz@{pos:#x}", depth + 1)

        # Fallback: scan for embedded ELF files
        if len(self._files) == files_before:
            self._scan_for_embedded_files(data, parent_name, depth)

    def _scan_for_embedded_files(self, data: bytes, parent_name: str, depth: int):
        """Scan container data for embedded files by magic bytes."""
        # Search for ELF files
        offset = 0
        found = 0
        while found < 50:
            pos = data.find(b'\x7fELF', offset)
            if pos == -1 or pos >= len(data) - 100:
                break
            # Extract a reasonable chunk (up to next ELF or 1MB)
            next_elf = data.find(b'\x7fELF', pos + 4)
            end = min(next_elf if next_elf > 0 else len(data), pos + 1024 * 1024)
            chunk = data[pos:end]
            self._files.append(UnpackedFile(
                name=f"{parent_name}/elf_{pos:#x}",
                data=chunk[:self._max_file_size],
                file_type="elf",
                depth=depth + 1,
            ))
            found += 1
            offset = pos + len(chunk)

    def _unpack_android_sparse(self, data: bytes, parent_name: str, depth: int):
        """Convert Android sparse image to raw and recurse."""
        from ..android.sparse import SparseImageParser

        parser = SparseImageParser()
        raw_size = parser.get_raw_size(data)

        # Only convert if reasonable size
        if raw_size > 2 * 1024 * 1024 * 1024:
            return

        raw_data = parser.to_raw(data, max_output_size=2 * 1024 * 1024 * 1024)
        if raw_data:
            inner_name = parent_name.replace('.simg', '').replace('.img', '') + '_raw'
            self.unpack(raw_data, inner_name, depth + 1)

    def _unpack_ext4(self, data: bytes, parent_name: str, depth: int):
        """Extract key files from ext4 filesystem."""
        from ..android.ext4_reader import Ext4Reader

        reader = Ext4Reader(data)
        if not reader.is_valid():
            return

        self._extract_from_filesystem(reader, parent_name, depth)

    def _unpack_erofs(self, data: bytes, parent_name: str, depth: int):
        """Extract key files from EROFS filesystem."""
        from ..android.erofs_reader import ErofsReader

        reader = ErofsReader(data)
        if not reader.is_valid():
            return

        self._extract_from_filesystem(reader, parent_name, depth)

    def _extract_from_filesystem(self, reader, parent_name: str, depth: int):
        """Extract priority files from a filesystem reader (ext4 or erofs)."""
        # Priority paths to extract
        priority_files = [
            "/build.prop", "/system/build.prop", "/vendor/build.prop",
            "/default.prop", "/product/build.prop",
        ]

        for file_path in priority_files:
            if len(self._files) >= self._max_files:
                break
            try:
                file_data = reader.read_file(file_path, max_size=self._max_file_size)
                if file_data:
                    self._files.append(UnpackedFile(
                        name=f"{parent_name}{file_path}",
                        data=file_data,
                        file_type="config",
                        depth=depth + 1,
                        parent=parent_name,
                    ))
            except Exception:
                continue

        # Scan for APKs and libraries
        scan_dirs = [
            "/system/app", "/system/priv-app", "/vendor/app",
            "/app", "/priv-app",
            "/system/lib64", "/system/lib", "/vendor/lib64", "/vendor/lib",
            "/lib64", "/lib",
        ]

        for dir_path in scan_dirs:
            if len(self._files) >= self._max_files:
                break
            try:
                entries = reader.list_directory(dir_path)
            except Exception:
                continue

            for entry in entries:
                if len(self._files) >= self._max_files:
                    break

                full_path = f"{dir_path.rstrip('/')}/{entry.name}"
                name_lower = entry.name.lower()

                if entry.is_dir and ("app" in dir_path):
                    # Look for APK inside app directory
                    try:
                        sub_entries = reader.list_directory(full_path)
                        for sub in sub_entries:
                            if sub.name.lower().endswith('.apk'):
                                apk_path = f"{full_path}/{sub.name}"
                                apk_data = reader.read_file(apk_path, max_size=self._max_file_size)
                                if apk_data:
                                    self._files.append(UnpackedFile(
                                        name=f"{parent_name}{apk_path}",
                                        data=apk_data,
                                        file_type="zip",
                                        depth=depth + 1,
                                        parent=parent_name,
                                    ))
                                break
                    except Exception:
                        continue

                elif entry.is_file and (name_lower.endswith('.so') or name_lower.endswith('.apk')):
                    file_data = reader.read_file(full_path, max_size=self._max_file_size)
                    if file_data:
                        ftype = "zip" if name_lower.endswith('.apk') else "elf"
                        self._files.append(UnpackedFile(
                            name=f"{parent_name}{full_path}",
                            data=file_data,
                            file_type=ftype,
                            depth=depth + 1,
                            parent=parent_name,
                        ))

    def get_all_files(self) -> list[UnpackedFile]:
        """Return all unpacked files."""
        return self._files

    def get_files_by_type(self, file_type: str) -> list[UnpackedFile]:
        """Return files of a specific type."""
        return [f for f in self._files if f.file_type == file_type]

    def get_summary(self) -> dict:
        """Return summary of unpacked contents."""
        from collections import Counter
        types = Counter(f.file_type for f in self._files)
        return {
            "total_files": len(self._files),
            "max_depth": max((f.depth for f in self._files), default=0),
            "by_type": dict(types),
        }
