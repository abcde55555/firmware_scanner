"""Android system image format handler.

Handles Android partition images in various formats:
- ext4 filesystem images (system.img, vendor.img, product.img)
- EROFS filesystem images (Android 12+)
- super.img (LP metadata containing multiple partitions)
- Android sparse images wrapping any of the above
"""

import struct
from pathlib import Path

from ..extension_api import DiskImageFormat
from ...extraction.models import UnpackResult, FirmwareSection
from ...android.sparse import SparseImageParser
from ...android.super_img import SuperImageParser
from ...android.ext4_reader import Ext4Reader
from ...android.erofs_reader import ErofsReader


# Magic bytes and offsets
EXT4_MAGIC = 0xEF53
EXT4_MAGIC_OFFSET = 0x438
EROFS_MAGIC = 0xE0F5E1E2
EROFS_MAGIC_OFFSET = 0x400
SPARSE_MAGIC = 0xED26FF3A
ANDROID_BOOT_MAGIC = b"ANDROID!"
LP_GEOMETRY_MAGIC = 0x616C4467

# Key files to extract as FirmwareSections for downstream analysis
PRIORITY_PATHS = [
    "/system/build.prop",
    "/vendor/build.prop",
    "/product/build.prop",
    "/default.prop",
    "/build.prop",
    "/system/etc/build.prop",
]


class AndroidSystemImageFormat(DiskImageFormat):
    """Handler for Android system/vendor/product partition images and super.img."""

    @property
    def format_name(self) -> str:
        return "Android System Image"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        name_lower = path.name.lower()

        # Check for super.img (LP metadata)
        if cls._is_super_img(data):
            return 0.95

        # Handle sparse wrapper
        raw_data = data
        if len(data) >= 4 and struct.unpack_from('<I', data, 0)[0] == SPARSE_MAGIC:
            parser = SparseImageParser()
            # Extract enough to check inner filesystem magic
            raw_data = parser.extract_region(data, 0, 0x500)

        # ext4 detection
        if cls._is_ext4(raw_data):
            # Higher confidence for Android-named files
            if any(kw in name_lower for kw in ('system', 'vendor', 'product',
                                                'system_ext', 'odm', 'oem')):
                return 0.93
            if name_lower.endswith('.img'):
                return 0.80
            return 0.70

        # EROFS detection
        if cls._is_erofs(raw_data):
            if any(kw in name_lower for kw in ('system', 'vendor', 'product')):
                return 0.93
            if name_lower.endswith('.img'):
                return 0.80
            return 0.70

        # Sparse image that we can't identify the inner format of
        if len(data) >= 4 and struct.unpack_from('<I', data, 0)[0] == SPARSE_MAGIC:
            if name_lower.endswith('.img'):
                return 0.60
            return 0.40

        return 0.0

    @classmethod
    def _is_ext4(cls, data: bytes) -> bool:
        if len(data) < EXT4_MAGIC_OFFSET + 2:
            return False
        return struct.unpack_from('<H', data, EXT4_MAGIC_OFFSET)[0] == EXT4_MAGIC

    @classmethod
    def _is_erofs(cls, data: bytes) -> bool:
        if len(data) < EROFS_MAGIC_OFFSET + 4:
            return False
        return struct.unpack_from('<I', data, EROFS_MAGIC_OFFSET)[0] == EROFS_MAGIC

    @classmethod
    def _is_super_img(cls, data: bytes) -> bool:
        """Check if this is a super.img with LP metadata."""
        # Direct LP geometry magic at primary offset
        if len(data) > 0x1000 + 4:
            if struct.unpack_from('<I', data, 0x1000)[0] == LP_GEOMETRY_MAGIC:
                return True

        # Sparse image wrapping super
        if len(data) >= 4 and struct.unpack_from('<I', data, 0)[0] == SPARSE_MAGIC:
            parser = SparseImageParser()
            region = parser.extract_region(data, 0x1000, 64)
            if len(region) >= 4 and struct.unpack_from('<I', region, 0)[0] == LP_GEOMETRY_MAGIC:
                return True

        return False

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        """Unpack Android system image into analyzable sections."""
        # Handle sparse images first
        raw_data = data
        is_sparse = False
        if len(data) >= 4 and struct.unpack_from('<I', data, 0)[0] == SPARSE_MAGIC:
            is_sparse = True
            sparse_parser = SparseImageParser()
            raw_size = sparse_parser.get_raw_size(data)
            # Only convert to raw if reasonable size (< 2GB for in-memory)
            if raw_size > 0 and raw_size < 2 * 1024 * 1024 * 1024:
                converted = sparse_parser.to_raw(data, max_output_size=2 * 1024 * 1024 * 1024)
                if converted:
                    raw_data = converted

        # Check if this is a super.img
        if self._is_super_img(raw_data):
            return self._unpack_super(raw_data, data, path)

        # Determine filesystem type and unpack
        if self._is_ext4(raw_data):
            return self._unpack_ext4(raw_data, path)
        elif self._is_erofs(raw_data):
            return self._unpack_erofs(raw_data, path)

        # Fallback: treat as raw partition
        return self._unpack_fallback(raw_data, path)

    def _unpack_super(self, raw_data: bytes, original_data: bytes, path: Path) -> UnpackResult:
        """Unpack super.img by extracting all contained partitions."""
        parser = SuperImageParser()
        partitions = parser.parse(raw_data)

        sections: list[FirmwareSection] = []
        metadata = {"super_partitions": [p.name for p in partitions]}

        for part_info in partitions:
            # Extract partition data
            part_data = parser.extract_partition(raw_data, part_info)
            if not part_data or len(part_data) < 1024:
                continue

            sections.append(FirmwareSection(
                name=f"{part_info.name}.img",
                offset=part_info.offset,
                size=part_info.size,
                data=part_data,
                section_type="partition",
            ))

            # For each extracted partition, also extract key files
            fs_sections = self._extract_key_files_from_partition(part_data, part_info.name)
            sections.extend(fs_sections)

        return UnpackResult(sections=sections, metadata=metadata)

    def _unpack_ext4(self, data: bytes, path: Path) -> UnpackResult:
        """Unpack ext4 filesystem image."""
        reader = Ext4Reader(data)
        if not reader.is_valid():
            return self._unpack_fallback(data, path)

        sections = self._extract_filesystem_sections(reader, path.stem)
        metadata = {"filesystem": "ext4", "partition_name": path.stem}

        return UnpackResult(sections=sections, metadata=metadata)

    def _unpack_erofs(self, data: bytes, path: Path) -> UnpackResult:
        """Unpack EROFS filesystem image."""
        reader = ErofsReader(data)
        if not reader.is_valid():
            return self._unpack_fallback(data, path)

        sections = self._extract_filesystem_sections(reader, path.stem)
        metadata = {"filesystem": "erofs", "partition_name": path.stem}

        return UnpackResult(sections=sections, metadata=metadata)

    def _extract_filesystem_sections(self, reader, partition_name: str) -> list[FirmwareSection]:
        """Extract key files from a filesystem reader (ext4 or erofs)."""
        sections: list[FirmwareSection] = []
        files_found = 0
        max_files = 500

        # First, extract priority files (build.prop, etc.)
        for priority_path in PRIORITY_PATHS:
            file_data = reader.read_file(priority_path)
            if file_data:
                sections.append(FirmwareSection(
                    name=f"{partition_name}{priority_path}",
                    offset=0,
                    size=len(file_data),
                    data=file_data,
                    section_type="config",
                ))
                files_found += 1

        # Scan key directories
        scan_dirs = [
            ("/system/app", "apk"),
            ("/system/priv-app", "apk"),
            ("/vendor/app", "apk"),
            ("/product/app", "apk"),
            ("/system/lib64", "lib"),
            ("/system/lib", "lib"),
            ("/vendor/lib64", "lib"),
            ("/vendor/lib", "lib"),
            ("/system/bin", "bin"),
            ("/vendor/bin", "bin"),
            ("/system/framework", "framework"),
            ("/app", "apk"),
            ("/priv-app", "apk"),
            ("/lib64", "lib"),
            ("/lib", "lib"),
            ("/bin", "bin"),
            ("/framework", "framework"),
        ]

        for dir_path, section_type in scan_dirs:
            if files_found >= max_files:
                break

            try:
                entries = reader.list_directory(dir_path)
            except Exception:
                continue

            for entry in entries:
                if files_found >= max_files:
                    break

                full_path = f"{dir_path.rstrip('/')}/{entry.name}"

                if entry.is_dir:
                    # For app directories, look for APK inside
                    if section_type == "apk":
                        self._extract_apk_from_dir(
                            reader, full_path, partition_name, sections
                        )
                        files_found += 1
                elif entry.is_file:
                    name_lower = entry.name.lower()
                    # Only extract relevant files
                    if (name_lower.endswith('.apk') or
                        name_lower.endswith('.so') or
                        name_lower.endswith('.jar') or
                        section_type == "bin"):

                        file_size = reader.file_size(full_path)
                        # Limit: read up to 32MB for APKs (need manifest), 8MB for others
                        max_read = 32 * 1024 * 1024 if name_lower.endswith('.apk') else 8 * 1024 * 1024
                        if file_size > 0:
                            file_data = reader.read_file(full_path, max_size=max_read)
                            if file_data:
                                sections.append(FirmwareSection(
                                    name=f"{partition_name}{full_path}",
                                    offset=0,
                                    size=len(file_data),
                                    data=file_data,
                                    section_type=section_type,
                                ))
                                files_found += 1

        return sections

    def _extract_apk_from_dir(self, reader, dir_path: str, partition_name: str,
                               sections: list[FirmwareSection]):
        """Extract APK file from an app directory (e.g., /system/app/Settings/)."""
        try:
            entries = reader.list_directory(dir_path)
        except Exception:
            return

        for entry in entries:
            if entry.name.lower().endswith('.apk'):
                full_path = f"{dir_path.rstrip('/')}/{entry.name}"
                file_data = reader.read_file(full_path, max_size=32 * 1024 * 1024)
                if file_data:
                    sections.append(FirmwareSection(
                        name=f"{partition_name}{full_path}",
                        offset=0,
                        size=len(file_data),
                        data=file_data,
                        section_type="apk",
                    ))
                break  # Usually only one APK per app dir

    def _extract_key_files_from_partition(self, data: bytes, partition_name: str) -> list[FirmwareSection]:
        """Try to extract key files from a partition's raw data."""
        sections: list[FirmwareSection] = []

        # Try ext4
        if self._is_ext4(data):
            reader = Ext4Reader(data)
            if reader.is_valid():
                for priority_path in PRIORITY_PATHS:
                    file_data = reader.read_file(priority_path)
                    if file_data:
                        sections.append(FirmwareSection(
                            name=f"{partition_name}{priority_path}",
                            offset=0,
                            size=len(file_data),
                            data=file_data,
                            section_type="config",
                        ))
            return sections

        # Try EROFS
        if self._is_erofs(data):
            reader = ErofsReader(data)
            if reader.is_valid():
                for priority_path in PRIORITY_PATHS:
                    file_data = reader.read_file(priority_path)
                    if file_data:
                        sections.append(FirmwareSection(
                            name=f"{partition_name}{priority_path}",
                            offset=0,
                            size=len(file_data),
                            data=file_data,
                            section_type="config",
                        ))

        return sections

    def _unpack_fallback(self, data: bytes, path: Path) -> UnpackResult:
        """Fallback for unrecognized partition format."""
        return UnpackResult(
            sections=[FirmwareSection(
                name=path.stem,
                offset=0,
                size=len(data),
                data=data,
                section_type="unknown",
            )],
            metadata={"format": "raw_partition"},
        )
