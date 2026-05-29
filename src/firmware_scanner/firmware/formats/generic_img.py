"""Generic disk image format handler - example extension for image formats."""

import struct
from pathlib import Path

from ..extension_api import DiskImageFormat
from ...extraction.models import UnpackResult, FirmwareSection


class GenericImageFormat(DiskImageFormat):
    """Handler for generic firmware .img files.

    Supports:
    - Android boot.img (ANDROID! magic)
    - Android sparse image (0xED26FF3A magic)
    - Raw partition images with known filesystem magic
    """

    @property
    def format_name(self) -> str:
        return "Generic Image"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if path.suffix.lower() not in (".img", ".image", ".partition"):
            return 0.0

        # Android boot image
        if data[:8] == b"ANDROID!":
            return 0.9

        # Android sparse image
        if len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] == 0xED26FF3A:
            return 0.85

        # Generic .img with no known magic - still try
        return 0.35

    def _find_partitions(self, data: bytes) -> list[tuple[str, int, int]]:
        """Detect partitions within the image."""
        partitions = []

        # Android boot image
        if data[:8] == b"ANDROID!":
            partitions.extend(self._parse_android_boot(data))
            return partitions

        # Try to find embedded ELF/filesystem markers
        partitions.extend(self._scan_for_embedded_images(data))

        return partitions

    def _parse_android_boot(self, data: bytes) -> list[tuple[str, int, int]]:
        """Parse Android boot image header."""
        if len(data) < 1632:
            return []

        # Standard Android boot image header
        kernel_size = struct.unpack_from("<I", data, 8)[0]
        kernel_addr = struct.unpack_from("<I", data, 12)[0]
        ramdisk_size = struct.unpack_from("<I", data, 16)[0]
        second_size = struct.unpack_from("<I", data, 24)[0]
        page_size = struct.unpack_from("<I", data, 36)[0]

        if page_size == 0:
            page_size = 2048

        partitions = []
        offset = page_size  # kernel starts after header page

        if kernel_size > 0:
            partitions.append(("kernel", offset, kernel_size))
            offset += (kernel_size + page_size - 1) // page_size * page_size

        if ramdisk_size > 0:
            partitions.append(("ramdisk", offset, ramdisk_size))
            offset += (ramdisk_size + page_size - 1) // page_size * page_size

        if second_size > 0:
            partitions.append(("second", offset, second_size))

        return partitions

    def _scan_for_embedded_images(self, data: bytes) -> list[tuple[str, int, int]]:
        """Scan for known filesystem/image magic within the data."""
        results = []
        scan_limit = min(len(data), 64 * 1024 * 1024)  # 64MB limit

        # SquashFS magic
        sqfs_pos = data.find(b"hsqs", 0, scan_limit)
        if sqfs_pos != -1:
            results.append(("squashfs", sqfs_pos, min(len(data) - sqfs_pos, 32 * 1024 * 1024)))

        # CramFS magic
        cramfs_pos = data.find(b"\x45\x3d\xcd\x28", 0, scan_limit)
        if cramfs_pos != -1:
            results.append(("cramfs", cramfs_pos, min(len(data) - cramfs_pos, 16 * 1024 * 1024)))

        # JFFS2 magic
        jffs2_pos = data.find(b"\x85\x19", 0, scan_limit)
        if jffs2_pos != -1:
            results.append(("jffs2", jffs2_pos, min(len(data) - jffs2_pos, 32 * 1024 * 1024)))

        return results
