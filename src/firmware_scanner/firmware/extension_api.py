"""Extension interfaces for adding new firmware formats easily.

This module provides simplified base classes and registration helpers
that make it easy to add support for new firmware types (APK, IMG, etc.)
without modifying existing code.
"""

from pathlib import Path
from typing import Callable

from .formats.base import FirmwareFormat
from ..extraction.models import UnpackResult, FirmwareSection

# Registry populated at runtime - avoids circular import
_EXTENSION_REGISTRY: list[type[FirmwareFormat]] = []


def register_format(handler_class: type[FirmwareFormat]) -> type[FirmwareFormat]:
    """Decorator to register a new firmware format handler.

    Usage:
        @register_format
        class MyNewFormat(FirmwareFormat):
            ...
    """
    _EXTENSION_REGISTRY.append(handler_class)
    return handler_class


def get_extension_formats() -> list[type[FirmwareFormat]]:
    """Get all extension-registered format handlers."""
    return _EXTENSION_REGISTRY.copy()


class ZipBasedFormat(FirmwareFormat):
    """Base class for ZIP-based firmware formats (APK, OTA packages, etc.).

    Subclass and implement:
    - format_name property
    - can_handle() classmethod
    - _get_files_to_analyze() to specify which files inside the ZIP to scan
    """

    @property
    def format_name(self) -> str:
        return "ZIP-based"

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        import zipfile
        import io

        sections: list[FirmwareSection] = []
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            target_files = self._get_files_to_analyze(zf)

            for i, name in enumerate(target_files):
                try:
                    file_data = zf.read(name)
                    if file_data and len(file_data) > 16:
                        section_type = self._classify_file(name)
                        sections.append(FirmwareSection(
                            name=name,
                            offset=i,
                            size=len(file_data),
                            data=file_data,
                            section_type=section_type,
                        ))
                except Exception:
                    continue
            zf.close()
        except Exception:
            pass

        return UnpackResult(sections=sections, metadata={"zip_files": len(sections)})

    def _get_files_to_analyze(self, zf) -> list[str]:
        """Override to filter which files inside the archive to analyze."""
        return zf.namelist()

    def _classify_file(self, name: str) -> str:
        """Classify file type by extension."""
        ext = Path(name).suffix.lower()
        if ext in (".so", ".dylib", ".dll", ".elf", ".bin"):
            return "code"
        elif ext in (".dex", ".class", ".jar"):
            return "code"
        elif ext in (".xml", ".json", ".txt", ".cfg", ".ini", ".properties"):
            return "data"
        return "unknown"


class DiskImageFormat(FirmwareFormat):
    """Base class for disk/partition image formats.

    Handles raw disk images, Android super.img, filesystem images, etc.
    Subclass and implement format-specific partition table parsing.
    """

    @property
    def format_name(self) -> str:
        return "Disk Image"

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        partitions = self._find_partitions(data)
        sections = []

        for name, offset, size in partitions:
            part_data = data[offset:offset + size]
            sections.append(FirmwareSection(
                name=name,
                offset=offset,
                size=size,
                data=part_data,
                section_type="code",
            ))

        if not sections:
            # Fallback: treat entire image as single section
            sections.append(FirmwareSection(
                name="raw_image",
                offset=0,
                size=len(data),
                data=data,
                section_type="unknown",
            ))

        return UnpackResult(sections=sections)

    def _find_partitions(self, data: bytes) -> list[tuple[str, int, int]]:
        """Override to implement partition detection. Returns [(name, offset, size)]."""
        return []
