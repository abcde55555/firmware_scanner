"""Flash filesystem format handlers: CramFS and JFFS2."""

from pathlib import Path

from .base import FirmwareFormat
from ..cramfs_reader import CramFSReader, CRAMFS_MAGIC_LE, CRAMFS_MAGIC_BE
from ..jffs2_reader import JFFS2Reader
from ...extraction.models import UnpackResult, FirmwareSection


class CramFSFormat(FirmwareFormat):
    """Handler for Compressed ROM File System (CramFS) images."""

    @property
    def format_name(self) -> str:
        return "CramFS Filesystem"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if len(data) < 64:
            return 0.0
        reader = CramFSReader(data[:4096])
        if reader.is_valid():
            return 0.95
        if path.suffix.lower() in (".cramfs", ".cram"):
            return 0.85
        return 0.0

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        result = UnpackResult()
        reader = CramFSReader(data)
        if not reader.is_valid():
            return result

        for entry in reader.list_files():
            content = reader.read_file(entry)
            sec_name = entry.path.lstrip("/")
            result.sections.append(FirmwareSection(
                name=sec_name,
                offset=entry.offset,
                size=len(content),
                data=content,
                section_type="file",
            ))

        return result


class JFFS2Format(FirmwareFormat):
    """Handler for Journalling Flash File System v2 (JFFS2) images."""

    @property
    def format_name(self) -> str:
        return "JFFS2 Flash Filesystem"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if len(data) < 16:
            return 0.0
        reader = JFFS2Reader(data[:65536])
        if reader.is_valid():
            return 0.92
        if path.suffix.lower() in (".jffs2", ".jffs"):
            return 0.85
        return 0.0

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        result = UnpackResult()
        reader = JFFS2Reader(data)
        if not reader.is_valid():
            return result

        for f_obj in reader.list_files():
            content = reader.read_file(f_obj)
            sec_name = f_obj.path.lstrip("/")
            result.sections.append(FirmwareSection(
                name=sec_name,
                offset=0,
                size=len(content),
                data=content,
                section_type="file",
            ))

        return result
