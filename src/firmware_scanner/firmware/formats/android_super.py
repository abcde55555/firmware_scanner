"""Android 10+ super.img (Logical Partition / LP metadata) format handler."""

import struct
from pathlib import Path

from .base import FirmwareFormat
from ...android.super_img import SuperImageParser, LP_GEOMETRY_MAGIC, LP_METADATA_MAGIC
from ...android.sparse import SparseImageParser
from ...extraction.models import UnpackResult, FirmwareSection


class AndroidSuperImageFormat(FirmwareFormat):
    """Handler for Android 10+ super.img dynamic partition containers."""

    @property
    def format_name(self) -> str:
        return "Android Super Image"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if len(data) < 8192:
            return 0.0

        # Case 1: Sparse image wrapping super.img
        sparse_parser = SparseImageParser()
        if sparse_parser.is_sparse(data):
            try:
                raw_header = sparse_parser.extract_region(data, 0, 8192)
                if len(raw_header) >= 8192:
                    for offset in (0x1000, 0x2000, 0x3000, 0x4000):
                        if struct.unpack_from('<I', raw_header, offset)[0] == LP_GEOMETRY_MAGIC:
                            return 0.98
            except Exception:
                pass

        # Case 2: Raw super.img with LP_GEOMETRY_MAGIC at 4096 or scanning
        for offset in (0x1000, 0x2000, 0x3000, 0x4000):
            if offset + 4 <= len(data):
                if struct.unpack_from('<I', data, offset)[0] == LP_GEOMETRY_MAGIC:
                    return 0.95

        # Case 3: Filename check fallback
        if "super" in path.name.lower() and path.suffix.lower() == ".img":
            if b"\x67\x44\x6C\x70" in data[:65536] or b"\x61\x6C\x44\x67" in data[:65536]:
                return 0.90

        return 0.0

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        result = UnpackResult()
        parser = SuperImageParser()
        partitions = parser.parse(data)

        sparse_parser = SparseImageParser()
        is_sparse = sparse_parser.is_sparse(data)

        for p in partitions:
            if p.size == 0:
                continue

            # Read partition payload
            if is_sparse:
                part_data = sparse_parser.extract_region(data, p.offset, p.size)
            else:
                part_data = data[p.offset:p.offset + p.size]

            sec_name = f"{p.name}.img" if not p.name.endswith(".img") else p.name
            result.sections.append(FirmwareSection(
                name=sec_name,
                offset=p.offset,
                size=p.size,
                data=part_data,
                section_type="filesystem" if any(k in p.name.lower() for k in ("system", "vendor", "product", "odm", "system_ext")) else "partition",
            ))

        return result
