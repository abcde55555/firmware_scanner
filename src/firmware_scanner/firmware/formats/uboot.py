"""U-Boot image format handler."""

import struct
from pathlib import Path

from .base import FirmwareFormat
from ...extraction.models import UnpackResult, FirmwareSection

# U-Boot image magic
UBOOT_MAGIC = 0x27051956
UBOOT_HEADER_SIZE = 64


class UBootFormat(FirmwareFormat):
    @property
    def format_name(self) -> str:
        return "U-Boot Image"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if len(data) < UBOOT_HEADER_SIZE:
            return 0.0
        magic = struct.unpack_from(">I", data, 0)[0]
        if magic == UBOOT_MAGIC:
            return 0.9
        return 0.0

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        if len(data) < UBOOT_HEADER_SIZE:
            return UnpackResult()

        magic = struct.unpack_from(">I", data, 0)[0]
        if magic != UBOOT_MAGIC:
            return UnpackResult()

        # Parse U-Boot header (big-endian)
        hdr_crc = struct.unpack_from(">I", data, 4)[0]
        timestamp = struct.unpack_from(">I", data, 8)[0]
        data_size = struct.unpack_from(">I", data, 12)[0]
        load_addr = struct.unpack_from(">I", data, 16)[0]
        entry_point = struct.unpack_from(">I", data, 20)[0]
        data_crc = struct.unpack_from(">I", data, 24)[0]
        os_type = data[28]
        arch_type = data[29]
        image_type = data[30]
        comp_type = data[31]
        name = data[32:64].split(b"\x00")[0].decode("ascii", errors="ignore")

        # Extract payload
        payload_offset = UBOOT_HEADER_SIZE
        payload = data[payload_offset:payload_offset + data_size]

        # Decompress if needed
        if comp_type == 1:  # gzip
            try:
                import gzip
                payload = gzip.decompress(payload)
            except Exception:
                # Fallback: try raw deflate (skip gzip header)
                try:
                    import zlib
                    # Find gzip magic in payload and decompress from there
                    gz_offset = payload.find(b"\x1f\x8b")
                    if gz_offset >= 0:
                        payload = zlib.decompress(payload[gz_offset + 10:], -15)
                    else:
                        payload = zlib.decompress(payload[10:], -15)
                except Exception:
                    pass
        elif comp_type == 2:  # bzip2
            try:
                import bz2
                payload = bz2.decompress(payload)
            except Exception:
                pass
        elif comp_type == 3:  # lzma
            try:
                import lzma
                payload = lzma.decompress(payload)
            except Exception:
                pass

        sections = [
            FirmwareSection(
                name=name or "uboot_payload",
                offset=payload_offset,
                size=len(payload),
                data=payload[:16 * 1024 * 1024],  # Cap at 16MB for analysis
                section_type="code",
            )
        ]

        metadata = {
            "uboot_name": name,
            "os_type": os_type,
            "arch_type": arch_type,
            "image_type": image_type,
            "compression": comp_type,
            "timestamp": timestamp,
        }

        return UnpackResult(
            sections=sections,
            entry_point=entry_point,
            load_address=load_addr,
            metadata=metadata,
        )
