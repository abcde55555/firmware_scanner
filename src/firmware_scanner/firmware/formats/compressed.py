"""Generic compressed firmware handler - auto-detects and decompresses."""

import gzip
import struct
from pathlib import Path

from .base import FirmwareFormat
from ...extraction.models import UnpackResult, FirmwareSection


class CompressedFirmwareFormat(FirmwareFormat):
    """Handles firmware wrapped in a compression layer (gzip, lzma, xz)."""

    @property
    def format_name(self) -> str:
        return "Compressed Firmware"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if len(data) < 4:
            return 0.0
        # gzip
        if data[:2] == b"\x1f\x8b":
            return 0.85
        # XZ
        if data[:6] == b"\xfd7zXZ\x00":
            return 0.85
        # LZMA (common header pattern)
        if data[:3] == b"\x5d\x00\x00" and path.suffix.lower() in (".lzma", ".bin", ".fw", ".img"):
            return 0.7
        # zstd
        if data[:4] == b"\x28\xb5\x2f\xfd":
            return 0.85
        return 0.0

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        decompressed = self._try_decompress(data)
        if not decompressed:
            return UnpackResult()

        sections = [
            FirmwareSection(
                name="decompressed_firmware",
                offset=0,
                size=len(decompressed),
                data=decompressed,
                section_type="code",
            )
        ]

        return UnpackResult(
            sections=sections,
            metadata={"compression": self._detect_type(data)},
        )

    def _try_decompress(self, data: bytes) -> bytes | None:
        # gzip
        if data[:2] == b"\x1f\x8b":
            try:
                return gzip.decompress(data)
            except Exception:
                pass

        # XZ / LZMA
        if data[:6] == b"\xfd7zXZ\x00" or data[:3] == b"\x5d\x00\x00":
            try:
                import lzma
                return lzma.decompress(data)
            except Exception:
                pass

        # zstd
        if data[:4] == b"\x28\xb5\x2f\xfd":
            try:
                import zstandard
                dctx = zstandard.ZstdDecompressor()
                return dctx.decompress(data, max_output_size=64 * 1024 * 1024)
            except Exception:
                pass

        return None

    def _detect_type(self, data: bytes) -> str:
        if data[:2] == b"\x1f\x8b":
            return "gzip"
        if data[:6] == b"\xfd7zXZ\x00":
            return "xz"
        if data[:3] == b"\x5d\x00\x00":
            return "lzma"
        if data[:4] == b"\x28\xb5\x2f\xfd":
            return "zstd"
        return "unknown"
