"""Allwinner PhoenixSuit / LiveSuite firmware image container format handler.

Supports Allwinner firmware images with IMAGEWTY magic header (v1 and v3),
containing partitions such as:
- system.fex (Android sparse ext4 or raw ext4 filesystem)
- boot.fex (Android boot.img)
- recovery.fex (Android recovery boot.img)
- u-boot.fex (U-Boot bootloader)
- sys_config.fex (Hardware / SoC pinmux config)
- env.fex, boot-resource.fex, etc.
"""

import struct
from pathlib import Path
from typing import Any

from .base import FirmwareFormat
from ...extraction.models import UnpackResult, FirmwareSection
from ...android.sparse import SparseImageParser

IMAGEWTY_MAGIC = b"IMAGEWTY"


class AllwinnerImageFormat(FirmwareFormat):
    """Handler for Allwinner PhoenixSuit / LiveSuite firmware images."""

    @property
    def format_name(self) -> str:
        return "Allwinner Firmware Image"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if len(data) >= 8 and data[:8] == IMAGEWTY_MAGIC:
            return 0.98
        return 0.0

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        """Unpack Allwinner firmware container into sections."""
        if len(data) < 1024 or data[:8] != IMAGEWTY_MAGIC:
            return UnpackResult(sections=[], metadata={"error": "Not a valid Allwinner image"})

        version, hdr_size, ram_base, fmt_ver, img_size, img_hdr_size = struct.unpack_from(
            "<6I", data, 8
        )

        metadata: dict[str, Any] = {
            "format": "allwinner_imagewty",
            "header_version": version,
            "format_version": fmt_ver,
            "ram_base": ram_base,
            "image_size": img_size,
        }

        # Determine number of files based on header version
        if version == 0x0300:
            num_files = struct.unpack_from("<I", data, 60)[0]
        else:
            num_files = struct.unpack_from("<I", data, 56)[0]

        if num_files <= 0 or num_files > 256:
            # Fallback sanity
            num_files = 32

        sections: list[FirmwareSection] = []
        sparse_parser = SparseImageParser()

        for i in range(num_files):
            fhdr_off = 1024 + i * 1024
            if fhdr_off + 1024 > len(data):
                break

            fhdr = data[fhdr_off : fhdr_off + 1024]
            maintype = fhdr[8:16].split(b"\x00")[0].decode("latin1", errors="ignore").strip()
            subtype = fhdr[16:32].split(b"\x00")[0].decode("latin1", errors="ignore").strip()

            if version == 0x0300:
                filename = fhdr[36:292].split(b"\x00")[0].decode("latin1", errors="ignore").strip()
                stored_len, pad1, orig_len, pad2, offset = struct.unpack_from("<5I", fhdr, 292)
            else:
                stored_len, orig_len, offset = struct.unpack_from("<3I", fhdr, 36)
                filename = fhdr[48:304].split(b"\x00")[0].decode("latin1", errors="ignore").strip()

            if not filename or offset >= len(data) or orig_len == 0:
                continue

            length = min(orig_len, len(data) - offset)
            file_bytes = data[offset : offset + length]

            # Detect sparse image and convert to raw
            if len(file_bytes) >= 4 and struct.unpack_from("<I", file_bytes, 0)[0] == 0xED26FF3A:
                raw_size = sparse_parser.get_raw_size(file_bytes)
                if 0 < raw_size < 2 * 1024 * 1024 * 1024:
                    raw_data = sparse_parser.to_raw(file_bytes, max_output_size=2 * 1024 * 1024 * 1024)
                    if raw_data:
                        file_bytes = raw_data

            # Classify section type
            section_type = "partition"
            section_name = filename

            if len(file_bytes) > 0x43A and file_bytes[0x438:0x43A] == b"\x53\xEF":
                section_type = "filesystem"
                if section_name.endswith(".fex"):
                    section_name = section_name[:-4] + ".img"
            elif len(file_bytes) > 0x404 and struct.unpack_from("<I", file_bytes, 0x400)[0] == 0xE0F5E1E2:
                section_type = "filesystem"
                if section_name.endswith(".fex"):
                    section_name = section_name[:-4] + ".img"
            elif file_bytes[:8] == b"ANDROID!":
                section_type = "boot_image"
            elif "UBOOT" in subtype.upper() or filename.lower().startswith("u-boot"):
                section_type = "bootloader"
            elif any(k in filename.lower() for k in ("sys_config", "config", "sys_partition")):
                section_type = "config"
                if filename == "sys_config.fex":
                    self._parse_sys_config(file_bytes, metadata)

            sections.append(
                FirmwareSection(
                    name=section_name,
                    offset=offset,
                    size=len(file_bytes),
                    data=file_bytes,
                    section_type=section_type,
                )
            )

        metadata["file_count"] = len(sections)
        return UnpackResult(sections=sections, metadata=metadata)

    def _parse_sys_config(self, data: bytes, metadata: dict[str, Any]) -> None:
        """Extract product and board metadata from sys_config.fex."""
        try:
            text = data.decode("latin1", errors="ignore")
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("machine") and "=" in line:
                    val = line.split("=", 1)[1].strip().strip('"').strip("'")
                    metadata["machine"] = val
                elif line.startswith("version") and "=" in line:
                    val = line.split("=", 1)[1].strip().strip('"').strip("'")
                    metadata["product_version"] = val
        except Exception:
            pass
