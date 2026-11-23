"""ESP-IDF firmware image format handler."""

import struct
from pathlib import Path

from ...extraction.models import FirmwareSection, UnpackResult
from .base import FirmwareFormat

# ESP-IDF image header magic
ESP_IMAGE_MAGIC = 0xE9
ESP_IMAGE_HEADER_SIZE = 24
ESP_SEGMENT_HEADER_SIZE = 8
ESP_APP_DESC_MAGIC = 0xABCD5432
ESP_APP_DESC_SIZE = 256


def _c_string(data: bytes, offset: int, size: int) -> str:
    """Decode one bounded NUL-terminated ESP application descriptor field."""
    return data[offset : offset + size].split(b"\0", 1)[0].decode("utf-8", errors="replace")


def _parse_app_descriptor(data: bytes) -> dict:
    """Read the optional ESP-IDF application descriptor from the image."""
    magic = struct.pack("<I", ESP_APP_DESC_MAGIC)
    descriptor_offset = data.find(magic, 0, min(len(data), 4096))
    if descriptor_offset < 0 or descriptor_offset + ESP_APP_DESC_SIZE > len(data):
        return {}

    descriptor = data[descriptor_offset : descriptor_offset + ESP_APP_DESC_SIZE]
    return {
        "file_offset": descriptor_offset,
        "secure_version": struct.unpack_from("<I", descriptor, 4)[0],
        "app_version": _c_string(descriptor, 0x10, 32),
        "project_name": _c_string(descriptor, 0x30, 32),
        "build_time": _c_string(descriptor, 0x50, 16),
        "build_date": _c_string(descriptor, 0x60, 16),
        "idf_version": _c_string(descriptor, 0x70, 32),
        "elf_sha256": descriptor[0x90:0xB0].hex(),
    }


class ESPIDFFormat(FirmwareFormat):
    @property
    def format_name(self) -> str:
        return "ESP-IDF Image"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if len(data) < ESP_IMAGE_HEADER_SIZE:
            return 0.0
        if data[0] == ESP_IMAGE_MAGIC:
            segment_count = data[1]
            if 1 <= segment_count <= 16:
                return 0.85
        return 0.0

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        if len(data) < ESP_IMAGE_HEADER_SIZE:
            return UnpackResult()

        magic = data[0]
        segment_count = data[1]
        spi_mode = data[2]
        spi_size_speed = data[3]
        entry_point = struct.unpack_from("<I", data, 4)[0]

        sections = []
        offset = ESP_IMAGE_HEADER_SIZE

        for i in range(segment_count):
            if offset + ESP_SEGMENT_HEADER_SIZE > len(data):
                break

            load_addr, seg_size = struct.unpack_from("<II", data, offset)
            offset += ESP_SEGMENT_HEADER_SIZE

            if offset + seg_size > len(data):
                seg_size = len(data) - offset

            seg_data = data[offset : offset + seg_size]
            offset += seg_size

            section_type = "code" if load_addr >= 0x40000000 else "data"
            sections.append(
                FirmwareSection(
                    name=f"segment_{i}_{load_addr:#010x}",
                    offset=load_addr,
                    size=seg_size,
                    data=seg_data,
                    section_type=section_type,
                )
            )

        metadata = {
            "esp_magic": hex(magic),
            "segment_count": segment_count,
            "spi_mode": spi_mode,
            "spi_size_speed": hex(spi_size_speed),
        }
        app_descriptor = _parse_app_descriptor(data)
        if app_descriptor:
            metadata["esp_app_desc"] = app_descriptor

        return UnpackResult(
            sections=sections,
            entry_point=entry_point,
            metadata=metadata,
        )
