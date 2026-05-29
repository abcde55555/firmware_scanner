"""ESP-IDF firmware image format handler."""

import struct
from pathlib import Path

from .base import FirmwareFormat
from ...extraction.models import UnpackResult, FirmwareSection


# ESP-IDF image header magic
ESP_IMAGE_MAGIC = 0xE9
ESP_IMAGE_HEADER_SIZE = 24
ESP_SEGMENT_HEADER_SIZE = 8


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

        return UnpackResult(
            sections=sections,
            entry_point=entry_point,
            metadata=metadata,
        )
