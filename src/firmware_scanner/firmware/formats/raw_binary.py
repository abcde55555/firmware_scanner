"""Raw binary format handler with entropy-based section detection."""

from pathlib import Path

from .base import FirmwareFormat
from ...extraction.models import UnpackResult, FirmwareSection
from ...utils.binary import compute_entropy


class RawBinaryFormat(FirmwareFormat):
    CHUNK_SIZE = 16384  # 16KB chunks to reduce over-segmentation

    @property
    def format_name(self) -> str:
        return "Raw Binary"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if path.suffix.lower() in (".bin", ".img", ".fw", ".firmware"):
            return 0.3
        return 0.1

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        sections = self._segment_by_entropy(data)
        return UnpackResult(
            sections=sections,
            load_address=0,
        )

    def _segment_by_entropy(self, data: bytes) -> list[FirmwareSection]:
        sections = []
        offset = 0
        current_type = None
        current_start = 0
        current_data = bytearray()

        while offset < len(data):
            chunk = data[offset : offset + self.CHUNK_SIZE]
            entropy = compute_entropy(chunk)

            if entropy < 1.0:
                chunk_type = "padding"
            elif entropy > 7.0:
                chunk_type = "compressed"
            elif entropy > 5.5:
                chunk_type = "code"
            else:
                chunk_type = "data"

            if chunk_type != current_type and current_type is not None:
                if current_type != "padding" and len(current_data) > 0:
                    sections.append(
                        FirmwareSection(
                            name=f"{current_type}_{current_start:#x}",
                            offset=current_start,
                            size=len(current_data),
                            data=bytes(current_data),
                            section_type=current_type,
                        )
                    )
                current_start = offset
                current_data = bytearray()

            current_type = chunk_type
            current_data.extend(chunk)
            offset += self.CHUNK_SIZE

        if current_type and current_type != "padding" and len(current_data) > 0:
            sections.append(
                FirmwareSection(
                    name=f"{current_type}_{current_start:#x}",
                    offset=current_start,
                    size=len(current_data),
                    data=bytes(current_data),
                    section_type=current_type,
                )
            )

        if not sections:
            sections.append(
                FirmwareSection(
                    name="raw",
                    offset=0,
                    size=len(data),
                    data=data,
                    section_type="unknown",
                )
            )

        return sections
