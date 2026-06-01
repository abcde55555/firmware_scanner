"""Firmware format detection and unpacking orchestrator."""

from pathlib import Path

from .formats.base import FirmwareFormat
from .formats.elf import ELFFormat
from .formats.intel_hex import IntelHEXFormat
from .formats.srec import SRecordFormat
from .formats.raw_binary import RawBinaryFormat
from .formats.esp_idf import ESPIDFFormat
from .formats.uboot import UBootFormat
from .formats.compressed import CompressedFirmwareFormat
from .formats.apk import APKFormat, GenericZIPFormat
from .formats.generic_img import GenericImageFormat
from .formats.android_system import AndroidSystemImageFormat
from .formats.android_ota import AndroidPayloadFormat, AndroidBlockOTAFormat
from ..extraction.models import UnpackResult

FORMAT_HANDLERS: list[type[FirmwareFormat]] = [
    ELFFormat,
    APKFormat,
    AndroidSystemImageFormat,
    AndroidPayloadFormat,
    AndroidBlockOTAFormat,
    GenericZIPFormat,
    UBootFormat,
    CompressedFirmwareFormat,
    GenericImageFormat,
    ESPIDFFormat,
    IntelHEXFormat,
    SRecordFormat,
    RawBinaryFormat,  # fallback, always last
]


class FirmwareUnpacker:
    def detect_format(self, data: bytes, path: Path) -> tuple[FirmwareFormat, float]:
        """Detect firmware format and return (handler, confidence)."""
        best_handler: FirmwareFormat | None = None
        best_confidence = 0.0

        for handler_cls in FORMAT_HANDLERS:
            try:
                confidence = handler_cls.can_handle(data, path)
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_handler = handler_cls()
            except Exception:
                continue

        if best_handler is None:
            best_handler = RawBinaryFormat()
            best_confidence = 0.1

        return best_handler, best_confidence

    def unpack(self, data: bytes, path: Path) -> tuple[UnpackResult, str]:
        """Detect format and unpack. Returns (result, format_name)."""
        handler, _ = self.detect_format(data, path)

        try:
            result = handler.unpack(data, path)
        except Exception:
            fallback = RawBinaryFormat()
            result = fallback.unpack(data, path)
            return result, fallback.format_name

        return result, handler.format_name
