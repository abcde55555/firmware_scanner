"""Motorola S-Record format handler."""

from pathlib import Path

from .base import FirmwareFormat
from ...extraction.models import UnpackResult, FirmwareSection


class SRecordFormat(FirmwareFormat):
    @property
    def format_name(self) -> str:
        return "Motorola S-Record"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if path.suffix.lower() in (".srec", ".s19", ".s28", ".s37", ".mot"):
            return 0.85
        try:
            text = data[:256].decode("ascii", errors="ignore")
            if text.startswith("S0") or text.startswith("S1") or text.startswith("S2"):
                return 0.8
        except Exception:
            pass
        return 0.0

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        text = data.decode("ascii", errors="ignore")
        lines = text.strip().splitlines()

        segments: dict[int, bytearray] = {}
        entry_point = 0

        for line in lines:
            line = line.strip()
            if not line or not line.startswith("S"):
                continue

            record_type = line[1]
            if record_type == "0":
                continue

            byte_count = int(line[2:4], 16)
            record_data = bytes.fromhex(line[4:4 + (byte_count * 2)])

            if record_type == "1":
                addr = int.from_bytes(record_data[0:2], "big")
                payload = record_data[2:-1]
            elif record_type == "2":
                addr = int.from_bytes(record_data[0:3], "big")
                payload = record_data[3:-1]
            elif record_type == "3":
                addr = int.from_bytes(record_data[0:4], "big")
                payload = record_data[4:-1]
            elif record_type == "7":
                entry_point = int.from_bytes(record_data[0:4], "big")
                continue
            elif record_type == "8":
                entry_point = int.from_bytes(record_data[0:3], "big")
                continue
            elif record_type == "9":
                entry_point = int.from_bytes(record_data[0:2], "big")
                continue
            else:
                continue

            if addr not in segments:
                segments[addr] = bytearray()
            segments[addr].extend(payload)

        sections = []
        for i, (addr, seg_data) in enumerate(sorted(segments.items())):
            sections.append(
                FirmwareSection(
                    name=f"segment_{i}",
                    offset=addr,
                    size=len(seg_data),
                    data=bytes(seg_data),
                    section_type="code" if i == 0 else "data",
                )
            )

        return UnpackResult(
            sections=sections,
            entry_point=entry_point,
            load_address=min(segments.keys()) if segments else 0,
        )
