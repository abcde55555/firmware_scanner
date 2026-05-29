"""Intel HEX format handler."""

from pathlib import Path
from intelhex import IntelHex

from .base import FirmwareFormat
from ...extraction.models import UnpackResult, FirmwareSection


class IntelHEXFormat(FirmwareFormat):
    @property
    def format_name(self) -> str:
        return "Intel HEX"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if path.suffix.lower() in (".hex", ".ihex", ".ihe"):
            try:
                text = data[:1024].decode("ascii", errors="ignore")
                if text.startswith(":") and "\n:" in text:
                    return 0.9
            except Exception:
                pass
        if data[:1] == b":":
            try:
                data[:256].decode("ascii")
                return 0.7
            except Exception:
                pass
        return 0.0

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        ih = IntelHex()
        ih.loadhex(str(path))

        segments = ih.segments()
        sections = []

        for i, (start, end) in enumerate(segments):
            seg_data = bytes(ih.tobinarray(start=start, end=end - 1))
            sections.append(
                FirmwareSection(
                    name=f"segment_{i}",
                    offset=start,
                    size=end - start,
                    data=seg_data,
                    section_type="code" if i == 0 else "data",
                )
            )

        entry = ih.start_addr
        entry_point = 0
        if entry:
            if "EIP" in entry:
                entry_point = entry["EIP"]
            elif "IP" in entry and "CS" in entry:
                entry_point = (entry["CS"] << 4) + entry["IP"]

        return UnpackResult(
            sections=sections,
            entry_point=entry_point,
            load_address=segments[0][0] if segments else 0,
        )
