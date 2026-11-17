"""U-Boot Flattened Image Tree (FIT) and Device Tree Blob (DTB) format handler."""

from pathlib import Path

from .base import FirmwareFormat
from ..fdt_parser import FDTParser, FDT_MAGIC
from ...extraction.models import UnpackResult, FirmwareSection


class FITImageFormat(FirmwareFormat):
    """Handler for U-Boot FIT Images (.itb) and DTB files."""

    @property
    def format_name(self) -> str:
        return "U-Boot FIT Image / Device Tree"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if len(data) < 32:
            return 0.0
        parser = FDTParser(data[:65536])
        if parser.is_valid():
            return 0.95
        if path.suffix.lower() in (".itb", ".fit", ".dtb"):
            return 0.85
        return 0.0

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        result = UnpackResult()
        parser = FDTParser(data)
        if not parser.is_valid():
            return result

        # If it's a FIT image containing sub-images
        for img in parser.fit_images:
            if not img.data:
                continue

            sec_name = img.node_name
            if img.image_type == "kernel":
                sec_name += ".bin"
            elif img.image_type == "ramdisk":
                sec_name += ".cpio"
            elif img.image_type == "flat_dt":
                sec_name += ".dtb"

            result.sections.append(FirmwareSection(
                name=sec_name,
                offset=0,
                size=len(img.data),
                data=img.data,
                section_type=img.image_type or "embedded_image",
            ))

        # If it's a pure DTB without sub-images, store DTB properties as a section for hardware metadata
        if not result.sections and parser.root:
            hw_info = parser.get_hardware_info()
            model = hw_info.get("model", "")
            compat = ", ".join(hw_info.get("compatible", []))
            summary_text = f"Hardware Model: {model}\nCompatibility: {compat}\n"
            result.sections.append(FirmwareSection(
                name="device_tree_info.txt",
                offset=0,
                size=len(summary_text),
                data=summary_text.encode("utf-8"),
                section_type="metadata",
            ))

        return result
