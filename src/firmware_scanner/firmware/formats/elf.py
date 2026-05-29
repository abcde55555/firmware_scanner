"""ELF format handler using LIEF library."""

from pathlib import Path

import lief

from .base import FirmwareFormat
from ...extraction.models import UnpackResult, FirmwareSection


class ELFFormat(FirmwareFormat):
    @property
    def format_name(self) -> str:
        return "ELF"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if len(data) < 4:
            return 0.0
        if data[:4] == b"\x7fELF":
            return 0.95
        return 0.0

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        binary = lief.parse(list(data))
        if binary is None:
            return UnpackResult()

        sections = []
        for section in binary.sections:
            if section.size == 0:
                continue
            section_data = bytes(section.content) if section.content else b""
            sections.append(
                FirmwareSection(
                    name=section.name,
                    offset=section.offset,
                    size=section.size,
                    data=section_data,
                    section_type=self._section_type(section),
                    permissions=self._section_perms(section),
                )
            )

        entry_point = binary.entrypoint if hasattr(binary, "entrypoint") else 0
        metadata = {
            "elf_type": str(binary.header.file_type) if hasattr(binary.header, "file_type") else "",
            "machine": str(binary.header.machine_type) if hasattr(binary.header, "machine_type") else "",
        }

        return UnpackResult(
            sections=sections,
            entry_point=entry_point,
            metadata=metadata,
        )

    def _section_type(self, section) -> str:
        name = section.name.lower()
        if name in (".text", ".isr_vector"):
            return "code"
        elif name in (".rodata", ".rodata.str1.1"):
            return "rodata"
        elif name in (".data",):
            return "data"
        elif name in (".bss",):
            return "bss"
        return "unknown"

    def _section_perms(self, section) -> str:
        flags = ""
        if hasattr(section, "flags_list"):
            flag_list = section.flags_list
            if lief.ELF.Section.FLAGS.ALLOC in flag_list:
                flags += "A"
            if lief.ELF.Section.FLAGS.WRITE in flag_list:
                flags += "W"
            if lief.ELF.Section.FLAGS.EXECINSTR in flag_list:
                flags += "X"
        return flags
