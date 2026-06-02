"""Component extraction data models."""

from enum import Enum
from pydantic import BaseModel


class ExtractionMethod(str, Enum):
    STRING_PATTERN = "string_pattern"
    SYMBOL_TABLE = "symbol_table"
    DISASSEMBLY = "disassembly"
    RADARE2 = "radare2"
    GHIDRA = "ghidra"
    BINARY_SIGNATURE = "binary_signature"
    RTOS_PLUGIN = "rtos_plugin"
    MANIFEST_BINARY = "manifest_binary"
    BUILD_METADATA = "build_metadata"
    STATIC_RULE = "static_rule"


class VersionConfidence(BaseModel):
    version: str
    confidence: float = 0.0
    method: ExtractionMethod = ExtractionMethod.STRING_PATTERN
    evidence: str = ""


class Component(BaseModel):
    name: str
    vendor: str = ""
    versions: list[VersionConfidence] = []
    resolved_version: str = ""
    component_type: str = "library"
    purl: str = ""
    cpe: str = ""
    licenses: list[str] = []
    description: str = ""


class FirmwareSection(BaseModel):
    name: str
    offset: int
    size: int
    data: bytes = b""
    section_type: str = "unknown"
    permissions: str = ""

    class Config:
        arbitrary_types_allowed = True


class UnpackResult(BaseModel):
    sections: list[FirmwareSection] = []
    entry_point: int = 0
    load_address: int = 0
    metadata: dict = {}

    class Config:
        arbitrary_types_allowed = True
