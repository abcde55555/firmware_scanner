"""Analysis context - shared state across pipeline stages."""

from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field

from ..arch.models import ArchInfo
from ..extraction.models import Component, UnpackResult


class AnalysisError(BaseModel):
    stage: str
    message: str
    fatal: bool = False


class AnalysisContext(BaseModel):
    firmware_path: Path
    raw_data: bytes = b""
    file_hash_sha256: str = ""
    file_hash_md5: str = ""
    arch_info: ArchInfo | None = None
    unpack_result: UnpackResult | None = None
    detected_rtos: str = ""
    rtos_confidence: float = 0.0
    components: list[Component] = Field(default_factory=list)
    errors: list[AnalysisError] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    elf_symbols: list[str] = Field(default_factory=list)

    class Config:
        arbitrary_types_allowed = True
