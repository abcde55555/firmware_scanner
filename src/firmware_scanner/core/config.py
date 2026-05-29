"""Configuration management."""

from pathlib import Path
from pydantic import BaseModel


class AnalysisConfig(BaseModel):
    radare2_path: str = "r2"
    ghidra_path: str = ""
    timeout: int = 300
    max_file_size: int = 512 * 1024 * 1024  # 512MB
    extractors: list[str] = []
    skip_extractors: list[str] = []
    rtos_hint: str = ""
    arch_hint: str = ""
    verbose: bool = False
    output_format: str = "cyclonedx"
    output_path: Path | None = None
