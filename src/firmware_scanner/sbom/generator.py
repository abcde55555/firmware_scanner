"""SBOM generation orchestrator."""

from ..core.context import AnalysisContext
from ..extraction.models import Component
from .cyclonedx import CycloneDXGenerator
from .spdx3 import SPDX3Generator


class SBOMGenerator:
    def __init__(self):
        self._cdx = CycloneDXGenerator()
        self._spdx3 = SPDX3Generator()

    def generate(self, context: AnalysisContext) -> str:
        """Generate CycloneDX 1.6 SBOM JSON by default."""
        return self.generate_cyclonedx(context)

    def generate_cyclonedx(self, context: AnalysisContext) -> str:
        arch_str = ""
        if context.arch_info:
            arch_str = (
                f"{context.arch_info.cpu_family.value} "
                f"{context.arch_info.endianness.value}-endian "
                f"{context.arch_info.word_size}bit"
            )

        bom = self._cdx.generate(
            components=context.components,
            firmware_path=str(context.firmware_path),
            firmware_hash_sha256=context.file_hash_sha256,
            firmware_hash_md5=context.file_hash_md5,
            arch_info=arch_str,
            detected_rtos=context.detected_rtos,
            analysis_warnings=context.warnings,
        )

        return self._cdx.to_json(bom)

    def generate_spdx(self, context: AnalysisContext) -> str:
        arch_str = ""
        if context.arch_info:
            arch_str = (
                f"{context.arch_info.cpu_family.value} "
                f"{context.arch_info.endianness.value}-endian "
                f"{context.arch_info.word_size}bit"
            )

        bom = self._spdx3.generate(
            components=context.components,
            firmware_path=str(context.firmware_path),
            firmware_hash_sha256=context.file_hash_sha256,
            firmware_hash_md5=context.file_hash_md5,
            arch_info=arch_str,
            detected_rtos=context.detected_rtos,
            analysis_warnings=context.warnings,
        )

        return self._spdx3.to_json(bom)

