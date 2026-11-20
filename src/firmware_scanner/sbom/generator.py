"""SBOM generation orchestrator."""

from ..core.context import AnalysisContext
from .cyclonedx import CycloneDXGenerator
from .spdx3 import SPDX3Generator


class SBOMGenerator:
    def __init__(self):
        self._cdx = CycloneDXGenerator()
        self._spdx3 = SPDX3Generator()

    def generate(self, context: AnalysisContext) -> str:
        """Generate CycloneDX 1.5 SBOM JSON by default for enterprise platform compatibility."""
        return self.generate_cyclonedx(context, spec_version="1.5")

    def generate_cyclonedx(self, context: AnalysisContext, spec_version: str = "1.5") -> str:
        arch_str = ""
        if context.arch_info:
            arch_str = (
                f"{context.arch_info.cpu_family.value} "
                f"{context.arch_info.endianness.value}-endian "
                f"{context.arch_info.word_size}bit"
            )

        android_info = context.metadata.get("android_build_info")
        if android_info is None and (
            context.metadata.get("database_stats")
            or context.metadata.get("analysis_stats")
            or context.metadata.get("family_provenance_stats")
            or context.metadata.get("provenance_stats")
            or context.metadata.get("license_stats")
            or context.metadata.get("rules")
        ):
            android_info = {
                "database_stats": context.metadata.get("database_stats", {}),
                "database_provenance": context.metadata.get(
                    "database_provenance", {}
                ),
                "analysis_stats": context.metadata.get("analysis_stats", {}),
                "family_provenance_stats": context.metadata.get("family_provenance_stats", {}),
                "provenance_stats": context.metadata.get("provenance_stats", {}),
                "license_stats": context.metadata.get("license_stats", {}),
                "rules": context.metadata.get("rules", {}),
            }
        elif android_info is not None:
            overlays = {
                key: context.metadata[key]
                for key in (
                    "database_provenance",
                    "family_provenance_stats",
                    "provenance_stats",
                    "license_stats",
                    "rules",
                )
                if context.metadata.get(key)
            }
            if overlays:
                android_info = {**android_info, **overlays}

        bom = self._cdx.generate(
            components=context.components,
            firmware_path=str(context.firmware_path),
            firmware_hash_sha256=context.file_hash_sha256,
            firmware_hash_md5=context.file_hash_md5,
            arch_info=arch_str,
            detected_rtos=context.detected_rtos,
            analysis_warnings=context.warnings,
            build_info=android_info,
            spec_version=spec_version,
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

