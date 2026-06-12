"""Mbed OS analysis plugin."""

import re
from ...core.context import AnalysisContext
from ...extraction.models import Component, VersionConfidence, ExtractionMethod
from ..base import RTOSPlugin
from ..registry import RTOSRegistry


@RTOSRegistry.register
class MbedPlugin(RTOSPlugin):
    @property
    def rtos_name(self) -> str:
        return "Mbed OS"

    @property
    def vendor(self) -> str:
        return "ARM"

    def detect(self, context: AnalysisContext) -> float:
        score = 0.0
        data = context.raw_data

        # High confidence strings
        if b"MBED_VERSION" in data:
            score += 0.4
        if b"mbed-os" in data or b"Mbed OS" in data:
            score += 0.35

        # Medium confidence strings
        if b"MBED_CONF_" in data or b"MBED_CONF_RTOS_" in data:
            score += 0.2
        if b"mbed_die" in data or b"mbed_error" in data:
            score += 0.2
        if b"osThreadNew" in data or b"osKernelStart" in data:
            score += 0.2
        if b"mbed_stats_" in data or b"mbed_heap_stats" in data:
            score += 0.15

        # Check symbols
        for sym in context.elf_symbols:
            if sym in ("mbed_die", "mbed_error", "osKernelStart", "osThreadNew"):
                score += 0.15

        return min(score, 1.0)

    async def analyze(self, context: AnalysisContext) -> list[Component]:
        components = []
        data = context.raw_data

        version = self._extract_version(data)
        components.append(Component(
            name="Mbed OS",
            vendor="ARM",
            versions=[VersionConfidence(
                version=version or "detected",
                confidence=0.85 if version else 0.5,
                method=ExtractionMethod.RTOS_PLUGIN,
                evidence=f"Version string: {version}" if version else "Detected via signatures",
            )],
            component_type="operating-system",
            purl=f"pkg:generic/mbed-os@{version}" if version else "",
            licenses=["Apache-2.0"],
        ))

        # Detect Mbed TLS if present alongside Mbed OS
        if b"mbedtls_" in data or b"MBEDTLS_" in data:
            components.append(Component(
                name="Mbed TLS",
                vendor="ARM",
                component_type="library",
                versions=[VersionConfidence(
                    version="detected",
                    confidence=0.7,
                    method=ExtractionMethod.RTOS_PLUGIN,
                )],
            ))

        return components

    def _extract_version(self, data: bytes) -> str:
        text = data.decode("ascii", errors="ignore")
        for pattern in self.get_version_patterns():
            match = re.search(pattern, text)
            if match:
                return match.group(1)
        return ""

    def get_version_patterns(self) -> list[str]:
        return [
            r"MBED_VERSION\s*[=:\"]+\s*(\d+\.\d+\.\d+)",
            r"[Mm]bed[- ]OS\s+[Vv]?(\d+\.\d+\.\d+)",
            r"mbed-os[/-](\d+\.\d+\.\d+)",
        ]

    def get_known_symbols(self) -> list[str]:
        return [
            "mbed_die", "mbed_error", "mbed_start_main",
            "osKernelStart", "osKernelInitialize", "osThreadNew",
            "osThreadTerminate", "osMutexNew", "osSemaphoreNew",
            "mbed_stats_heap_get", "mbed_stats_stack_get",
            "mbed_file_handle", "mbed_poll", "mbed_assert_internal",
        ]
