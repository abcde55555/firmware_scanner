"""Zephyr RTOS analysis plugin."""

import re
from ...core.context import AnalysisContext
from ...extraction.models import Component, VersionConfidence, ExtractionMethod
from ..base import RTOSPlugin
from ..registry import RTOSRegistry


@RTOSRegistry.register
class ZephyrPlugin(RTOSPlugin):
    @property
    def rtos_name(self) -> str:
        return "Zephyr RTOS"

    @property
    def vendor(self) -> str:
        return "Zephyr Project"

    def detect(self, context: AnalysisContext) -> float:
        score = 0.0
        data = context.raw_data

        if b"zephyr" in data or b"Zephyr" in data:
            score += 0.3
        if b"k_thread_create" in data:
            score += 0.25
        if b"k_sem_init" in data or b"k_mutex_init" in data:
            score += 0.15
        if b"__device_dts_ord_" in data:
            score += 0.2
        if b"CONFIG_" in data and b"CONFIG_KERNEL" in data:
            score += 0.1
        if b"z_swap" in data or b"z_reschedule" in data:
            score += 0.2

        return min(score, 1.0)

    async def analyze(self, context: AnalysisContext) -> list[Component]:
        data = context.raw_data
        text = data.decode("ascii", errors="ignore")

        version = ""
        for pattern in self.get_version_patterns():
            match = re.search(pattern, text)
            if match:
                version = match.group(1)
                break

        components = [Component(
            name="Zephyr RTOS",
            vendor="Zephyr Project",
            versions=[VersionConfidence(
                version=version or "detected",
                confidence=0.8 if version else 0.5,
                method=ExtractionMethod.RTOS_PLUGIN,
            )],
            component_type="operating-system",
            purl=f"pkg:generic/zephyr@{version}" if version else "",
            licenses=["Apache-2.0"],
        )]

        if b"net_context" in data or b"net_if" in data:
            components.append(Component(
                name="Zephyr Networking",
                vendor="Zephyr Project",
                component_type="library",
                versions=[VersionConfidence(version="detected", confidence=0.6, method=ExtractionMethod.RTOS_PLUGIN)],
            ))

        return components

    def get_version_patterns(self) -> list[str]:
        return [
            r"Zephyr\s+[Vv]?(\d+\.\d+\.\d+)",
            r"zephyr-v(\d+\.\d+\.\d+)",
            r"KERNELVERSION\s*=\s*(\d+\.\d+\.\d+)",
            r"BUILD_VERSION\s+(\d+\.\d+\.\d+)",
        ]

    def get_known_symbols(self) -> list[str]:
        return [
            "k_thread_create", "k_sem_init", "k_mutex_init", "k_msgq_init",
            "k_work_submit", "k_timer_start", "z_swap", "z_reschedule",
        ]
