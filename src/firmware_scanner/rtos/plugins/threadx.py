"""ThreadX (Azure RTOS) analysis plugin."""

import re
from ...core.context import AnalysisContext
from ...extraction.models import Component, VersionConfidence, ExtractionMethod
from ..base import RTOSPlugin
from ..registry import RTOSRegistry


@RTOSRegistry.register
class ThreadXPlugin(RTOSPlugin):
    @property
    def rtos_name(self) -> str:
        return "ThreadX"

    @property
    def vendor(self) -> str:
        return "Microsoft"

    def detect(self, context: AnalysisContext) -> float:
        score = 0.0
        data = context.raw_data

        if b"ThreadX" in data or b"THREADX" in data:
            score += 0.4
        if b"Azure RTOS" in data:
            score += 0.3
        if b"tx_thread_create" in data:
            score += 0.25
        if b"tx_kernel_enter" in data:
            score += 0.2
        if b"_tx_thread_current_ptr" in data:
            score += 0.15

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
            name="ThreadX",
            vendor="Microsoft",
            versions=[VersionConfidence(
                version=version or "detected",
                confidence=0.8 if version else 0.5,
                method=ExtractionMethod.RTOS_PLUGIN,
            )],
            component_type="operating-system",
            purl=f"pkg:generic/threadx@{version}" if version else "",
            licenses=["MIT"],
        )]

        # Detect Azure RTOS middleware
        if b"nx_" in data and b"nx_tcp_" in data:
            components.append(Component(name="NetX Duo", vendor="Microsoft", component_type="library",
                versions=[VersionConfidence(version="detected", confidence=0.6, method=ExtractionMethod.RTOS_PLUGIN)]))
        if b"fx_" in data and b"fx_file_" in data:
            components.append(Component(name="FileX", vendor="Microsoft", component_type="library",
                versions=[VersionConfidence(version="detected", confidence=0.6, method=ExtractionMethod.RTOS_PLUGIN)]))
        if b"ux_" in data and b"ux_device_" in data:
            components.append(Component(name="USBX", vendor="Microsoft", component_type="library",
                versions=[VersionConfidence(version="detected", confidence=0.6, method=ExtractionMethod.RTOS_PLUGIN)]))

        return components

    def get_version_patterns(self) -> list[str]:
        return [
            r"ThreadX\s+[Vv]?(\d+\.\d+(?:\.\d+)?)",
            r"Azure\s+RTOS\s+ThreadX\s+[Vv]?(\d+\.\d+\.\d+)",
            r"_tx_version_id.*?(\d+\.\d+\.\d+)",
        ]

    def get_known_symbols(self) -> list[str]:
        return [
            "tx_thread_create", "tx_semaphore_create", "tx_mutex_create",
            "tx_queue_create", "tx_kernel_enter", "tx_timer_create",
        ]
