"""RT-Thread analysis plugin."""

import re
from ...core.context import AnalysisContext
from ...extraction.models import Component, VersionConfidence, ExtractionMethod
from ..base import RTOSPlugin
from ..registry import RTOSRegistry


@RTOSRegistry.register
class RTThreadPlugin(RTOSPlugin):
    @property
    def rtos_name(self) -> str:
        return "RT-Thread"

    @property
    def vendor(self) -> str:
        return "RT-Thread"

    def detect(self, context: AnalysisContext) -> float:
        score = 0.0
        data = context.raw_data

        if b"RT-Thread" in data or b"rt-thread" in data:
            score += 0.4
        if b"rt_thread_create" in data:
            score += 0.25
        if b"rt_sem_create" in data or b"rt_mutex_create" in data:
            score += 0.15
        if b"rt_device_register" in data:
            score += 0.15
        if b"rt_object_init" in data:
            score += 0.1
        if b"finsh" in data or b"msh>" in data:
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
            name="RT-Thread",
            vendor="RT-Thread",
            versions=[VersionConfidence(
                version=version or "detected",
                confidence=0.8 if version else 0.5,
                method=ExtractionMethod.RTOS_PLUGIN,
            )],
            component_type="operating-system",
            purl=f"pkg:generic/rt-thread@{version}" if version else "",
            licenses=["Apache-2.0"],
        )]

        if b"finsh" in data:
            components.append(Component(
                name="FinSH Shell",
                vendor="RT-Thread",
                component_type="library",
                versions=[VersionConfidence(version="detected", confidence=0.6, method=ExtractionMethod.RTOS_PLUGIN)],
            ))

        return components

    def get_version_patterns(self) -> list[str]:
        return [
            r"RT-Thread\s+[Vv]?(\d+\.\d+\.\d+)",
            r"rtthread.*?(\d+\.\d+\.\d+)",
        ]

    def get_known_symbols(self) -> list[str]:
        return [
            "rt_thread_create", "rt_sem_create", "rt_mutex_create",
            "rt_mq_create", "rt_device_register", "rt_system_scheduler_start",
        ]
