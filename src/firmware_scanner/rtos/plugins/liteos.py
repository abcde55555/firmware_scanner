"""LiteOS analysis plugin."""

import re
from ...core.context import AnalysisContext
from ...extraction.models import Component, VersionConfidence, ExtractionMethod
from ..base import RTOSPlugin
from ..registry import RTOSRegistry


@RTOSRegistry.register
class LiteOSPlugin(RTOSPlugin):
    @property
    def rtos_name(self) -> str:
        return "LiteOS"

    @property
    def vendor(self) -> str:
        return "Huawei"

    def detect(self, context: AnalysisContext) -> float:
        score = 0.0
        data = context.raw_data

        if b"LiteOS" in data or b"Huawei LiteOS" in data:
            score += 0.4
        if b"LOS_TaskCreate" in data:
            score += 0.25
        if b"LOS_SemCreate" in data or b"LOS_MuxCreate" in data:
            score += 0.15
        if b"LOS_KernelInit" in data:
            score += 0.2
        if b"LOS_ERRNO" in data:
            score += 0.1

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

        return [Component(
            name="LiteOS",
            vendor="Huawei",
            versions=[VersionConfidence(
                version=version or "detected",
                confidence=0.8 if version else 0.5,
                method=ExtractionMethod.RTOS_PLUGIN,
            )],
            component_type="operating-system",
            purl=f"pkg:generic/liteos@{version}" if version else "",
            licenses=["BSD-3-Clause"],
        )]

    def get_version_patterns(self) -> list[str]:
        return [
            r"Huawei\s+LiteOS\s+[Vv]?(\d+\.\d+\.\d+)",
            r"LiteOS\s+[Vv](\d+\.\d+(?:\.\d+)?)",
        ]

    def get_known_symbols(self) -> list[str]:
        return ["LOS_TaskCreate", "LOS_SemCreate", "LOS_MuxCreate", "LOS_KernelInit"]
