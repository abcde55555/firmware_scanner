"""VxWorks analysis plugin."""

import re
from ...core.context import AnalysisContext
from ...extraction.models import Component, VersionConfidence, ExtractionMethod
from ..base import RTOSPlugin
from ..registry import RTOSRegistry


@RTOSRegistry.register
class VxWorksPlugin(RTOSPlugin):
    @property
    def rtos_name(self) -> str:
        return "VxWorks"

    @property
    def vendor(self) -> str:
        return "Wind River"

    def detect(self, context: AnalysisContext) -> float:
        score = 0.0
        data = context.raw_data

        if b"VxWorks" in data or b"vxWorks" in data:
            score += 0.4
        if b"Wind River" in data:
            score += 0.3
        if b"taskSpawn" in data:
            score += 0.2
        if b"semBCreate" in data or b"semMCreate" in data:
            score += 0.15
        if b"WDB_AGENT" in data:
            score += 0.1
        if b"sysClkRateGet" in data:
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
            name="VxWorks",
            vendor="Wind River",
            versions=[VersionConfidence(
                version=version or "detected",
                confidence=0.85 if version else 0.5,
                method=ExtractionMethod.RTOS_PLUGIN,
            )],
            component_type="operating-system",
            purl=f"pkg:generic/vxworks@{version}" if version else "",
            licenses=["Proprietary"],
        )]

    def get_version_patterns(self) -> list[str]:
        return [
            r"VxWorks\s+(\d+\.\d+(?:\.\d+)?)",
            r"vxWorks.*?version\s+(\d+\.\d+)",
            r"WIND_RIVER_VER\s+\"(\d+\.\d+)\"",
        ]

    def get_known_symbols(self) -> list[str]:
        return [
            "taskSpawn", "taskDelay", "semBCreate", "semMCreate",
            "msgQCreate", "sysClkRateGet", "intConnect",
        ]
