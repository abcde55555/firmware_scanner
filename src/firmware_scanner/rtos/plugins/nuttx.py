"""NuttX analysis plugin."""

import re
from ...core.context import AnalysisContext
from ...extraction.models import Component, VersionConfidence, ExtractionMethod
from ..base import RTOSPlugin
from ..registry import RTOSRegistry


@RTOSRegistry.register
class NuttXPlugin(RTOSPlugin):
    @property
    def rtos_name(self) -> str:
        return "NuttX"

    @property
    def vendor(self) -> str:
        return "Apache"

    def detect(self, context: AnalysisContext) -> float:
        score = 0.0
        data = context.raw_data

        if b"NuttX" in data:
            score += 0.4
        if b"nsh>" in data:
            score += 0.2
        if b"nxsched_" in data or b"nxtask_" in data:
            score += 0.25
        if b"nxsem_" in data or b"nxmutex_" in data:
            score += 0.15
        if b"CONFIG_NUTTX" in data:
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
            name="NuttX",
            vendor="Apache",
            versions=[VersionConfidence(
                version=version or "detected",
                confidence=0.8 if version else 0.5,
                method=ExtractionMethod.RTOS_PLUGIN,
            )],
            component_type="operating-system",
            purl=f"pkg:generic/nuttx@{version}" if version else "",
            licenses=["Apache-2.0"],
        )]

    def get_version_patterns(self) -> list[str]:
        return [r"NuttX\s+(\d+\.\d+\.\d+)", r"nuttx-(\d+\.\d+\.\d+)"]

    def get_known_symbols(self) -> list[str]:
        return ["nxsched_add_readytorun", "nxtask_create", "nxsem_post", "nx_start"]
