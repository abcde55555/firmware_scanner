"""uC/OS analysis plugin."""

import re
from ...core.context import AnalysisContext
from ...extraction.models import Component, VersionConfidence, ExtractionMethod
from ..base import RTOSPlugin
from ..registry import RTOSRegistry


@RTOSRegistry.register
class UCOSPlugin(RTOSPlugin):
    @property
    def rtos_name(self) -> str:
        return "uC/OS"

    @property
    def vendor(self) -> str:
        return "Micrium"

    def detect(self, context: AnalysisContext) -> float:
        score = 0.0
        data = context.raw_data

        if b"uC/OS" in data or b"Micrium" in data:
            score += 0.4
        if b"OSTaskCreate" in data:
            score += 0.25
        if b"OSSemCreate" in data or b"OSMutexCreate" in data:
            score += 0.15
        if b"OSInit" in data and b"OSStart" in data:
            score += 0.2
        if b"OSIntNestingCtr" in data:
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

        # Detect uC/OS variant (II vs III)
        name = "uC/OS"
        if b"uC/OS-III" in data or b"OS_III" in data:
            name = "uC/OS-III"
        elif b"uC/OS-II" in data or b"OS_II" in data:
            name = "uC/OS-II"

        return [Component(
            name=name,
            vendor="Micrium",
            versions=[VersionConfidence(
                version=version or "detected",
                confidence=0.8 if version else 0.5,
                method=ExtractionMethod.RTOS_PLUGIN,
            )],
            component_type="operating-system",
            purl=f"pkg:generic/ucos@{version}" if version else "",
            licenses=["Apache-2.0"],
        )]

    def get_version_patterns(self) -> list[str]:
        return [
            r"uC/OS-I{1,3}\s+[Vv]?(\d+\.\d+\.\d+)",
            r"Micrium.*?[Vv](\d+\.\d+\.\d+)",
        ]

    def get_known_symbols(self) -> list[str]:
        return ["OSTaskCreate", "OSSemCreate", "OSMutexCreate", "OSStart", "OSInit"]
