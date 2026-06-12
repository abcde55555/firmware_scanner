"""RIOT OS analysis plugin."""

import re
from ...core.context import AnalysisContext
from ...extraction.models import Component, VersionConfidence, ExtractionMethod
from ..base import RTOSPlugin
from ..registry import RTOSRegistry


@RTOSRegistry.register
class RIOTPlugin(RTOSPlugin):
    @property
    def rtos_name(self) -> str:
        return "RIOT OS"

    @property
    def vendor(self) -> str:
        return "RIOT Community"

    def detect(self, context: AnalysisContext) -> float:
        score = 0.0
        data = context.raw_data

        # High confidence strings
        if b"RIOT_VERSION" in data:
            score += 0.4
        if b"RIOTBOARD" in data or b"RIOT_BOARD" in data:
            score += 0.35

        # Medium confidence strings
        if b"riot_thread_create" in data or b"thread_create" in data:
            score += 0.2
        if b"gnrc_netif" in data:
            score += 0.2
        if b"gnrc_pktbuf" in data:
            score += 0.15
        if b"xtimer_set" in data or b"ztimer_set" in data:
            score += 0.2
        if b"auto_init_module" in data:
            score += 0.1

        # Check symbols
        for sym in context.elf_symbols:
            if sym in ("riot_thread_create", "thread_create", "gnrc_netif_init"):
                score += 0.15

        return min(score, 1.0)

    async def analyze(self, context: AnalysisContext) -> list[Component]:
        components = []
        data = context.raw_data

        version = self._extract_version(data)
        components.append(Component(
            name="RIOT OS",
            vendor="RIOT Community",
            versions=[VersionConfidence(
                version=version or "detected",
                confidence=0.85 if version else 0.5,
                method=ExtractionMethod.RTOS_PLUGIN,
                evidence=f"Version string: {version}" if version else "Detected via signatures",
            )],
            component_type="operating-system",
            purl=f"pkg:generic/riot-os@{version}" if version else "",
            licenses=["LGPL-2.1"],
        ))

        # Detect GNRC network stack
        if b"gnrc_netif" in data or b"gnrc_pktbuf" in data:
            components.append(Component(
                name="RIOT-GNRC",
                vendor="RIOT Community",
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
            r"RIOT_VERSION\s*[=:\"]+\s*(\d{4}\.\d{2})",
            r"RIOT[- ](?:OS\s+)?[Vv]?(\d{4}\.\d{2})",
            r"riot[/-](\d{4}\.\d{2})",
        ]

    def get_known_symbols(self) -> list[str]:
        return [
            "riot_thread_create", "thread_create", "thread_yield",
            "gnrc_netif_init", "gnrc_pktbuf_add", "gnrc_pktbuf_release",
            "xtimer_set", "ztimer_set", "ztimer_now",
            "auto_init_module", "msg_send", "msg_receive",
            "mutex_lock", "mutex_unlock", "sema_create",
        ]
