"""FreeRTOS analysis plugin."""

import re
from ...core.context import AnalysisContext
from ...extraction.models import Component, VersionConfidence, ExtractionMethod
from ..base import RTOSPlugin
from ..registry import RTOSRegistry


@RTOSRegistry.register
class FreeRTOSPlugin(RTOSPlugin):
    @property
    def rtos_name(self) -> str:
        return "FreeRTOS"

    @property
    def vendor(self) -> str:
        return "Amazon"

    def detect(self, context: AnalysisContext) -> float:
        score = 0.0
        data = context.raw_data

        if b"FreeRTOS" in data:
            score += 0.4
        if b"xTaskCreate" in data or b"vTaskDelay" in data:
            score += 0.3
        if b"pvPortMalloc" in data or b"vPortFree" in data:
            score += 0.15
        if b"vTaskStartScheduler" in data:
            score += 0.15
        if b"xQueueCreate" in data:
            score += 0.1
        if b"Tmr Svc" in data:
            score += 0.1

        # Check symbols
        for sym in context.elf_symbols:
            if sym in ("xTaskCreate", "vTaskStartScheduler", "pvPortMalloc"):
                score += 0.15

        return min(score, 1.0)

    async def analyze(self, context: AnalysisContext) -> list[Component]:
        components = []
        data = context.raw_data

        version = self._extract_version(data)
        components.append(Component(
            name="FreeRTOS",
            vendor="Amazon",
            versions=[VersionConfidence(
                version=version or "detected",
                confidence=0.85 if version else 0.5,
                method=ExtractionMethod.RTOS_PLUGIN,
                evidence=f"Version string: {version}" if version else "Detected via signatures",
            )],
            component_type="operating-system",
            purl=f"pkg:generic/freertos@{version}" if version else "",
            licenses=["MIT"],
        ))

        # Detect FreeRTOS+ components
        if b"FreeRTOS_Socket" in data or b"FreeRTOS+TCP" in data:
            components.append(Component(
                name="FreeRTOS+TCP",
                vendor="Amazon",
                component_type="library",
                versions=[VersionConfidence(
                    version="detected",
                    confidence=0.7,
                    method=ExtractionMethod.RTOS_PLUGIN,
                )],
            ))

        if b"ff_" in data and (b"FF_GetBuffer" in data or b"ff_fopen" in data):
            components.append(Component(
                name="FreeRTOS+FAT",
                vendor="Amazon",
                component_type="library",
                versions=[VersionConfidence(
                    version="detected",
                    confidence=0.6,
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
            r"FreeRTOS\s+[Vv](\d+\.\d+\.\d+)",
            r"FreeRTOS\s+[Vv](\d{6}\.\d{2})",
            r"tskKERNEL_VERSION_NUMBER\s+\"([^\"]+)\"",
            r"FreeRTOS\s+Kernel\s+[Vv](\d+\.\d+\.\d+)",
        ]

    def get_known_symbols(self) -> list[str]:
        return [
            "xTaskCreate", "vTaskDelete", "vTaskDelay", "vTaskStartScheduler",
            "xQueueCreate", "xQueueSend", "xQueueReceive",
            "xSemaphoreCreateMutex", "xSemaphoreCreateBinary",
            "pvPortMalloc", "vPortFree", "xPortGetFreeHeapSize",
            "xTimerCreate", "xEventGroupCreate", "xStreamBufferCreate",
        ]
