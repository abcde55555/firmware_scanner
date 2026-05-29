"""ESP-IDF analysis plugin."""

import re
from ...core.context import AnalysisContext
from ...extraction.models import Component, VersionConfidence, ExtractionMethod
from ..base import RTOSPlugin
from ..registry import RTOSRegistry


@RTOSRegistry.register
class ESPIDFPlugin(RTOSPlugin):
    @property
    def rtos_name(self) -> str:
        return "ESP-IDF"

    @property
    def vendor(self) -> str:
        return "Espressif"

    def detect(self, context: AnalysisContext) -> float:
        score = 0.0
        data = context.raw_data

        if data[0:1] == b"\xe9":
            score += 0.2
        if b"esp_idf" in data or b"ESP-IDF" in data:
            score += 0.35
        if b"esp_wifi_" in data:
            score += 0.15
        if b"esp_err_t" in data or b"ESP_OK" in data:
            score += 0.15
        if b"esp_log" in data or b"ESP_LOG" in data:
            score += 0.1
        if b"nvs_flash" in data:
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

        components = [Component(
            name="ESP-IDF",
            vendor="Espressif",
            versions=[VersionConfidence(
                version=version or "detected",
                confidence=0.8 if version else 0.5,
                method=ExtractionMethod.RTOS_PLUGIN,
            )],
            component_type="operating-system",
            purl=f"pkg:generic/esp-idf@{version}" if version else "",
            licenses=["Apache-2.0"],
        )]

        if b"esp_wifi_" in data:
            components.append(Component(name="ESP WiFi", vendor="Espressif", component_type="library",
                versions=[VersionConfidence(version="detected", confidence=0.7, method=ExtractionMethod.RTOS_PLUGIN)]))
        if b"esp_bt_" in data or b"esp_ble_" in data:
            components.append(Component(name="ESP Bluetooth", vendor="Espressif", component_type="library",
                versions=[VersionConfidence(version="detected", confidence=0.7, method=ExtractionMethod.RTOS_PLUGIN)]))

        return components

    def get_version_patterns(self) -> list[str]:
        return [
            r"ESP-IDF\s+[Vv]?(\d+\.\d+(?:\.\d+)?)",
            r"esp-idf/v(\d+\.\d+(?:\.\d+)?)",
            r"IDF_VER\s*[=:]\s*\"?[Vv]?(\d+\.\d+\.\d+)",
        ]

    def get_known_symbols(self) -> list[str]:
        return [
            "esp_wifi_init", "esp_wifi_start", "esp_event_loop_create_default",
            "nvs_flash_init", "esp_bt_controller_init",
        ]
