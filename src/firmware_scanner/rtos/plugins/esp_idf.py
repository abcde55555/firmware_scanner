"""ESP-IDF analysis plugin."""

import re

from ...core.context import AnalysisContext
from ...extraction.models import Component, ExtractionMethod, VersionConfidence
from ..base import RTOSPlugin
from ..registry import RTOSRegistry

_IDF_SOURCE_COMPONENT_RE = re.compile(
    rb"IDF/(?:components|examples/common_components)/([A-Za-z0-9_.-]+)/"
)
_IDF_EXTERNAL_COMPONENTS = {
    "freertos": ("FreeRTOS", "Amazon", "operating-system"),
    "lwip": ("lwIP", "lwIP", "library"),
    "mbedtls": ("mbedTLS", "ARM", "library"),
    "newlib": ("Newlib", "Red Hat", "library"),
    "http_parser": ("HTTP Parser", "NGINX", "library"),
    "wpa_supplicant": ("wpa_supplicant", "w1.fi", "library"),
    "esp_wifi": ("ESP-IDF WiFi", "Espressif", "library"),
}


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
        app_desc = {}
        if context.unpack_result:
            app_desc = context.unpack_result.metadata.get("esp_app_desc", {})

        version = app_desc.get("idf_version", "")
        version_evidence = ""
        if version:
            version_evidence = (
                f"ESP-IDF app descriptor idf_ver={version!r} "
                f"at file offset {app_desc.get('file_offset', 0):#x}"
            )
        else:
            for pattern in self.get_version_patterns():
                match = re.search(pattern, text)
                if match:
                    version = match.group(1)
                    version_evidence = match.group(0)[:100]
                    break

        components = [
            Component(
                name="ESP-IDF",
                vendor="Espressif",
                versions=[
                    VersionConfidence(
                        version=version or "detected",
                        confidence=0.99 if app_desc else (0.8 if version else 0.5),
                        method=ExtractionMethod.BUILD_METADATA
                        if app_desc
                        else ExtractionMethod.RTOS_PLUGIN,
                        evidence=version_evidence,
                    )
                ],
                resolved_version=version,
                component_type="framework",
                purl=f"pkg:generic/esp-idf@{version}" if version else "",
                licenses=["Apache-2.0"],
                properties=[
                    {
                        "name": "firmware:esp:project_name",
                        "value": app_desc.get("project_name", ""),
                    },
                    {"name": "firmware:esp:build_date", "value": app_desc.get("build_date", "")},
                    {
                        "name": "firmware:esp:app_elf_sha256",
                        "value": app_desc.get("elf_sha256", ""),
                    },
                ]
                if app_desc
                else [],
            )
        ]

        if app_desc.get("project_name"):
            components.append(
                Component(
                    name=app_desc["project_name"],
                    component_type="application",
                    resolved_version=app_desc.get("app_version", ""),
                    versions=[
                        VersionConfidence(
                            version=app_desc.get("app_version", ""),
                            confidence=0.99,
                            method=ExtractionMethod.BUILD_METADATA,
                            evidence=(
                                f"ESP-IDF app descriptor project_name={app_desc['project_name']!r}, "
                                f"version={app_desc.get('app_version', '')!r}"
                            ),
                        )
                    ],
                )
            )

        if b"esp_wifi_" in data:
            components.append(
                Component(
                    name="ESP-IDF WiFi",
                    vendor="Espressif",
                    component_type="library",
                    versions=[
                        VersionConfidence(
                            version="detected", confidence=0.7, method=ExtractionMethod.RTOS_PLUGIN
                        )
                    ],
                )
            )
        if b"esp_bt_" in data or b"esp_ble_" in data:
            components.append(
                Component(
                    name="ESP Bluetooth",
                    vendor="Espressif",
                    component_type="library",
                    versions=[
                        VersionConfidence(
                            version="detected", confidence=0.7, method=ExtractionMethod.RTOS_PLUGIN
                        )
                    ],
                )
            )

        if version:
            components.extend(self._components_from_source_paths(data, version))

        return components

    def _components_from_source_paths(self, data: bytes, idf_version: str) -> list[Component]:
        """Build component identity claims from linked IDF source-path strings."""
        source_paths: dict[str, list[str]] = {}
        for match in _IDF_SOURCE_COMPONENT_RE.finditer(data):
            component_id = match.group(1).decode("ascii", errors="ignore")
            path_start = (
                max(
                    data.rfind(b"\0", 0, match.start()),
                    data.rfind(b"\n", 0, match.start()),
                    data.rfind(b"\r", 0, match.start()),
                )
                + 1
            )
            path_end = data.find(b"\0", match.end())
            if path_start < 0 or path_end < 0 or path_end - path_start > 512:
                continue
            try:
                source_path = data[path_start:path_end].decode("ascii")
            except UnicodeDecodeError:
                continue
            source_paths.setdefault(component_id, []).append(source_path)

        components = []
        for component_id, paths in sorted(source_paths.items())[:64]:
            paths = sorted(set(paths))
            evidence = f"linked ESP-IDF source path: {paths[0]}"
            if len(paths) > 1:
                evidence += f" (+{len(paths) - 1} more)"

            external = _IDF_EXTERNAL_COMPONENTS.get(component_id)
            if external:
                name, vendor, component_type = external
                resolved_version = ""
                claim = VersionConfidence(
                    version="detected",
                    confidence=0.75,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=evidence,
                )
            else:
                name = f"component-{component_id.replace('_', '-')}"
                vendor = "Espressif"
                component_type = "library"
                resolved_version = idf_version
                claim = VersionConfidence(
                    version=idf_version,
                    confidence=0.90,
                    method=ExtractionMethod.BUILD_METADATA,
                    evidence=f"ESP-IDF {idf_version}: {evidence}",
                )

            properties = [
                {"name": "firmware:esp:parent_idf_version", "value": idf_version},
                {
                    "name": "firmware:evidence:source_path",
                    "value": paths[0],
                },
            ]
            components.append(
                Component(
                    name=name,
                    vendor=vendor,
                    component_type=component_type,
                    resolved_version=resolved_version,
                    versions=[claim],
                    properties=properties,
                )
            )
        return components

    def get_version_patterns(self) -> list[str]:
        return [
            r"ESP-IDF\s+[Vv]?(\d+\.\d+(?:\.\d+)?)",
            r"esp-idf/v(\d+\.\d+(?:\.\d+)?)",
            r"IDF_VER\s*[=:]\s*\"?[Vv]?(\d+\.\d+\.\d+)",
        ]

    def get_known_symbols(self) -> list[str]:
        return [
            "esp_wifi_init",
            "esp_wifi_start",
            "esp_event_loop_create_default",
            "nvs_flash_init",
            "esp_bt_controller_init",
        ]
