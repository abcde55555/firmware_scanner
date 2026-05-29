"""String pattern-based component and version extraction."""

import re
from ...core.context import AnalysisContext
from ..models import Component, VersionConfidence, ExtractionMethod
from .base import BaseExtractor

VERSION_PATTERNS = [
    # Generic version patterns
    (r"(?:version|ver|v)\s*[=:]\s*[\"']?(\d+\.\d+(?:\.\d+)?(?:[-_.]\w+)?)", None, None),
    (r"(\d+\.\d+\.\d+)(?:\s*\([\w\s]+\))?", None, None),

    # FreeRTOS
    (r"FreeRTOS\s+[Vv](\d+\.\d+\.\d+)", "FreeRTOS", "Amazon"),
    (r"FreeRTOS\s+[Vv](\d{6}\.\d{2})", "FreeRTOS", "Amazon"),
    (r"tskKERNEL_VERSION_NUMBER\s+\"([^\"]+)\"", "FreeRTOS", "Amazon"),
    (r"FreeRTOS/Source.*?[Vv](\d+\.\d+\.\d+)", "FreeRTOS", "Amazon"),

    # Zephyr
    (r"Zephyr\s+[Vv]?(\d+\.\d+\.\d+)", "Zephyr RTOS", "Zephyr Project"),
    (r"KERNELVERSION\s*=\s*(\d+\.\d+\.\d+)", "Zephyr RTOS", "Zephyr Project"),
    (r"zephyr-v(\d+\.\d+\.\d+)", "Zephyr RTOS", "Zephyr Project"),

    # RT-Thread
    (r"RT-Thread\s+[Vv]?(\d+\.\d+\.\d+)", "RT-Thread", "RT-Thread"),
    (r"rtthread\s+version\s+(\d+\.\d+\.\d+)", "RT-Thread", "RT-Thread"),

    # ESP-IDF
    (r"ESP-IDF\s+[Vv]?(\d+\.\d+(?:\.\d+)?)", "ESP-IDF", "Espressif"),
    (r"esp-idf/v(\d+\.\d+(?:\.\d+)?)", "ESP-IDF", "Espressif"),
    (r"IDF_VER\s*[=:]\s*\"?[Vv]?(\d+\.\d+\.\d+)", "ESP-IDF", "Espressif"),

    # VxWorks
    (r"VxWorks\s+(\d+\.\d+(?:\.\d+)?)", "VxWorks", "Wind River"),
    (r"WIND_RIVER_VER\s+\"(\d+\.\d+)\"", "VxWorks", "Wind River"),
    (r"vxWorks\s+\(compiled.*?version\s+(\d+\.\d+)", "VxWorks", "Wind River"),

    # ThreadX (Azure RTOS)
    (r"ThreadX\s+[Vv]?(\d+\.\d+(?:\.\d+)?)", "ThreadX", "Microsoft"),
    (r"Azure\s+RTOS\s+ThreadX\s+[Vv]?(\d+\.\d+\.\d+)", "ThreadX", "Microsoft"),
    (r"_tx_version_id.*?(\d+\.\d+\.\d+)", "ThreadX", "Microsoft"),

    # NuttX
    (r"NuttX\s+(\d+\.\d+\.\d+)", "NuttX", "Apache"),
    (r"nuttx-(\d+\.\d+\.\d+)", "NuttX", "Apache"),

    # LiteOS
    (r"Huawei\s+LiteOS\s+[Vv]?(\d+\.\d+\.\d+)", "LiteOS", "Huawei"),
    (r"LiteOS\s+[Vv](\d+\.\d+(?:\.\d+)?)", "LiteOS", "Huawei"),

    # uC/OS
    (r"uC/OS-I{1,3}\s+[Vv]?(\d+\.\d+\.\d+)", "uC/OS", "Micrium"),
    (r"Micrium.*?[Vv](\d+\.\d+\.\d+)", "uC/OS", "Micrium"),

    # Common libraries
    (r"mbed\s+TLS\s+(\d+\.\d+\.\d+)", "mbedTLS", "ARM"),
    (r"mbedtls[/-](\d+\.\d+\.\d+)", "mbedTLS", "ARM"),
    (r"wolfSSL\s+(\d+\.\d+\.\d+)", "wolfSSL", "wolfSSL"),
    (r"lwIP\s+(\d+\.\d+\.\d+)", "lwIP", "lwIP"),
    (r"LWIP_VERSION_STRING\s+\"(\d+\.\d+\.\d+)\"", "lwIP", "lwIP"),
    (r"FatFs\s+[Rr]?(\d+\.\d+\w?)", "FatFs", "ChaN"),
    (r"newlib\s+(\d+\.\d+\.\d+)", "Newlib", "Red Hat"),
    (r"picolibc\s+(\d+\.\d+(?:\.\d+)?)", "picolibc", "picolibc"),
    (r"tinycrypt\s+(\d+\.\d+\.\d+)", "TinyCrypt", "Intel"),
    (r"libcoap\s+(\d+\.\d+\.\d+)", "libcoap", "libcoap"),
    (r"cJSON\s+(\d+\.\d+\.\d+)", "cJSON", "DaveGamble"),
    (r"protobuf-c\s+(\d+\.\d+\.\d+)", "protobuf-c", "protobuf-c"),
    (r"nanopb\s+(\d+\.\d+\.\d+)", "nanopb", "nanopb"),
    (r"SEGGER.*?[Vv](\d+\.\d+\w?)", "SEGGER RTT", "SEGGER"),
    (r"U-Boot\s+(\d{4}\.\d{2})", "U-Boot", "DENX"),
    (r"OpenOCD\s+(\d+\.\d+\.\d+)", "OpenOCD", "OpenOCD"),
]

COPYRIGHT_PATTERNS = [
    (r"Copyright.*?(\d{4}).*?([A-Z][\w\s]+(?:Inc|LLC|Ltd|Corp|GmbH|Foundation)\.?)", None, None),
]


class StringPatternExtractor(BaseExtractor):
    @property
    def name(self) -> str:
        return "string_patterns"

    def is_available(self) -> bool:
        return True

    @property
    def priority(self) -> int:
        return 80

    async def extract(self, context: AnalysisContext) -> list[Component]:
        components: dict[str, Component] = {}
        data = context.raw_data

        # Extract all ASCII strings first
        text_data = data.decode("ascii", errors="ignore")

        for pattern, comp_name, vendor in VERSION_PATTERNS:
            matches = re.finditer(pattern, text_data, re.IGNORECASE)
            for match in matches:
                version = match.group(1)
                if not self._is_valid_version(version):
                    continue

                name = comp_name or self._infer_component_name(match, text_data)
                if not name:
                    continue

                key = name.lower()
                if key not in components:
                    components[key] = Component(
                        name=name,
                        vendor=vendor or "",
                        component_type="operating-system" if comp_name in (
                            "FreeRTOS", "Zephyr RTOS", "RT-Thread", "VxWorks",
                            "ThreadX", "NuttX", "LiteOS", "uC/OS"
                        ) else "library",
                    )

                components[key].versions.append(
                    VersionConfidence(
                        version=version,
                        confidence=0.7 if comp_name else 0.4,
                        method=ExtractionMethod.STRING_PATTERN,
                        evidence=match.group(0)[:100],
                    )
                )

        return list(components.values())

    def _is_valid_version(self, version: str) -> bool:
        if not version:
            return False
        parts = re.split(r"[.\-_]", version)
        if len(parts) < 2:
            return False
        try:
            major = int(parts[0])
            if major > 9999:
                return False
        except ValueError:
            return False
        return True

    def _infer_component_name(self, match: re.Match, text: str) -> str:
        start = max(0, match.start() - 50)
        context_str = text[start : match.start()]
        # Look for a capitalized word before the version
        name_match = re.search(r"([A-Z][\w-]+)\s*$", context_str)
        if name_match:
            return name_match.group(1)
        return ""
