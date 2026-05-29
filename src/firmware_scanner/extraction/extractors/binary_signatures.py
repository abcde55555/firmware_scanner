"""Binary signature/fingerprint-based component detection."""

import hashlib
import json
from pathlib import Path

from ...core.context import AnalysisContext
from ..models import Component, VersionConfidence, ExtractionMethod
from .base import BaseExtractor

# Known binary fingerprints: (byte_sequence, component_name, vendor, min_confidence)
BINARY_SIGNATURES = [
    # FreeRTOS task control block magic patterns
    (b"IdleTask\x00", "FreeRTOS", "Amazon", 0.6),
    (b"IDLE\x00\x00\x00\x00", "FreeRTOS", "Amazon", 0.5),
    (b"Tmr Svc\x00", "FreeRTOS", "Amazon", 0.7),

    # Zephyr
    (b"ZEPHYR_BASE", "Zephyr RTOS", "Zephyr Project", 0.8),
    (b"__device_dts_ord_", "Zephyr RTOS", "Zephyr Project", 0.7),
    (b"zephyr/kernel", "Zephyr RTOS", "Zephyr Project", 0.8),

    # RT-Thread
    (b"rt-thread", "RT-Thread", "RT-Thread", 0.7),
    (b"rtthread", "RT-Thread", "RT-Thread", 0.6),
    (b"\x23\x23\x23\x23", "RT-Thread", "RT-Thread", 0.3),  # RT-Thread object magic

    # ESP-IDF markers
    (b"esp_idf", "ESP-IDF", "Espressif", 0.7),
    (b"ESP_ERROR_CHECK", "ESP-IDF", "Espressif", 0.6),
    (b"esp_wifi_", "ESP-IDF WiFi", "Espressif", 0.7),
    (b"esp_bt_", "ESP-IDF Bluetooth", "Espressif", 0.7),

    # VxWorks
    (b"Wind River Systems", "VxWorks", "Wind River", 0.9),
    (b"VxWorks", "VxWorks", "Wind River", 0.8),
    (b"WDB_AGENT", "VxWorks", "Wind River", 0.7),

    # ThreadX
    (b"Azure RTOS", "ThreadX", "Microsoft", 0.9),
    (b"ThreadX", "ThreadX", "Microsoft", 0.8),
    (b"THREADX", "ThreadX", "Microsoft", 0.7),

    # NuttX
    (b"NuttX", "NuttX", "Apache", 0.8),
    (b"nsh>", "NuttX", "Apache", 0.6),

    # LiteOS
    (b"Huawei LiteOS", "LiteOS", "Huawei", 0.9),
    (b"LiteOS", "LiteOS", "Huawei", 0.7),
    (b"LOS_ERRNO", "LiteOS", "Huawei", 0.6),

    # uC/OS
    (b"Micrium", "uC/OS", "Micrium", 0.8),
    (b"uC/OS", "uC/OS", "Micrium", 0.8),
    (b"uCOS", "uC/OS", "Micrium", 0.7),

    # Common libraries
    (b"mbedTLS", "mbedTLS", "ARM", 0.8),
    (b"MBEDTLS_", "mbedTLS", "ARM", 0.7),
    (b"wolfSSL", "wolfSSL", "wolfSSL", 0.8),
    (b"lwIP", "lwIP", "lwIP", 0.7),
    (b"LWIP_", "lwIP", "lwIP", 0.6),
    (b"FatFs", "FatFs", "ChaN", 0.8),
    (b"SEGGER", "SEGGER RTT", "SEGGER", 0.7),
    (b"U-Boot", "U-Boot", "DENX", 0.8),
    (b"cJSON", "cJSON", "DaveGamble", 0.7),
    (b"nanopb", "nanopb", "nanopb", 0.7),
    (b"protobuf-c", "protobuf-c", "protobuf-c", 0.7),

    # Qualcomm
    (b"QUALCOMM", "Qualcomm BSP", "Qualcomm", 0.8),
    (b"QC_IMAGE_VERSION_STRING", "Qualcomm BSP", "Qualcomm", 0.9),
    (b"QCOM", "Qualcomm BSP", "Qualcomm", 0.6),

    # MediaTek
    (b"MediaTek", "MediaTek BSP", "MediaTek", 0.8),
    (b"MTK_FW", "MediaTek BSP", "MediaTek", 0.7),
]


class BinarySignatureExtractor(BaseExtractor):
    def __init__(self, signature_dir: Path | None = None):
        self._signature_dir = signature_dir
        self._extra_signatures: list[tuple] = []
        if signature_dir:
            self._load_external_signatures(signature_dir)

    @property
    def name(self) -> str:
        return "binary_signatures"

    def is_available(self) -> bool:
        return True

    @property
    def priority(self) -> int:
        return 60

    async def extract(self, context: AnalysisContext) -> list[Component]:
        components: dict[str, Component] = {}
        data = context.raw_data

        all_signatures = BINARY_SIGNATURES + self._extra_signatures

        for signature, comp_name, vendor, base_confidence in all_signatures:
            count = data.count(signature)
            if count == 0:
                continue

            key = comp_name.lower()
            # Boost confidence with multiple occurrences
            confidence = min(base_confidence + (count - 1) * 0.05, 0.95)

            if key not in components:
                components[key] = Component(
                    name=comp_name,
                    vendor=vendor,
                    component_type=self._infer_type(comp_name),
                )

            # Find first occurrence offset
            offset = data.find(signature)
            components[key].versions.append(
                VersionConfidence(
                    version="detected",
                    confidence=confidence,
                    method=ExtractionMethod.BINARY_SIGNATURE,
                    evidence=f"Signature '{signature.decode('ascii', errors='replace')}' "
                    f"at offset {offset:#x} ({count} occurrences)",
                )
            )

        return list(components.values())

    def _infer_type(self, name: str) -> str:
        os_names = {
            "FreeRTOS", "Zephyr RTOS", "RT-Thread", "VxWorks",
            "ThreadX", "NuttX", "LiteOS", "uC/OS",
        }
        if name in os_names:
            return "operating-system"
        if "BSP" in name:
            return "firmware"
        return "library"

    def _load_external_signatures(self, sig_dir: Path) -> None:
        """Load additional signatures from JSON files."""
        if not sig_dir.exists():
            return
        for json_file in sig_dir.glob("*.json"):
            try:
                data = json.loads(json_file.read_text())
                for entry in data.get("signatures", []):
                    sig_bytes = bytes.fromhex(entry["hex"]) if "hex" in entry else entry["ascii"].encode()
                    self._extra_signatures.append(
                        (sig_bytes, entry["name"], entry.get("vendor", ""), entry.get("confidence", 0.7))
                    )
            except Exception:
                continue
