"""Radare2-based deep analysis extractor via r2pipe."""

import json

from ...core.context import AnalysisContext
from ..models import Component, VersionConfidence, ExtractionMethod
from .base import BaseExtractor

R2PIPE_AVAILABLE = False
try:
    import r2pipe
    R2PIPE_AVAILABLE = True
except Exception:
    pass


RTOS_FUNCTION_SIGNATURES = {
    "FreeRTOS": [
        "xTaskCreate", "vTaskDelete", "vTaskDelay", "vTaskStartScheduler",
        "xQueueCreate", "xQueueSend", "xQueueReceive", "xSemaphoreCreateMutex",
        "pvPortMalloc", "vPortFree", "xPortGetFreeHeapSize",
        "xTimerCreate", "xEventGroupCreate", "xStreamBufferCreate",
    ],
    "Zephyr RTOS": [
        "k_thread_create", "k_sem_init", "k_mutex_init", "k_msgq_init",
        "k_work_submit", "k_timer_start", "k_heap_alloc",
        "z_impl_k_sleep", "z_swap", "z_reschedule",
    ],
    "RT-Thread": [
        "rt_thread_create", "rt_sem_create", "rt_mutex_create",
        "rt_mq_create", "rt_device_register", "rt_system_scheduler_start",
        "rt_object_init", "rt_timer_create",
    ],
    "ThreadX": [
        "tx_thread_create", "tx_semaphore_create", "tx_mutex_create",
        "tx_queue_create", "tx_kernel_enter", "tx_timer_create",
        "_tx_thread_schedule", "_tx_thread_system_suspend",
    ],
    "VxWorks": [
        "taskSpawn", "semBCreate", "semMCreate", "msgQCreate",
        "taskDelay", "sysClkRateGet", "intConnect", "taskSafe",
    ],
    "NuttX": [
        "nxsched_add_readytorun", "nxtask_create", "nxsem_post",
        "nx_start", "nxmutex_init", "nxsig_dispatch",
    ],
    "uC/OS": [
        "OSTaskCreate", "OSSemCreate", "OSMutexCreate",
        "OSStart", "OSInit", "OSTimeDly", "OSQCreate",
    ],
    "LiteOS": [
        "LOS_TaskCreate", "LOS_SemCreate", "LOS_MuxCreate",
        "LOS_QueueCreate", "LOS_KernelInit", "LOS_Start",
    ],
}

LIBRARY_FUNCTION_SIGNATURES = {
    "mbedTLS": [
        "mbedtls_ssl_init", "mbedtls_x509_crt_parse", "mbedtls_aes_init",
        "mbedtls_ssl_handshake", "mbedtls_entropy_init",
    ],
    "wolfSSL": [
        "wolfSSL_Init", "wolfSSL_CTX_new", "wolfSSL_new",
        "wolfSSL_connect", "wolfCrypt_Init",
    ],
    "lwIP": [
        "tcp_new", "tcp_bind", "tcp_listen", "tcp_connect",
        "udp_new", "netconn_new", "pbuf_alloc", "etharp_output",
    ],
    "FatFs": [
        "f_open", "f_read", "f_write", "f_close", "f_mount",
        "f_mkdir", "f_unlink", "f_stat",
    ],
}


class Radare2Extractor(BaseExtractor):
    def __init__(self, r2_path: str = "r2"):
        self._r2_path = r2_path

    @property
    def name(self) -> str:
        return "radare2"

    def is_available(self) -> bool:
        if not R2PIPE_AVAILABLE:
            return False
        try:
            import shutil
            return shutil.which(self._r2_path) is not None
        except Exception:
            return False

    @property
    def priority(self) -> int:
        return 30

    async def extract(self, context: AnalysisContext) -> list[Component]:
        if not R2PIPE_AVAILABLE:
            return []

        firmware_path = str(context.firmware_path)
        components: dict[str, Component] = {}

        try:
            r2 = r2pipe.open(firmware_path, flags=["-2"])
            r2.cmd("aaa")  # Full analysis

            # Get function list
            functions_json = r2.cmd("aflj")
            functions = json.loads(functions_json) if functions_json else []
            func_names = [f.get("name", "") for f in functions]

            # Get strings
            strings_json = r2.cmd("izj")
            strings = json.loads(strings_json) if strings_json else []
            string_values = [s.get("string", "") for s in strings]

            # Match RTOS functions
            for rtos_name, signatures in RTOS_FUNCTION_SIGNATURES.items():
                matched = [s for s in signatures if any(s in fn for fn in func_names)]
                if len(matched) >= 2:
                    confidence = min(0.4 + len(matched) * 0.1, 0.95)
                    components[rtos_name.lower()] = Component(
                        name=rtos_name,
                        component_type="operating-system",
                        versions=[
                            VersionConfidence(
                                version="detected",
                                confidence=confidence,
                                method=ExtractionMethod.RADARE2,
                                evidence=f"Functions: {', '.join(matched[:5])}",
                            )
                        ],
                    )

            # Match library functions
            for lib_name, signatures in LIBRARY_FUNCTION_SIGNATURES.items():
                matched = [s for s in signatures if any(s in fn for fn in func_names)]
                if len(matched) >= 2:
                    confidence = min(0.4 + len(matched) * 0.1, 0.9)
                    components[lib_name.lower()] = Component(
                        name=lib_name,
                        component_type="library",
                        versions=[
                            VersionConfidence(
                                version="detected",
                                confidence=confidence,
                                method=ExtractionMethod.RADARE2,
                                evidence=f"Functions: {', '.join(matched[:5])}",
                            )
                        ],
                    )

            # Extract version strings from r2 string analysis
            self._extract_versions_from_strings(string_values, components)

            # Get imports if available
            imports_json = r2.cmd("iij")
            if imports_json:
                imports = json.loads(imports_json)
                self._analyze_imports(imports, components)

            r2.quit()

        except Exception:
            pass

        return list(components.values())

    def _extract_versions_from_strings(
        self, strings: list[str], components: dict[str, Component]
    ) -> None:
        """Cross-reference r2 strings with known components for version extraction."""
        import re

        version_hints = {
            "FreeRTOS": r"FreeRTOS\s+[Vv](\d+\.\d+\.\d+)",
            "Zephyr RTOS": r"zephyr[/-]v?(\d+\.\d+\.\d+)",
            "mbedTLS": r"mbed\s*TLS\s+(\d+\.\d+\.\d+)",
            "lwIP": r"lwIP[/-](\d+\.\d+\.\d+)",
        }

        for s in strings:
            for comp_name, pattern in version_hints.items():
                match = re.search(pattern, s, re.IGNORECASE)
                if match:
                    key = comp_name.lower()
                    if key not in components:
                        components[key] = Component(
                            name=comp_name,
                            component_type="library",
                        )
                    components[key].versions.append(
                        VersionConfidence(
                            version=match.group(1),
                            confidence=0.85,
                            method=ExtractionMethod.RADARE2,
                            evidence=f"String: {s[:80]}",
                        )
                    )

    def _analyze_imports(self, imports: list[dict], components: dict[str, Component]) -> None:
        """Analyze import table for library detection."""
        for imp in imports:
            name = imp.get("name", "")
            if "mbedtls_" in name and "mbedtls" not in components:
                components["mbedtls"] = Component(
                    name="mbedTLS",
                    vendor="ARM",
                    component_type="library",
                    versions=[
                        VersionConfidence(
                            version="detected",
                            confidence=0.8,
                            method=ExtractionMethod.RADARE2,
                            evidence=f"Import: {name}",
                        )
                    ],
                )
