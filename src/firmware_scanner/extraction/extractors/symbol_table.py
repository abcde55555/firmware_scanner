"""ELF symbol table-based component extraction."""

from pathlib import Path

import lief

from ...core.context import AnalysisContext
from ..models import Component, VersionConfidence, ExtractionMethod
from .base import BaseExtractor

# Known function symbols mapped to components
SYMBOL_COMPONENT_MAP = {
    # FreeRTOS
    "xTaskCreate": ("FreeRTOS", "Amazon", "operating-system"),
    "vTaskStartScheduler": ("FreeRTOS", "Amazon", "operating-system"),
    "xQueueCreate": ("FreeRTOS", "Amazon", "operating-system"),
    "xSemaphoreCreateMutex": ("FreeRTOS", "Amazon", "operating-system"),
    "pvPortMalloc": ("FreeRTOS", "Amazon", "operating-system"),
    "vPortFree": ("FreeRTOS", "Amazon", "operating-system"),
    "xTimerCreate": ("FreeRTOS", "Amazon", "operating-system"),
    "xEventGroupCreate": ("FreeRTOS", "Amazon", "operating-system"),
    "xStreamBufferCreate": ("FreeRTOS", "Amazon", "operating-system"),
    "ulTaskNotifyTake": ("FreeRTOS", "Amazon", "operating-system"),

    # Zephyr
    "k_thread_create": ("Zephyr RTOS", "Zephyr Project", "operating-system"),
    "k_sem_init": ("Zephyr RTOS", "Zephyr Project", "operating-system"),
    "k_mutex_init": ("Zephyr RTOS", "Zephyr Project", "operating-system"),
    "k_msgq_init": ("Zephyr RTOS", "Zephyr Project", "operating-system"),
    "k_work_submit": ("Zephyr RTOS", "Zephyr Project", "operating-system"),
    "z_impl_k_sleep": ("Zephyr RTOS", "Zephyr Project", "operating-system"),

    # RT-Thread
    "rt_thread_create": ("RT-Thread", "RT-Thread", "operating-system"),
    "rt_sem_create": ("RT-Thread", "RT-Thread", "operating-system"),
    "rt_mutex_create": ("RT-Thread", "RT-Thread", "operating-system"),
    "rt_mq_create": ("RT-Thread", "RT-Thread", "operating-system"),
    "rt_device_register": ("RT-Thread", "RT-Thread", "operating-system"),
    "rt_system_scheduler_start": ("RT-Thread", "RT-Thread", "operating-system"),

    # ThreadX
    "tx_thread_create": ("ThreadX", "Microsoft", "operating-system"),
    "tx_semaphore_create": ("ThreadX", "Microsoft", "operating-system"),
    "tx_mutex_create": ("ThreadX", "Microsoft", "operating-system"),
    "tx_queue_create": ("ThreadX", "Microsoft", "operating-system"),
    "tx_kernel_enter": ("ThreadX", "Microsoft", "operating-system"),

    # NuttX
    "nxsched_add_readytorun": ("NuttX", "Apache", "operating-system"),
    "nxtask_create": ("NuttX", "Apache", "operating-system"),
    "nxsem_post": ("NuttX", "Apache", "operating-system"),
    "nx_start": ("NuttX", "Apache", "operating-system"),

    # VxWorks
    "taskSpawn": ("VxWorks", "Wind River", "operating-system"),
    "semBCreate": ("VxWorks", "Wind River", "operating-system"),
    "msgQCreate": ("VxWorks", "Wind River", "operating-system"),
    "semTake": ("VxWorks", "Wind River", "operating-system"),
    "taskDelay": ("VxWorks", "Wind River", "operating-system"),
    "sysClkRateGet": ("VxWorks", "Wind River", "operating-system"),

    # uC/OS
    "OSTaskCreate": ("uC/OS", "Micrium", "operating-system"),
    "OSSemCreate": ("uC/OS", "Micrium", "operating-system"),
    "OSMutexCreate": ("uC/OS", "Micrium", "operating-system"),
    "OSStart": ("uC/OS", "Micrium", "operating-system"),
    "OSInit": ("uC/OS", "Micrium", "operating-system"),

    # LiteOS
    "LOS_TaskCreate": ("LiteOS", "Huawei", "operating-system"),
    "LOS_SemCreate": ("LiteOS", "Huawei", "operating-system"),
    "LOS_MuxCreate": ("LiteOS", "Huawei", "operating-system"),
    "LOS_QueueCreate": ("LiteOS", "Huawei", "operating-system"),
    "LOS_KernelInit": ("LiteOS", "Huawei", "operating-system"),

    # mbedTLS
    "mbedtls_ssl_init": ("mbedTLS", "ARM", "library"),
    "mbedtls_x509_crt_parse": ("mbedTLS", "ARM", "library"),
    "mbedtls_aes_init": ("mbedTLS", "ARM", "library"),
    "mbedtls_sha256_init": ("mbedTLS", "ARM", "library"),

    # wolfSSL
    "wolfSSL_Init": ("wolfSSL", "wolfSSL", "library"),
    "wolfSSL_CTX_new": ("wolfSSL", "wolfSSL", "library"),

    # lwIP
    "tcp_new": ("lwIP", "lwIP", "library"),
    "netconn_new": ("lwIP", "lwIP", "library"),
    "pbuf_alloc": ("lwIP", "lwIP", "library"),
    "etharp_output": ("lwIP", "lwIP", "library"),
    "dns_gethostbyname": ("lwIP", "lwIP", "library"),

    # FatFs
    "f_open": ("FatFs", "ChaN", "library"),
    "f_read": ("FatFs", "ChaN", "library"),
    "f_write": ("FatFs", "ChaN", "library"),
    "f_mount": ("FatFs", "ChaN", "library"),
}


class SymbolTableExtractor(BaseExtractor):
    @property
    def name(self) -> str:
        return "symbol_table"

    def is_available(self) -> bool:
        return True

    @property
    def priority(self) -> int:
        return 70

    async def extract(self, context: AnalysisContext) -> list[Component]:
        if not context.raw_data[:4] == b"\x7fELF":
            # Fall back to string-based symbol detection for non-ELF
            return self._extract_from_strings(context)

        return self._extract_from_elf(context)

    def _extract_from_elf(self, context: AnalysisContext) -> list[Component]:
        binary = lief.parse(list(context.raw_data))
        if binary is None:
            return []

        symbols: list[str] = []
        if hasattr(binary, "symbols"):
            symbols = [s.name for s in binary.symbols if s.name]
        if hasattr(binary, "static_symbols"):
            symbols.extend(s.name for s in binary.static_symbols if s.name)

        # Store symbols in context for other extractors
        context.elf_symbols = symbols

        return self._match_symbols(symbols)

    def _extract_from_strings(self, context: AnalysisContext) -> list[Component]:
        """For non-ELF: look for symbol-like strings in the binary."""
        data = context.raw_data
        found_symbols = []

        for symbol in SYMBOL_COMPONENT_MAP:
            if symbol.encode("ascii") in data:
                found_symbols.append(symbol)

        return self._match_symbols(found_symbols)

    def _match_symbols(self, symbols: list[str]) -> list[Component]:
        components: dict[str, Component] = {}
        symbol_evidence: dict[str, list[str]] = {}

        for sym in symbols:
            if sym in SYMBOL_COMPONENT_MAP:
                name, vendor, comp_type = SYMBOL_COMPONENT_MAP[sym]
                key = name.lower()

                if key not in components:
                    components[key] = Component(
                        name=name,
                        vendor=vendor,
                        component_type=comp_type,
                    )
                    symbol_evidence[key] = []

                symbol_evidence[key].append(sym)

        for key, comp in components.items():
            evidence = symbol_evidence[key]
            confidence = min(0.3 + len(evidence) * 0.1, 0.9)
            comp.versions.append(
                VersionConfidence(
                    version="detected",
                    confidence=confidence,
                    method=ExtractionMethod.SYMBOL_TABLE,
                    evidence=f"Symbols: {', '.join(evidence[:5])}",
                )
            )

        return list(components.values())
