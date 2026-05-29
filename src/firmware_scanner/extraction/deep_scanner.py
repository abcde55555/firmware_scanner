"""Deep scanner engine - exhaustive per-section analysis with proximity-based version detection."""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterator, Callable

from ..core.context import AnalysisContext
from ..extraction.models import Component, VersionConfidence, ExtractionMethod
from ..utils.binary import find_strings


@dataclass
class StringHit:
    offset: int
    value: str
    section_name: str = ""


@dataclass
class ComponentHit:
    name: str
    vendor: str
    component_type: str
    offset: int
    matched_pattern: str
    section_name: str = ""
    nearby_strings: list[str] = field(default_factory=list)


PROXIMITY_WINDOW = 512  # bytes around a component hit to search for version
MAX_SECTION_SCAN_SIZE = 8 * 1024 * 1024  # 8MB max per section for pattern scanning
SCAN_TIMEOUT_PER_SECTION = 30  # seconds


class DeepScanner:
    """Exhaustive firmware scanner that analyzes every section and performs
    proximity-based version detection around each component signature hit."""

    def __init__(self, component_db: "ComponentDatabase", max_threads: int = 4,
                 progress_callback: Callable[[int, int, str], None] | None = None):
        self._db = component_db
        self._max_threads = max_threads
        self._progress_callback = progress_callback

    def scan(self, context: AnalysisContext) -> list[Component]:
        """Perform deep scan across all firmware sections using thread pool."""
        sections_to_scan = self._get_sections(context)
        total_sections = len(sections_to_scan)

        all_hits: list[ComponentHit] = []
        completed = 0

        if self._progress_callback:
            self._progress_callback(0, total_sections, "Starting deep scan...")

        # Multi-threaded section scanning
        with ThreadPoolExecutor(max_workers=self._max_threads) as executor:
            futures = {}
            for section_name, section_data in sections_to_scan:
                future = executor.submit(self._scan_one_section, section_data, section_name)
                futures[future] = section_name

            for future in as_completed(futures, timeout=SCAN_TIMEOUT_PER_SECTION * total_sections):
                section_name = futures[future]
                completed += 1
                try:
                    hits = future.result(timeout=SCAN_TIMEOUT_PER_SECTION)
                    all_hits.extend(hits)
                except TimeoutError:
                    pass
                except Exception:
                    pass
                if self._progress_callback:
                    self._progress_callback(completed, total_sections, f"Scanned: {section_name}")

        # Phase 4: Resolve versions from nearby strings (uses raw_data, single-threaded)
        if self._progress_callback:
            self._progress_callback(total_sections, total_sections, "Resolving versions...")

        components = self._resolve_components(all_hits, context)
        return components

    def _scan_one_section(self, section_data: bytes, section_name: str) -> list[ComponentHit]:
        """Scan a single section - designed to run in a thread."""
        # Limit large sections to avoid hanging
        scan_data = section_data[:MAX_SECTION_SCAN_SIZE]
        hits = self._scan_section(scan_data, section_name)
        # For each hit, extract nearby strings for version detection
        strings_in_section = find_strings(scan_data, min_length=4)
        for hit in hits:
            hit.nearby_strings = self._get_nearby_strings(
                hit.offset, strings_in_section, scan_data
            )
        return hits

        # Phase 4: Resolve versions from nearby strings
        components = self._resolve_components(all_hits, context)

        return components

    def _get_sections(self, context: AnalysisContext) -> list[tuple[str, bytes]]:
        """Get all analyzable data sections from the firmware."""
        sections: list[tuple[str, bytes]] = []

        # Always include the full raw data as a section
        sections.append(("raw_firmware", context.raw_data))

        # Add unpacked sections
        if context.unpack_result:
            for section in context.unpack_result.sections:
                if section.data and len(section.data) > 16:
                    sections.append((section.name, section.data))

        return sections

    def _scan_section(self, data: bytes, section_name: str) -> list[ComponentHit]:
        """Scan a section for all known component signatures."""
        hits: list[ComponentHit] = []

        for entry in self._db.get_all_signatures():
            pattern_bytes = entry.pattern.encode("ascii", errors="ignore")
            # Skip very short patterns (too many false positives)
            if len(pattern_bytes) < 5:
                continue
            # For patterns under 8 bytes, require word boundary (not inside another word)
            require_boundary = len(pattern_bytes) < 8
            offset = 0
            while True:
                pos = data.find(pattern_bytes, offset)
                if pos == -1:
                    break
                # Word boundary check: byte before must not be alphanumeric
                if require_boundary and pos > 0:
                    prev_byte = data[pos - 1]
                    if (0x30 <= prev_byte <= 0x39) or (0x41 <= prev_byte <= 0x5A) or (0x61 <= prev_byte <= 0x7A) or prev_byte == 0x5F:
                        offset = pos + len(pattern_bytes)
                        continue
                hits.append(ComponentHit(
                    name=entry.name,
                    vendor=entry.vendor,
                    component_type=entry.component_type,
                    offset=pos,
                    matched_pattern=entry.pattern,
                    section_name=section_name,
                ))
                offset = pos + len(pattern_bytes)

        # Also scan with regex patterns for version-embedded strings
        text = data.decode("ascii", errors="ignore")
        for entry in self._db.get_all_version_patterns():
            for match in re.finditer(entry.pattern, text):
                hits.append(ComponentHit(
                    name=entry.name,
                    vendor=entry.vendor,
                    component_type=entry.component_type,
                    offset=match.start(),
                    matched_pattern=match.group(0),
                    section_name=section_name,
                    nearby_strings=[match.group(0)],
                ))

        return hits

    def _get_nearby_strings(
        self, offset: int, all_strings: list[tuple[int, str]], data: bytes
    ) -> list[str]:
        """Get strings within PROXIMITY_WINDOW bytes of the hit."""
        nearby = []
        window_start = max(0, offset - PROXIMITY_WINDOW)
        window_end = offset + PROXIMITY_WINDOW

        for str_offset, str_value in all_strings:
            if window_start <= str_offset <= window_end:
                nearby.append(str_value)

        return nearby

    def _resolve_components(
        self, hits: list[ComponentHit], context: AnalysisContext
    ) -> list[Component]:
        """Merge hits and resolve versions using all available evidence."""
        # Group hits by component name
        groups: dict[str, list[ComponentHit]] = {}
        for hit in hits:
            key = hit.name.lower()
            if key not in groups:
                groups[key] = []
            groups[key].append(hit)

        components: list[Component] = []
        for key, group in groups.items():
            # Check if any hit came from a version pattern (high confidence, one is enough)
            has_version_hit = any(h.nearby_strings and h.matched_pattern == h.nearby_strings[0] for h in group)
            if not has_version_hit:
                # For pure signature hits, require at least 2 distinct patterns
                unique_patterns = set(h.matched_pattern for h in group)
                if len(unique_patterns) < 2:
                    continue
            comp = self._merge_hits(group, context)
            if comp:
                components.append(comp)

        return components

    def _merge_hits(self, hits: list[ComponentHit], context: AnalysisContext) -> Component | None:
        if not hits:
            return None

        base = hits[0]
        # Collect all nearby strings for version extraction
        all_nearby = []
        for hit in hits:
            all_nearby.extend(hit.nearby_strings)

        # Try to extract version from nearby strings
        version = self._extract_version_from_context(base.name, all_nearby, context.raw_data)

        # Calculate confidence based on number of hits and methods
        unique_sections = set(h.section_name for h in hits)
        confidence = min(0.4 + len(hits) * 0.05 + len(unique_sections) * 0.1, 0.95)
        if version:
            confidence = min(confidence + 0.15, 0.95)

        evidence_parts = []
        unique_patterns = set(h.matched_pattern for h in hits)
        evidence_parts.append(f"Matched: {', '.join(list(unique_patterns)[:3])}")
        evidence_parts.append(f"Hits: {len(hits)} across {len(unique_sections)} sections")

        return Component(
            name=base.name,
            vendor=base.vendor,
            component_type=base.component_type,
            resolved_version=version or "detected (version unknown)",
            versions=[VersionConfidence(
                version=version or "detected",
                confidence=confidence,
                method=ExtractionMethod.STRING_PATTERN,
                evidence=" | ".join(evidence_parts),
            )],
            purl=f"pkg:generic/{base.name.lower().replace(' ', '-')}@{version}" if version else "",
        )

    def _extract_version_from_context(
        self, component_name: str, nearby_strings: list[str], raw_data: bytes
    ) -> str:
        """Try multiple strategies to extract version for a component."""
        # Strategy 1: Look in nearby strings for version patterns
        version = self._find_version_in_strings(nearby_strings, component_name)
        if version:
            return version

        # Strategy 2: Search globally for "ComponentName vX.Y.Z" patterns
        version = self._search_global_version(component_name, raw_data)
        if version:
            return version

        # Strategy 3: Look for version defines (e.g., COMPONENT_VERSION "X.Y.Z")
        version = self._search_version_defines(component_name, raw_data)
        if version:
            return version

        return ""

    def _find_version_in_strings(self, strings: list[str], comp_name: str) -> str:
        """Search nearby strings for version number patterns."""
        version_re = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[-_.]\w+)?)")

        for s in strings:
            # Direct version match in the string
            if comp_name.lower() in s.lower():
                match = version_re.search(s)
                if match:
                    v = match.group(1)
                    if self._is_plausible_version(v):
                        return v

        # Second pass: look for standalone version patterns
        for s in strings:
            if re.match(r"^[Vv]?\d+\.\d+\.\d+", s):
                v = version_re.search(s).group(1)
                if self._is_plausible_version(v):
                    return v

        return ""

    def _search_global_version(self, comp_name: str, data: bytes) -> str:
        """Search entire firmware for component name + version pattern."""
        text = data.decode("ascii", errors="ignore")
        # Try common patterns
        patterns = [
            rf"{re.escape(comp_name)}\s+[Vv]?(\d+\.\d+(?:\.\d+)?)",
            rf"{re.escape(comp_name)}[/\-_](\d+\.\d+(?:\.\d+)?)",
            rf"{re.escape(comp_name)}\s+version\s+(\d+\.\d+(?:\.\d+)?)",
        ]
        for pat in patterns:
            match = re.search(pat, text, re.IGNORECASE)
            if match:
                v = match.group(1)
                if self._is_plausible_version(v):
                    return v
        return ""

    def _search_version_defines(self, comp_name: str, data: bytes) -> str:
        """Search for C-style version defines."""
        text = data.decode("ascii", errors="ignore")
        name_upper = comp_name.upper().replace(" ", "_").replace("-", "_")
        patterns = [
            rf"{name_upper}_VERSION\s+\"(\d+\.\d+(?:\.\d+)?)\"",
            rf"{name_upper}_VERSION_STRING\s+\"(\d+\.\d+(?:\.\d+)?)\"",
            rf"{name_upper}_VER\s+\"(\d+\.\d+(?:\.\d+)?)\"",
            rf"{name_upper}_VERSION_MAJOR\s+(\d+)",
        ]
        for pat in patterns:
            match = re.search(pat, text)
            if match:
                return match.group(1)

        # Try to combine MAJOR.MINOR.PATCH
        major_pat = rf"{name_upper}_VERSION_MAJOR\s+(\d+)"
        minor_pat = rf"{name_upper}_VERSION_MINOR\s+(\d+)"
        patch_pat = rf"{name_upper}_VERSION_PATCH\s+(\d+)"

        major_m = re.search(major_pat, text)
        minor_m = re.search(minor_pat, text)
        if major_m and minor_m:
            patch_m = re.search(patch_pat, text)
            patch = patch_m.group(1) if patch_m else "0"
            return f"{major_m.group(1)}.{minor_m.group(1)}.{patch}"

        return ""

    def _is_plausible_version(self, version: str) -> bool:
        """Check if a version string is plausible (not a date, IP, or protocol number)."""
        parts = version.split(".")
        if len(parts) < 2:
            return False
        try:
            major = int(parts[0])
            if major > 999:  # Likely a date or IP
                return False
            # Reject IEEE 802.x network protocol numbers (e.g., "802.1", "802.11")
            if 800 <= major <= 899:
                return False
            return True
        except ValueError:
            return False


@dataclass
class SignatureEntry:
    pattern: str
    name: str
    vendor: str
    component_type: str


@dataclass
class VersionPatternEntry:
    pattern: str
    name: str
    vendor: str
    component_type: str


class ComponentDatabase:
    """Database of known component signatures and version patterns."""

    def __init__(self):
        self._signatures: list[SignatureEntry] = []
        self._version_patterns: list[VersionPatternEntry] = []
        self._load_builtin()

    def add_signatures(self, entries: list[SignatureEntry]) -> None:
        self._signatures.extend(entries)

    def add_version_patterns(self, entries: list[VersionPatternEntry]) -> None:
        self._version_patterns.extend(entries)

    def get_all_signatures(self) -> list[SignatureEntry]:
        return self._signatures

    def get_all_version_patterns(self) -> list[VersionPatternEntry]:
        return self._version_patterns

    def _load_builtin(self) -> None:
        """Load the massive built-in signature database."""
        self._signatures = _BUILTIN_SIGNATURES.copy()
        self._version_patterns = _BUILTIN_VERSION_PATTERNS.copy()


# =============================================================================
# MASSIVE BUILT-IN SIGNATURE DATABASE
# =============================================================================

_BUILTIN_SIGNATURES: list[SignatureEntry] = [
    # === RTOS Kernels ===
    SignatureEntry("FreeRTOS", "FreeRTOS", "Amazon", "operating-system"),
    SignatureEntry("xTaskCreate", "FreeRTOS", "Amazon", "operating-system"),
    SignatureEntry("vTaskStartScheduler", "FreeRTOS", "Amazon", "operating-system"),
    SignatureEntry("pvPortMalloc", "FreeRTOS", "Amazon", "operating-system"),
    SignatureEntry("vTaskDelay", "FreeRTOS", "Amazon", "operating-system"),
    SignatureEntry("xQueueCreate", "FreeRTOS", "Amazon", "operating-system"),
    SignatureEntry("xSemaphoreCreateMutex", "FreeRTOS", "Amazon", "operating-system"),
    SignatureEntry("xTimerCreate", "FreeRTOS", "Amazon", "operating-system"),
    SignatureEntry("Tmr Svc", "FreeRTOS", "Amazon", "operating-system"),

    SignatureEntry("k_thread_create", "Zephyr RTOS", "Zephyr Project", "operating-system"),
    SignatureEntry("k_sem_init", "Zephyr RTOS", "Zephyr Project", "operating-system"),
    SignatureEntry("k_mutex_init", "Zephyr RTOS", "Zephyr Project", "operating-system"),
    SignatureEntry("z_swap", "Zephyr RTOS", "Zephyr Project", "operating-system"),
    SignatureEntry("__device_dts_ord_", "Zephyr RTOS", "Zephyr Project", "operating-system"),
    SignatureEntry("CONFIG_KERNEL", "Zephyr RTOS", "Zephyr Project", "operating-system"),

    SignatureEntry("rt_thread_create", "RT-Thread", "RT-Thread", "operating-system"),
    SignatureEntry("rt_sem_create", "RT-Thread", "RT-Thread", "operating-system"),
    SignatureEntry("rt_device_register", "RT-Thread", "RT-Thread", "operating-system"),
    SignatureEntry("rt_system_scheduler_start", "RT-Thread", "RT-Thread", "operating-system"),

    SignatureEntry("tx_thread_create", "ThreadX", "Microsoft", "operating-system"),
    SignatureEntry("tx_kernel_enter", "ThreadX", "Microsoft", "operating-system"),
    SignatureEntry("_tx_thread_schedule", "ThreadX", "Microsoft", "operating-system"),

    SignatureEntry("taskSpawn", "VxWorks", "Wind River", "operating-system"),
    SignatureEntry("semBCreate", "VxWorks", "Wind River", "operating-system"),
    SignatureEntry("Wind River", "VxWorks", "Wind River", "operating-system"),

    SignatureEntry("OSTaskCreate", "uC/OS", "Micrium", "operating-system"),
    SignatureEntry("OSInit", "uC/OS", "Micrium", "operating-system"),
    SignatureEntry("OSStart", "uC/OS", "Micrium", "operating-system"),

    SignatureEntry("LOS_TaskCreate", "LiteOS", "Huawei", "operating-system"),
    SignatureEntry("LOS_KernelInit", "LiteOS", "Huawei", "operating-system"),

    SignatureEntry("nxsched_add_readytorun", "NuttX", "Apache", "operating-system"),
    SignatureEntry("nx_start", "NuttX", "Apache", "operating-system"),
    SignatureEntry("nsh>", "NuttX", "Apache", "operating-system"),

    SignatureEntry("esp_idf", "ESP-IDF", "Espressif", "operating-system"),
    SignatureEntry("esp_wifi_init", "ESP-IDF", "Espressif", "operating-system"),
    SignatureEntry("esp_event_loop", "ESP-IDF", "Espressif", "operating-system"),

    # === TLS/Crypto Libraries ===
    SignatureEntry("mbedtls_ssl_init", "mbedTLS", "ARM", "library"),
    SignatureEntry("mbedtls_x509_crt_parse", "mbedTLS", "ARM", "library"),
    SignatureEntry("mbedtls_aes_init", "mbedTLS", "ARM", "library"),
    SignatureEntry("mbedtls_sha256", "mbedTLS", "ARM", "library"),
    SignatureEntry("mbedtls_entropy_init", "mbedTLS", "ARM", "library"),
    SignatureEntry("mbedtls_ctr_drbg_init", "mbedTLS", "ARM", "library"),
    SignatureEntry("mbedtls_pk_init", "mbedTLS", "ARM", "library"),
    SignatureEntry("MBEDTLS_", "mbedTLS", "ARM", "library"),

    SignatureEntry("wolfSSL_Init", "wolfSSL", "wolfSSL Inc", "library"),
    SignatureEntry("wolfSSL_CTX_new", "wolfSSL", "wolfSSL Inc", "library"),
    SignatureEntry("wolfCrypt_Init", "wolfSSL", "wolfSSL Inc", "library"),
    SignatureEntry("wc_AesSetKey", "wolfSSL", "wolfSSL Inc", "library"),
    SignatureEntry("wc_RsaPublicEncrypt", "wolfSSL", "wolfSSL Inc", "library"),

    SignatureEntry("BearSSL", "BearSSL", "BearSSL", "library"),
    SignatureEntry("br_ssl_engine", "BearSSL", "BearSSL", "library"),

    SignatureEntry("OpenSSL", "OpenSSL", "OpenSSL", "library"),
    SignatureEntry("SSL_CTX_new", "OpenSSL", "OpenSSL", "library"),
    SignatureEntry("EVP_EncryptInit", "OpenSSL", "OpenSSL", "library"),

    SignatureEntry("tinycrypt", "TinyCrypt", "Intel", "library"),
    SignatureEntry("tc_sha256_init", "TinyCrypt", "Intel", "library"),
    SignatureEntry("tc_aes_encrypt", "TinyCrypt", "Intel", "library"),

    SignatureEntry("HACL*", "HACL*", "Project Everest", "library"),
    SignatureEntry("Hacl_Chacha20", "HACL*", "Project Everest", "library"),

    SignatureEntry("libsodium", "libsodium", "libsodium", "library"),
    SignatureEntry("crypto_secretbox", "libsodium", "libsodium", "library"),
    SignatureEntry("sodium_init", "libsodium", "libsodium", "library"),

    SignatureEntry("micro-ecc", "micro-ecc", "micro-ecc", "library"),
    SignatureEntry("uECC_sign", "micro-ecc", "micro-ecc", "library"),
    SignatureEntry("uECC_verify", "micro-ecc", "micro-ecc", "library"),

    # === Network Stacks ===
    SignatureEntry("lwIP", "lwIP", "lwIP", "library"),
    SignatureEntry("tcp_new", "lwIP", "lwIP", "library"),
    SignatureEntry("netconn_new", "lwIP", "lwIP", "library"),
    SignatureEntry("pbuf_alloc", "lwIP", "lwIP", "library"),
    SignatureEntry("etharp_output", "lwIP", "lwIP", "library"),
    SignatureEntry("dns_gethostbyname", "lwIP", "lwIP", "library"),
    SignatureEntry("LWIP_", "lwIP", "lwIP", "library"),

    SignatureEntry("uIP", "uIP", "Contiki", "library"),
    SignatureEntry("uip_init", "uIP", "Contiki", "library"),

    SignatureEntry("MQTT", "MQTT", "Eclipse Paho", "library"),
    SignatureEntry("MQTTClient", "MQTT Client", "Eclipse Paho", "library"),
    SignatureEntry("mqtt_connect", "MQTT", "Eclipse Paho", "library"),
    SignatureEntry("MQTTPublish", "MQTT Client", "Eclipse Paho", "library"),

    SignatureEntry("CoAP", "CoAP", "libcoap", "library"),
    SignatureEntry("coap_new_pdu", "libcoap", "libcoap", "library"),
    SignatureEntry("coap_send", "libcoap", "libcoap", "library"),

    SignatureEntry("http_parser", "http-parser", "Node.js", "library"),
    SignatureEntry("llhttp_init", "llhttp", "Node.js", "library"),

    SignatureEntry("picohttpparser", "picohttpparser", "h2o", "library"),

    SignatureEntry("mongoose", "Mongoose", "Cesanta", "library"),
    SignatureEntry("mg_http_listen", "Mongoose", "Cesanta", "library"),

    SignatureEntry("civetweb", "CivetWeb", "CivetWeb", "library"),

    SignatureEntry("libwebsockets", "libwebsockets", "libwebsockets", "library"),
    SignatureEntry("lws_create_context", "libwebsockets", "libwebsockets", "library"),

    SignatureEntry("curl_easy", "libcurl", "curl", "library"),
    SignatureEntry("CURLOPT_", "libcurl", "curl", "library"),

    # === Bluetooth ===
    SignatureEntry("nimble", "NimBLE", "Apache", "library"),
    SignatureEntry("ble_gap_", "NimBLE", "Apache", "library"),
    SignatureEntry("ble_gatt_", "NimBLE", "Apache", "library"),

    SignatureEntry("BTstack", "BTstack", "BlueKitchen", "library"),
    SignatureEntry("btstack_run_loop", "BTstack", "BlueKitchen", "library"),

    SignatureEntry("esp_bt_controller", "ESP-BT", "Espressif", "library"),
    SignatureEntry("esp_ble_gap", "ESP-BLE", "Espressif", "library"),

    # === File Systems ===
    SignatureEntry("FatFs", "FatFs", "ChaN", "library"),
    SignatureEntry("f_open", "FatFs", "ChaN", "library"),
    SignatureEntry("f_mount", "FatFs", "ChaN", "library"),
    SignatureEntry("f_read", "FatFs", "ChaN", "library"),

    SignatureEntry("LittleFS", "LittleFS", "ARM", "library"),
    SignatureEntry("lfs_mount", "LittleFS", "ARM", "library"),
    SignatureEntry("lfs_file_open", "LittleFS", "ARM", "library"),
    SignatureEntry("littlefs", "LittleFS", "ARM", "library"),

    SignatureEntry("SPIFFS", "SPIFFS", "SPIFFS", "library"),
    SignatureEntry("spiffs_mount", "SPIFFS", "SPIFFS", "library"),

    SignatureEntry("JFFS2", "JFFS2", "Linux", "library"),

    SignatureEntry("yaffs", "YAFFS", "Aleph One", "library"),
    SignatureEntry("yaffs_mount", "YAFFS", "Aleph One", "library"),

    SignatureEntry("SquashFS", "SquashFS", "SquashFS", "library"),
    SignatureEntry("hsqs", "SquashFS", "SquashFS", "library"),

    SignatureEntry("CramFS", "CramFS", "Linux", "library"),

    SignatureEntry("nvs_flash_init", "NVS Flash", "Espressif", "library"),

    # === USB ===
    SignatureEntry("TinyUSB", "TinyUSB", "hathach", "library"),
    SignatureEntry("tud_", "TinyUSB", "hathach", "library"),
    SignatureEntry("tusb_init", "TinyUSB", "hathach", "library"),

    SignatureEntry("CherryUSB", "CherryUSB", "CherryUSB", "library"),
    SignatureEntry("usbd_initialize", "CherryUSB", "CherryUSB", "library"),

    SignatureEntry("USBX", "USBX", "Microsoft", "library"),
    SignatureEntry("ux_device_", "USBX", "Microsoft", "library"),

    # === Serialization / Protocol Buffers ===
    SignatureEntry("cJSON", "cJSON", "DaveGamble", "library"),
    SignatureEntry("cJSON_Parse", "cJSON", "DaveGamble", "library"),
    SignatureEntry("cJSON_CreateObject", "cJSON", "DaveGamble", "library"),

    SignatureEntry("jansson", "Jansson", "Jansson", "library"),
    SignatureEntry("json_loads", "Jansson", "Jansson", "library"),

    SignatureEntry("jsmn", "JSMN", "Serge Zaitsev", "library"),
    SignatureEntry("jsmn_parse", "JSMN", "Serge Zaitsev", "library"),

    SignatureEntry("nanopb", "nanopb", "nanopb", "library"),
    SignatureEntry("pb_encode", "nanopb", "nanopb", "library"),
    SignatureEntry("pb_decode", "nanopb", "nanopb", "library"),

    SignatureEntry("protobuf-c", "protobuf-c", "protobuf-c", "library"),

    SignatureEntry("MessagePack", "MessagePack", "MessagePack", "library"),
    SignatureEntry("msgpack_pack", "MessagePack", "MessagePack", "library"),

    SignatureEntry("CBOR", "TinyCBOR", "Intel", "library"),
    SignatureEntry("cbor_encoder", "TinyCBOR", "Intel", "library"),

    SignatureEntry("flatbuffers", "FlatBuffers", "Google", "library"),

    # === Compression ===
    SignatureEntry("miniz", "miniz", "richgel999", "library"),
    SignatureEntry("mz_inflate", "miniz", "richgel999", "library"),

    SignatureEntry("zlib", "zlib", "zlib", "library"),
    SignatureEntry("inflate", "zlib", "zlib", "library"),
    SignatureEntry("deflate", "zlib", "zlib", "library"),

    SignatureEntry("lz4", "LZ4", "Yann Collet", "library"),
    SignatureEntry("LZ4_decompress", "LZ4", "Yann Collet", "library"),

    SignatureEntry("snappy", "Snappy", "Google", "library"),
    SignatureEntry("heatshrink", "Heatshrink", "Heatshrink", "library"),

    SignatureEntry("uzlib", "uzlib", "pfalcon", "library"),

    # === Logging / Debug ===
    SignatureEntry("SEGGER", "SEGGER RTT", "SEGGER", "library"),
    SignatureEntry("SEGGER_RTT", "SEGGER RTT", "SEGGER", "library"),

    SignatureEntry("log_module_register", "Zephyr Logging", "Zephyr Project", "library"),

    SignatureEntry("NRF_LOG", "nRF Logger", "Nordic", "library"),

    SignatureEntry("ESP_LOG", "ESP-IDF Logging", "Espressif", "library"),
    SignatureEntry("esp_log_write", "ESP-IDF Logging", "Espressif", "library"),

    # === Bootloaders ===
    SignatureEntry("U-Boot", "U-Boot", "DENX", "firmware"),
    SignatureEntry("MCUboot", "MCUboot", "MCUboot", "firmware"),
    SignatureEntry("mcuboot", "MCUboot", "MCUboot", "firmware"),
    SignatureEntry("MCUBOOT_", "MCUboot", "MCUboot", "firmware"),

    SignatureEntry("SecureBoot", "Secure Boot", "Generic", "firmware"),

    # === HAL / Drivers ===
    SignatureEntry("HAL_Init", "STM32 HAL", "STMicroelectronics", "library"),
    SignatureEntry("HAL_GPIO_", "STM32 HAL", "STMicroelectronics", "library"),
    SignatureEntry("HAL_UART_", "STM32 HAL", "STMicroelectronics", "library"),
    SignatureEntry("HAL_SPI_", "STM32 HAL", "STMicroelectronics", "library"),
    SignatureEntry("HAL_I2C_", "STM32 HAL", "STMicroelectronics", "library"),
    SignatureEntry("HAL_TIM_", "STM32 HAL", "STMicroelectronics", "library"),
    SignatureEntry("__HAL_RCC", "STM32 HAL", "STMicroelectronics", "library"),
    SignatureEntry("STM32", "STM32 HAL", "STMicroelectronics", "library"),

    SignatureEntry("nrf_drv_", "nRF SDK", "Nordic Semiconductor", "library"),
    SignatureEntry("nrfx_", "nRFX Drivers", "Nordic Semiconductor", "library"),
    SignatureEntry("NRF_", "nRF SDK", "Nordic Semiconductor", "library"),
    SignatureEntry("nrf_gpio_", "nRF SDK", "Nordic Semiconductor", "library"),

    SignatureEntry("CMSIS", "CMSIS", "ARM", "library"),
    SignatureEntry("__CMSIS_", "CMSIS", "ARM", "library"),
    SignatureEntry("SystemCoreClock", "CMSIS", "ARM", "library"),
    SignatureEntry("NVIC_SetPriority", "CMSIS", "ARM", "library"),

    SignatureEntry("driverlib", "TI DriverLib", "Texas Instruments", "library"),
    SignatureEntry("MAP_GPIO", "TI DriverLib", "Texas Instruments", "library"),

    SignatureEntry("fsl_", "NXP SDK", "NXP", "library"),
    SignatureEntry("BOARD_Init", "NXP SDK", "NXP", "library"),

    SignatureEntry("cyhal_", "Cypress HAL", "Infineon", "library"),
    SignatureEntry("cy_", "Cypress PDL", "Infineon", "library"),

    SignatureEntry("R_", "Renesas FSP", "Renesas", "library"),
    SignatureEntry("BSP_IO_", "Renesas FSP", "Renesas", "library"),

    SignatureEntry("XMC_", "XMC Lib", "Infineon", "library"),

    SignatureEntry("LL_GPIO", "STM32 LL", "STMicroelectronics", "library"),
    SignatureEntry("LL_USART", "STM32 LL", "STMicroelectronics", "library"),

    # === RTOS Middleware ===
    SignatureEntry("FreeRTOS+TCP", "FreeRTOS+TCP", "Amazon", "library"),
    SignatureEntry("FreeRTOS_Socket", "FreeRTOS+TCP", "Amazon", "library"),
    SignatureEntry("FreeRTOS+FAT", "FreeRTOS+FAT", "Amazon", "library"),
    SignatureEntry("FreeRTOS+CLI", "FreeRTOS+CLI", "Amazon", "library"),

    SignatureEntry("NetX", "NetX Duo", "Microsoft", "library"),
    SignatureEntry("nx_tcp_", "NetX Duo", "Microsoft", "library"),
    SignatureEntry("FileX", "FileX", "Microsoft", "library"),
    SignatureEntry("fx_file_", "FileX", "Microsoft", "library"),
    SignatureEntry("GUIX", "GUIX", "Microsoft", "library"),
    SignatureEntry("gx_widget", "GUIX", "Microsoft", "library"),
    SignatureEntry("LevelX", "LevelX", "Microsoft", "library"),

    # === Graphics ===
    SignatureEntry("LVGL", "LVGL", "LVGL", "library"),
    SignatureEntry("lv_obj_create", "LVGL", "LVGL", "library"),
    SignatureEntry("lv_disp_", "LVGL", "LVGL", "library"),
    SignatureEntry("lv_label_", "LVGL", "LVGL", "library"),

    SignatureEntry("emWin", "emWin", "SEGGER", "library"),
    SignatureEntry("GUI_Init", "emWin", "SEGGER", "library"),

    SignatureEntry("TouchGFX", "TouchGFX", "STMicroelectronics", "library"),

    SignatureEntry("u8g2", "u8g2", "olikraus", "library"),
    SignatureEntry("u8g2_Setup", "u8g2", "olikraus", "library"),

    # === Sensor / DSP ===
    SignatureEntry("arm_fir_", "CMSIS-DSP", "ARM", "library"),
    SignatureEntry("arm_cfft_", "CMSIS-DSP", "ARM", "library"),
    SignatureEntry("arm_mat_", "CMSIS-DSP", "ARM", "library"),
    SignatureEntry("arm_pid_", "CMSIS-DSP", "ARM", "library"),

    SignatureEntry("arm_nn_", "CMSIS-NN", "ARM", "library"),
    SignatureEntry("arm_convolve", "CMSIS-NN", "ARM", "library"),

    SignatureEntry("TensorFlow Lite", "TFLite Micro", "Google", "library"),
    SignatureEntry("tflite::", "TFLite Micro", "Google", "library"),

    # === OTA / Update ===
    SignatureEntry("aws_iot_", "AWS IoT SDK", "Amazon", "library"),
    SignatureEntry("AWS_IOT_", "AWS IoT SDK", "Amazon", "library"),

    SignatureEntry("az_iot_", "Azure IoT SDK", "Microsoft", "library"),
    SignatureEntry("AZURE_IOT", "Azure IoT SDK", "Microsoft", "library"),

    SignatureEntry("ota_", "OTA Update", "Generic", "library"),
    SignatureEntry("OTA_", "OTA Update", "Generic", "library"),

    SignatureEntry("golioth", "Golioth SDK", "Golioth", "library"),

    # === Testing ===
    SignatureEntry("Unity", "Unity Test", "ThrowTheSwitch", "library"),
    SignatureEntry("TEST_ASSERT", "Unity Test", "ThrowTheSwitch", "library"),

    SignatureEntry("cmocka", "CMocka", "CMocka", "library"),

    # === Vendor Specific ===
    SignatureEntry("QUALCOMM", "Qualcomm BSP", "Qualcomm", "firmware"),
    SignatureEntry("QC_IMAGE_VERSION", "Qualcomm BSP", "Qualcomm", "firmware"),

    SignatureEntry("MediaTek", "MediaTek BSP", "MediaTek", "firmware"),
    SignatureEntry("MTK_FW", "MediaTek BSP", "MediaTek", "firmware"),

    SignatureEntry("Realtek", "Realtek SDK", "Realtek", "firmware"),
    SignatureEntry("rtl_", "Realtek SDK", "Realtek", "firmware"),

    SignatureEntry("Broadcom", "Broadcom BSP", "Broadcom", "firmware"),
    SignatureEntry("Marvell", "Marvell BSP", "Marvell", "firmware"),

    SignatureEntry("silicon_labs", "Silicon Labs SDK", "Silicon Labs", "library"),
    SignatureEntry("sl_", "Silicon Labs SDK", "Silicon Labs", "library"),

    SignatureEntry("ATMEL", "Atmel ASF", "Microchip", "library"),
    SignatureEntry("atmel_start", "Atmel START", "Microchip", "library"),

    SignatureEntry("Microchip", "Microchip Harmony", "Microchip", "library"),
    SignatureEntry("MPLAB", "MPLAB Harmony", "Microchip", "library"),
    SignatureEntry("DRV_", "Microchip Harmony", "Microchip", "library"),

    # === Power Management ===
    SignatureEntry("pm_device_", "Zephyr PM", "Zephyr Project", "library"),
    SignatureEntry("esp_sleep_", "ESP Sleep", "Espressif", "library"),
    SignatureEntry("HAL_PWR_", "STM32 Power", "STMicroelectronics", "library"),

    # === Shell / CLI ===
    SignatureEntry("shell_print", "Zephyr Shell", "Zephyr Project", "library"),
    SignatureEntry("finsh", "FinSH", "RT-Thread", "library"),
    SignatureEntry("msh>", "MSH Shell", "RT-Thread", "library"),

    # === Misc Libraries ===
    SignatureEntry("printf", "printf", "mpaland", "library"),
    SignatureEntry("newlib", "Newlib", "Red Hat", "library"),
    SignatureEntry("picolibc", "picolibc", "picolibc", "library"),
    SignatureEntry("_sbrk", "Newlib", "Red Hat", "library"),

    SignatureEntry("FreeModbus", "FreeModbus", "FreeModbus", "library"),
    SignatureEntry("eMBInit", "FreeModbus", "FreeModbus", "library"),

    SignatureEntry("CANopen", "CANopenNode", "CANopenNode", "library"),
    SignatureEntry("CO_CANmodule", "CANopenNode", "CANopenNode", "library"),


    SignatureEntry("i2c_master", "I2C Driver", "Generic", "library"),
    SignatureEntry("spi_master", "SPI Driver", "Generic", "library"),

    SignatureEntry("OpenThread", "OpenThread", "Google", "library"),
    SignatureEntry("otThreadStart", "OpenThread", "Google", "library"),

    SignatureEntry("Matter", "Matter", "CSA", "library"),
    SignatureEntry("chip::", "Matter", "CSA", "library"),

    # Linux Kernel
    SignatureEntry("Linux version", "Linux Kernel", "Linux", "operating-system"),
    SignatureEntry("linux_banner", "Linux Kernel", "Linux", "operating-system"),
    SignatureEntry("vmlinux", "Linux Kernel", "Linux", "operating-system"),
    SignatureEntry("init_task", "Linux Kernel", "Linux", "operating-system"),
    SignatureEntry("swapper/0", "Linux Kernel", "Linux", "operating-system"),
    SignatureEntry("kernel_init", "Linux Kernel", "Linux", "operating-system"),

    # OpenWrt
    SignatureEntry("OpenWrt", "OpenWrt", "OpenWrt", "operating-system"),
    SignatureEntry("openwrt", "OpenWrt", "OpenWrt", "operating-system"),
    SignatureEntry("LEDE", "OpenWrt", "OpenWrt", "operating-system"),

    # BusyBox
    SignatureEntry("BusyBox", "BusyBox", "BusyBox", "library"),
    SignatureEntry("busybox", "BusyBox", "BusyBox", "library"),

    # uClibc / musl
    SignatureEntry("uClibc", "uClibc", "uClibc", "library"),
    SignatureEntry("musl libc", "musl", "musl", "library"),

    # iptables/netfilter
    SignatureEntry("iptables", "iptables", "netfilter", "library"),
    SignatureEntry("nf_conntrack", "Netfilter", "Linux", "library"),

    # dropbear SSH
    SignatureEntry("Dropbear", "Dropbear", "Dropbear", "library"),
    SignatureEntry("dropbear", "Dropbear", "Dropbear", "library"),

    # dnsmasq
    SignatureEntry("dnsmasq", "dnsmasq", "dnsmasq", "library"),

    # OpenSSH
    SignatureEntry("OpenSSH", "OpenSSH", "OpenBSD", "library"),
]


_BUILTIN_VERSION_PATTERNS: list[VersionPatternEntry] = [
    # RTOS
    VersionPatternEntry(r"FreeRTOS\s+[Vv](\d+\.\d+\.\d+)", "FreeRTOS", "Amazon", "operating-system"),
    VersionPatternEntry(r"FreeRTOS\s+[Vv](\d{6}\.\d{2})", "FreeRTOS", "Amazon", "operating-system"),
    VersionPatternEntry(r"Zephyr\s+[Vv]?(\d+\.\d+\.\d+)", "Zephyr RTOS", "Zephyr Project", "operating-system"),
    VersionPatternEntry(r"zephyr-v(\d+\.\d+\.\d+)", "Zephyr RTOS", "Zephyr Project", "operating-system"),
    VersionPatternEntry(r"RT-Thread\s+[Vv]?(\d+\.\d+\.\d+)", "RT-Thread", "RT-Thread", "operating-system"),
    VersionPatternEntry(r"ESP-IDF\s+[Vv]?(\d+\.\d+(?:\.\d+)?)", "ESP-IDF", "Espressif", "operating-system"),
    VersionPatternEntry(r"esp-idf/v(\d+\.\d+(?:\.\d+)?)", "ESP-IDF", "Espressif", "operating-system"),
    VersionPatternEntry(r"VxWorks\s+(\d+\.\d+(?:\.\d+)?)", "VxWorks", "Wind River", "operating-system"),
    VersionPatternEntry(r"ThreadX\s+[Vv]?(\d+\.\d+(?:\.\d+)?)", "ThreadX", "Microsoft", "operating-system"),
    VersionPatternEntry(r"NuttX\s+(\d+\.\d+\.\d+)", "NuttX", "Apache", "operating-system"),
    VersionPatternEntry(r"LiteOS\s+[Vv](\d+\.\d+(?:\.\d+)?)", "LiteOS", "Huawei", "operating-system"),
    VersionPatternEntry(r"uC/OS-I{1,3}\s+[Vv]?(\d+\.\d+\.\d+)", "uC/OS", "Micrium", "operating-system"),

    # Crypto/TLS
    VersionPatternEntry(r"mbed\s*TLS\s+(\d+\.\d+\.\d+)", "mbedTLS", "ARM", "library"),
    VersionPatternEntry(r"mbedtls[/-](\d+\.\d+\.\d+)", "mbedTLS", "ARM", "library"),
    VersionPatternEntry(r"MBEDTLS_VERSION_STRING\s+\"(\d+\.\d+\.\d+)\"", "mbedTLS", "ARM", "library"),
    VersionPatternEntry(r"wolfSSL\s+(\d+\.\d+\.\d+)", "wolfSSL", "wolfSSL Inc", "library"),
    VersionPatternEntry(r"BearSSL\s+(\d+\.\d+)", "BearSSL", "BearSSL", "library"),
    VersionPatternEntry(r"OpenSSL\s+(\d+\.\d+\.\d+)", "OpenSSL", "OpenSSL", "library"),

    # Network
    VersionPatternEntry(r"lwIP\s+(\d+\.\d+\.\d+)", "lwIP", "lwIP", "library"),
    VersionPatternEntry(r"LWIP_VERSION_STRING\s+\"(\d+\.\d+\.\d+)\"", "lwIP", "lwIP", "library"),
    VersionPatternEntry(r"lwip-(\d+\.\d+\.\d+)", "lwIP", "lwIP", "library"),
    VersionPatternEntry(r"libcurl[/-](\d+\.\d+\.\d+)", "libcurl", "curl", "library"),
    VersionPatternEntry(r"Mongoose\s+[Vv]?(\d+\.\d+\.\d+)", "Mongoose", "Cesanta", "library"),

    # File Systems
    VersionPatternEntry(r"FatFs\s+[Rr]?(\d+\.\d+\w?)", "FatFs", "ChaN", "library"),
    VersionPatternEntry(r"LittleFS\s+[Vv]?(\d+\.\d+\.\d+)", "LittleFS", "ARM", "library"),
    VersionPatternEntry(r"littlefs[/-]v?(\d+\.\d+\.\d+)", "LittleFS", "ARM", "library"),

    # Serialization
    VersionPatternEntry(r"cJSON\s+(\d+\.\d+\.\d+)", "cJSON", "DaveGamble", "library"),
    VersionPatternEntry(r"nanopb\s+(\d+\.\d+\.\d+)", "nanopb", "nanopb", "library"),
    VersionPatternEntry(r"protobuf-c\s+(\d+\.\d+\.\d+)", "protobuf-c", "protobuf-c", "library"),

    # Graphics
    VersionPatternEntry(r"LVGL\s+[Vv]?(\d+\.\d+\.\d+)", "LVGL", "LVGL", "library"),
    VersionPatternEntry(r"lvgl-(\d+\.\d+\.\d+)", "LVGL", "LVGL", "library"),

    # Bootloader
    VersionPatternEntry(r"U-Boot\s+(\d{4}\.\d{2})", "U-Boot", "DENX", "firmware"),
    VersionPatternEntry(r"MCUboot\s+[Vv]?(\d+\.\d+\.\d+)", "MCUboot", "MCUboot", "firmware"),

    # USB
    VersionPatternEntry(r"TinyUSB\s+(\d+\.\d+\.\d+)", "TinyUSB", "hathach", "library"),

    # BLE
    VersionPatternEntry(r"NimBLE\s+(\d+\.\d+\.\d+)", "NimBLE", "Apache", "library"),

    # HAL/SDK
    VersionPatternEntry(r"STM32Cube\s+[Vv]?(\d+\.\d+\.\d+)", "STM32Cube", "STMicroelectronics", "library"),
    VersionPatternEntry(r"nRF5\s+SDK\s+[Vv]?(\d+\.\d+\.\d+)", "nRF5 SDK", "Nordic Semiconductor", "library"),

    # Compression
    VersionPatternEntry(r"zlib\s+(\d+\.\d+\.\d+)", "zlib", "zlib", "library"),
    VersionPatternEntry(r"LZ4\s+[Vv]?(\d+\.\d+\.\d+)", "LZ4", "Yann Collet", "library"),
    VersionPatternEntry(r"miniz\s+(\d+\.\d+\.\d+)", "miniz", "richgel999", "library"),

    # IoT SDKs
    VersionPatternEntry(r"aws-iot-device-sdk[/-]v?(\d+\.\d+\.\d+)", "AWS IoT SDK", "Amazon", "library"),
    VersionPatternEntry(r"azure-iot-sdk[/-](\d+\.\d+\.\d+)", "Azure IoT SDK", "Microsoft", "library"),

    # Misc
    VersionPatternEntry(r"SEGGER\s+RTT\s+[Vv]?(\d+\.\d+\w?)", "SEGGER RTT", "SEGGER", "library"),
    VersionPatternEntry(r"OpenThread[/-](\d+\.\d+\.\d+)", "OpenThread", "Google", "library"),
    VersionPatternEntry(r"Newlib\s+(\d+\.\d+\.\d+)", "Newlib", "Red Hat", "library"),
    VersionPatternEntry(r"picolibc\s+(\d+\.\d+(?:\.\d+)?)", "picolibc", "picolibc", "library"),
    VersionPatternEntry(r"CMSIS\s+[Vv]?(\d+\.\d+\.\d+)", "CMSIS", "ARM", "library"),

    # Linux / OpenWrt
    VersionPatternEntry(r"Linux version (\d+\.\d+\.\d+)", "Linux Kernel", "Linux", "operating-system"),
    VersionPatternEntry(r"OpenWrt\s+(\d+\.\d+\.\d+)", "OpenWrt", "OpenWrt", "operating-system"),
    VersionPatternEntry(r"BusyBox\s+v(\d+\.\d+\.\d+)", "BusyBox", "BusyBox", "library"),
    VersionPatternEntry(r"Dropbear\s+v?(\d+\.\d+)", "Dropbear", "Dropbear", "library"),
    VersionPatternEntry(r"dnsmasq-(\d+\.\d+)", "dnsmasq", "dnsmasq", "library"),
    VersionPatternEntry(r"OpenSSH[_\s](\d+\.\d+)", "OpenSSH", "OpenBSD", "library"),
]
