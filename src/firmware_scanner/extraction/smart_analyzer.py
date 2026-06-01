"""Smart section analyzer - dispatches analysis based on file type.

After unpacking firmware (ZIP/APK/IMG), each section is a distinct file type.
This module routes each section to the appropriate sub-analyzer rather than
applying one-size-fits-all raw byte pattern matching.
"""

import gzip
import json
import lzma

# Suppress lief's verbose warnings about malformed/truncated ELFs
try:
    import lief
    lief.logging.disable()
except ImportError:
    pass
import re
import struct
from pathlib import Path
from typing import Callable

from .models import Component, VersionConfidence, ExtractionMethod
from .extractors.symbol_table import SYMBOL_COMPONENT_MAP


# =============================================================================
# DEX Package -> Component mapping
# =============================================================================

DEX_PACKAGE_MAP: dict[str, tuple[str, str, str]] = {
    # (package prefix): (component_name, vendor, version_hint)
    "com/squareup/okhttp3": ("OkHttp", "Square", "3.x"),
    "com/squareup/retrofit2": ("Retrofit", "Square", "2.x"),
    "com/google/gson": ("Gson", "Google", ""),
    "io/reactivex/rxjava3": ("RxJava", "ReactiveX", "3.x"),
    "io/reactivex/rxjava2": ("RxJava", "ReactiveX", "2.x"),
    "com/bumptech/glide": ("Glide", "Bump Technologies", ""),
    "com/squareup/picasso": ("Picasso", "Square", ""),
    "org/apache/http": ("Apache HttpClient", "Apache", ""),
    "com/fasterxml/jackson": ("Jackson", "FasterXML", ""),
    "org/json": ("org.json", "JSON.org", ""),
    "com/google/android/material": ("Material Components", "Google", ""),
    "androidx/": ("AndroidX", "Google", ""),
    "kotlin/": ("Kotlin Stdlib", "JetBrains", ""),
    "kotlinx/coroutines": ("Kotlin Coroutines", "JetBrains", ""),
    "com/google/protobuf": ("Protocol Buffers", "Google", ""),
    "org/bouncycastle": ("Bouncy Castle", "Legion of the Bouncy Castle", ""),
    "com/google/firebase": ("Firebase", "Google", ""),
    "io/netty": ("Netty", "Netty Project", ""),
    "org/slf4j": ("SLF4J", "QOS.ch", ""),
    "ch/qos/logback": ("Logback", "QOS.ch", ""),
    "com/google/dagger": ("Dagger", "Google", ""),
    "io/ktor": ("Ktor", "JetBrains", ""),
    "org/koin": ("Koin", "Koin", ""),
    "com/jakewharton": ("Jake Wharton Libraries", "Jake Wharton", ""),
    "org/conscrypt": ("Conscrypt", "Google", ""),
    "io/grpc": ("gRPC", "Google", ""),
    "com/android/volley": ("Volley", "Google", ""),
    "org/eclipse/paho": ("Eclipse Paho MQTT", "Eclipse", ""),
    "com/github/bumptech/glide": ("Glide", "Bump Technologies", ""),
    "org/greenrobot/eventbus": ("EventBus", "greenrobot", ""),
    "com/squareup/moshi": ("Moshi", "Square", ""),
    "com/squareup/leakcanary": ("LeakCanary", "Square", ""),
    "io/realm": ("Realm", "MongoDB", ""),
    "com/facebook/react": ("React Native", "Meta", ""),
    "io/flutter": ("Flutter Engine", "Google", ""),
}

# Sorted by specificity (longer prefixes first) to avoid early matching on short prefixes
_DEX_PACKAGE_PREFIXES_SORTED = sorted(DEX_PACKAGE_MAP.keys(), key=len, reverse=True)


# =============================================================================
# Config file dependency patterns
# =============================================================================

# Gradle dependency pattern: implementation 'group:artifact:version'
_GRADLE_DEP_RE = re.compile(
    r"""(?:implementation|api|compile|classpath|runtimeOnly|compileOnly|testImplementation)\s*"""
    r"""[\('\"]([^:'"]+):([^:'"]+):([^'"]+)[\)'\"]""",
    re.MULTILINE,
)

# package.json dependency entries: "name": "^1.2.3"
_NPM_DEP_RE = re.compile(
    r'"([^"@][^"]*)":\s*"[\^~>=<]*(\d+\.\d+(?:\.\d+)?[^"]*)"'
)

# Maven/POM XML: <artifactId>...</artifactId> with <version>
_MAVEN_ARTIFACT_RE = re.compile(
    r"<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>", re.DOTALL
)

# YAML dependency pattern for manifest.yml / pubspec.yaml etc.
_YAML_DEP_RE = re.compile(
    r"^\s*-?\s*([a-zA-Z][\w\-\.]+):\s*[\^~>=<]*(\d+\.\d+(?:\.\d+)?)", re.MULTILINE
)


# =============================================================================
# Source file patterns
# =============================================================================

_INCLUDE_RE = re.compile(r'#include\s*[<"]([^>"]+)[>"]')
_DEFINE_VERSION_RE = re.compile(
    r'#define\s+(\w+(?:_VERSION|_VER|_RELEASE)\w*)\s+"?(\d+\.\d+(?:\.\d+)?)"?'
)
_VERSION_CONST_RE = re.compile(
    r'(?:const\s+)?(?:char|string)\s+\*?\s*\w*version\w*\s*=\s*"(\d+\.\d+(?:\.\d+)?)"',
    re.IGNORECASE,
)

# Include -> component mapping (common embedded library headers)
_INCLUDE_COMPONENT_MAP: dict[str, tuple[str, str]] = {
    "FreeRTOS.h": ("FreeRTOS", "Amazon"),
    "freertos/FreeRTOS.h": ("FreeRTOS", "Amazon"),
    "task.h": ("FreeRTOS", "Amazon"),
    "zephyr/kernel.h": ("Zephyr RTOS", "Zephyr Project"),
    "zephyr.h": ("Zephyr RTOS", "Zephyr Project"),
    "rtthread.h": ("RT-Thread", "RT-Thread"),
    "lwip/tcp.h": ("lwIP", "lwIP"),
    "lwip/ip.h": ("lwIP", "lwIP"),
    "lwip/netconn.h": ("lwIP", "lwIP"),
    "mbedtls/ssl.h": ("mbedTLS", "ARM"),
    "mbedtls/aes.h": ("mbedTLS", "ARM"),
    "wolfssl/ssl.h": ("wolfSSL", "wolfSSL Inc"),
    "openssl/ssl.h": ("OpenSSL", "OpenSSL"),
    "cJSON.h": ("cJSON", "DaveGamble"),
    "lv_conf.h": ("LVGL", "LVGL"),
    "lvgl.h": ("LVGL", "LVGL"),
    "fatfs.h": ("FatFs", "ChaN"),
    "ff.h": ("FatFs", "ChaN"),
    "lfs.h": ("LittleFS", "ARM"),
    "tusb.h": ("TinyUSB", "hathach"),
    "nanopb/pb.h": ("nanopb", "nanopb"),
    "pb_encode.h": ("nanopb", "nanopb"),
    "stm32f4xx_hal.h": ("STM32 HAL", "STMicroelectronics"),
    "stm32f1xx_hal.h": ("STM32 HAL", "STMicroelectronics"),
    "stm32f7xx_hal.h": ("STM32 HAL", "STMicroelectronics"),
    "stm32h7xx_hal.h": ("STM32 HAL", "STMicroelectronics"),
    "nrf.h": ("nRF SDK", "Nordic Semiconductor"),
    "nrfx.h": ("nRFX Drivers", "Nordic Semiconductor"),
    "driver/gpio.h": ("ESP-IDF", "Espressif"),
    "esp_wifi.h": ("ESP-IDF", "Espressif"),
    "cmsis_os.h": ("CMSIS", "ARM"),
    "core_cm4.h": ("CMSIS", "ARM"),
    "core_cm3.h": ("CMSIS", "ARM"),
    "arm_math.h": ("CMSIS-DSP", "ARM"),
    "tensorflow/lite/micro/micro_interpreter.h": ("TFLite Micro", "Google"),
}


# =============================================================================
# Text file version patterns
# =============================================================================

_TEXT_VERSION_PATTERNS = [
    # Changelog headers: ## 3.4.0, ## [1.2.3], ## v2.0.0
    re.compile(r"^##\s+\[?[Vv]?(\d+\.\d+(?:\.\d+)?)\]?", re.MULTILINE),
    # Version: 1.2.3
    re.compile(r"^[Vv]ersion:?\s*[Vv]?(\d+\.\d+(?:\.\d+)?)", re.MULTILINE),
    # v1.2.3 at line start
    re.compile(r"^[Vv](\d+\.\d+\.\d+)", re.MULTILINE),
    # Release X.Y.Z
    re.compile(r"[Rr]elease\s+[Vv]?(\d+\.\d+(?:\.\d+)?)", re.MULTILINE),
]


# =============================================================================
# SmartSectionAnalyzer
# =============================================================================

class SmartSectionAnalyzer:
    """Analyzes unpacked sections using type-appropriate methods.

    After firmware unpacking, each FirmwareSection carries a `name` (the filename
    from ZIP/APK extraction) and `data` (raw bytes). This class examines both to
    dispatch to the correct sub-analyzer, yielding higher-confidence Component
    detections than raw byte scanning alone.
    """

    def analyze_section(self, name: str, data: bytes) -> list[Component]:
        """Route to appropriate analyzer based on section name/content.

        Args:
            name: Original filename (e.g., "lib/arm64-v8a/libnative.so")
            data: Raw section bytes

        Returns:
            List of Component objects detected in this section.
        """
        components: list[Component] = []
        lower_name = name.lower()

        # ELF/SO files - extract symbols
        if data[:4] == b'\x7fELF' or lower_name.endswith('.so'):
            components.extend(self._analyze_elf(name, data))

        # DEX files - parse string pool
        elif lower_name.endswith('.dex') or data[:4] == b'dex\n':
            components.extend(self._analyze_dex(name, data))

        # Android build.prop / default.prop
        elif 'build.prop' in lower_name or 'default.prop' in lower_name:
            components.extend(self._analyze_build_prop(name, data))

        # Compressed data - decompress then recurse
        elif data[:2] == b'\x1f\x8b':  # gzip magic
            components.extend(self._analyze_compressed(name, data, 'gzip'))
        elif data[:6] == b'\xfd7zXZ\x00':  # xz magic
            components.extend(self._analyze_compressed(name, data, 'xz'))

        # Config/manifest files
        elif lower_name.endswith(('.yml', '.yaml', '.json', '.xml', '.properties', '.gradle')):
            components.extend(self._analyze_config(name, data))

        # Source/header files
        elif lower_name.endswith(('.h', '.c', '.cpp', '.cmake')):
            components.extend(self._analyze_source(name, data))

        # Text files (changelog, version, readme)
        elif (
            lower_name.endswith(('.txt', '.md', '.rst'))
            or 'version' in lower_name
            or 'history' in lower_name
            or 'changelog' in lower_name
        ):
            components.extend(self._analyze_text_file(name, data))

        return components

    # =========================================================================
    # ELF / Shared Object analysis
    # =========================================================================

    def _analyze_elf(self, name: str, data: bytes) -> list[Component]:
        """Parse ELF symbol table and match against known library function databases."""
        try:
            import lief
        except ImportError:
            # Fallback: do raw string scan for known symbol names
            return self._analyze_elf_fallback(name, data)

        try:
            binary = lief.parse(list(data))
        except Exception:
            return self._analyze_elf_fallback(name, data)

        if binary is None:
            return self._analyze_elf_fallback(name, data)

        # Collect all symbol names
        symbols: list[str] = []
        if hasattr(binary, "symbols"):
            symbols = [s.name for s in binary.symbols if s.name]
        if hasattr(binary, "static_symbols"):
            symbols.extend(s.name for s in binary.static_symbols if s.name)
        if hasattr(binary, "dynamic_symbols"):
            symbols.extend(s.name for s in binary.dynamic_symbols if s.name)

        return self._match_elf_symbols(symbols, name)

    def _analyze_elf_fallback(self, name: str, data: bytes) -> list[Component]:
        """Fallback ELF analysis when lief is not available - scan for symbol strings."""
        found_symbols: list[str] = []
        for symbol in SYMBOL_COMPONENT_MAP:
            if symbol.encode("ascii") in data:
                found_symbols.append(symbol)
        return self._match_elf_symbols(found_symbols, name)

    def _match_elf_symbols(self, symbols: list[str], section_name: str) -> list[Component]:
        """Match symbol names against SYMBOL_COMPONENT_MAP and return Components."""
        components: dict[str, Component] = {}
        symbol_evidence: dict[str, list[str]] = {}

        for sym in symbols:
            if sym in SYMBOL_COMPONENT_MAP:
                comp_name, vendor, comp_type = SYMBOL_COMPONENT_MAP[sym]
                key = comp_name.lower()

                if key not in components:
                    components[key] = Component(
                        name=comp_name,
                        vendor=vendor,
                        component_type=comp_type,
                    )
                    symbol_evidence[key] = []

                symbol_evidence[key].append(sym)

        for key, comp in components.items():
            evidence = symbol_evidence[key]
            confidence = min(0.4 + len(evidence) * 0.12, 0.95)
            comp.versions.append(
                VersionConfidence(
                    version="detected",
                    confidence=confidence,
                    method=ExtractionMethod.SYMBOL_TABLE,
                    evidence=f"ELF symbols in {section_name}: {', '.join(evidence[:5])}",
                )
            )

        return list(components.values())

    # =========================================================================
    # DEX file analysis
    # =========================================================================

    def _analyze_dex(self, name: str, data: bytes) -> list[Component]:
        """Parse DEX string pool and match package names to known libraries.

        DEX file format:
        - Offset 0x00: magic "dex\\n035\\x00" (or 036, 037, 038, 039)
        - Offset 0x38 (32-bit LE): string_ids_size (count of strings)
        - Offset 0x3C (32-bit LE): string_ids_off (offset to string ID table)
        - Each string ID is a 4-byte LE offset pointing to string data
        - String data: ULEB128 length prefix, then UTF-8 bytes
        """
        strings = self._extract_dex_strings(data)
        if not strings:
            return []

        return self._match_dex_strings(strings, name)

    def _extract_dex_strings(self, data: bytes) -> list[str]:
        """Extract all strings from a DEX file's string pool."""
        # Validate magic
        if len(data) < 0x70:
            return []

        magic = data[:4]
        if magic != b'dex\n':
            return []

        # Read string IDs table info
        try:
            string_ids_size = struct.unpack_from('<I', data, 0x38)[0]
            string_ids_off = struct.unpack_from('<I', data, 0x3C)[0]
        except struct.error:
            return []

        # Sanity checks
        if string_ids_size > 500_000 or string_ids_off >= len(data):
            return []

        strings: list[str] = []
        max_strings = min(string_ids_size, 100_000)  # Cap to avoid OOM

        for i in range(max_strings):
            id_offset = string_ids_off + i * 4
            if id_offset + 4 > len(data):
                break

            try:
                string_data_off = struct.unpack_from('<I', data, id_offset)[0]
            except struct.error:
                break

            if string_data_off >= len(data):
                continue

            # Read ULEB128 length
            str_len, consumed = self._read_uleb128(data, string_data_off)
            if str_len == 0 or str_len > 4096:
                continue

            str_start = string_data_off + consumed
            str_end = str_start + str_len

            if str_end > len(data):
                continue

            try:
                s = data[str_start:str_end].decode('utf-8', errors='replace')
                # Only keep strings that look like package paths or identifiers
                if len(s) >= 4:
                    strings.append(s)
            except Exception:
                continue

        return strings

    def _read_uleb128(self, data: bytes, offset: int) -> tuple[int, int]:
        """Read a ULEB128-encoded integer. Returns (value, bytes_consumed)."""
        result = 0
        shift = 0
        consumed = 0

        while offset < len(data):
            byte = data[offset]
            offset += 1
            consumed += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
            if consumed > 5:  # ULEB128 max 5 bytes for 32-bit
                break

        return result, consumed

    def _match_dex_strings(self, strings: list[str], section_name: str) -> list[Component]:
        """Match DEX strings against known Android library packages."""
        found_components: dict[str, tuple[str, str, str, list[str]]] = {}
        # (key) -> (name, vendor, version_hint, evidence_strings)

        for s in strings:
            # Normalize: DEX type descriptors use 'L' prefix and '/' separators
            # e.g., "Lcom/squareup/okhttp3/OkHttpClient;"
            check_str = s
            if check_str.startswith('L'):
                check_str = check_str[1:]
            if check_str.endswith(';'):
                check_str = check_str[:-1]

            for prefix in _DEX_PACKAGE_PREFIXES_SORTED:
                if check_str.startswith(prefix) or f"/{prefix}" in check_str:
                    comp_name, vendor, version_hint = DEX_PACKAGE_MAP[prefix]
                    key = comp_name.lower()
                    if key not in found_components:
                        found_components[key] = (comp_name, vendor, version_hint, [])
                    found_components[key][3].append(s[:80])
                    break

        # Also search for version strings embedded in constants
        version_strings: dict[str, str] = {}
        version_re = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[-_.]\w+)?)")
        for s in strings:
            for key, (comp_name, _, _, _) in found_components.items():
                if comp_name.lower() in s.lower():
                    m = version_re.search(s)
                    if m and self._is_plausible_version(m.group(1)):
                        version_strings[key] = m.group(1)

        # Build Component objects
        components: list[Component] = []
        for key, (comp_name, vendor, version_hint, evidence) in found_components.items():
            version = version_strings.get(key, version_hint)
            confidence = min(0.5 + len(evidence) * 0.05, 0.95)
            if version and version not in ("", "detected"):
                confidence = min(confidence + 0.1, 0.95)

            comp = Component(
                name=comp_name,
                vendor=vendor,
                component_type="library",
                resolved_version=version if version else "detected (version unknown)",
                versions=[VersionConfidence(
                    version=version if version else "detected",
                    confidence=confidence,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"DEX packages in {section_name}: {', '.join(evidence[:3])}",
                )],
            )
            if version and not version.endswith('.x'):
                comp.purl = f"pkg:maven/{comp_name.lower().replace(' ', '-')}@{version}"
            components.append(comp)

        return components

    # =========================================================================
    # Android build.prop analysis
    # =========================================================================

    def _analyze_build_prop(self, name: str, data: bytes) -> list[Component]:
        """Parse Android build.prop/default.prop for system metadata."""
        from ..android.build_prop import BuildPropParser
        parser = BuildPropParser()
        info = parser.parse(data)
        return parser.to_components(info)

    # =========================================================================
    # Compressed data analysis
    # =========================================================================

    def _analyze_compressed(self, name: str, data: bytes, comp_type: str) -> list[Component]:
        """Decompress data and recurse into decompressed content."""
        decompressed: bytes | None = None
        try:
            if comp_type == 'gzip':
                decompressed = gzip.decompress(data)
            elif comp_type == 'xz':
                decompressed = lzma.decompress(data)
        except Exception:
            return []

        if decompressed and len(decompressed) > 64:
            # Recurse into decompressed data, capped at 4MB to prevent OOM
            return self.analyze_section(
                name + '.decompressed',
                decompressed[:4 * 1024 * 1024],
            )
        return []

    # =========================================================================
    # Config / manifest file analysis
    # =========================================================================

    def _analyze_config(self, name: str, data: bytes) -> list[Component]:
        """Parse config/manifest files for structured dependency declarations."""
        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            return []

        lower_name = name.lower()
        components: list[Component] = []

        if lower_name.endswith('.gradle') or 'build.gradle' in lower_name:
            components.extend(self._parse_gradle(text, name))
        elif lower_name.endswith('.json'):
            components.extend(self._parse_json_config(text, name))
        elif lower_name.endswith('.xml'):
            components.extend(self._parse_xml_config(text, name))
        elif lower_name.endswith(('.yml', '.yaml')):
            components.extend(self._parse_yaml_config(text, name))
        elif lower_name.endswith('.properties'):
            components.extend(self._parse_properties(text, name))

        return components

    def _parse_gradle(self, text: str, section_name: str) -> list[Component]:
        """Parse build.gradle for dependency declarations."""
        components: list[Component] = []
        seen: set[str] = set()

        for match in _GRADLE_DEP_RE.finditer(text):
            group_id = match.group(1).strip()
            artifact_id = match.group(2).strip()
            version = match.group(3).strip()

            key = f"{group_id}:{artifact_id}".lower()
            if key in seen:
                continue
            seen.add(key)

            comp_name = artifact_id
            vendor = group_id.split('.')[-1] if '.' in group_id else group_id

            # Clean version (remove variable references like $var)
            if '$' in version or '{' in version:
                version = ""

            components.append(Component(
                name=comp_name,
                vendor=vendor,
                component_type="library",
                resolved_version=version if version else "detected (version unknown)",
                versions=[VersionConfidence(
                    version=version if version else "detected",
                    confidence=0.90 if version else 0.70,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"Gradle dependency in {section_name}: {group_id}:{artifact_id}:{version}",
                )],
                purl=f"pkg:maven/{group_id}/{artifact_id}@{version}" if version else "",
            ))

        return components

    def _parse_json_config(self, text: str, section_name: str) -> list[Component]:
        """Parse package.json or similar JSON configs."""
        components: list[Component] = []

        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            # Fallback to regex for malformed JSON
            return self._parse_json_regex_fallback(text, section_name)

        if not isinstance(data, dict):
            return []

        # package.json style
        dep_sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']
        for dep_key in dep_sections:
            deps = data.get(dep_key, {})
            if not isinstance(deps, dict):
                continue
            for pkg_name, version_spec in deps.items():
                if not isinstance(version_spec, str):
                    continue
                # Strip semver range operators
                version = re.sub(r'^[\^~>=<\s*|]+', '', version_spec).strip()
                version = version.split(' ')[0]  # Take first version in range

                components.append(Component(
                    name=pkg_name,
                    vendor="npm",
                    component_type="library",
                    resolved_version=version,
                    versions=[VersionConfidence(
                        version=version,
                        confidence=0.95,
                        method=ExtractionMethod.STRING_PATTERN,
                        evidence=f"package.json {dep_key} in {section_name}",
                    )],
                    purl=f"pkg:npm/{pkg_name}@{version}" if version else "",
                ))

        # Also check for "name" and "version" at top level (self-identification)
        if 'name' in data and 'version' in data:
            pkg_name = data['name']
            pkg_version = data['version']
            if isinstance(pkg_name, str) and isinstance(pkg_version, str):
                components.append(Component(
                    name=pkg_name,
                    vendor=data.get('author', '') if isinstance(data.get('author'), str) else "",
                    component_type="library",
                    resolved_version=pkg_version,
                    versions=[VersionConfidence(
                        version=pkg_version,
                        confidence=0.95,
                        method=ExtractionMethod.STRING_PATTERN,
                        evidence=f"package.json self-declaration in {section_name}",
                    )],
                    purl=f"pkg:npm/{pkg_name}@{pkg_version}",
                ))

        return components

    def _parse_json_regex_fallback(self, text: str, section_name: str) -> list[Component]:
        """Regex fallback for JSON parsing when json.loads fails."""
        components: list[Component] = []
        seen: set[str] = set()

        for match in _NPM_DEP_RE.finditer(text):
            pkg_name = match.group(1)
            version = match.group(2)
            key = pkg_name.lower()
            if key in seen:
                continue
            seen.add(key)

            components.append(Component(
                name=pkg_name,
                vendor="npm",
                component_type="library",
                resolved_version=version,
                versions=[VersionConfidence(
                    version=version,
                    confidence=0.80,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"JSON dependency pattern in {section_name}",
                )],
                purl=f"pkg:npm/{pkg_name}@{version}" if version else "",
            ))

        return components

    def _parse_xml_config(self, text: str, section_name: str) -> list[Component]:
        """Parse Maven POM XML or Android manifest XML for dependencies."""
        components: list[Component] = []
        seen: set[str] = set()

        # Maven POM dependencies
        for match in _MAVEN_ARTIFACT_RE.finditer(text):
            artifact_id = match.group(1).strip()
            version = match.group(2).strip()
            key = artifact_id.lower()
            if key in seen or '$' in version:
                continue
            seen.add(key)

            components.append(Component(
                name=artifact_id,
                vendor="",
                component_type="library",
                resolved_version=version,
                versions=[VersionConfidence(
                    version=version,
                    confidence=0.90,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"Maven POM in {section_name}",
                )],
                purl=f"pkg:maven/{artifact_id}@{version}" if version else "",
            ))

        # Android Manifest: check for uses-library
        lib_re = re.compile(r'<uses-library\s+android:name="([^"]+)"')
        for match in lib_re.finditer(text):
            lib_name = match.group(1)
            if lib_name.lower() not in seen:
                seen.add(lib_name.lower())
                components.append(Component(
                    name=lib_name,
                    vendor="Android",
                    component_type="library",
                    versions=[VersionConfidence(
                        version="detected",
                        confidence=0.70,
                        method=ExtractionMethod.STRING_PATTERN,
                        evidence=f"AndroidManifest uses-library in {section_name}",
                    )],
                ))

        return components

    def _parse_yaml_config(self, text: str, section_name: str) -> list[Component]:
        """Parse YAML manifests for dependency-like entries."""
        components: list[Component] = []
        seen: set[str] = set()

        for match in _YAML_DEP_RE.finditer(text):
            dep_name = match.group(1)
            version = match.group(2)
            key = dep_name.lower()
            if key in seen:
                continue
            seen.add(key)

            components.append(Component(
                name=dep_name,
                vendor="",
                component_type="library",
                resolved_version=version,
                versions=[VersionConfidence(
                    version=version,
                    confidence=0.85,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"YAML dependency in {section_name}",
                )],
            ))

        return components

    def _parse_properties(self, text: str, section_name: str) -> list[Component]:
        """Parse .properties files for version declarations."""
        components: list[Component] = []
        version_prop_re = re.compile(
            r'^(\w[\w.\-]*)\.version\s*=\s*(\d+\.\d+(?:\.\d+)?)', re.MULTILINE
        )

        for match in version_prop_re.finditer(text):
            dep_name = match.group(1)
            version = match.group(2)
            components.append(Component(
                name=dep_name,
                vendor="",
                component_type="library",
                resolved_version=version,
                versions=[VersionConfidence(
                    version=version,
                    confidence=0.85,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"Properties version in {section_name}",
                )],
            ))

        return components

    # =========================================================================
    # Source / header file analysis
    # =========================================================================

    def _analyze_source(self, name: str, data: bytes) -> list[Component]:
        """Analyze C/C++ source and header files for includes and version patterns."""
        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            return []

        components: list[Component] = []
        seen_components: set[str] = set()

        # Analyze #include directives
        for match in _INCLUDE_RE.finditer(text):
            include_path = match.group(1)
            # Check direct match
            if include_path in _INCLUDE_COMPONENT_MAP:
                comp_name, vendor = _INCLUDE_COMPONENT_MAP[include_path]
                key = comp_name.lower()
                if key not in seen_components:
                    seen_components.add(key)
                    components.append(Component(
                        name=comp_name,
                        vendor=vendor,
                        component_type="library",
                        versions=[VersionConfidence(
                            version="detected",
                            confidence=0.80,
                            method=ExtractionMethod.STRING_PATTERN,
                            evidence=f"#include <{include_path}> in {name}",
                        )],
                    ))
            else:
                # Check partial match (e.g., "lwip/something.h" matches "lwip/")
                for known_include, (comp_name, vendor) in _INCLUDE_COMPONENT_MAP.items():
                    if include_path.startswith(known_include.split('/')[0] + '/'):
                        key = comp_name.lower()
                        if key not in seen_components:
                            seen_components.add(key)
                            components.append(Component(
                                name=comp_name,
                                vendor=vendor,
                                component_type="library",
                                versions=[VersionConfidence(
                                    version="detected",
                                    confidence=0.75,
                                    method=ExtractionMethod.STRING_PATTERN,
                                    evidence=f"#include <{include_path}> in {name}",
                                )],
                            ))
                        break

        # Analyze #define VERSION patterns
        for match in _DEFINE_VERSION_RE.finditer(text):
            define_name = match.group(1)
            version = match.group(2)
            # Try to map the define to a component
            comp_name = self._define_to_component_name(define_name)
            if comp_name:
                key = comp_name.lower()
                if key in seen_components:
                    # Update version on existing component
                    for comp in components:
                        if comp.name.lower() == key:
                            comp.resolved_version = version
                            comp.versions.append(VersionConfidence(
                                version=version,
                                confidence=0.90,
                                method=ExtractionMethod.STRING_PATTERN,
                                evidence=f"#define {define_name} {version} in {name}",
                            ))
                            break
                else:
                    seen_components.add(key)
                    components.append(Component(
                        name=comp_name,
                        vendor="",
                        component_type="library",
                        resolved_version=version,
                        versions=[VersionConfidence(
                            version=version,
                            confidence=0.85,
                            method=ExtractionMethod.STRING_PATTERN,
                            evidence=f"#define {define_name} {version} in {name}",
                        )],
                    ))

        # Analyze version constants (const char* version = "X.Y.Z")
        for match in _VERSION_CONST_RE.finditer(text):
            version = match.group(1)
            if self._is_plausible_version(version):
                # This is a self-version of whatever this source file belongs to
                base_name = Path(name).stem
                components.append(Component(
                    name=base_name,
                    vendor="",
                    component_type="library",
                    resolved_version=version,
                    versions=[VersionConfidence(
                        version=version,
                        confidence=0.70,
                        method=ExtractionMethod.STRING_PATTERN,
                        evidence=f"Version constant in {name}",
                    )],
                ))

        return components

    def _define_to_component_name(self, define_name: str) -> str:
        """Map a #define name like LWIP_VERSION to a component name."""
        # Common patterns: COMPONENT_VERSION, COMPONENT_VER, etc.
        name = define_name.upper()
        for suffix in ('_VERSION', '_VER', '_VERSION_STRING', '_RELEASE'):
            if name.endswith(suffix):
                raw = name[:-len(suffix)]
                # Map known prefixes
                known = {
                    'LWIP': 'lwIP',
                    'MBEDTLS': 'mbedTLS',
                    'FREERTOS': 'FreeRTOS',
                    'WOLFSSL': 'wolfSSL',
                    'OPENSSL': 'OpenSSL',
                    'ZEPHYR': 'Zephyr RTOS',
                    'LFS': 'LittleFS',
                    'FATFS': 'FatFs',
                    'LVGL': 'LVGL',
                    'CJSON': 'cJSON',
                    'NANOPB': 'nanopb',
                    'TINYUSB': 'TinyUSB',
                    'MCUBOOT': 'MCUboot',
                    'ZLIB': 'zlib',
                    'LZ4': 'LZ4',
                    'SEGGER_RTT': 'SEGGER RTT',
                    'CMSIS': 'CMSIS',
                }
                if raw in known:
                    return known[raw]
                # Return cleaned-up name
                return raw.replace('_', ' ').title()
        return ""

    # =========================================================================
    # Text file analysis (changelog, version files, READMEs)
    # =========================================================================

    def _analyze_text_file(self, name: str, data: bytes) -> list[Component]:
        """Analyze text files for version declarations and changelog entries."""
        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            return []

        components: list[Component] = []

        # Try to identify what component this text file belongs to
        base_name = Path(name).stem.lower()
        parent_dir = str(Path(name).parent).replace('\\', '/').lower()

        # Look for version patterns
        best_version = ""
        for pattern in _TEXT_VERSION_PATTERNS:
            match = pattern.search(text)
            if match:
                version = match.group(1)
                if self._is_plausible_version(version):
                    best_version = version
                    break

        if best_version:
            # Determine component name from context
            comp_name = self._infer_component_from_path(name)
            if comp_name:
                components.append(Component(
                    name=comp_name,
                    vendor="",
                    component_type="library",
                    resolved_version=best_version,
                    versions=[VersionConfidence(
                        version=best_version,
                        confidence=0.70,
                        method=ExtractionMethod.STRING_PATTERN,
                        evidence=f"Version in text file {name}",
                    )],
                ))

        # If name contains 'version' specifically, also try KEY=VALUE patterns
        if 'version' in base_name:
            version_kv_re = re.compile(
                r'^(?:VERSION|version|Version)\s*[:=]\s*["\']?(\d+\.\d+(?:\.\d+)?)["\']?',
                re.MULTILINE,
            )
            for match in version_kv_re.finditer(text):
                version = match.group(1)
                if self._is_plausible_version(version):
                    comp_name = self._infer_component_from_path(name)
                    if comp_name and not any(c.name == comp_name for c in components):
                        components.append(Component(
                            name=comp_name,
                            vendor="",
                            component_type="library",
                            resolved_version=version,
                            versions=[VersionConfidence(
                                version=version,
                                confidence=0.80,
                                method=ExtractionMethod.STRING_PATTERN,
                                evidence=f"Version file {name}: {version}",
                            )],
                        ))

        return components

    # =========================================================================
    # Utility methods
    # =========================================================================

    def _infer_component_from_path(self, name: str) -> str:
        """Infer a component name from a file path.

        Examples:
            'lib/okhttp/CHANGELOG.md' -> 'okhttp'
            'vendor/lwip/VERSION' -> 'lwip'
            'components/mbedtls/version.txt' -> 'mbedtls'
        """
        parts = Path(name).parts
        # Skip the filename itself, look at parent directories
        for part in reversed(parts[:-1]):
            lower = part.lower()
            # Skip generic directory names
            if lower in ('lib', 'libs', 'vendor', 'third_party', 'thirdparty',
                         'external', 'ext', 'components', 'packages', 'deps',
                         'src', 'source', 'include', 'doc', 'docs'):
                continue
            if len(part) >= 2:
                return part
        # Fallback to filename stem if it's not a generic name
        stem = Path(name).stem.lower()
        if stem not in ('version', 'changelog', 'history', 'readme', 'changes', 'news'):
            return Path(name).stem
        return ""

    def _is_plausible_version(self, version: str) -> bool:
        """Check if a version string is plausible (not a date, IP, or protocol)."""
        parts = version.split(".")
        if len(parts) < 2:
            return False
        try:
            major = int(parts[0])
            if major > 999:
                return False
            # Reject IEEE 802.x style numbers
            if 800 <= major <= 899:
                return False
            return True
        except ValueError:
            return False
