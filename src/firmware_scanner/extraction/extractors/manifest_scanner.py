"""Manifest and SDK source distribution scanner.

Parses manifest.yml/manifest.json, version.h headers, package.json,
and CMakeLists.txt version declarations embedded in firmware binary data.
"""

import json
import re
from typing import Any

from ...core.context import AnalysisContext
from ..models import Component, VersionConfidence, ExtractionMethod
from .base import BaseExtractor


# Regex patterns for locating manifest-like YAML content in binary data
_YAML_DEPENDENCY_BLOCK = re.compile(
    r'dependencies:\s*\n((?:\s+-\s+name:\s*"[^"]+"\s*\n\s+version:\s*"[^"]+"\s*\n?)+)',
    re.MULTILINE,
)
_YAML_ENTRY = re.compile(
    r'-\s+name:\s*"(?P<name>[^"]+)"\s*\n\s+version:\s*"(?P<version>[^"]+)"'
)

# version.h style defines
_VERSION_STRING_DEFINE = re.compile(
    r'#define\s+(\w+?)_VERSION_STRING\s+"([^"]+)"'
)
_VERSION_DEFINE = re.compile(
    r'#define\s+(\w+?)_VERSION\s+"([^"]+)"'
)
_FREERTOS_VERSION_DEFINE = re.compile(
    r'#define\s+FREERTOS_VERSION\s+"([^"]+)"'
)
_VERSION_MAJOR_MINOR_PATCH = re.compile(
    r'#define\s+(?P<prefix>\w+?)_VERSION_MAJOR\s+(?P<major>\d+)\s*\n'
    r'(?:.*?\n)*?'
    r'#define\s+(?P=prefix)_VERSION_MINOR\s+(?P<minor>\d+)\s*\n'
    r'(?:.*?\n)*?'
    r'#define\s+(?P=prefix)_VERSION_PATCH\s+(?P<patch>\d+)',
    re.MULTILINE,
)

# package.json patterns
_PACKAGE_JSON_BLOCK = re.compile(
    r'\{\s*"name"\s*:\s*"(?P<name>[^"]+)"[^}]*?"version"\s*:\s*"(?P<version>[^"]+)"',
    re.DOTALL,
)
_PACKAGE_JSON_BLOCK_ALT = re.compile(
    r'\{\s*"version"\s*:\s*"(?P<version>[^"]+)"[^}]*?"name"\s*:\s*"(?P<name>[^"]+)"',
    re.DOTALL,
)

# CMakeLists.txt version patterns
_CMAKE_PROJECT_VERSION = re.compile(
    r'project\s*\(\s*(?P<name>\w+)[^)]*VERSION\s+(?P<version>\d+\.\d+(?:\.\d+)?(?:\.\d+)?)',
    re.IGNORECASE,
)
_CMAKE_SET_VERSION = re.compile(
    r'set\s*\(\s*(?P<var>\w+?)_VERSION\s+"?(?P<version>\d+\.\d+(?:\.\d+)?)"?\s*\)',
    re.IGNORECASE,
)

# Known component name normalizations for version.h prefix -> component name
_PREFIX_TO_COMPONENT: dict[str, tuple[str, str]] = {
    "MBEDTLS": ("mbedTLS", "ARM"),
    "FREERTOS": ("FreeRTOS", "Amazon"),
    "WOLFSSL": ("wolfSSL", "wolfSSL Inc"),
    "LWIP": ("lwIP", "lwIP"),
    "LFS": ("LittleFS", "ARM"),
    "LITTLEFS": ("LittleFS", "ARM"),
    "FATFS": ("FatFs", "ChaN"),
    "CJSON": ("cJSON", "DaveGamble"),
    "NANOPB": ("nanopb", "nanopb"),
    "TINYUSB": ("TinyUSB", "hathach"),
    "LVGL": ("LVGL", "LVGL"),
    "ZEPHYR": ("Zephyr RTOS", "Zephyr Project"),
    "NIMBLE": ("NimBLE", "Apache"),
    "OPENTHREAD": ("OpenThread", "Google"),
    "MCUBOOT": ("MCUboot", "MCUboot"),
    "LZ4": ("LZ4", "Yann Collet"),
    "MINIZ": ("miniz", "richgel999"),
    "SEGGER_RTT": ("SEGGER RTT", "SEGGER"),
    "NEWLIB": ("Newlib", "Red Hat"),
    "PICOLIBC": ("picolibc", "picolibc"),
    "PROTOBUF_C": ("protobuf-c", "protobuf-c"),
    "LIBCOAP": ("libcoap", "libcoap"),
    "MONGOOSE": ("Mongoose", "Cesanta"),
    "LIBCURL": ("libcurl", "curl"),
    "ZLIB": ("zlib", "zlib"),
    "AWS_IOT": ("AWS IoT SDK", "Amazon"),
    "AZURE_IOT": ("Azure IoT SDK", "Microsoft"),
}


class ManifestScannerExtractor(BaseExtractor):
    """Extracts component information from SDK manifest files, version.h
    headers, package.json, and CMakeLists.txt content embedded in firmware."""

    @property
    def name(self) -> str:
        return "manifest_scanner"

    def is_available(self) -> bool:
        return True

    @property
    def priority(self) -> int:
        # High priority since manifest data is authoritative
        return 90

    async def extract(self, context: AnalysisContext) -> list[Component]:
        components: dict[str, Component] = {}

        # Gather all data sources to scan
        data_sources = self._gather_data_sources(context)

        for source_name, data in data_sources:
            text = data.decode("utf-8", errors="ignore")

            # Strategy 1: Parse YAML manifest dependencies
            self._scan_yaml_manifests(text, source_name, components)

            # Strategy 2: Parse version.h #define patterns
            self._scan_version_headers(text, source_name, components)

            # Strategy 3: Parse package.json blocks
            self._scan_package_json(text, source_name, components)

            # Strategy 4: Parse CMakeLists.txt VERSION declarations
            self._scan_cmake_versions(text, source_name, components)

        return list(components.values())

    def _gather_data_sources(self, context: AnalysisContext) -> list[tuple[str, bytes]]:
        """Collect all data blobs to scan from the analysis context."""
        sources: list[tuple[str, bytes]] = []

        # Raw firmware data
        if context.raw_data:
            sources.append(("raw_firmware", context.raw_data))

        # Unpacked sections
        if context.unpack_result:
            for section in context.unpack_result.sections:
                if section.data and len(section.data) > 32:
                    sources.append((section.name, section.data))

        return sources

    def _scan_yaml_manifests(
        self, text: str, source_name: str, components: dict[str, Component]
    ) -> None:
        """Look for YAML manifest dependency blocks."""
        for block_match in _YAML_DEPENDENCY_BLOCK.finditer(text):
            block = block_match.group(0)
            for entry_match in _YAML_ENTRY.finditer(block):
                name = entry_match.group("name")
                version = entry_match.group("version")

                # Strip common version prefixes for resolved_version
                clean_version = self._clean_version(version)
                if not self._is_valid_version(clean_version):
                    continue

                key = name.lower().replace("-", "").replace("_", "")
                if key not in components:
                    components[key] = Component(
                        name=name,
                        vendor=self._infer_vendor(name),
                        component_type=self._infer_type(name),
                    )

                components[key].versions.append(
                    VersionConfidence(
                        version=clean_version,
                        confidence=0.9,
                        method=ExtractionMethod.STRING_PATTERN,
                        evidence=f"manifest.yml dependency in {source_name}: {name} {version}",
                    )
                )
                components[key].resolved_version = clean_version

    def _scan_version_headers(
        self, text: str, source_name: str, components: dict[str, Component]
    ) -> None:
        """Scan for C header #define VERSION patterns."""
        # Pattern: #define COMPONENT_VERSION_STRING "x.y.z"
        for match in _VERSION_STRING_DEFINE.finditer(text):
            prefix = match.group(1)
            version = match.group(2)
            clean_version = self._clean_version(version)
            if not self._is_valid_version(clean_version):
                continue
            self._add_version_from_define(
                prefix, clean_version, source_name, match.group(0), components
            )

        # Pattern: #define COMPONENT_VERSION "x.y.z"
        for match in _VERSION_DEFINE.finditer(text):
            prefix = match.group(1)
            version = match.group(2)
            clean_version = self._clean_version(version)
            if not self._is_valid_version(clean_version):
                continue
            self._add_version_from_define(
                prefix, clean_version, source_name, match.group(0), components
            )

        # Pattern: #define FREERTOS_VERSION "Vx.y.z"
        for match in _FREERTOS_VERSION_DEFINE.finditer(text):
            version = match.group(1)
            clean_version = self._clean_version(version)
            if not self._is_valid_version(clean_version):
                continue
            key = "freertos"
            if key not in components:
                components[key] = Component(
                    name="FreeRTOS",
                    vendor="Amazon",
                    component_type="operating-system",
                )
            components[key].versions.append(
                VersionConfidence(
                    version=clean_version,
                    confidence=0.9,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"version define in {source_name}: {match.group(0)}",
                )
            )
            components[key].resolved_version = clean_version

        # Pattern: MAJOR/MINOR/PATCH triplets
        for match in _VERSION_MAJOR_MINOR_PATCH.finditer(text):
            prefix = match.group("prefix")
            version = f"{match.group('major')}.{match.group('minor')}.{match.group('patch')}"
            if not self._is_valid_version(version):
                continue
            self._add_version_from_define(
                prefix, version, source_name,
                f"#define {prefix}_VERSION_MAJOR/MINOR/PATCH", components
            )

    def _scan_package_json(
        self, text: str, source_name: str, components: dict[str, Component]
    ) -> None:
        """Scan for package.json-like content."""
        for pattern in (_PACKAGE_JSON_BLOCK, _PACKAGE_JSON_BLOCK_ALT):
            for match in pattern.finditer(text):
                name = match.group("name")
                version = match.group("version")

                clean_version = self._clean_version(version)
                if not self._is_valid_version(clean_version):
                    continue

                # Skip overly generic or clearly non-component names
                if len(name) < 2 or name.startswith("."):
                    continue

                key = name.lower().replace("-", "").replace("_", "").replace("/", "")
                if key not in components:
                    components[key] = Component(
                        name=name,
                        vendor=self._infer_vendor(name),
                        component_type=self._infer_type(name),
                    )

                components[key].versions.append(
                    VersionConfidence(
                        version=clean_version,
                        confidence=0.9,
                        method=ExtractionMethod.STRING_PATTERN,
                        evidence=f"package.json in {source_name}: {name}@{version}",
                    )
                )
                components[key].resolved_version = clean_version

    def _scan_cmake_versions(
        self, text: str, source_name: str, components: dict[str, Component]
    ) -> None:
        """Scan for CMakeLists.txt project VERSION declarations."""
        # project(Name VERSION x.y.z)
        for match in _CMAKE_PROJECT_VERSION.finditer(text):
            name = match.group("name")
            version = match.group("version")

            if not self._is_valid_version(version):
                continue

            key = name.lower().replace("-", "").replace("_", "")
            if key not in components:
                components[key] = Component(
                    name=name,
                    vendor=self._infer_vendor(name),
                    component_type=self._infer_type(name),
                )

            components[key].versions.append(
                VersionConfidence(
                    version=version,
                    confidence=0.9,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"CMakeLists.txt in {source_name}: project({name} VERSION {version})",
                )
            )
            components[key].resolved_version = version

        # set(COMPONENT_VERSION "x.y.z")
        for match in _CMAKE_SET_VERSION.finditer(text):
            var_prefix = match.group("var")
            version = match.group("version")

            if not self._is_valid_version(version):
                continue

            key = var_prefix.lower().replace("-", "").replace("_", "")
            name = var_prefix.replace("_", "-")

            # Try to resolve to a known component
            upper_prefix = var_prefix.upper()
            if upper_prefix in _PREFIX_TO_COMPONENT:
                comp_name, vendor = _PREFIX_TO_COMPONENT[upper_prefix]
            else:
                comp_name = name
                vendor = ""

            resolved_key = comp_name.lower().replace("-", "").replace("_", "")
            if resolved_key not in components:
                components[resolved_key] = Component(
                    name=comp_name,
                    vendor=vendor,
                    component_type=self._infer_type(comp_name),
                )

            components[resolved_key].versions.append(
                VersionConfidence(
                    version=version,
                    confidence=0.9,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"CMakeLists.txt in {source_name}: set({var_prefix}_VERSION {version})",
                )
            )
            components[resolved_key].resolved_version = version

    def _add_version_from_define(
        self,
        prefix: str,
        version: str,
        source_name: str,
        evidence_str: str,
        components: dict[str, Component],
    ) -> None:
        """Add a component version from a #define pattern."""
        upper_prefix = prefix.upper()

        # Map known prefixes to component names
        if upper_prefix in _PREFIX_TO_COMPONENT:
            comp_name, vendor = _PREFIX_TO_COMPONENT[upper_prefix]
        else:
            # Use the prefix as the component name, cleaned up
            comp_name = prefix.replace("_", " ").strip()
            vendor = ""

        key = comp_name.lower().replace("-", "").replace("_", "").replace(" ", "")
        if key not in components:
            components[key] = Component(
                name=comp_name,
                vendor=vendor,
                component_type=self._infer_type(comp_name),
            )

        components[key].versions.append(
            VersionConfidence(
                version=version,
                confidence=0.9,
                method=ExtractionMethod.STRING_PATTERN,
                evidence=f"version define in {source_name}: {evidence_str}",
            )
        )
        components[key].resolved_version = version

    def _clean_version(self, version: str) -> str:
        """Strip common version prefixes like 'V', 'v', etc."""
        version = version.strip()
        # Remove leading 'V' or 'v' prefix
        if version and version[0] in ("V", "v") and len(version) > 1 and version[1:2].isdigit():
            version = version[1:]
        # Remove trailing stability suffixes for cleanliness but keep them if they
        # look like semver pre-release (e.g., "5.6.4-stable" stays as-is)
        return version

    def _is_valid_version(self, version: str) -> bool:
        """Validate that a string looks like a real version number."""
        if not version:
            return False
        # Must start with a digit
        if not version[0].isdigit():
            return False
        parts = version.split(".")
        if len(parts) < 2:
            return False
        try:
            major = int(parts[0])
            # Reject network protocol numbers (802.x) and overly large numbers
            if major > 999:
                return False
            if major >= 800 and major <= 899:
                # Reject IEEE 802.x patterns
                return False
        except ValueError:
            return False
        return True

    def _infer_vendor(self, name: str) -> str:
        """Try to infer vendor from component name."""
        name_lower = name.lower()
        vendor_hints: dict[str, str] = {
            "freertos": "Amazon",
            "mbedtls": "ARM",
            "wolfssl": "wolfSSL Inc",
            "lwip": "lwIP",
            "zephyr": "Zephyr Project",
            "littlefs": "ARM",
            "fatfs": "ChaN",
            "tinyusb": "hathach",
            "lvgl": "LVGL",
            "nimble": "Apache",
            "cjson": "DaveGamble",
            "nanopb": "nanopb",
            "mcuboot": "MCUboot",
            "openthread": "Google",
            "esp-idf": "Espressif",
            "nrf": "Nordic Semiconductor",
            "stm32": "STMicroelectronics",
        }
        for hint_key, vendor in vendor_hints.items():
            if hint_key in name_lower:
                return vendor
        return ""

    def _infer_type(self, name: str) -> str:
        """Infer component type from name."""
        name_lower = name.lower()
        os_keywords = ("rtos", "freertos", "zephyr", "threadx", "nuttx", "liteos", "vxworks")
        for kw in os_keywords:
            if kw in name_lower:
                return "operating-system"
        fw_keywords = ("boot", "u-boot", "mcuboot")
        for kw in fw_keywords:
            if kw in name_lower:
                return "firmware"
        return "library"
