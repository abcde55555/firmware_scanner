"""Android system scanner orchestrator.

Coordinates scanning an entire Android filesystem to identify all
components (APKs, native libraries, executables) with their versions.
"""

import zipfile
import io
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..extraction.models import Component, VersionConfidence, ExtractionMethod
from ..extraction.emba_rules import scan_binary_with_rules, get_rules
from .axml import AXMLParser, AndroidManifestInfo
from .build_prop import BuildPropParser, AndroidBuildInfo


class FilesystemReader(Protocol):
    """Protocol for filesystem readers (ext4 or erofs)."""

    def is_valid(self) -> bool: ...
    def list_directory(self, path: str) -> list: ...
    def read_file(self, path: str, max_size: int = 16 * 1024 * 1024) -> bytes | None: ...
    def file_size(self, path: str) -> int: ...
    def exists(self, path: str) -> bool: ...
    def walk(self, root: str = "/", max_depth: int = 10): ...


@dataclass
class AndroidScanResult:
    build_info: AndroidBuildInfo = field(default_factory=AndroidBuildInfo)
    components: list[Component] = field(default_factory=list)
    apk_count: int = 0
    lib_count: int = 0
    bin_count: int = 0
    warnings: list[str] = field(default_factory=list)


# Directories to scan for APKs
APK_DIRECTORIES = [
    "/system/priv-app",
    "/system/app",
    "/vendor/app",
    "/product/app",
    "/product/priv-app",
    "/system_ext/app",
    "/system_ext/priv-app",
    # Also check without /system prefix (for system.img where / is the partition root)
    "/priv-app",
    "/app",
]

# Directories for native libraries (including common subdirs)
LIB_DIRECTORIES = [
    "/system/lib64",
    "/system/lib",
    "/system/lib64/hw",
    "/system/lib/hw",
    "/system/lib64/egl",
    "/system/lib/egl",
    "/system/lib64/soundfx",
    "/system/lib/soundfx",
    "/vendor/lib64",
    "/vendor/lib",
    "/vendor/lib64/hw",
    "/vendor/lib/hw",
    "/vendor/lib64/egl",
    "/vendor/lib/egl",
    "/product/lib64",
    "/product/lib",
    "/lib64",
    "/lib",
    "/lib/hw",
    "/lib/egl",
    "/lib/soundfx",
    "/lib/bluez-plugin",
]

# Directories for executables
BIN_DIRECTORIES = [
    "/system/bin",
    "/system/xbin",
    "/vendor/bin",
    "/bin",
    "/sbin",
    "/xbin",
]

# Framework JARs
FRAMEWORK_DIRECTORIES = [
    "/system/framework",
    "/framework",
]

# Build property file locations
BUILD_PROP_PATHS = [
    "/system/build.prop",
    "/vendor/build.prop",
    "/product/build.prop",
    "/system_ext/build.prop",
    "/build.prop",
    "/default.prop",
]


class AndroidSystemScanner:
    """Orchestrates scanning of an extracted Android filesystem."""

    def __init__(
        self,
        fs_reader: FilesystemReader,
        max_apks: int = 200,
        max_libs: int = 500,
        max_bins: int = 400,
    ):
        self._fs = fs_reader
        self._max_apks = max_apks
        self._max_libs = max_libs
        self._max_bins = max_bins
        self._axml_parser = AXMLParser()
        self._build_prop_parser = BuildPropParser()

    def scan(self) -> AndroidScanResult:
        """Perform full Android system scan."""
        result = AndroidScanResult()

        if not self._fs.is_valid():
            result.warnings.append("Filesystem reader is not valid")
            return result

        # 1. Parse build.prop for system-level metadata
        result.build_info = self._scan_build_props()
        result.components.extend(
            self._build_prop_parser.to_components(result.build_info)
        )

        # 2. Scan APKs
        apk_components = self._scan_apks()
        result.components.extend(apk_components)
        result.apk_count = len(apk_components)

        # 3. Scan native libraries
        lib_components = self._scan_native_libs()
        result.components.extend(lib_components)
        result.lib_count = len(lib_components)

        # 4. Scan executables
        bin_components = self._scan_executables()
        result.components.extend(bin_components)
        result.bin_count = len(bin_components)

        # 5. Scan framework JARs
        framework_components = self._scan_framework_jars()
        result.components.extend(framework_components)

        # 6. Apply OS version as fallback for unversioned system components
        self._apply_os_version_fallback(result)

        return result

    def _scan_build_props(self) -> AndroidBuildInfo:
        """Find and parse all build.prop files, merging into one info object."""
        merged_info = AndroidBuildInfo()

        for prop_path in BUILD_PROP_PATHS:
            data = self._fs.read_file(prop_path, max_size=64 * 1024)
            if data:
                info = self._build_prop_parser.parse(data)
                self._merge_build_info(merged_info, info)

        return merged_info

    def _merge_build_info(self, target: AndroidBuildInfo, source: AndroidBuildInfo):
        """Merge source build info into target, preferring non-empty values."""
        for field_name in (
            'android_version', 'sdk_version', 'security_patch', 'build_fingerprint',
            'manufacturer', 'model', 'brand', 'board', 'device', 'build_type',
            'build_id', 'incremental', 'vendor_security_patch', 'kernel_version',
            'baseband_version', 'bootloader_version', 'hardware', 'platform', 'abi',
        ):
            source_val = getattr(source, field_name, None)
            target_val = getattr(target, field_name, None)
            if source_val and not target_val:
                setattr(target, field_name, source_val)

        target.all_properties.update(source.all_properties)

    def _apply_os_version_fallback(self, result: AndroidScanResult):
        """Apply Android OS version as fallback for unversioned system components.

        System libraries, framework JARs, and executables bundled in AOSP follow
        the OS release version. When no independent version is extracted, the OS
        version is a reasonable approximation for vulnerability matching.
        """
        os_version = result.build_info.android_version
        if not os_version:
            return

        build_id = result.build_info.build_id or ""
        fallback_evidence = f"Inherited from Android {os_version} (build {build_id})" if build_id else f"Inherited from Android {os_version}"

        for comp in result.components:
            if comp.component_type == "operating-system":
                continue

            has_real_version = (
                comp.resolved_version
                and comp.resolved_version != "detected"
            )
            if has_real_version:
                continue

            # Apply OS version as fallback
            comp.resolved_version = os_version
            comp.versions.append(VersionConfidence(
                version=os_version,
                confidence=0.45,
                method=ExtractionMethod.BUILD_METADATA,
                evidence=fallback_evidence,
            ))

    def _scan_apks(self) -> list[Component]:
        """Scan all APK directories and extract package info."""
        components: list[Component] = []
        scanned = 0

        for dir_path in APK_DIRECTORIES:
            if scanned >= self._max_apks:
                break
            if not self._fs.exists(dir_path):
                continue

            entries = self._fs.list_directory(dir_path)
            for entry in entries:
                if scanned >= self._max_apks:
                    break

                full_path = f"{dir_path.rstrip('/')}/{entry.name}"

                if entry.is_dir:
                    # App directories contain the APK inside
                    comp = self._scan_apk_dir(full_path)
                    if comp:
                        components.append(comp)
                        scanned += 1
                elif entry.name.lower().endswith('.apk'):
                    comp = self._scan_single_apk(full_path)
                    if comp:
                        components.append(comp)
                        scanned += 1

        return components

    def _scan_apk_dir(self, dir_path: str) -> Component | None:
        """Scan an app directory (e.g., /system/app/Settings/) for its APK."""
        try:
            entries = self._fs.list_directory(dir_path)
        except Exception:
            return None

        for entry in entries:
            if entry.name.lower().endswith('.apk'):
                apk_path = f"{dir_path.rstrip('/')}/{entry.name}"
                return self._scan_single_apk(apk_path)

        return None

    def _scan_single_apk(self, apk_path: str) -> Component | None:
        """Scan a single APK file to extract its manifest info."""
        apk_data = self._fs.read_file(apk_path, max_size=32 * 1024 * 1024)
        if not apk_data:
            # File unreadable but we know it exists - create minimal entry
            name = Path(apk_path).stem
            return Component(
                name=name,
                component_type="application",
                resolved_version="detected",
                versions=[VersionConfidence(
                    version="detected",
                    confidence=0.45,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"APK at {apk_path} (unreadable)",
                )],
            )

        return self._analyze_apk_data(apk_data, apk_path)

    def _analyze_apk_data(self, apk_data: bytes, apk_path: str) -> Component | None:
        """Analyze APK data (ZIP format) to extract manifest info."""
        manifest_info = None

        # Try standard ZIP parsing if data starts with PK signature
        if apk_data[:2] == b'PK':
            try:
                zf = zipfile.ZipFile(io.BytesIO(apk_data))
                try:
                    if 'AndroidManifest.xml' in zf.namelist():
                        manifest_data = zf.read('AndroidManifest.xml')
                        manifest_info = self._axml_parser.get_manifest_info(manifest_data)
                except Exception:
                    pass
                zf.close()
            except Exception:
                pass

        # If ZIP parsing didn't yield manifest, try raw local header extraction
        if not manifest_info:
            manifest_info = self._extract_manifest_from_raw(apk_data)

        if not manifest_info or not manifest_info.package_name:
            # Fallback: use filename as component name
            name = Path(apk_path).stem
            return Component(
                name=name,
                component_type="application",
                resolved_version="detected",
                versions=[VersionConfidence(
                    version="detected",
                    confidence=0.50,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"APK found at {apk_path}",
                )],
            )

        # Build component from manifest info
        version = manifest_info.version_name or str(manifest_info.version_code) if manifest_info.version_code else ""
        confidence = 0.95 if version else 0.80

        comp = Component(
            name=manifest_info.package_name,
            component_type="application",
            resolved_version=version,
            versions=[VersionConfidence(
                version=version if version else "detected",
                confidence=confidence,
                method=ExtractionMethod.MANIFEST_BINARY,
                evidence=f"AndroidManifest.xml in {apk_path}",
            )],
            purl=f"pkg:apk/{manifest_info.package_name}@{version}" if version else "",
            description=f"minSdk={manifest_info.min_sdk_version}, targetSdk={manifest_info.target_sdk_version}" if manifest_info.target_sdk_version else "",
        )

        return comp

    def _extract_manifest_from_raw(self, apk_data: bytes) -> AndroidManifestInfo | None:
        """Extract AndroidManifest.xml directly from ZIP local file headers.

        When the ZIP central directory is corrupted (common in YAFFS2 dumps due to
        page reordering), local file headers are still intact. This method finds the
        manifest entry and decompresses it directly.
        """
        import struct
        import zlib

        # Find the local file header for AndroidManifest.xml
        search_name = b'AndroidManifest.xml'
        pos = apk_data.find(search_name)
        if pos == -1:
            return None

        # Back up to find the PK\x03\x04 local header
        search_start = max(0, pos - 100)
        header_pos = apk_data.rfind(b'PK\x03\x04', search_start, pos)
        if header_pos == -1:
            return None

        # Parse local file header
        if header_pos + 30 > len(apk_data):
            return None
        comp_method = struct.unpack_from('<H', apk_data, header_pos + 8)[0]
        comp_size = struct.unpack_from('<I', apk_data, header_pos + 18)[0]
        uncomp_size = struct.unpack_from('<I', apk_data, header_pos + 22)[0]
        fname_len = struct.unpack_from('<H', apk_data, header_pos + 26)[0]
        extra_len = struct.unpack_from('<H', apk_data, header_pos + 28)[0]

        data_start = header_pos + 30 + fname_len + extra_len

        if comp_size == 0 or comp_size > 1024 * 1024:
            return None
        if data_start + comp_size > len(apk_data):
            return None

        compressed = apk_data[data_start:data_start + comp_size]

        manifest_data = None
        try:
            if comp_method == 0:
                manifest_data = compressed
            elif comp_method == 8:
                manifest_data = zlib.decompress(compressed, -15)
            else:
                return None
        except zlib.error:
            # Partial decompression - common when YAFFS2 page boundaries corrupt
            # the tail of compressed data. Package name and version are near the start.
            try:
                d = zlib.decompressobj(-15)
                manifest_data = d.decompress(compressed)
            except Exception:
                return None

        if not manifest_data:
            return None

        return self._axml_parser.get_manifest_info(manifest_data)

    def _scan_native_libs(self) -> list[Component]:
        """Scan native library directories for .so files."""
        components: list[Component] = []
        scanned = 0
        seen_names: set[str] = set()

        for dir_path in LIB_DIRECTORIES:
            if scanned >= self._max_libs:
                break
            if not self._fs.exists(dir_path):
                continue

            entries = self._fs.list_directory(dir_path)
            for entry in entries:
                if scanned >= self._max_libs:
                    break

                name_lower = entry.name.lower()
                if not name_lower.endswith('.so') and '.so.' not in name_lower:
                    continue

                # Skip checksum files (e.g., libbcc.so.sha1)
                checksum_exts = ('.sha1', '.sha256', '.md5', '.sig', '.hash')
                if any(name_lower.endswith(ext) for ext in checksum_exts):
                    continue

                # Deduplicate (lib64 vs lib)
                if entry.name in seen_names:
                    continue
                seen_names.add(entry.name)

                full_path = f"{dir_path.rstrip('/')}/{entry.name}"
                comp = self._analyze_native_lib(full_path, entry.name)
                if comp:
                    components.append(comp)
                    scanned += 1

        return components

    def _analyze_native_lib(self, path: str, filename: str) -> Component | None:
        """Analyze a native .so library."""
        # Read first 8MB for symbol analysis
        data = self._fs.read_file(path, max_size=8 * 1024 * 1024)
        if not data:
            return None

        # Extract library name from filename
        lib_name = filename
        if lib_name.startswith('lib'):
            lib_name = lib_name[3:]
        # Remove .so suffix and version suffix (e.g., .so.1.2.3)
        so_idx = lib_name.find('.so')
        if so_idx > 0:
            version_suffix = lib_name[so_idx + 3:]
            lib_name = lib_name[:so_idx]
        else:
            version_suffix = ""

        # Try to extract version from the .so version suffix
        version = ""
        if version_suffix.startswith('.'):
            version = version_suffix[1:]

        # Use the existing ELF analysis from smart_analyzer via symbols
        from ..extraction.smart_analyzer import SmartSectionAnalyzer
        analyzer = SmartSectionAnalyzer()
        sub_components = analyzer.analyze_section(path, data)

        if sub_components:
            return sub_components[0]

        # Try EMBA static rules (529 patterns for known components)
        emba_results = scan_binary_with_rules(data, filename)
        if emba_results:
            best = emba_results[0]
            best.versions[0] = VersionConfidence(
                version=best.resolved_version,
                confidence=0.85,
                method=ExtractionMethod.STATIC_RULE,
                evidence=best.versions[0].evidence if best.versions else f"EMBA rule match in {path}",
            )
            return best

        # Try well-known library version extraction from binary strings
        known_version = self._extract_known_lib_version(lib_name, data)
        if known_version:
            return Component(
                name=filename,
                component_type="library",
                resolved_version=known_version[0],
                versions=[VersionConfidence(
                    version=known_version[0],
                    confidence=0.85,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=known_version[1],
                )],
            )

        # Fallback: create component from filename
        return Component(
            name=filename,
            component_type="library",
            resolved_version=version if version else "detected",
            versions=[VersionConfidence(
                version=version if version else "detected",
                confidence=0.60 if version else 0.40,
                method=ExtractionMethod.STRING_PATTERN,
                evidence=f"Native library at {path}",
            )],
        )

    # Patterns for extracting versions from well-known libraries
    _KNOWN_LIB_PATTERNS: dict[str, list[tuple[bytes, str]]] = {
        "ssl": [
            (rb'OpenSSL (\d+\.\d+\.\d+[a-z]?)', "OpenSSL version string"),
            (rb'BoringSSL', "BoringSSL (unversioned)"),
        ],
        "crypto": [
            (rb'OpenSSL (\d+\.\d+\.\d+[a-z]?)', "OpenSSL version string"),
        ],
        "sqlite": [
            (rb'(\d+\.\d+\.\d+(?:\.\d+)?)\x00.{0,32}SQLite', "SQLite version string"),
            (rb'SQLite (\d+\.\d+\.\d+)', "SQLite version string"),
            (rb'(3\.\d+\.\d+)\x00', "SQLite 3.x version string"),
        ],
        "expat": [
            (rb'expat_(\d+\.\d+\.\d+)', "expat version string"),
            (rb'(\d+\.\d+\.\d+)\x00.{0,16}expat', "expat version string"),
        ],
        "curl": [
            (rb'libcurl/(\d+\.\d+\.\d+)', "libcurl version string"),
            (rb'curl (\d+\.\d+\.\d+)', "curl version string"),
        ],
        "z": [
            (rb'(\d+\.\d+\.\d+(?:\.\d+)?)\x00.{0,8}deflate', "zlib version string"),
            (rb'inflate (\d+\.\d+\.\d+)', "zlib version string"),
        ],
        "png": [
            (rb'libpng-(\d+\.\d+\.\d+)', "libpng version string"),
            (rb'PNG Library (\d+\.\d+\.\d+)', "libpng version string"),
        ],
        "png16": [
            (rb'libpng-(\d+\.\d+\.\d+)', "libpng version string"),
        ],
        "jpeg": [
            (rb'(\d+\.\d+)\x00.{0,16}JFIF', "libjpeg version string"),
            (rb'libjpeg-turbo (\d+\.\d+\.\d+)', "libjpeg-turbo version string"),
        ],
        "freetype": [
            (rb'FreeType (\d+\.\d+\.\d+)', "FreeType version string"),
            (rb'(\d+\.\d+\.\d+)\x00.{0,16}freetype', "FreeType version string"),
        ],
        "harfbuzz": [
            (rb'HarfBuzz (\d+\.\d+\.\d+)', "HarfBuzz version string"),
            (rb'(\d+\.\d+\.\d+)\x00.{0,16}[Hh]arf[Bb]uzz', "HarfBuzz version string"),
        ],
        "xml2": [
            (rb'libxml2-(\d+\.\d+\.\d+)', "libxml2 version string"),
            (rb'(\d+\.\d+\.\d+)\x00.{0,16}libxml', "libxml2 version string"),
        ],
        "icuuc": [
            (rb'ICU (\d+\.\d+(?:\.\d+)?)', "ICU version string"),
            (rb'icudt(\d+)', "ICU data version"),
        ],
        "icui18n": [
            (rb'ICU (\d+\.\d+(?:\.\d+)?)', "ICU version string"),
        ],
        "sqlite_jni": [
            (rb'(3\.\d+\.\d+)\x00', "SQLite 3.x version string"),
        ],
        "webcore": [
            (rb'WebKit/(\d+\.\d+)', "WebKit version string"),
            (rb'AppleWebKit/(\d+\.\d+)', "WebKit version string"),
        ],
        "stlport": [
            (rb'STLport-(\d+\.\d+)', "STLport version string"),
        ],
        "binder": [],
        "utils": [],
        "cutils": [],
        "log": [],
    }

    def _extract_known_lib_version(self, lib_name: str, data: bytes) -> tuple[str, str] | None:
        """Try to extract version from well-known library binary data."""
        patterns = self._KNOWN_LIB_PATTERNS.get(lib_name.lower())
        if patterns is None:
            return None

        # Search in first 2MB for version strings (they're usually in .rodata near the start)
        search_data = data[:2 * 1024 * 1024]

        for pattern, evidence_desc in patterns:
            match = re.search(pattern, search_data)
            if match:
                if match.groups():
                    version = match.group(1).decode('ascii', errors='replace')
                    return (version, f"{evidence_desc}: {match.group(0).decode('ascii', errors='replace')}")
                else:
                    # Pattern matched but no capture group (e.g., BoringSSL)
                    return ("detected", evidence_desc)

        return None

    def _scan_executables(self) -> list[Component]:
        """Scan binary directories for executables."""
        components: list[Component] = []
        scanned = 0
        seen_names: set[str] = set()

        for dir_path in BIN_DIRECTORIES:
            if scanned >= self._max_bins:
                break
            if not self._fs.exists(dir_path):
                continue

            entries = self._fs.list_directory(dir_path)
            for entry in entries:
                if scanned >= self._max_bins:
                    break
                if not entry.is_file:
                    continue
                if entry.name in seen_names:
                    continue
                seen_names.add(entry.name)

                full_path = f"{dir_path.rstrip('/')}/{entry.name}"
                # Read small chunk to identify format
                data = self._fs.read_file(full_path, max_size=1 * 1024 * 1024)
                if not data or len(data) < 16:
                    continue

                # Only process ELF binaries
                if data[:4] != b'\x7fELF':
                    continue

                # Try EMBA rules to extract version from binary
                emba_results = scan_binary_with_rules(data, entry.name)
                if emba_results:
                    best = emba_results[0]
                    best.component_type = "application"
                    best.versions[0] = VersionConfidence(
                        version=best.resolved_version,
                        confidence=0.82,
                        method=ExtractionMethod.STATIC_RULE,
                        evidence=best.versions[0].evidence if best.versions else f"EMBA rule match in {full_path}",
                    )
                    components.append(best)
                else:
                    components.append(Component(
                        name=entry.name,
                        component_type="application",
                        resolved_version="detected",
                        versions=[VersionConfidence(
                            version="detected",
                            confidence=0.50,
                            method=ExtractionMethod.BINARY_SIGNATURE,
                            evidence=f"ELF executable at {full_path}",
                        )],
                    ))
                scanned += 1

        return components

    def _scan_framework_jars(self) -> list[Component]:
        """Scan framework JAR and APK files for component identification."""
        components: list[Component] = []

        for dir_path in FRAMEWORK_DIRECTORIES:
            if not self._fs.exists(dir_path):
                continue

            entries = self._fs.list_directory(dir_path)
            for entry in entries:
                name_lower = entry.name.lower()
                if not name_lower.endswith('.jar') and not name_lower.endswith('.apk'):
                    continue

                full_path = f"{dir_path.rstrip('/')}/{entry.name}"
                jar_data = self._fs.read_file(full_path, max_size=16 * 1024 * 1024)
                if not jar_data or jar_data[:2] != b'PK':
                    continue

                # Create component from JAR/APK name
                jar_name = entry.name.rsplit('.', 1)[0]
                components.append(Component(
                    name=f"framework/{jar_name}",
                    component_type="framework",
                    resolved_version="detected",
                    versions=[VersionConfidence(
                        version="detected",
                        confidence=0.60,
                        method=ExtractionMethod.STRING_PATTERN,
                        evidence=f"Framework JAR at {full_path}",
                    )],
                ))

                # Try to parse DEX inside JAR for more specific components
                try:
                    zf = zipfile.ZipFile(io.BytesIO(jar_data))
                    for name in zf.namelist():
                        if name.endswith('.dex'):
                            dex_data = zf.read(name)
                            if dex_data and dex_data[:4] == b'dex\n':
                                from ..extraction.smart_analyzer import SmartSectionAnalyzer
                                analyzer = SmartSectionAnalyzer()
                                dex_components = analyzer.analyze_section(
                                    f"{full_path}/{name}", dex_data
                                )
                                components.extend(dex_components)
                            break  # Only first DEX
                    zf.close()
                except Exception:
                    pass

        return components
