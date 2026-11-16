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
    apex_count: int = 0
    warnings: list[str] = field(default_factory=list)


# Directories for APEX mainline modules
APEX_DIRECTORIES = [
    "/system/apex",
    "/apex",
    "/product/apex",
    "/system_ext/apex",
    "/vendor/apex",
]

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
        max_apks: int = 500,
        max_libs: int = 2000,
        max_bins: int = 1000,
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

        # 2. Scan APEX mainline modules
        apex_components = self._scan_apex_modules()
        result.components.extend(apex_components)
        result.apex_count = len(apex_components)

        # 3. Scan APKs and embedded Maven libraries
        apk_components = self._scan_apks()
        result.components.extend(apk_components)
        result.apk_count = len(apk_components)

        # 4. Scan native libraries (with path isolation)
        lib_components = self._scan_native_libs()
        result.components.extend(lib_components)
        result.lib_count = len(lib_components)

        # Build library version map to resolve dynamically linked frontend binaries (e.g. sqlite3 -> libsqlite.so)
        lib_version_map: dict[str, str] = {}
        for c in lib_components:
            if c.resolved_version and not c.resolved_version.endswith("+") and c.resolved_version != "detected":
                lib_version_map[c.name] = c.resolved_version
                base = c.name
                if base.startswith("lib"):
                    base = base[3:]
                if base.endswith(".so"):
                    base = base[:-3]
                lib_version_map[base] = c.resolved_version
                if base == "sqlite":
                    lib_version_map["sqlite3"] = c.resolved_version

        # 5. Scan executables
        bin_components = self._scan_executables(lib_version_map)
        result.components.extend(bin_components)
        result.bin_count = len(bin_components)

        # 6. Scan framework JARs (and embedded Maven libraries)
        framework_components = self._scan_framework_jars()
        result.components.extend(framework_components)

        # 7. Apply AOSP baseline metadata annotation without mass fake 16 versions
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
        """Annotate unversioned system components with AOSP baseline and SPL watermark.

        Instead of falsely stamping OS release (e.g. '16') as upstream package versions,
        we attach the AOSP platform baseline, build ID, and Security Patch Level (SPL)
        metadata to descriptions and evidence.
        """
        os_version = result.build_info.android_version or ""
        spl = result.build_info.security_patch or ""
        build_id = result.build_info.build_id or ""

        baseline_parts = []
        if os_version:
            baseline_parts.append(f"Android {os_version}")
        if spl:
            baseline_parts.append(f"SPL {spl}")
        if build_id:
            baseline_parts.append(f"build {build_id}")
        baseline_desc = f"AOSP platform component | Baseline: {', '.join(baseline_parts)}" if baseline_parts else "AOSP platform component"

        for comp in result.components:
            # The Android OS component keeps the OS version
            if comp.component_type == "operating-system" or comp.name.lower() == "android":
                if not comp.resolved_version and os_version:
                    comp.resolved_version = os_version
                continue

            # Clear any placeholder 'detected' version
            if comp.resolved_version == "detected":
                comp.resolved_version = ""

            # If component has no version, annotate description with AOSP platform baseline
            if not comp.resolved_version:
                if not comp.description:
                    comp.description = baseline_desc
                elif "Baseline:" not in comp.description and "AOSP" not in comp.description:
                    comp.description = f"{comp.description} | {baseline_desc}"

    def _extract_embedded_maven_libs(self, zf: zipfile.ZipFile, origin_path: str) -> list[Component]:
        """Extract third-party Java/Kotlin libraries from embedded pom.properties in APK/JAR."""
        components: list[Component] = []
        seen: set[str] = set()
        for name in zf.namelist():
            if name.endswith("pom.properties"):
                try:
                    data = zf.read(name).decode("utf-8", errors="ignore")
                    props = {}
                    for line in data.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            props[k.strip()] = v.strip()
                    group_id = props.get("groupId", "")
                    artifact_id = props.get("artifactId", "")
                    version = props.get("version", "")
                    if artifact_id and version:
                        comp_name = f"{group_id}:{artifact_id}" if group_id else artifact_id
                        if comp_name in seen:
                            continue
                        seen.add(comp_name)
                        purl = f"pkg:maven/{group_id}/{artifact_id}@{version}" if group_id else f"pkg:generic/{artifact_id}@{version}"
                        components.append(Component(
                            name=comp_name,
                            component_type="library",
                            resolved_version=version,
                            purl=purl,
                            description=f"Embedded Java/Kotlin library in {origin_path}",
                            versions=[VersionConfidence(
                                version=version,
                                confidence=0.98,
                                method=ExtractionMethod.MANIFEST_BINARY,
                                evidence=f"{name} in {origin_path}",
                            )],
                        ))
                except Exception:
                    continue
        return components

    def _scan_apex_modules(self) -> list[Component]:
        """Scan APEX packages for mainline modules, versionCodes, and bundled libraries."""
        components: list[Component] = []
        seen_names: set[str] = set()

        for dir_path in APEX_DIRECTORIES:
            if not self._fs.exists(dir_path):
                continue
            entries = self._fs.list_directory(dir_path)
            for entry in entries:
                if not entry.name.endswith(".apex"):
                    continue
                if entry.name in seen_names:
                    continue
                seen_names.add(entry.name)

                full_path = f"{dir_path.rstrip('/')}/{entry.name}"
                data = self._fs.read_file(full_path, max_size=64 * 1024 * 1024)
                if not data or data[:2] != b'PK':
                    continue

                try:
                    zf = zipfile.ZipFile(io.BytesIO(data))
                    manifest_info = None
                    if "AndroidManifest.xml" in zf.namelist():
                        manifest_data = zf.read("AndroidManifest.xml")
                        manifest_info = self._axml_parser.get_manifest_info(manifest_data)

                    bundled_libs = []
                    if "apex_manifest.pb" in zf.namelist():
                        pb_data = zf.read("apex_manifest.pb")
                        so_matches = re.findall(rb'([a-zA-Z0-9_\-\.]+\.so)', pb_data)
                        bundled_libs = [m.decode('ascii', errors='ignore') for m in so_matches]

                    zf.close()

                    pkg_name = manifest_info.package_name if manifest_info and manifest_info.package_name else entry.name[:-5]
                    version_str = ""
                    if manifest_info and manifest_info.version_code:
                        version_str = str(manifest_info.version_code)
                    elif manifest_info and manifest_info.version_name:
                        version_str = manifest_info.version_name

                    purl = f"pkg:generic/{pkg_name}@{version_str}" if version_str else f"pkg:generic/{pkg_name}"
                    desc_parts = [f"APEX Mainline module at {full_path}"]
                    if version_str:
                        desc_parts.append(f"versionCode={version_str}")
                    if bundled_libs:
                        desc_parts.append(f"Bundled libs: {', '.join(bundled_libs[:5])}")

                    components.append(Component(
                        name=pkg_name,
                        component_type="application",
                        resolved_version=version_str,
                        purl=purl,
                        description=" | ".join(desc_parts),
                        versions=[VersionConfidence(
                            version=version_str if version_str else "",
                            confidence=0.95 if version_str else 0.70,
                            method=ExtractionMethod.MANIFEST_BINARY,
                            evidence=f"APEX package at {full_path}",
                        )],
                    ))
                except Exception:
                    continue

        return components

    def _scan_apks(self) -> list[Component]:
        """Scan all APK directories and extract package info and embedded libraries."""
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
                    comps = self._scan_apk_dir(full_path)
                    if comps:
                        components.extend(comps)
                        scanned += 1
                elif entry.name.lower().endswith('.apk'):
                    comps = self._scan_single_apk(full_path)
                    if comps:
                        components.extend(comps)
                        scanned += 1

        return components

    def _scan_apk_dir(self, dir_path: str) -> list[Component]:
        """Scan an app directory (e.g., /system/app/Settings/) for its APK."""
        try:
            entries = self._fs.list_directory(dir_path)
        except Exception:
            return []

        for entry in entries:
            if entry.name.lower().endswith('.apk'):
                apk_path = f"{dir_path.rstrip('/')}/{entry.name}"
                return self._scan_single_apk(apk_path)

        return []

    def _scan_single_apk(self, apk_path: str) -> list[Component]:
        """Scan a single APK file to extract its manifest info and embedded libraries."""
        apk_data = self._fs.read_file(apk_path, max_size=32 * 1024 * 1024)
        if not apk_data:
            name = Path(apk_path).stem
            return [Component(
                name=name,
                component_type="application",
                resolved_version="",
                description=f"APK at {apk_path} (unreadable)",
                versions=[VersionConfidence(
                    version="",
                    confidence=0.45,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"APK at {apk_path} (unreadable)",
                )],
            )]

        return self._analyze_apk_data(apk_data, apk_path)

    def _analyze_apk_data(self, apk_data: bytes, apk_path: str) -> list[Component]:
        """Analyze APK data (ZIP format) to extract manifest info and embedded libraries."""
        manifest_info = None
        embedded_libs: list[Component] = []

        # Try standard ZIP parsing if data starts with PK signature
        if apk_data[:2] == b'PK':
            try:
                zf = zipfile.ZipFile(io.BytesIO(apk_data))
                try:
                    if 'AndroidManifest.xml' in zf.namelist():
                        manifest_data = zf.read('AndroidManifest.xml')
                        manifest_info = self._axml_parser.get_manifest_info(manifest_data)
                    embedded_libs = self._extract_embedded_maven_libs(zf, apk_path)
                except Exception:
                    pass
                zf.close()
            except Exception:
                pass

        # If ZIP parsing didn't yield manifest, try raw local header extraction
        if not manifest_info:
            manifest_info = self._extract_manifest_from_raw(apk_data)

        if not manifest_info or not manifest_info.package_name:
            name = Path(apk_path).stem
            apk_comp = Component(
                name=name,
                component_type="application",
                resolved_version="",
                description=f"APK found at {apk_path}",
                versions=[VersionConfidence(
                    version="",
                    confidence=0.50,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"APK found at {apk_path}",
                )],
            )
            return [apk_comp] + embedded_libs

        # Build component from manifest info
        version = manifest_info.version_name or (str(manifest_info.version_code) if manifest_info.version_code else "")
        confidence = 0.95 if version else 0.80

        desc_parts = []
        if manifest_info.target_sdk_version:
            desc_parts.append(f"targetSdk={manifest_info.target_sdk_version}")
        if manifest_info.min_sdk_version:
            desc_parts.append(f"minSdk={manifest_info.min_sdk_version}")
        if manifest_info.shared_user_id:
            desc_parts.append(f"sharedUserId={manifest_info.shared_user_id}")
        if manifest_info.is_system_uid:
            desc_parts.append("SYSTEM_UID (High Privilege)")
        if manifest_info.exported_components_count > 0:
            desc_parts.append(f"exportedComponents={manifest_info.exported_components_count}")

        apk_comp = Component(
            name=manifest_info.package_name,
            component_type="application",
            resolved_version=version,
            versions=[VersionConfidence(
                version=version if version else "",
                confidence=confidence,
                method=ExtractionMethod.MANIFEST_BINARY,
                evidence=f"AndroidManifest.xml in {apk_path}",
            )],
            purl=f"pkg:apk/{manifest_info.package_name}@{version}" if version else f"pkg:apk/{manifest_info.package_name}",
            description="; ".join(desc_parts),
        )

        return [apk_comp] + embedded_libs

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
        """Scan native library directories for .so files with partition path isolation."""
        components: list[Component] = []
        scanned = 0
        seen_keys: set[tuple[str, str]] = set()

        for dir_path in LIB_DIRECTORIES:
            if scanned >= self._max_libs:
                break
            if not self._fs.exists(dir_path):
                continue

            parts = dir_path.strip('/').split('/')
            partition = parts[0] if parts else "system"

            entries = list(self._fs.list_directory(dir_path))
            from ..extraction.elf_deep_extractor import KNOWN_RODATA_PATTERNS

            def _lib_priority(entry_name: str) -> tuple[int, str]:
                nl = entry_name.lower()
                clean = nl.replace("lib", "").replace(".so", "")
                for k in KNOWN_RODATA_PATTERNS.keys():
                    if len(k) >= 3 and (k in clean or k in nl):
                        return (0, nl)
                if "@" in nl or "-v" in nl:
                    return (1, nl)
                return (2, nl)

            entries.sort(key=lambda e: _lib_priority(e.name))
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

                # Path isolation: preserve (partition, filename)
                key = (partition, entry.name)
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                full_path = f"{dir_path.rstrip('/')}/{entry.name}"
                comp = self._analyze_native_lib(full_path, entry.name, partition)
                if comp:
                    components.append(comp)
                    scanned += 1

        return components

    def _analyze_native_lib(self, path: str, filename: str, partition: str = "system") -> Component | None:
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

        # 1. Multi-tier deep ELF extractor (SONAME, symbol versioning, rodata banners, landmark symbols, HAL interfaces)
        from ..extraction.elf_deep_extractor import ELFDeepExtractor
        deep_extractor = ELFDeepExtractor()
        deep_res = deep_extractor.extract(filename, data)
        if deep_res and deep_res.version:
            evidence_str = deep_res.evidence or f"ELF deep extraction in {path}"
            if deep_res.toolchain:
                evidence_str += f" | Toolchain: {deep_res.toolchain[:60]}"
            return Component(
                name=filename,
                component_type="library",
                resolved_version=deep_res.version,
                description=f"Native library in /{partition} at {path}",
                purl=deep_res.purl or f"pkg:generic/{filename}@{deep_res.version}",
                versions=[VersionConfidence(
                    version=deep_res.version,
                    confidence=deep_res.confidence,
                    method=deep_res.method,
                    evidence=evidence_str,
                )],
            )

        # 2. Try EMBA static rules (529 patterns for known components)
        emba_results = scan_binary_with_rules(data, filename)
        if emba_results and emba_results[0].resolved_version:
            best = emba_results[0]
            best.description = f"Native library in /{partition} at {path}"
            best.versions[0] = VersionConfidence(
                version=best.resolved_version,
                confidence=0.85,
                method=ExtractionMethod.STATIC_RULE,
                evidence=best.versions[0].evidence if best.versions else f"EMBA rule match in {path}",
            )
            return best

        # 3. Try well-known library version extraction from binary strings
        known_version = self._extract_known_lib_version(lib_name, data)
        if known_version and known_version[0]:
            return Component(
                name=filename,
                component_type="library",
                resolved_version=known_version[0],
                description=f"Native library in /{partition} at {path}",
                purl=f"pkg:generic/{filename}@{known_version[0]}",
                versions=[VersionConfidence(
                    version=known_version[0],
                    confidence=0.85,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=known_version[1],
                )],
            )

        # 4. Symbol table matching fallback via SmartSectionAnalyzer
        from ..extraction.smart_analyzer import SmartSectionAnalyzer
        analyzer = SmartSectionAnalyzer()
        sub_components = analyzer.analyze_section(path, data)
        if sub_components and sub_components[0].resolved_version and sub_components[0].resolved_version != "detected":
            return sub_components[0]

        # Fallback: create component from filename without fake version
        return Component(
            name=filename,
            component_type="library",
            resolved_version=version,
            description=f"AOSP native library in /{partition} at {path}",
            versions=[VersionConfidence(
                version=version,
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
        "vpx": [
            (rb'libvpx v(\d+\.\d+\.\d+)', "libvpx version string"),
            (rb'v(\d+\.\d+\.\d+)\x00.{0,32}vpx', "libvpx version string"),
        ],
        "opus": [
            (rb'libopus (\d+\.\d+(?:\.\d+)?)', "libopus version string"),
        ],
        "pcre2": [
            (rb'(\d+\.\d+)\s+\d{4}-\d{2}-\d{2}', "PCRE2 version string"),
        ],
        "pcre": [
            (rb'(\d+\.\d+)\s+\d{4}-\d{2}-\d{2}', "PCRE version string"),
        ],
        "binder": [],
        "utils": [],
        "cutils": [],
        "log": [],
    }

    # Patterns for extracting versions from well-known executables
    _KNOWN_BIN_PATTERNS: dict[str, list[tuple[bytes, str]]] = {
        "toybox": [
            (rb'(\d+\.\d+\.\d+)-android', "Toybox Android version string"),
            (rb'toybox (\d+\.\d+\.\d+)', "Toybox version string"),
        ],
        "curl": [
            (rb'curl (\d+\.\d+\.\d+)', "curl version string"),
            (rb'libcurl/(\d+\.\d+\.\d+)', "libcurl version string"),
        ],
        "e2fsck": [
            (rb'version of e2fsck!\x00(\d+\.\d+\.\d+)', "e2fsck version string"),
            (rb'e2fsck (\d+\.\d+\.\d+)', "e2fsck version string"),
            (rb'(\d+\.\d+\.\d+)\x00%12u non-contiguous', "e2fsck version string"),
        ],
        "dnsmasq": [
            (rb'dnsmasq(?: version)? (\d+\.\d+(?:\.\d+)?)', "dnsmasq version string"),
        ],
        "wpa_supplicant": [
            (rb'wpa_supplicant v(\d+\.\d+(?:\.\d+)?)', "wpa_supplicant version string"),
        ],
        "busybox": [
            (rb'BusyBox v(\d+\.\d+\.\d+)', "BusyBox version string"),
        ],
        "iptables": [
            (rb'iptables v(\d+\.\d+\.\d+)', "iptables version string"),
        ],
        "ip6tables": [
            (rb'ip6tables v(\d+\.\d+\.\d+)', "ip6tables version string"),
        ],
        "grep": [
            (rb'grep \(GNU grep\) (\d+\.\d+)', "GNU grep version string"),
        ],
        "tar": [
            (rb'tar \(GNU tar\) (\d+\.\d+)', "GNU tar version string"),
        ],
        "gzip": [
            (rb'gzip (\d+\.\d+\.\d+)', "gzip version string"),
        ],
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
                    return ("", evidence_desc)

        return None

    def _extract_known_bin_version(self, bin_name: str, data: bytes) -> tuple[str, str] | None:
        """Try to extract version from well-known binary data."""
        patterns = self._KNOWN_BIN_PATTERNS.get(bin_name.lower())
        if not patterns:
            return None
        search_data = data[:1024 * 1024]
        for pattern, desc in patterns:
            match = re.search(pattern, search_data)
            if match and match.groups():
                return (match.group(1).decode('ascii', errors='replace'), f"{desc}: {match.group(0).decode('ascii', errors='replace')}")
        return None

    def _scan_executables(self, lib_version_map: dict[str, str] | None = None) -> list[Component]:
        """Scan binary directories for executables."""
        components: list[Component] = []
        scanned = 0
        seen_names: set[str] = set()
        lib_versions = lib_version_map or {}

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

                # Check if executable dynamically links to a library with known exact version (e.g. sqlite3 -> libsqlite.so)
                linked_lib_ver = lib_versions.get(entry.name)

                # 1. Multi-tier deep ELF extractor for binaries
                from ..extraction.elf_deep_extractor import ELFDeepExtractor
                deep_extractor = ELFDeepExtractor()
                deep_res = deep_extractor.extract(entry.name, data)
                if deep_res and deep_res.version:
                    bin_ver = deep_res.version
                    bin_confidence = deep_res.confidence
                    evidence_str = deep_res.evidence or f"ELF binary version in {full_path}"
                    
                    # If version is an API floor landmark (ends with +) and we have a linked lib exact version, use it!
                    if (bin_ver.endswith("+") or bin_ver == "detected") and linked_lib_ver:
                        bin_ver = linked_lib_ver
                        bin_confidence = 0.95
                        evidence_str = f"Derived from dynamically linked lib{entry.name}.so ({linked_lib_ver})"
                    elif bin_ver.endswith("+"):
                        # Keep evidence but do not propagate '+' to version string for semver compatibility
                        bin_ver = bin_ver.rstrip("+")

                    if deep_res.toolchain:
                        evidence_str += f" | Toolchain: {deep_res.toolchain[:60]}"
                    components.append(Component(
                        name=entry.name,
                        component_type="application",
                        resolved_version=bin_ver,
                        purl=f"pkg:generic/{entry.name}@{bin_ver}" if bin_ver else "",
                        description=f"ELF binary at {full_path}",
                        versions=[VersionConfidence(
                            version=bin_ver,
                            confidence=bin_confidence,
                            method=deep_res.method,
                            evidence=evidence_str,
                        )],
                    ))
                    scanned += 1
                    continue

                # Check if linked lib version is available when no deep_res version was extracted
                if linked_lib_ver:
                    components.append(Component(
                        name=entry.name,
                        component_type="application",
                        resolved_version=linked_lib_ver,
                        purl=f"pkg:generic/{entry.name}@{linked_lib_ver}",
                        description=f"ELF binary at {full_path}",
                        versions=[VersionConfidence(
                            version=linked_lib_ver,
                            confidence=0.90,
                            method=ExtractionMethod.STRING_PATTERN,
                            evidence=f"Derived from dynamically linked library version ({linked_lib_ver})",
                        )],
                    ))
                    scanned += 1
                    continue

                # Check known binary patterns next (e.g. toybox, curl, e2fsck)
                known_bin = self._extract_known_bin_version(entry.name, data)
                if known_bin:
                    components.append(Component(
                        name=entry.name,
                        component_type="application",
                        resolved_version=known_bin[0],
                        purl=f"pkg:generic/{entry.name}@{known_bin[0]}",
                        description=f"ELF binary at {full_path}",
                        versions=[VersionConfidence(
                            version=known_bin[0],
                            confidence=0.90,
                            method=ExtractionMethod.STRING_PATTERN,
                            evidence=known_bin[1],
                        )],
                    ))
                    scanned += 1
                    continue

                # Try EMBA rules to extract version from binary
                emba_results = scan_binary_with_rules(data, entry.name)
                if emba_results:
                    best = emba_results[0]
                    best.component_type = "application"
                    best.description = f"ELF binary at {full_path}"
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
                        resolved_version="",
                        description=f"ELF binary at {full_path}",
                        versions=[VersionConfidence(
                            version="",
                            confidence=0.50,
                            method=ExtractionMethod.BINARY_SIGNATURE,
                            evidence=f"ELF executable at {full_path}",
                        )],
                    ))
                scanned += 1

        return components

    def _scan_framework_jars(self) -> list[Component]:
        """Scan framework JAR and APK files for component identification and embedded libraries."""
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
                jar_ver = ""
                m_aidl_jar = re.search(r'-V(\d+(?:\.\d+)?)(?:-java)?$', jar_name)
                if m_aidl_jar:
                    jar_ver = f"V{m_aidl_jar.group(1)}"

                components.append(Component(
                    name=f"framework/{jar_name}",
                    component_type="framework",
                    resolved_version=jar_ver,
                    purl=f"pkg:generic/framework/{jar_name}@{jar_ver}" if jar_ver else "",
                    description=f"Framework JAR at {full_path}",
                    versions=[VersionConfidence(
                        version=jar_ver,
                        confidence=0.90 if jar_ver else 0.60,
                        method=ExtractionMethod.MANIFEST_BINARY if jar_ver else ExtractionMethod.STRING_PATTERN,
                        evidence=f"Framework interface {jar_ver}" if jar_ver else f"Framework JAR at {full_path}",
                    )],
                ))

                # Extract embedded Maven libraries and DEX components
                try:
                    zf = zipfile.ZipFile(io.BytesIO(jar_data))
                    embedded_libs = self._extract_embedded_maven_libs(zf, full_path)
                    components.extend(embedded_libs)

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
