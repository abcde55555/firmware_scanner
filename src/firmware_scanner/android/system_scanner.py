"""Android system scanner orchestrator.

Coordinates scanning an entire Android filesystem to identify all
components (APKs, native libraries, executables) with their versions.
"""

import gzip
import hashlib
import io
import json
import re
import xml.etree.ElementTree as ET
import zipfile
import zlib
from contextlib import ExitStack
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Protocol

from ..extraction.models import Component, ExtractionMethod, VersionConfidence
from .archive_licenses import ArchiveLicenseEvidence, extract_package_license_evidence
from .axml import AndroidManifestInfo, AXMLParser
from .build_prop import AndroidBuildInfo, BuildPropParser
from .notice_licenses import apply_notice_licenses, parse_notice_licenses
from .provenance import (
    apply_android_provenance,
    parse_notice_attributions,
    source_manifest_matches_image,
)


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
    provenance_stats: dict = field(default_factory=dict)
    database_stats: dict = field(default_factory=dict)
    analysis_stats: dict = field(default_factory=dict)
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

NOTICE_PATHS = [
    "/etc/NOTICE.html.gz",
    "/etc/NOTICE.html",
    "/system/etc/NOTICE.xml.gz",
    "/product/etc/NOTICE.xml.gz",
    "/vendor/etc/NOTICE.xml.gz",
    "/system_ext/etc/NOTICE.xml.gz",
    "/vendor/etc/NOTICE.xml",
    "/system/etc/NOTICE.xml",
]


class AndroidSystemScanner:
    """Orchestrates scanning of an extracted Android filesystem."""

    _MAX_DEX_SIZE = 64 * 1024 * 1024
    _MAX_TOTAL_DEX_SIZE = 256 * 1024 * 1024
    _MAX_DEX_ENTRIES = 64

    def __init__(
        self,
        fs_reader: FilesystemReader,
        max_apks: int = 500,
        max_libs: int = 2000,
        max_bins: int = 1000,
        source_manifest: dict | None = None,
        image_sha256: str | None = None,
        database_paths: dict[str, str | Path] | None = None,
        verify_database_integrity: bool = True,
    ):
        self._fs = fs_reader
        self._max_apks = max_apks
        self._max_libs = max_libs
        self._max_bins = max_bins
        self._source_manifest_error = ""
        if source_manifest is not None and not source_manifest_matches_image(
            source_manifest, image_sha256
        ):
            self._source_manifest = None
            self._source_manifest_error = (
                "Explicit Android source manifest lacks the scanned image SHA-256 or "
                "does not match it; source revisions were not applied"
            )
        else:
            self._source_manifest = source_manifest or self._registered_source_manifest(
                image_sha256
            )
        self._source_project_rules = self._load_source_project_rules()
        self._database_paths = {
            kind: Path(path) for kind, path in (database_paths or {}).items() if path
        }
        self._verify_database_integrity = verify_database_integrity
        self._database_enricher = None
        if self._database_paths:
            from ..databases import DatabaseEnricher

            self._database_enricher = DatabaseEnricher.from_paths(
                blint_path=self._database_paths.get("blintdb"),
                nsrl_path=self._database_paths.get("nsrl"),
                verify_hash=verify_database_integrity,
            )
        self._axml_parser = AXMLParser()
        self._build_prop_parser = BuildPropParser()

        from ..extraction.aibom import AIBOMScanner, DiscoveredAIModel, DiscoveredAIRuntime
        from ..extraction.cbom import CBOMScanner, DiscoveredCryptoAsset

        self._cbom_scanner = CBOMScanner()
        self._aibom_scanner = AIBOMScanner()
        self._crypto_assets_map: dict[str, DiscoveredCryptoAsset] = {}
        self._ai_models: list[DiscoveredAIModel] = []
        self._ai_runtimes: list[DiscoveredAIRuntime] = []
        self._binary_asset_cache: dict[
            bytes,
            tuple[list[DiscoveredCryptoAsset], list[DiscoveredAIRuntime]],
        ] = {}
        self._binary_asset_cache_hits = 0
        self._binary_asset_scans = 0
        self._cbom_regex_passes = 0
        self._aibom_regex_passes = 0
        self._cbom_detail_passes = 0
        self._aibom_detail_passes = 0
        self._cbom_scan_bytes = 0
        self._aibom_scan_bytes = 0
        self._coverage_warnings: set[str] = set()

    def scan(self) -> AndroidScanResult:
        """Perform full Android system scan."""
        result = AndroidScanResult()

        if not self._fs.is_valid():
            result.warnings.append("Filesystem reader is not valid")
            return result

        # 1. Parse build.prop for system-level metadata
        result.build_info = self._scan_build_props()
        if self._source_manifest_error:
            result.warnings.append(self._source_manifest_error)
        result.components.extend(self._build_prop_parser.to_components(result.build_info))

        # 2. Scan APEX mainline modules
        apex_components = self._scan_apex_modules()
        result.components.extend(apex_components)
        result.apex_count = sum(
            any(
                p.get("name") == "firmware:version:kind"
                and p.get("value") == "android-version-code"
                for p in c.properties
            )
            for c in apex_components
        )

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
            if (
                c.resolved_version
                and not c.resolved_version.endswith("+")
                and c.resolved_version != "detected"
            ):
                lib_version_map[c.name] = c.resolved_version
                base = c.name
                base = base.removeprefix("lib")
                base = base.removesuffix(".so")
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

        # 7. Scan common directories for AI/ML models
        ai_model_components = self._scan_ai_models()
        result.components.extend(ai_model_components)

        # 8. Apply AOSP baseline metadata annotation
        self._apply_os_version_fallback(result)
        result.provenance_stats = self._apply_android_provenance(result)

        # 9. Cryptographic Bill of Materials (CBOM)
        if self._crypto_assets_map:
            cbom_comps = self._cbom_scanner.to_components(list(self._crypto_assets_map.values()))
            result.components.extend(cbom_comps)

        # 10. AI Bill of Materials (AIBOM) runtimes
        if self._ai_runtimes:
            # Deduplicate runtimes
            seen_rts = set()
            unique_rts = []
            for rt in self._ai_runtimes:
                k = (rt.runtime_key, rt.binary_path)
                if k not in seen_rts:
                    seen_rts.add(k)
                    unique_rts.append(rt)
            aibom_comps = self._aibom_scanner.to_components([], unique_rts)
            result.components.extend(aibom_comps)

        # 11. Synthesize canonical NVD CPE 2.3 for components with valid upstream versions
        if self._database_enricher is not None:
            self._database_enricher.reconcile(result.components)
        from ..extraction.cpe_synthesizer import synthesize_component_cpe

        for c in result.components:
            if c.resolved_version and not c.cpe and self._should_synthesize_upstream_cpe(c):
                cpe_str = synthesize_component_cpe(c)
                if cpe_str:
                    c.cpe = cpe_str

        result.warnings.extend(sorted(self._coverage_warnings))
        if self._database_enricher is not None:
            result.database_stats = self._database_enricher.stats.as_dict()
            self._database_enricher.close()
        analysis_stats = self._inventory.analysis_stats if hasattr(self, "_inventory") else {}
        analysis_stats.update(
            {
                "binary_asset_cache_hits": self._binary_asset_cache_hits,
                "binary_asset_cache_entries": len(self._binary_asset_cache),
                "binary_asset_scans": self._binary_asset_scans,
                "cbom_regex_passes": self._cbom_regex_passes,
                "aibom_regex_passes": self._aibom_regex_passes,
                "cbom_detail_passes": self._cbom_detail_passes,
                "aibom_detail_passes": self._aibom_detail_passes,
                "cbom_scan_bytes": self._cbom_scan_bytes,
                "aibom_scan_bytes": self._aibom_scan_bytes,
            }
        )
        result.analysis_stats = analysis_stats
        return result

    @staticmethod
    def _should_synthesize_upstream_cpe(component) -> bool:
        resolution_state = next(
            (
                str(prop.get("value", ""))
                for prop in component.properties
                if prop.get("name") == "firmware:version:resolution-state"
            ),
            "",
        )
        if resolution_state and resolution_state != "exact":
            return False
        version_kind = next(
            (
                str(prop.get("value", ""))
                for prop in component.properties
                if prop.get("name") == "firmware:version:kind"
            ),
            "",
        )
        return not version_kind.startswith(("estimated-", "parent-package-"))

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
            "android_version",
            "sdk_version",
            "security_patch",
            "build_fingerprint",
            "manufacturer",
            "model",
            "brand",
            "board",
            "device",
            "build_type",
            "build_id",
            "incremental",
            "vendor_security_patch",
            "kernel_version",
            "baseband_version",
            "bootloader_version",
            "hardware",
            "platform",
            "abi",
        ):
            source_val = getattr(source, field_name, None)
            target_val = getattr(target, field_name, None)
            if source_val and not target_val:
                setattr(target, field_name, source_val)

        target.all_properties.update(source.all_properties)

    def _apply_os_version_fallback(self, result: AndroidScanResult):
        """Attach the Android build context; unknown library releases stay unknown."""
        info = result.build_info
        context = [
            ("release", info.android_version),
            ("security_patch", info.security_patch),
            ("build_id", info.build_id),
            ("fingerprint", info.build_fingerprint),
        ]
        for comp in result.components:
            if comp.component_type == "operating-system":
                if not comp.resolved_version and info.android_version:
                    comp.resolved_version = info.android_version
                continue
            if comp.resolved_version in ("detected", "unknown", "BoringSSL"):
                comp.resolved_version = ""
            for name, value in context:
                prop = {"name": f"firmware:android:{name}", "value": str(value)}
                if value and prop not in comp.properties:
                    comp.properties.append(prop)

    def _apply_android_provenance(self, result: AndroidScanResult) -> dict:
        """Attach image-local NOTICE/source provenance and parent package versions."""
        attributions: dict[str, set[str]] = {}
        license_stats = {
            "notice_files_matched": 0,
            "components_licensed": 0,
            "existing_licenses_preserved": 0,
        }
        for path in NOTICE_PATHS:
            data = self._fs.read_file(path, max_size=16 * 1024 * 1024)
            if not data:
                continue
            try:
                if data.startswith(b"\x1f\x8b"):
                    data = gzip.GzipFile(fileobj=io.BytesIO(data)).read(16 * 1024 * 1024 + 1)
                if len(data) > 16 * 1024 * 1024:
                    raise ValueError("decompressed NOTICE exceeds 16 MiB")
                if path.endswith((".html", ".html.gz")):
                    stats = apply_notice_licenses(
                        result.components,
                        parse_notice_licenses(data),
                        source=path,
                    )
                    for key, value in stats.items():
                        license_stats[key] += value
                else:
                    for location, labels in parse_notice_attributions(data).items():
                        attributions.setdefault(location, set()).update(labels)
            except (OSError, ValueError, EOFError, ET.ParseError) as exc:
                self._coverage_warnings.add(
                    f"Cannot parse Android NOTICE attribution {path}: {type(exc).__name__}: {exc}"
                )
        provenance = apply_android_provenance(
            result.components,
            notice_attributions=attributions,
            source_manifest=self._source_manifest,
            source_project_rules=self._source_project_rules,
        )
        provenance["notice_license_attribution"] = license_stats
        return provenance

    @staticmethod
    def _registered_source_manifest(image_sha256: str | None) -> dict | None:
        """Select an exact image-hash-matched source manifest from the rule pack."""
        if not image_sha256:
            return None
        root = Path(__file__).resolve().parents[1] / "data" / "provenance"
        if not root.is_dir():
            return None
        for path in sorted(root.glob("*.json")):
            try:
                manifest = json.loads(path.read_text())
            except (OSError, ValueError, TypeError):
                continue
            if str(manifest.get("image_sha256", "")).casefold() == image_sha256.casefold():
                return manifest
        return None

    @staticmethod
    def _load_source_project_rules() -> list[dict]:
        path = (
            Path(__file__).resolve().parents[1]
            / "data"
            / "provenance"
            / "android_source_project_rules.json"
        )
        try:
            rules = json.loads(path.read_text()).get("rules", [])
        except (OSError, ValueError, TypeError):
            return []
        return [rule for rule in rules if isinstance(rule, dict)]

    def _extract_embedded_maven_libs(
        self, zf: zipfile.ZipFile, origin_path: str
    ) -> list[Component]:
        """Read bounded, explicitly attributed dependency declarations."""
        from ..extraction.archive_metadata import extract_archive_metadata
        from ..extraction.sdk_metadata import extract_sdk_metadata

        warnings = []
        components = extract_archive_metadata(zf, origin_path, warnings)
        components.extend(extract_sdk_metadata(zf, origin_path, warnings))
        self._coverage_warnings.update(warnings)
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
                if not entry.name.endswith((".apex", ".capex")):
                    continue
                if entry.name in seen_names:
                    continue
                seen_names.add(entry.name)

                full_path = f"{dir_path.rstrip('/')}/{entry.name}"
                if self._fs.file_size(full_path) > 64 * 1024 * 1024:
                    self._coverage_warnings.add(
                        f"APEX archive exceeds the 64 MiB read limit: {full_path}"
                    )
                    continue
                data = self._fs.read_file(full_path, max_size=64 * 1024 * 1024)
                if not data or data[:2] != b"PK":
                    continue

                from .apex_payload import scan_apex_payload

                payload_result = scan_apex_payload(data, full_path, self._binary_inventory())
                components.extend(payload_result.components)
                self._coverage_warnings.update(payload_result.warnings)

                try:
                    zf = zipfile.ZipFile(io.BytesIO(data))
                    manifest_info = None
                    if "AndroidManifest.xml" in zf.namelist():
                        if zf.getinfo("AndroidManifest.xml").file_size <= 8 * 1024 * 1024:
                            manifest_data = zf.read("AndroidManifest.xml")
                            manifest_info = self._axml_parser.get_manifest_info(manifest_data)

                    bundled_libs = []
                    if (
                        "apex_manifest.pb" in zf.namelist()
                        and zf.getinfo("apex_manifest.pb").file_size <= 1024 * 1024
                    ):
                        pb_data = zf.read("apex_manifest.pb")
                        so_matches = re.findall(rb"([a-zA-Z0-9_\-\.]+\.so)", pb_data)
                        bundled_libs = [m.decode("ascii", errors="ignore") for m in so_matches]

                    zf.close()

                    pkg_name = (
                        manifest_info.package_name
                        if manifest_info and manifest_info.package_name
                        else entry.name.rsplit(".", 1)[0]
                    )
                    version_str = ""
                    if manifest_info and manifest_info.version_code:
                        version_str = str(manifest_info.version_code)
                    elif manifest_info and manifest_info.version_name:
                        version_str = manifest_info.version_name

                    purl = (
                        f"pkg:generic/{pkg_name}@{version_str}"
                        if version_str
                        else f"pkg:generic/{pkg_name}"
                    )
                    desc_parts = [f"APEX Mainline module at {full_path}"]
                    if version_str:
                        desc_parts.append(f"versionCode={version_str}")
                    if bundled_libs:
                        desc_parts.append(f"Bundled libs: {', '.join(bundled_libs[:5])}")

                    components.append(
                        Component(
                            name=pkg_name,
                            component_type="application",
                            resolved_version=version_str,
                            purl=purl,
                            description=" | ".join(desc_parts),
                            properties=[
                                {"name": "firmware:evidence:location", "value": full_path},
                                {"name": "firmware:version:kind", "value": "android-version-code"},
                            ],
                            versions=[
                                VersionConfidence(
                                    version=version_str if version_str else "",
                                    confidence=0.95 if version_str else 0.70,
                                    method=ExtractionMethod.MANIFEST_BINARY,
                                    evidence=f"APEX package at {full_path}",
                                )
                            ],
                        )
                    )
                except (
                    OSError,
                    ValueError,
                    zipfile.BadZipFile,
                    RuntimeError,
                    EOFError,
                    zlib.error,
                ) as exc:
                    self._coverage_warnings.add(
                        f"Cannot parse APEX module manifest: {full_path}: {exc}"
                    )
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
                elif entry.name.lower().endswith(".apk"):
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
            if entry.name.lower().endswith(".apk"):
                apk_path = f"{dir_path.rstrip('/')}/{entry.name}"
                return self._scan_single_apk(apk_path)

        return []

    def _scan_single_apk(self, apk_path: str) -> list[Component]:
        """Scan a single APK file to extract its manifest info and embedded libraries."""
        if callable(getattr(self._fs, "read_file_range", None)):
            from .archive_reader import FilesystemFile

            try:
                with (
                    FilesystemFile(self._fs, apk_path) as handle,
                    zipfile.ZipFile(handle) as archive,
                ):
                    return self._analyze_apk_archive(archive, apk_path)
            except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as error:
                self._coverage_warnings.add(
                    f"Cannot read complete APK archive: {apk_path}: {type(error).__name__}"
                )
        limit = 128 * 1024 * 1024
        if hasattr(self._fs, "file_size") and self._fs.file_size(apk_path) > limit:
            self._coverage_warnings.add(
                f"APK exceeds 128 MiB scan limit: {apk_path}; embedded libraries may be unavailable"
            )
        apk_data = self._fs.read_file(apk_path, max_size=limit)
        if not apk_data:
            name = Path(apk_path).stem
            return [
                Component(
                    name=name,
                    component_type="application",
                    resolved_version="",
                    description=f"APK at {apk_path} (unreadable)",
                    properties=[
                        {
                            "name": "firmware:evidence:location",
                            "value": apk_path,
                        }
                    ],
                    versions=[
                        VersionConfidence(
                            version="",
                            confidence=0.45,
                            method=ExtractionMethod.STRING_PATTERN,
                            evidence=f"APK at {apk_path} (unreadable)",
                        )
                    ],
                )
            ]

        return self._analyze_apk_data(apk_data, apk_path)

    def _analyze_apk_data(self, apk_data: bytes, apk_path: str) -> list[Component]:
        """Analyze APK data (ZIP format) to extract manifest info and embedded libraries."""
        if apk_data[:2] == b"PK":
            try:
                with zipfile.ZipFile(io.BytesIO(apk_data)) as archive:
                    return self._analyze_apk_archive(archive, apk_path, apk_data)
            except (OSError, ValueError, RuntimeError, zipfile.BadZipFile):
                pass
        manifest_info = self._extract_manifest_from_raw(apk_data)
        return self._components_from_apk_manifest(manifest_info, apk_path, [])

    def _analyze_apk_archive(self, archive, apk_path, raw_data=None):
        """Analyse selected archive entries, keeping APK size independent of RAM."""
        manifest_info = None
        license_evidence = extract_package_license_evidence(archive, apk_path)
        try:
            entry = archive.getinfo("AndroidManifest.xml")
            if entry.file_size > 8 * 1024 * 1024:
                self._coverage_warnings.add(f"APK manifest exceeds 8 MiB budget: {apk_path}")
            else:
                with archive.open(entry) as stream:
                    manifest = stream.read(8 * 1024 * 1024 + 1)
                if len(manifest) <= 8 * 1024 * 1024:
                    manifest_info = self._axml_parser.get_manifest_info(manifest)
        except KeyError:
            pass
        except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, zlib.error, EOFError):
            self._coverage_warnings.add(f"Cannot read APK manifest: {apk_path}")
        if not manifest_info and raw_data is not None:
            manifest_info = self._extract_manifest_from_raw(raw_data)
        embedded_libs = self._extract_embedded_maven_libs(archive, apk_path)
        embedded_libs.extend(self._extract_embedded_native_libs(archive, apk_path))
        embedded_libs.extend(self._extract_embedded_dex_components(archive, apk_path))
        return self._components_from_apk_manifest(
            manifest_info,
            apk_path,
            embedded_libs,
            license_evidence=license_evidence,
        )

    def _extract_embedded_dex_components(self, archive, origin):
        """Analyze root multidex entries with per-entry and aggregate size bounds."""
        dex_entries = []
        for entry in archive.infolist():
            match = re.fullmatch(r"classes([2-9]|[1-9][0-9]{1,5})?\.dex", entry.filename)
            if match:
                dex_index = int(match.group(1) or "1")
                dex_entries.append((dex_index, entry.filename, entry))
        dex_entries.sort(key=lambda item: (item[0], item[1]))

        if len(dex_entries) > self._MAX_DEX_ENTRIES:
            self._coverage_warnings.add(
                f"DEX entry count exceeds {self._MAX_DEX_ENTRIES}: {origin}; remaining DEX files were skipped"
            )

        from ..extraction.smart_analyzer import SmartSectionAnalyzer

        analyzer = SmartSectionAnalyzer()
        components = []
        total_size = 0
        for _, entry_name, entry in dex_entries[: self._MAX_DEX_ENTRIES]:
            path = f"{origin}!/{entry_name}"
            remaining = self._MAX_TOTAL_DEX_SIZE - total_size
            if entry.file_size > self._MAX_DEX_SIZE:
                self._coverage_warnings.add(
                    f"DEX entry exceeds {self._MAX_DEX_SIZE // (1024 * 1024)} MiB limit: {path}"
                )
                continue
            if entry.file_size > remaining:
                self._coverage_warnings.add(f"DEX total decompression budget exceeded: {path}")
                continue

            # Reserve the member's entire budget before reading: a CRC error
            # may occur after decompression without returning the final bytes.
            total_size += entry.file_size
            try:
                with archive.open(entry) as stream:
                    data = bytearray()
                    while len(data) <= entry.file_size:
                        chunk = stream.read(min(1024 * 1024, entry.file_size + 1 - len(data)))
                        if not chunk:
                            break
                        data.extend(chunk)
                if len(data) != entry.file_size:
                    self._coverage_warnings.add(f"Cannot completely read DEX entry: {path}")
                    continue
                if data[:4] != b"dex\n":
                    self._coverage_warnings.add(f"Invalid DEX entry: {path}")
                    continue
                if data[4:8] not in (b"035\0", b"036\0", b"037\0", b"038\0", b"039\0", b"040\0"):
                    self._coverage_warnings.add(f"Unsupported DEX format version: {path}")
                    continue
                found = analyzer.analyze_section(path, bytes(data))
                self._merge_dex_components(components, found)
            except Exception as error:  # noqa: BLE001 - isolate failures to this archive member
                self._coverage_warnings.add(
                    f"Cannot analyze DEX entry: {path}: {type(error).__name__}"
                )
        return components

    @staticmethod
    def _merge_dex_components(target, discovered):
        """Merge repeated DEX findings while retaining distinct location evidence."""
        by_identity = {
            (
                component.name,
                component.component_type,
                component.resolved_version,
                component.purl,
            ): component
            for component in target
        }
        for component in discovered:
            identity = (
                component.name,
                component.component_type,
                component.resolved_version,
                component.purl,
            )
            existing = by_identity.get(identity)
            if existing is None:
                target.append(component)
                by_identity[identity] = component
                continue
            existing_evidence = {
                (version.version, version.method, version.evidence) for version in existing.versions
            }
            for version in component.versions:
                evidence = (version.version, version.method, version.evidence)
                if evidence not in existing_evidence:
                    existing.versions.append(version)
                    existing_evidence.add(evidence)
            for prop in component.properties:
                if prop not in existing.properties:
                    existing.properties.append(prop)

    def _components_from_apk_manifest(
        self,
        manifest_info,
        apk_path,
        embedded_libs,
        *,
        license_evidence: ArchiveLicenseEvidence | None = None,
    ):
        if not manifest_info or not manifest_info.package_name:
            name = Path(apk_path).stem
            apk_comp = Component(
                name=name,
                component_type="application",
                resolved_version="",
                description=f"APK found at {apk_path}",
                versions=[
                    VersionConfidence(
                        version="",
                        confidence=0.50,
                        method=ExtractionMethod.STRING_PATTERN,
                        evidence=f"APK found at {apk_path}",
                    )
                ],
            )
            self._apply_package_license_evidence(apk_comp, license_evidence)
            return [apk_comp] + embedded_libs

        # Build component from manifest info
        version = manifest_info.version_name or (
            str(manifest_info.version_code) if manifest_info.version_code else ""
        )
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
            versions=[
                VersionConfidence(
                    version=version if version else "",
                    confidence=confidence,
                    method=ExtractionMethod.MANIFEST_BINARY,
                    evidence=f"AndroidManifest.xml in {apk_path}",
                )
            ],
            purl=f"pkg:apk/{manifest_info.package_name}@{version}"
            if version
            else f"pkg:apk/{manifest_info.package_name}",
            description="; ".join(desc_parts),
            properties=[
                {
                    "name": "firmware:evidence:location",
                    "value": apk_path,
                }
            ],
        )
        self._apply_package_license_evidence(apk_comp, license_evidence)

        return [apk_comp] + embedded_libs

    @staticmethod
    def _apply_package_license_evidence(
        component: Component,
        evidence: ArchiveLicenseEvidence | None,
    ) -> None:
        if evidence is None or not evidence.licenses:
            return
        component.licenses = sorted(set(component.licenses) | set(evidence.licenses))
        for location in evidence.files:
            prop = {"name": "firmware:license:evidence", "value": location}
            if prop not in component.properties:
                component.properties.append(prop)
        component.properties.append(
            {
                "name": "firmware:license:match-confidence",
                "value": "0.95",
            }
        )

    def _extract_embedded_native_libs(self, archive, origin):
        components = []
        total = 0
        count = 0
        for entry in archive.infolist():
            if not re.fullmatch(r"lib/[^/]+/[^/]+\.so", entry.filename):
                continue
            # Chromium and speech runtimes routinely exceed 32 MiB. Bound each
            # binary and the archive total, while streaming compressed members.
            limit = 256 * 1024 * 1024
            if (
                count >= 1000
                or entry.file_size > limit
                or total + entry.file_size > 512 * 1024 * 1024
            ):
                self._coverage_warnings.add(
                    f"Embedded native library scan limit reached: {origin}!/{entry.filename}"
                )
                continue
            try:
                with archive.open(entry) as stream:
                    buffer = io.BytesIO()
                    while buffer.tell() <= entry.file_size:
                        chunk = stream.read(min(1024 * 1024, entry.file_size + 1 - buffer.tell()))
                        if not chunk:
                            break
                        buffer.write(chunk)
                    data = buffer.getvalue()
                if len(data) != entry.file_size or len(data) > limit:
                    self._coverage_warnings.add(
                        f"Truncated or oversized embedded native library: {origin}!/{entry.filename}"
                    )
                    continue
                total += len(data)
                count += 1
                path = f"{origin}!/{entry.filename}"
                components.extend(
                    self._binary_inventory().extract(data, Path(entry.filename).name, path)
                )
            except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, zlib.error, EOFError):
                self._coverage_warnings.add(
                    f"Cannot read embedded native library: {origin}!/{entry.filename}"
                )
        return components

    def _extract_manifest_from_raw(self, apk_data: bytes) -> AndroidManifestInfo | None:
        """Extract AndroidManifest.xml directly from ZIP local file headers.

        When the ZIP central directory is corrupted (common in YAFFS2 dumps due to
        page reordering), local file headers are still intact. This method finds the
        manifest entry and decompresses it directly.
        """
        import struct
        import zlib

        # Find the local file header for AndroidManifest.xml
        search_name = b"AndroidManifest.xml"
        pos = apk_data.find(search_name)
        if pos == -1:
            return None

        # Back up to find the PK\x03\x04 local header
        search_start = max(0, pos - 100)
        header_pos = apk_data.rfind(b"PK\x03\x04", search_start, pos)
        if header_pos == -1:
            return None

        # Parse local file header
        if header_pos + 30 > len(apk_data):
            return None
        comp_method = struct.unpack_from("<H", apk_data, header_pos + 8)[0]
        comp_size = struct.unpack_from("<I", apk_data, header_pos + 18)[0]
        uncomp_size = struct.unpack_from("<I", apk_data, header_pos + 22)[0]
        fname_len = struct.unpack_from("<H", apk_data, header_pos + 26)[0]
        extra_len = struct.unpack_from("<H", apk_data, header_pos + 28)[0]

        data_start = header_pos + 30 + fname_len + extra_len

        if comp_size == 0 or comp_size > 1024 * 1024:
            return None
        if data_start + comp_size > len(apk_data):
            return None

        compressed = apk_data[data_start : data_start + comp_size]

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

    def _binary_inventory(self):
        if not hasattr(self, "_inventory"):
            from ..extraction.binary_inventory import BinaryInventory

            self._inventory = BinaryInventory(
                database_enricher=self._database_enricher,
                source_manifest=self._source_manifest,
            )
        return self._inventory

    def _read_elf_bytes(self, path):
        limit = 32 * 1024 * 1024
        if hasattr(self._fs, "file_size") and self._fs.file_size(path) > limit:
            self._coverage_warnings.add(
                f"ELF exceeds 32 MiB scan limit: {path}; symbol and version extraction may be incomplete"
            )
        return self._fs.read_file(path, max_size=limit)

    def _collect_binary_assets(self, path, data):
        content_key = hashlib.sha256(data).digest()
        cached = self._binary_asset_cache.get(content_key)
        if cached is None:
            self._binary_asset_scans += 1
            cached = (
                self._cbom_scanner.scan_binary(path, data),
                self._aibom_scanner.scan_binary_for_runtimes(path, data),
            )
            self._cbom_regex_passes += self._cbom_scanner.last_scan_passes
            self._aibom_regex_passes += self._aibom_scanner.last_scan_passes
            self._cbom_detail_passes += self._cbom_scanner.last_detail_passes
            self._aibom_detail_passes += self._aibom_scanner.last_detail_passes
            self._cbom_scan_bytes += self._cbom_scanner.last_scan_bytes
            self._aibom_scan_bytes += self._aibom_scanner.last_scan_bytes
            if len(self._binary_asset_cache) < 2048:
                self._binary_asset_cache[content_key] = cached
        else:
            self._binary_asset_cache_hits += 1

        crypto_assets, ai_runtimes = cached
        for ca in crypto_assets:
            ca = replace(ca, matched_locations=[path])
            existing = self._crypto_assets_map.get(ca.algorithm_key)
            if existing:
                existing.hit_count += ca.hit_count
                if path not in existing.matched_locations:
                    existing.matched_locations.append(path)
            else:
                self._crypto_assets_map[ca.algorithm_key] = ca
        self._ai_runtimes.extend(replace(runtime, binary_path=path) for runtime in ai_runtimes)

    def _walk_binary_directories(self, roots, max_depth=3):
        seen = set()
        pending = [(root, 0) for root in roots]
        while pending:
            directory, depth = pending.pop(0)
            if directory in seen or not self._fs.exists(directory):
                continue
            seen.add(directory)
            for entry in sorted(self._fs.list_directory(directory), key=lambda e: e.name):
                path = f"{directory.rstrip('/')}/{entry.name}"
                if entry.is_dir and depth < max_depth:
                    pending.append((path, depth + 1))
                elif entry.is_file:
                    yield path, entry.name

    def _scan_native_libs(self) -> list[Component]:
        components = []
        seen_paths = set()
        scanned = 0
        for path, filename in self._walk_binary_directories(LIB_DIRECTORIES):
            if scanned >= self._max_libs:
                break
            if path in seen_paths or not re.search(
                r"\.so(?:\.\d[\d.]*)?$", filename, re.IGNORECASE
            ):
                continue
            seen_paths.add(path)
            data = self._read_elf_bytes(path)
            if not data or not data.startswith(b"\x7fELF"):
                continue
            self._collect_binary_assets(path, data)
            components.extend(self._binary_inventory().extract(data, filename, path))
            scanned += 1
        return components

    def _analyze_native_lib(
        self, path: str, filename: str, partition: str = "system"
    ) -> Component | None:
        data = self._read_elf_bytes(path)
        if not data:
            return None
        components = self._binary_inventory().extract(data, filename, path)
        return components[0] if components else None

    # Patterns for extracting versions from well-known libraries
    _KNOWN_LIB_PATTERNS: dict[str, list[tuple[bytes, str]]] = {
        "ssl": [
            (rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)", "OpenSSL version string"),
            (rb"BoringSSL", "BoringSSL (unversioned)"),
        ],
        "crypto": [
            (rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)", "OpenSSL version string"),
        ],
        "sqlite": [
            (rb"(\d+\.\d+\.\d+(?:\.\d+)?)\x00.{0,32}SQLite", "SQLite version string"),
            (rb"SQLite (\d+\.\d+\.\d+)", "SQLite version string"),
            (rb"(3\.\d+\.\d+)\x00", "SQLite 3.x version string"),
        ],
        "expat": [
            (rb"expat_(\d+\.\d+\.\d+)", "expat version string"),
            (rb"(\d+\.\d+\.\d+)\x00.{0,16}expat", "expat version string"),
        ],
        "curl": [
            (rb"libcurl/(\d+\.\d+\.\d+)", "libcurl version string"),
            (rb"curl (\d+\.\d+\.\d+)", "curl version string"),
        ],
        "z": [
            (rb"(\d+\.\d+\.\d+(?:\.\d+)?)\x00.{0,8}deflate", "zlib version string"),
            (rb"inflate (\d+\.\d+\.\d+)", "zlib version string"),
        ],
        "png": [
            (rb"libpng-(\d+\.\d+\.\d+)", "libpng version string"),
            (rb"PNG Library (\d+\.\d+\.\d+)", "libpng version string"),
        ],
        "png16": [
            (rb"libpng-(\d+\.\d+\.\d+)", "libpng version string"),
        ],
        "jpeg": [
            (rb"(\d+\.\d+)\x00.{0,16}JFIF", "libjpeg version string"),
            (rb"libjpeg-turbo (\d+\.\d+\.\d+)", "libjpeg-turbo version string"),
        ],
        "freetype": [
            (rb"FreeType (\d+\.\d+\.\d+)", "FreeType version string"),
            (rb"(\d+\.\d+\.\d+)\x00.{0,16}freetype", "FreeType version string"),
        ],
        "harfbuzz": [
            (rb"HarfBuzz (\d+\.\d+\.\d+)", "HarfBuzz version string"),
            (rb"(\d+\.\d+\.\d+)\x00.{0,16}[Hh]arf[Bb]uzz", "HarfBuzz version string"),
        ],
        "xml2": [
            (rb"libxml2-(\d+\.\d+\.\d+)", "libxml2 version string"),
            (rb"(\d+\.\d+\.\d+)\x00.{0,16}libxml", "libxml2 version string"),
        ],
        "icuuc": [
            (rb"ICU (\d+\.\d+(?:\.\d+)?)", "ICU version string"),
            (rb"icudt(\d+)", "ICU data version"),
        ],
        "icui18n": [
            (rb"ICU (\d+\.\d+(?:\.\d+)?)", "ICU version string"),
        ],
        "sqlite_jni": [
            (rb"(3\.\d+\.\d+)\x00", "SQLite 3.x version string"),
        ],
        "webcore": [
            (rb"WebKit/(\d+\.\d+)", "WebKit version string"),
            (rb"AppleWebKit/(\d+\.\d+)", "WebKit version string"),
        ],
        "stlport": [
            (rb"STLport-(\d+\.\d+)", "STLport version string"),
        ],
        "vpx": [
            (rb"libvpx v(\d+\.\d+\.\d+)", "libvpx version string"),
            (rb"v(\d+\.\d+\.\d+)\x00.{0,32}vpx", "libvpx version string"),
        ],
        "opus": [
            (rb"libopus (\d+\.\d+(?:\.\d+)?)", "libopus version string"),
        ],
        "pcre2": [
            (rb"(\d+\.\d+)\s+\d{4}-\d{2}-\d{2}", "PCRE2 version string"),
        ],
        "pcre": [
            (rb"(\d+\.\d+)\s+\d{4}-\d{2}-\d{2}", "PCRE version string"),
        ],
        "binder": [],
        "utils": [],
        "cutils": [],
        "log": [],
    }

    # Patterns for extracting versions from well-known executables
    _KNOWN_BIN_PATTERNS: dict[str, list[tuple[bytes, str]]] = {
        "toybox": [
            (rb"(\d+\.\d+\.\d+)-android", "Toybox Android version string"),
            (rb"toybox (\d+\.\d+\.\d+)", "Toybox version string"),
        ],
        "curl": [
            (rb"curl (\d+\.\d+\.\d+)", "curl version string"),
            (rb"libcurl/(\d+\.\d+\.\d+)", "libcurl version string"),
        ],
        "e2fsck": [
            (rb"version of e2fsck!\x00(\d+\.\d+\.\d+)", "e2fsck version string"),
            (rb"e2fsck (\d+\.\d+\.\d+)", "e2fsck version string"),
            (rb"(\d+\.\d+\.\d+)\x00%12u non-contiguous", "e2fsck version string"),
        ],
        "dnsmasq": [
            (rb"dnsmasq(?: version)? (\d+\.\d+(?:\.\d+)?)", "dnsmasq version string"),
        ],
        "wpa_supplicant": [
            (rb"wpa_supplicant v(\d+\.\d+(?:\.\d+)?)", "wpa_supplicant version string"),
        ],
        "busybox": [
            (rb"BusyBox v(\d+\.\d+\.\d+)", "BusyBox version string"),
        ],
        "iptables": [
            (rb"iptables v(\d+\.\d+\.\d+)", "iptables version string"),
        ],
        "ip6tables": [
            (rb"ip6tables v(\d+\.\d+\.\d+)", "ip6tables version string"),
        ],
        "grep": [
            (rb"grep \(GNU grep\) (\d+\.\d+)", "GNU grep version string"),
        ],
        "tar": [
            (rb"tar \(GNU tar\) (\d+\.\d+)", "GNU tar version string"),
        ],
        "gzip": [
            (rb"gzip (\d+\.\d+\.\d+)", "gzip version string"),
        ],
    }

    def _extract_known_lib_version(self, lib_name: str, data: bytes) -> tuple[str, str] | None:
        """Try to extract version from well-known library binary data."""
        patterns = self._KNOWN_LIB_PATTERNS.get(lib_name.lower())
        if patterns is None:
            return None

        # Search in first 2MB for version strings (they're usually in .rodata near the start)
        search_data = data[: 2 * 1024 * 1024]

        for pattern, evidence_desc in patterns:
            match = re.search(pattern, search_data)
            if match:
                if match.groups():
                    version = match.group(1).decode("ascii", errors="replace")
                    return (
                        version,
                        f"{evidence_desc}: {match.group(0).decode('ascii', errors='replace')}",
                    )
                else:
                    # Pattern matched but no capture group (e.g., BoringSSL)
                    return ("", evidence_desc)

        return None

    def _extract_known_bin_version(self, bin_name: str, data: bytes) -> tuple[str, str] | None:
        """Try to extract version from well-known binary data."""
        patterns = self._KNOWN_BIN_PATTERNS.get(bin_name.lower())
        if not patterns:
            return None
        search_data = data[: 1024 * 1024]
        for pattern, desc in patterns:
            match = re.search(pattern, search_data)
            if match and match.groups():
                return (
                    match.group(1).decode("ascii", errors="replace"),
                    f"{desc}: {match.group(0).decode('ascii', errors='replace')}",
                )
        return None

    def _scan_executables(self, lib_version_map: dict[str, str] | None = None) -> list[Component]:
        # A similarly named library is not evidence for an executable's release.
        components = []
        seen_paths = set()
        scanned = 0
        for path, filename in self._walk_binary_directories(BIN_DIRECTORIES):
            if scanned >= self._max_bins:
                break
            if path in seen_paths:
                continue
            seen_paths.add(path)
            data = self._read_elf_bytes(path)
            if not data or not data.startswith(b"\x7fELF"):
                continue
            self._collect_binary_assets(path, data)
            components.extend(self._binary_inventory().extract(data, filename, path, "application"))
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
                if not name_lower.endswith(".jar") and not name_lower.endswith(".apk"):
                    continue

                full_path = f"{dir_path.rstrip('/')}/{entry.name}"
                try:
                    with ExitStack() as stack:
                        if callable(getattr(self._fs, "read_file_range", None)):
                            from .archive_reader import FilesystemFile

                            handle = stack.enter_context(FilesystemFile(self._fs, full_path))
                        else:
                            limit = 128 * 1024 * 1024
                            if (
                                callable(getattr(self._fs, "file_size", None))
                                and self._fs.file_size(full_path) > limit
                            ):
                                self._coverage_warnings.add(
                                    f"Framework archive exceeds 128 MiB fallback limit: {full_path}"
                                )
                                continue
                            jar_data = self._fs.read_file(full_path, max_size=limit)
                            if not jar_data or jar_data[:2] != b"PK":
                                continue
                            handle = stack.enter_context(io.BytesIO(jar_data))
                        zf = stack.enter_context(zipfile.ZipFile(handle))
                        jar_name = entry.name.rsplit(".", 1)[0]
                        match = re.search(r"-V(\d+(?:\.\d+)?)(?:-java)?$", jar_name)
                        jar_ver = f"V{match.group(1)}" if match else ""
                        components.append(
                            Component(
                                name=f"framework/{jar_name}",
                                component_type="framework",
                                resolved_version=jar_ver,
                                purl=f"pkg:generic/framework/{jar_name}@{jar_ver}"
                                if jar_ver
                                else "",
                                description=f"Framework JAR at {full_path}",
                                versions=[
                                    VersionConfidence(
                                        version=jar_ver,
                                        confidence=0.90 if jar_ver else 0.60,
                                        method=(
                                            ExtractionMethod.MANIFEST_BINARY
                                            if jar_ver
                                            else ExtractionMethod.STRING_PATTERN
                                        ),
                                        evidence=(
                                            f"Framework interface {jar_ver}"
                                            if jar_ver
                                            else f"Framework JAR at {full_path}"
                                        ),
                                    )
                                ],
                            )
                        )
                        components.extend(self._extract_embedded_maven_libs(zf, full_path))
                        components.extend(self._extract_embedded_dex_components(zf, full_path))
                except (
                    OSError,
                    ValueError,
                    RuntimeError,
                    zipfile.BadZipFile,
                    zlib.error,
                    EOFError,
                ) as error:
                    self._coverage_warnings.add(
                        f"Cannot scan framework archive: {full_path}: {type(error).__name__}"
                    )

        return components

    def _scan_ai_models(self) -> list[Component]:
        """Scan common firmware directories for AI/ML model files."""
        model_dirs = [
            "/system/etc",
            "/system/vendor/etc",
            "/vendor/etc",
            "/product/etc",
            "/system_ext/etc",
            "/system/usr",
            "/etc",
        ]
        discovered_models = []
        seen_paths: set[str] = set()

        for dir_path in model_dirs:
            if not self._fs.exists(dir_path):
                continue
            try:
                entries = self._fs.list_directory(dir_path)
            except Exception:
                continue

            for entry in entries:
                if entry.is_dir:
                    sub_path = f"{dir_path.rstrip('/')}/{entry.name}"
                    try:
                        sub_entries = self._fs.list_directory(sub_path)
                    except Exception:
                        continue
                    for sub_entry in sub_entries:
                        if sub_entry.is_file:
                            full_sub = f"{sub_path}/{sub_entry.name}"
                            if full_sub not in seen_paths:
                                seen_paths.add(full_sub)
                                head = self._fs.read_file(full_sub, max_size=4096)
                                if head:
                                    sz = self._fs.file_size(full_sub)
                                    m = self._aibom_scanner.scan_file_header(full_sub, head, sz)
                                    if m:
                                        discovered_models.append(m)
                elif entry.is_file:
                    full_path = f"{dir_path.rstrip('/')}/{entry.name}"
                    if full_path not in seen_paths:
                        seen_paths.add(full_path)
                        head = self._fs.read_file(full_path, max_size=4096)
                        if head:
                            sz = self._fs.file_size(full_path)
                            m = self._aibom_scanner.scan_file_header(full_path, head, sz)
                            if m:
                                discovered_models.append(m)

        self._ai_models.extend(discovered_models)
        return self._aibom_scanner.to_components(discovered_models, [])
