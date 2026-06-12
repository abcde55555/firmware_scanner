"""Vulnerability matcher - orchestrates component scanning against OSV."""

import urllib.error
from typing import Callable

from ..extraction.models import Component
from .models import ComponentVulnResult, VulnScanResult, Severity
from .osv_client import OSVClient


# Maps firmware library names to upstream project names recognized by OSV
_NAME_ALIASES: dict[str, str] = {
    "libcrypto": "openssl",
    "libssl": "openssl",
    "openssl": "openssl",
    "libz": "zlib",
    "zlib": "zlib",
    "libcurl": "curl",
    "curl": "curl",
    "libsqlite": "sqlite3",
    "libsqlite3": "sqlite3",
    "sqlite": "sqlite3",
    "libexpat": "expat",
    "libxml2": "libxml2",
    "libpng": "libpng",
    "libpng16": "libpng",
    "libjpeg": "libjpeg-turbo",
    "libjpeg-turbo": "libjpeg-turbo",
    "libfreetype": "freetype",
    "freetype": "freetype",
    "libpcre": "pcre2",
    "libpcre2": "pcre2",
    "libbz2": "bzip2",
    "bzip2": "bzip2",
    "liblzma": "xz",
    "xz": "xz",
    "libnghttp2": "nghttp2",
    "nghttp2": "nghttp2",
    "libprotobuf": "protobuf",
    "protobuf": "protobuf",
    "libboringssl": "boringssl",
    "boringssl": "boringssl",
    "libbrotli": "brotli",
    "brotli": "brotli",
    "libicu": "icu",
    "icu4c": "icu",
    "libharfbuzz": "harfbuzz",
    "harfbuzz": "harfbuzz",
    "libwebp": "libwebp",
    "libtiff": "libtiff",
    "libavcodec": "ffmpeg",
    "libavformat": "ffmpeg",
    "libavutil": "ffmpeg",
    "ffmpeg": "ffmpeg",
    "libopus": "opus",
    "libvpx": "libvpx",
    "libuv": "libuv",
    "libssh2": "libssh2",
    "libssh": "libssh",
    "dnsmasq": "dnsmasq",
    "busybox": "busybox",
    "dropbear": "dropbear",
    "lighttpd": "lighttpd",
    "nginx": "nginx",
    "apache": "apache-http-server",
    "hostapd": "hostapd",
    "wpa_supplicant": "wpa_supplicant",
    "dbus": "dbus",
    "libdbus": "dbus",
    "glib": "glib",
    "libglib": "glib",
    "bluez": "bluez",
    "kernel": "linux",
    "linux": "linux",
    "u-boot": "u-boot",
    "uboot": "u-boot",
    "grub": "grub2",
    "openssh": "openssh",
    "libopenssh": "openssh",
    "mbedtls": "mbedtls",
    "libmbedtls": "mbedtls",
    "wolfssl": "wolfssl",
    "libwolfssl": "wolfssl",
    "libnss": "nss",
    "nss": "nss",
    "libgnutls": "gnutls",
    "gnutls": "gnutls",
    "miniupnpc": "miniupnpc",
    "miniupnpd": "miniupnpd",
    "libminiupnpc": "miniupnpc",
    "android": "Android",
}


def _normalize_name(name: str) -> str:
    """Normalize component name to upstream project name for OSV lookup."""
    lower = name.lower().strip()
    # Strip common suffixes
    for suffix in (".so", ".a", ".dylib", ".dll"):
        if lower.endswith(suffix):
            lower = lower[: -len(suffix)]
    # Strip version suffixes like libcrypto.so.1.1
    while lower and lower[-1].isdigit() or lower.endswith("."):
        lower = lower.rstrip("0123456789.")
    # Direct alias lookup
    if lower in _NAME_ALIASES:
        return _NAME_ALIASES[lower]
    # Try without 'lib' prefix
    if lower.startswith("lib") and lower[3:] in _NAME_ALIASES:
        return _NAME_ALIASES[lower[3:]]
    return name


# Versions that aren't real version numbers
_INVALID_VERSIONS = {"detected", "unknown", "n/a", ""}


def _is_scannable(component: Component) -> bool:
    """Check if a component has enough info for a meaningful vulnerability query."""
    ver = component.resolved_version.strip().lower()
    if ver in _INVALID_VERSIONS:
        return False
    # Skip pure Android framework components
    if component.name.startswith("framework/"):
        return False
    # Skip Android APK packages (pkg:apk/...) - they're not tracked in OSV
    if component.purl and component.purl.startswith("pkg:apk/"):
        return False
    # Skip Java/Android package names (com.xxx.yyy style)
    if "." in component.name:
        parts = component.name.split(".")
        if len(parts) >= 2 and all(p.replace("_", "").isalnum() for p in parts):
            return False
    # Has a non-APK purl (npm, pypi, maven, etc.) - always scan
    if component.purl:
        return True
    # Known upstream project mapping - always scan
    normalized = _normalize_name(component.name)
    if normalized.lower() != component.name.lower():
        return True
    # Unknown lib without known mapping - only scan if 3-part version
    lower = component.name.lower()
    if lower.startswith("lib"):
        if not _is_real_version(ver):
            return False
    return True


def _is_real_version(ver: str) -> bool:
    """Check if version looks like a genuine upstream version (e.g., 1.2.3, 7.79.1)."""
    parts = ver.split(".")
    if len(parts) < 3:
        return False
    try:
        int(parts[0])
        return True
    except ValueError:
        return False


class VulnMatcher:
    def __init__(
        self,
        client: OSVClient | None = None,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ):
        self._client = client or OSVClient()
        self._progress = progress_callback

    def scan(self, components: list[Component]) -> VulnScanResult:
        scannable = [c for c in components if _is_scannable(c)]
        result = VulnScanResult(total_components_scanned=len(scannable))

        if not scannable:
            return result

        # Deduplicate by normalized name + version to avoid redundant queries
        seen: dict[str, int] = {}
        unique_queries: list[dict] = []
        query_map: list[int] = []  # maps scannable index -> unique_queries index

        for comp in scannable:
            q = self._build_query(comp)
            dedup_key = f"{q.get('name', q.get('purl', ''))}@{q.get('version', '')}"
            if dedup_key in seen:
                query_map.append(seen[dedup_key])
            else:
                seen[dedup_key] = len(unique_queries)
                query_map.append(len(unique_queries))
                unique_queries.append(q)

        if self._progress:
            self._progress(0, len(scannable), "Checking cache freshness...")

        is_fresh, age = self._client.check_cache_freshness()
        if age is not None and not is_fresh:
            result.errors.append(f"Vulnerability cache is {age:.1f}h old (>24h), refreshing from OSV...")

        if self._progress:
            self._progress(0, len(unique_queries), f"Querying OSV ({len(unique_queries)} unique packages)...")

        try:
            unique_results = self._client.query_with_cache(unique_queries)
        except (urllib.error.URLError, OSError) as e:
            result.errors.append(f"OSV API unreachable: {e}. Using cached data where available.")
            unique_results = [[] for _ in unique_queries]

        for idx, comp in enumerate(scannable):
            if self._progress:
                self._progress(idx + 1, len(scannable), comp.name)

            raw_vulns = unique_results[query_map[idx]]
            vulns = self._client.parse_vulns(raw_vulns)
            comp_result = ComponentVulnResult(
                component_name=comp.name,
                component_version=comp.resolved_version,
                purl=comp.purl,
                cpe=comp.cpe,
                vulnerabilities=vulns,
            )
            result.results.append(comp_result)
            result.total_vulnerabilities += len(vulns)
            for v in vulns:
                if v.severity == Severity.CRITICAL:
                    result.critical_count += 1
                elif v.severity == Severity.HIGH:
                    result.high_count += 1
                elif v.severity == Severity.MEDIUM:
                    result.medium_count += 1
                elif v.severity == Severity.LOW:
                    result.low_count += 1
                else:
                    result.unknown_count += 1

        return result

    def _build_query(self, component: Component) -> dict:
        if component.purl:
            return {
                "purl": component.purl,
                "name": component.name,
                "version": component.resolved_version,
            }
        normalized = _normalize_name(component.name)
        ecosystem = self._infer_ecosystem(component)
        return {
            "name": normalized,
            "version": component.resolved_version,
            "ecosystem": ecosystem,
        }

    def _infer_ecosystem(self, component: Component) -> str:
        if component.purl:
            parts = component.purl.split("/")
            if len(parts) >= 2:
                scheme = parts[0].replace("pkg:", "")
                ecosystem_map = {
                    "npm": "npm",
                    "pypi": "PyPI",
                    "maven": "Maven",
                    "cargo": "crates.io",
                    "golang": "Go",
                    "nuget": "NuGet",
                    "gem": "RubyGems",
                    "composer": "Packagist",
                    "deb": "Debian",
                    "apk": "Alpine",
                    "rpm": "Red Hat",
                }
                return ecosystem_map.get(scheme, "")
        # "Android" as a component (the OS itself) - use Android ecosystem
        if component.name.lower() == "android":
            return "Android"
        return ""
