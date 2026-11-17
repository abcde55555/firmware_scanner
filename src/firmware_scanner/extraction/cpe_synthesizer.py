"""Canonical CPE 2.3 synthesizer for embedded firmware components.

Maps raw firmware library/binary names (e.g. libssl.so, libcrypto.so, libopenssl.so)
to official NVD CPE 2.3 dictionaries (e.g. cpe:2.3:a:openssl:openssl:<version>:*:*:*:*:*:*:*).
"""

import re

# Canonical vendor and product mapping for known open-source components
_CANONICAL_CPE_MAP: dict[str, tuple[str, str]] = {
    # OpenSSL family (maps libssl, libcrypto, libopenssl -> openssl:openssl)
    "openssl": ("openssl", "openssl"),
    "libssl": ("openssl", "openssl"),
    "libcrypto": ("openssl", "openssl"),
    "libopenssl": ("openssl", "openssl"),

    # SQLite
    "sqlite": ("sqlite", "sqlite"),
    "sqlite3": ("sqlite", "sqlite"),
    "libsqlite": ("sqlite", "sqlite"),
    "libsqlite3": ("sqlite", "sqlite"),

    # Curl
    "curl": ("haxx", "curl"),
    "libcurl": ("haxx", "curl"),

    # Zlib
    "zlib": ("zlib", "zlib"),
    "libz": ("zlib", "zlib"),

    # Libpng
    "libpng": ("libpng", "libpng"),
    "libpng16": ("libpng", "libpng"),

    # Libjpeg-turbo / libjpeg
    "libjpeg": ("libjpeg-turbo", "libjpeg-turbo"),
    "libjpeg-turbo": ("libjpeg-turbo", "libjpeg-turbo"),

    # Expat
    "expat": ("libexpat_project", "libexpat"),
    "libexpat": ("libexpat_project", "libexpat"),

    # Libxml2
    "libxml2": ("xmlsoft", "libxml2"),

    # PCRE / PCRE2
    "pcre": ("pcre", "pcre"),
    "pcre2": ("pcre", "pcre2"),
    "libpcre": ("pcre", "pcre"),
    "libpcre2": ("pcre", "pcre2"),

    # Bzip2
    "bzip2": ("bzip", "bzip2"),
    "libbz2": ("bzip", "bzip2"),

    # Iptables
    "iptables": ("netfilter", "iptables"),

    # Busybox & Toybox
    "busybox": ("busybox", "busybox"),
    "toybox": ("landley", "toybox"),

    # Dnsmasq
    "dnsmasq": ("thekelleys", "dnsmasq"),

    # E2fsprogs / e2fsck
    "e2fsck": ("e2fsprogs_project", "e2fsprogs"),
    "e2fsprogs": ("e2fsprogs_project", "e2fsprogs"),

    # Wpa_supplicant / Hostapd
    "wpa_supplicant": ("w1.fi", "wpa_supplicant"),
    "hostapd": ("w1.fi", "hostapd"),

    # Dropbear & OpenSSH
    "dropbear": ("dropbear_ssh_project", "dropbear_ssh"),
    "openssh": ("openbsd", "openssh"),

    # Web servers
    "lighttpd": ("lighttpd", "lighttpd"),
    "nginx": ("f5", "nginx"),

    # Audio/Video codecs
    "ffmpeg": ("ffmpeg", "ffmpeg"),
    "libavcodec": ("ffmpeg", "ffmpeg"),
    "libavformat": ("ffmpeg", "ffmpeg"),
    "libavutil": ("ffmpeg", "ffmpeg"),
    "libopus": ("xiph", "opus"),
    "opus": ("xiph", "opus"),
    "libvpx": ("webmproject", "libvpx"),
    "vpx": ("webmproject", "libvpx"),
    "libwebp": ("webmproject", "libwebp"),
    "libtiff": ("libtiff", "libtiff"),

    # Other Cryptographic libraries
    "mbedtls": ("arm", "mbed_tls"),
    "libmbedtls": ("arm", "mbed_tls"),
    "libmbedcrypto": ("arm", "mbed_tls"),
    "libmbedx509": ("arm", "mbed_tls"),
    "polarssl": ("polarssl", "polarssl"),
    "wolfssl": ("wolfssl", "wolfssl"),
    "libwolfssl": ("wolfssl", "wolfssl"),
    "gnutls": ("gnu", "gnutls"),
    "libgnutls": ("gnu", "gnutls"),
    "libssh": ("libssh", "libssh"),
    "libssh2": ("libssh2", "libssh2"),

    # Compression formats
    "xz": ("tukaani", "xz"),
    "liblzma": ("tukaani", "xz"),
    "lz4": ("yann_collet", "lz4"),
    "liblz4": ("yann_collet", "lz4"),
    "zstd": ("facebook", "zstandard"),
    "libzstd": ("facebook", "zstandard"),
    "brotli": ("google", "brotli"),
    "libbrotli": ("google", "brotli"),

    # Fonts & Rendering
    "freetype": ("freetype", "freetype"),
    "libfreetype": ("freetype", "freetype"),
    "harfbuzz": ("harfbuzz_project", "harfbuzz"),
    "libharfbuzz": ("harfbuzz_project", "harfbuzz"),
    "libharfbuzz_ng": ("harfbuzz_project", "harfbuzz"),

    # Networking & Events
    "libevent": ("libevent_project", "libevent"),
    "libev": ("libev_project", "libev"),
    "libuv": ("libuv", "libuv"),
    "libpcap": ("tcpdump", "libpcap"),
    "tcpdump": ("tcpdump", "tcpdump"),
    "nghttp2": ("nghttp2", "nghttp2"),
    "libnghttp2": ("nghttp2", "nghttp2"),
    "c-ares": ("c-ares_project", "c-ares"),
    "cares": ("c-ares_project", "c-ares"),
    "mosquitto": ("eclipse", "mosquitto"),
    "libmosquitto": ("eclipse", "mosquitto"),

    # JSON & XML
    "cjson": ("cjson_project", "cjson"),
    "jansson": ("jansson_project", "jansson"),
    "json-c": ("json-c_project", "json-c"),
    "json_c": ("json-c_project", "json-c"),
    "libxslt": ("xmlsoft", "libxslt"),

    # C Libraries
    "glibc": ("gnu", "glibc"),
    "libc": ("gnu", "glibc"),
    "musl": ("musl-libc", "musl"),
    "uclibc": ("uclibc", "uclibc"),
    "uclibc-ng": ("uclibc-ng", "uclibc-ng"),

    # BoringSSL (Google fork - distinct from OpenSSL)
    "boringssl": ("google", "boringssl"),
    "libboringssl": ("google", "boringssl"),

    # Bluetooth & System Services
    "bluez": ("bluez", "bluez"),
    "bluetoothd": ("bluez", "bluez"),
    "libbluetooth": ("bluez", "bluez"),
    "leveldb": ("google", "leveldb"),
    "libleveldb": ("google", "leveldb"),
    "protobuf": ("google", "protobuf"),
    "libprotobuf": ("google", "protobuf"),
    "libprotobuf-lite": ("google", "protobuf"),
    "libprotobuf-cpp-full": ("google", "protobuf"),
    "libprotobuf-cpp-lite": ("google", "protobuf"),
    "tinyxml2": ("tinyxml2_project", "tinyxml2"),
    "libtinyxml2": ("tinyxml2_project", "tinyxml2"),
    "libdb": ("oracle", "berkeley_db"),
    "berkeley_db": ("oracle", "berkeley_db"),
    "icu": ("icu-project", "international_components_for_unicode"),
    "libicuuc": ("icu-project", "international_components_for_unicode"),
    "libicui18n": ("icu-project", "international_components_for_unicode"),
    "miniupnpd": ("miniupnp_project", "miniupnpd"),
    "miniupnpc": ("miniupnp_project", "miniupnpc"),
    "libminiupnpc": ("miniupnp_project", "miniupnpc"),
    "libbpf": ("libbpf", "libbpf"),
    "bpf": ("libbpf", "libbpf"),
    "mksh": ("mirbsd", "mksh"),
    "zlib-ng": ("zlib-ng", "zlib-ng"),
}

# Dynamically load expanded catalog from gangmu rules if available
import json
from pathlib import Path

_CATALOG_PATH = Path(__file__).parent / "cpe_catalog.json"
if _CATALOG_PATH.exists():
    try:
        with open(_CATALOG_PATH, "r", encoding="utf-8") as _f:
            _loaded = json.load(_f)
            for _k, _v in _loaded.items():
                if _k not in _CANONICAL_CPE_MAP:
                    _CANONICAL_CPE_MAP[_k] = tuple(_v)
    except Exception:
        pass


def normalize_cpe_name(name: str) -> str:
    """Normalize raw binary/library filename to canonical key."""
    lower = name.lower().strip()
    # Strip version suffix after .so (e.g. libcrypto.so.1.1 -> libcrypto.so)
    if ".so." in lower:
        lower = lower.split(".so.", 1)[0] + ".so"
    for suffix in (".so", ".a", ".dylib", ".dll"):
        if lower.endswith(suffix):
            lower = lower[:-len(suffix)]
    # Strip trailing numbers like libcrypto1.1 -> libcrypto
    while lower and (lower[-1].isdigit() or lower.endswith(".")):
        lower = lower.rstrip("0123456789.")
    return lower


def synthesize_cpe(name: str, version: str) -> str:
    """Synthesize standard NVD CPE 2.3 string from component name and version.

    Returns:
        Formatted CPE 2.3 string (e.g. cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*)
        or empty string if not a known mapping or missing version.
    """
    clean_ver = version.strip()
    # Strip milestone + signs
    if clean_ver.endswith("+"):
        clean_ver = clean_ver.rstrip("+")

    if not clean_ver or clean_ver.lower() in ("detected", "unknown", "n/a", "boringssl"):
        return ""

    key = normalize_cpe_name(name)
    mapping = _CANONICAL_CPE_MAP.get(key)
    if not mapping and key.startswith("lib"):
        mapping = _CANONICAL_CPE_MAP.get(key[3:])

    if not mapping:
        return ""

    vendor, product = mapping
    # Special handling: BoringSSL is NOT OpenSSL
    if "boring" in clean_ver.lower() or "boring" in name.lower():
        return f"cpe:2.3:a:google:boringssl:{clean_ver}:*:*:*:*:*:*:*"

    return f"cpe:2.3:a:{vendor}:{product}:{clean_ver}:*:*:*:*:*:*:*"
