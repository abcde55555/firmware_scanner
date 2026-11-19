"""Multi-layer ELF deep version extractor.

Implements the five-layer extraction strategy for ELF binaries and shared libraries:
1. ELF Dynamic Section (SONAME, RUNPATH) and Symbol Versioning (.gnu.version_d, .gnu.version_r)
2. Read-Only Data (.rodata) Banner Signatures and Compiler/Toolchain (.comment)
3. Exported Symbol Milestones and Interface Versioning (HIDL/AIDL HALs)
4. Cryptographic Magic Constants & Lookup Tables
5. Platform Component Provenance Attribution
"""

import io
import re
import struct
from dataclasses import dataclass, field

try:
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile

    HAVE_ELFTOOLS = True
except ImportError:
    HAVE_ELFTOOLS = False

from .models import ExtractionMethod

# Crypto constants
AES_SBOX_PREFIX = b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76"
CHACHA20_MAGIC = b"expand 32-byte k"
SHA256_IV = b"\x67\xe6\x09\x6a\x85\xae\x67\xbb\x72\xf3\x6e\x3c\x3a\xa5\x4f\xa5"


@dataclass
class ELFExtractionResult:
    canonical_name: str = ""
    version: str = ""
    confidence: float = 0.0
    method: ExtractionMethod = ExtractionMethod.STRING_PATTERN
    evidence: str = ""
    purl: str = ""
    toolchain: str = ""
    target_sdk: int = 0
    is_platform_component: bool = False
    version_kind: str = "release"
    facts: list[dict[str, str]] = field(default_factory=list)
    defined_symbols: set[str] | None = None


# Milestone symbols mapping for landmark API fingerprinting
LANDMARK_SYMBOLS: list[tuple[str, str, str, str]] = [
    (
        "EVP_MAC_CTX_new",
        "OpenSSL/BoringSSL",
        "3.0+",
        "EVP_MAC API introduced in OpenSSL 3.0+ / BoringSSL",
    ),
    ("TLS_method", "OpenSSL", "1.1+", "TLS_method API introduced in OpenSSL 1.1.0"),
    (
        "EVP_CIPHER_CTX_reset",
        "OpenSSL",
        "1.1.0+",
        "EVP_CIPHER_CTX_reset introduced in OpenSSL 1.1.0",
    ),
    ("deflatePending", "zlib", "1.2.11+", "deflatePending API introduced in zlib 1.2.11"),
    (
        "sqlite3_autocommit",
        "sqlite3",
        "3.37.0+",
        "sqlite3_autocommit API introduced in SQLite 3.37.0",
    ),
    (
        "sqlite3_drop_modules",
        "sqlite3",
        "3.30.0+",
        "sqlite3_drop_modules API introduced in SQLite 3.30.0",
    ),
    (
        "sqlite3_keyword_name",
        "sqlite3",
        "3.24.0+",
        "sqlite3_keyword_name API introduced in SQLite 3.24.0",
    ),
    ("sqlite3_prepare_v3", "sqlite3", "3.20.0+", "sqlite3_prepare_v3 introduced in SQLite 3.20.0"),
    ("curl_ws_send", "curl", "7.86.0+", "WebSocket support API introduced in curl 7.86.0"),
    ("curl_multi_wakeup", "curl", "7.68.0+", "curl_multi_wakeup API introduced in curl 7.68.0"),
    ("curl_mime_init", "curl", "7.56.0+", "MIME API introduced in curl 7.56.0"),
    ("xmlSAX2ResolveEntity", "libxml2", "2.6.0+", "xmlSAX2 API introduced in libxml2 2.6.0"),
    ("cJSON_Version", "cjson", "1.0.0+", "cJSON_Version API introduced in cJSON 1.0.0"),
    ("FT_Library_Version", "freetype", "2.0.0+", "FT_Library_Version API in FreeType"),
    ("hb_version_string", "harfbuzz", "1.0.0+", "HarfBuzz version API"),
    ("uv_version_string", "libuv", "1.0.0+", "libuv version API"),
    ("event_base_new", "libevent", "2.0.1+", "event_base_new introduced in libevent 2.0"),
    (
        "ChildElementCount",
        "tinyxml2",
        "9.0.0+",
        "ChildElementCount API introduced in TinyXML-2 9.0.0",
    ),
    (
        "QueryUnsigned64Value",
        "tinyxml2",
        "8.0.0+",
        "QueryUnsigned64Value API introduced in TinyXML-2 8.0.0",
    ),
    (
        "hb_subset_plan_create_or_fail",
        "harfbuzz",
        "2.9.0+",
        "hb_subset_plan API introduced in HarfBuzz 2.9.0",
    ),
    ("ext2fs_open2", "e2fsprogs", "1.42.0+", "ext2fs_open2 API in e2fsprogs"),
]


# Known rodata patterns (library -> list of (regex, desc))
KNOWN_RODATA_PATTERNS: dict[str, list[tuple[bytes, str]]] = {
    "sqlite": [
        (rb"(?:SQLite version |^|\x00)(3\.\d{1,2}\.\d+)", "SQLite version string"),
    ],
    "png": [
        (rb"libpng version (\d+\.\d+\.\d+)", "libpng version string"),
        (rb"PNG Library (\d+\.\d+\.\d+)", "PNG Library version string"),
    ],
    "jpeg": [
        (rb"libjpeg-turbo version (\d+\.\d+\.\d+(?:\.\d+)?)", "libjpeg-turbo version string"),
    ],
    "zlib": [
        (rb"deflate (\d+\.\d+\.\d+(?:\.\d+)?)", "zlib version string"),
        (rb"inflate (\d+\.\d+\.\d+)", "zlib version string"),
        (rb"(\d+\.\d+\.\d+(?:\.\d+)?)\x00.{0,8}deflate", "zlib deflate version"),
    ],
    "z": [
        (rb"deflate (\d+\.\d+\.\d+(?:\.\d+)?)", "zlib version string"),
        (rb"inflate (\d+\.\d+\.\d+)", "zlib version string"),
        (rb"(\d+\.\d+\.\d+(?:\.\d+)?)\x00.{0,8}deflate", "zlib deflate version"),
    ],
    "libz": [
        (rb"deflate (\d+\.\d+\.\d+(?:\.\d+)?)", "zlib version string"),
        (rb"inflate (\d+\.\d+\.\d+)", "zlib version string"),
        (rb"(\d+\.\d+\.\d+(?:\.\d+)?)\x00.{0,8}deflate", "zlib deflate version"),
    ],
    "expat": [
        (rb"expat_(\d+\.\d+\.\d+)", "expat version string"),
        (rb"(\d+\.\d+\.\d+)\x00.{0,16}expat", "expat version string"),
    ],
    "xml2": [
        (rb"(\d+-GITv\d+\.\d+\.\d+(?:-[A-Za-z0-9_.]+)+)", "libxml2 development snapshot"),
        (rb"(?:GITv|libxml2-)(\d+\.\d+\.\d+)", "libxml2 version string"),
        (rb"(\d+\.\d+\.\d+)\x00.{0,16}libxml", "libxml2 version string"),
    ],
    "harfbuzz": [
        (rb"(\d{1,2}\.\d{1,2}\.\d{1,2})\x00end table", "HarfBuzz version string"),
        (rb"HarfBuzz (\d+\.\d+\.\d+)", "HarfBuzz version string"),
    ],
    "harfbuzz_ng": [
        (rb"(\d{1,2}\.\d{1,2}\.\d{1,2})\x00end table", "HarfBuzz version string"),
        (rb"HarfBuzz (\d+\.\d+\.\d+)", "HarfBuzz version string"),
    ],
    "pcre2": [
        (rb"(\d+\.\d+)\s+\d{4}-\d{2}-\d{2}", "PCRE2 release date version"),
    ],
    "pcre": [
        (rb"(\d+\.\d+)\s+\d{4}-\d{2}-\d{2}", "PCRE release date version"),
    ],
    "pcap": [
        (rb"libpcap version (\d+\.\d+\.\d+)", "libpcap version string"),
    ],
    "event": [
        (
            rb"(\d+\.\d+\.\d+-(?:stable|beta|alpha)(?:[-+][A-Za-z0-9._+-]+)?)(?=\x00|\s)",
            "libevent version string",
        ),
    ],
    "ext2fs": [
        (rb"\x00(1\.\d{1,2}\.\d+)\x00Test_io", "libext2fs version string"),
        (rb"version of e2fsck!\x00(1\.\d+\.\d+)", "e2fsck version string"),
    ],
    "ext2_blkid": [
        (rb"\x00(1\.\d{1,2}\.\d+)\x00Test_io", "libext2fs version string"),
        (rb"version of e2fsck!\x00(1\.\d+\.\d+)", "e2fsck version string"),
    ],
    "curl": [
        (rb"libcurl/(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9_.-]+)?)", "libcurl version string"),
        (rb"(?<![A-Za-z0-9_])curl (\d+\.\d+\.\d+(?:[-+][A-Za-z0-9_.-]+)?)", "curl version string"),
    ],
    "toybox": [
        (rb"(\d+\.\d+\.\d+)-android", "Toybox Android version string"),
        (rb"toybox (\d+\.\d+\.\d+)", "Toybox version string"),
    ],
    "e2fsck": [
        (rb"version of e2fsck!\x00(\d+\.\d+\.\d+)", "e2fsck version string"),
        (rb"(\d+\.\d+\.\d+)\x00%12u non-contiguous", "e2fsck version string"),
        (rb"e2fsck (\d+\.\d+\.\d+)", "e2fsck version string"),
    ],
    "tune2fs": [
        (rb"\x00(1\.\d{1,2}\.\d+)\x00", "tune2fs version string"),
        (rb"version of e2fsck!\x00(\d+\.\d+\.\d+)", "tune2fs version string"),
    ],
    "resize2fs": [
        (rb"\x00(1\.\d{1,2}\.\d+)\x00", "resize2fs version string"),
        (rb"version of e2fsck!\x00(\d+\.\d+\.\d+)", "resize2fs version string"),
    ],
    "mke2fs": [
        (rb"\x00(1\.\d{1,2}\.\d+)\x00", "mke2fs version string"),
        (rb"version of e2fsck!\x00(\d+\.\d+\.\d+)", "mke2fs version string"),
    ],
    "dnsmasq": [
        (rb"dnsmasq(?: version)? (\d+\.\d+(?:\.\d+)?)", "dnsmasq version string"),
    ],
    "wpa_supplicant": [
        (
            rb"(?:^|[\x00\n])wpa_supplicant v(\d+\.\d+(?:\.\d+)*[A-Za-z0-9._+-]*)(?=[\x00\s])",
            "wpa_supplicant version string",
        ),
    ],
    "busybox": [
        (rb"BusyBox v(\d+\.\d+\.\d+)", "BusyBox version string"),
    ],
    "iptables": [
        (rb"(\d+\.\d+\.\d+) \(legacy\)", "iptables version string"),
        (rb"iptables v(\d+\.\d+\.\d+)", "iptables version string"),
    ],
    "ip6tables": [
        (rb"(\d+\.\d+\.\d+) \(legacy\)", "ip6tables version string"),
        (rb"ip6tables v(\d+\.\d+\.\d+)", "ip6tables version string"),
    ],
    "bzip2": [
        (rb"(\d+\.\d+\.\d+), \d{1,2}-[A-Za-z]{3}-\d{4}", "bzip2 version string"),
        (rb"\x00(1\.\d+\.\d+)\x00(?:[^\x00]*?)Julian Seward", "bzip2 version string"),
        (rb"bzip2.*?Version (\d+\.\d+\.\d+)", "bzip2 version string"),
    ],
    "sh": [
        (rb"@\(#\)MIRBSD KSH (R\d+)", "MirBSD Korn Shell version"),
    ],
    "mksh": [
        (rb"@\(#\)MIRBSD KSH (R\d+)", "MirBSD Korn Shell version"),
    ],
    "bc": [
        (rb"divide by 0\x00(\d+\.\d+\.\d+)\x00", "bc version string"),
    ],
    "awk": [
        (rb"version (\d{8})", "awk version string"),
    ],
    "ssl": [
        (rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)", "OpenSSL version string"),
        (rb"BoringSSL", "BoringSSL (unversioned AOSP fork)"),
    ],
    "crypto": [
        (rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)", "OpenSSL version string"),
        (rb"BoringSSL", "BoringSSL (unversioned AOSP fork)"),
    ],
    "icuuc": [
        (rb"ICU (\d+\.\d+(?:\.\d+)?)", "ICU version string"),
    ],
    "icui18n": [
        (rb"ICU (\d+\.\d+(?:\.\d+)?)", "ICU version string"),
    ],
    "opus": [
        (rb"libopus (\d+\.\d+(?:\.\d+)?)", "libopus version string"),
    ],
    "vpx": [
        (rb"libvpx v(\d+\.\d+\.\d+)", "libvpx version string"),
        (rb"v(\d+\.\d+\.\d+)\x00.{0,32}vpx", "libvpx version string"),
    ],
    "mbedtls": [
        (rb"mbed\s+TLS\s+(\d+\.\d+\.\d+)", "mbed TLS version string"),
        (rb"PolarSSL\s+(\d+\.\d+\.\d+)", "PolarSSL version string"),
    ],
    "mbedcrypto": [
        (rb"mbed\s+TLS\s+(\d+\.\d+\.\d+)", "mbed TLS version string"),
    ],
    "wolfssl": [
        (rb"wolfSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]?)", "wolfSSL version string"),
        (rb"CyaSSL\s+([0-9]+\.[0-9]+\.[0-9]+)", "CyaSSL version string"),
    ],
    "gnutls": [
        (rb"GnuTLS\s+([0-9]+\.[0-9]+\.[0-9]+)", "GnuTLS version string"),
        (rb"gnutls_([0-9]+\.[0-9]+\.[0-9]+)", "GnuTLS version string"),
    ],
    "ssh": [
        (rb"libssh[_-]([0-9]+\.[0-9]+\.[0-9]+)", "libssh version string"),
    ],
    "ssh2": [
        (rb"libssh2/([0-9]+\.[0-9]+\.[0-9]+)", "libssh2 version string"),
        (rb"libssh2_([0-9]+\.[0-9]+\.[0-9]+)", "libssh2 SSH banner version"),
    ],
    "dropbear": [
        (rb"Dropbear\s+v?([0-9]{4}\.[0-9]+)", "Dropbear version string"),
    ],
    "sshd": [
        (rb"OpenSSH_([0-9]+\.[0-9]+(?:p[0-9]+)?)", "OpenSSH version string"),
    ],
    "openssh": [
        (rb"OpenSSH_([0-9]+\.[0-9]+(?:p[0-9]+)?)", "OpenSSH version string"),
    ],
    "nghttp2": [
        (rb"nghttp2/([0-9]+\.[0-9]+\.[0-9]+)", "nghttp2 version string"),
    ],
    "cares": [
        (rb"c-ares\s+(?:library\s+)?version\s+([0-9]+\.[0-9]+\.[0-9]+)", "c-ares version string"),
    ],
    "mosquitto": [
        (rb"mosquitto\s+version\s+([0-9]+\.[0-9]+\.[0-9]+)", "Mosquitto version string"),
    ],
    "lighttpd": [
        (rb"lighttpd/([0-9]+\.[0-9]+\.[0-9]+)", "lighttpd version string"),
    ],
    "nginx": [
        (rb"nginx/([0-9]+\.[0-9]+\.[0-9]+)", "nginx version string"),
    ],
    "zstd": [
        (rb"zstd\s+v?([0-9]+\.[0-9]+\.[0-9]+)", "zstandard version string"),
        (rb"\x00(1\.[0-9]+\.[0-9]+)\x00.{0,16}ZSTD", "zstd version string"),
    ],
    "brotli": [
        (rb"brotli\s+v?([0-9]+\.[0-9]+\.[0-9]+)", "brotli version string"),
    ],
    "cjson": [
        (rb"cJSON\s+([0-9]+\.[0-9]+\.[0-9]+)", "cJSON version string"),
    ],
    "jansson": [
        (rb"jansson\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "jansson version string"),
    ],
    "json-c": [
        (rb"json-c\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "json-c version string"),
        (rb"json_c_version\s+([0-9]+\.[0-9]+)", "json-c version string"),
    ],
    "freetype": [
        (rb"FreeType\s+([0-9]+\.[0-9]+\.[0-9]+)", "FreeType version string"),
    ],
    "tiff": [
        (rb"LIBTIFF,\s+Version\s+([0-9]+\.[0-9]+\.[0-9]+)", "libtiff version string"),
    ],
    "webp": [
        (rb"libwebp\s+([0-9]+\.[0-9]+\.[0-9]+)", "libwebp version string"),
    ],
    "bluez": [
        (rb"bluez\s+([0-9]+\.[0-9]+)", "BlueZ version string"),
        (rb"bluetoothd\s+([0-9]+\.[0-9]+)", "BlueZ bluetoothd version string"),
    ],
    "leveldb": [
        (rb"leveldb\s+version\s+([0-9]+\.[0-9]+)", "LevelDB version string"),
    ],
    "protobuf": [
        (rb"libprotobuf\s+([0-9]+\.[0-9]+\.[0-9]+)", "Protobuf version string"),
        (rb"protobuf\s+([0-9]+\.[0-9]+\.[0-9]+)", "Protobuf version string"),
    ],
}

# Anchored format-string + version-shape extraction patterns (from gangmu)
ANCHORED_PATTERNS: list[tuple[str, str, tuple[bytes, ...], bytes]] = [
    ("dnsmasq", "dnsmasq", (b"Dnsmasq version %s", b"dnsmasq-"), rb"2\.\d{2,3}"),
    ("dropbear", "dropbear", (b"SSH-2.0-dropbear", b"Dropbear SSH"), rb"20\d\d\.\d{2}"),
    ("ppp", "ppp", (b"pppd version %s",), rb"2\.[45]\.\d{1,2}"),
    ("musl", "musl", (b"musl libc (",), rb"1\.[0-2]\.\d{1,2}"),
    ("hostapd", "hostapd", (b"hostapd v%s",), rb"2\.\d{1,2}(?:[-+_][A-Za-z0-9][A-Za-z0-9._+-]*)?"),
    (
        "wpa_supplicant",
        "wpa_supplicant",
        (b"wpa_supplicant v%s",),
        rb"2\.\d{1,2}(?:[-+_][A-Za-z0-9][A-Za-z0-9._+-]*)?",
    ),
    ("iw", "iw", (b"iw version %s",), rb"[4-9]\.\d{1,2}"),
    ("json-c", "json-c", (b"json_c_version_num", b"json-c version"), rb"0\.1\d(?:\.\d{1,2})?"),
    ("busybox", "busybox", (b"BusyBox v%s",), rb"1\.\d{2}\.\d{1,2}"),
]

# Multi-symbol sets containment matching for stripped libraries (from gangmu)
SYMBOL_SETS: list[tuple[str, str, int, tuple[str, ...]]] = [
    (
        "libogg",
        "ogg",
        12,
        (
            "ogg_stream_init",
            "ogg_stream_clear",
            "ogg_stream_packetin",
            "ogg_stream_pageout",
            "ogg_stream_pagein",
            "ogg_stream_packetout",
            "ogg_stream_flush",
            "ogg_sync_init",
            "ogg_sync_buffer",
            "ogg_sync_wrote",
            "ogg_sync_pageout",
            "ogg_sync_pageseek",
            "ogg_page_serialno",
            "ogg_page_granulepos",
            "ogg_page_checksum_set",
            "oggpack_writeinit",
            "oggpack_read",
            "oggpack_write",
            "oggpackB_read",
        ),
    ),
    (
        "speexdsp",
        "speex",
        8,
        (
            "speex_echo_state_init",
            "speex_echo_cancellation",
            "speex_echo_capture",
            "speex_echo_playback",
            "speex_preprocess_state_init",
            "speex_preprocess_run",
            "speex_resampler_init",
            "speex_resampler_process_float",
            "jitter_buffer_init",
            "jitter_buffer_put",
            "jitter_buffer_get",
            "speex_decorrelate_new",
            "speex_buffer_init",
            "kiss_fft_alloc",
            "kiss_fftr_alloc",
            "filterbank_new",
        ),
    ),
    (
        "sonic",
        "sonic",
        8,
        (
            "sonicCreateStream",
            "sonicDestroyStream",
            "sonicFlushStream",
            "sonicSetSpeed",
            "sonicSetPitch",
            "sonicSetRate",
            "sonicSetVolume",
            "sonicSetChordPitch",
            "sonicWriteShortToStream",
            "sonicReadShortFromStream",
            "sonicWriteFloatToStream",
            "sonicReadFloatFromStream",
            "sonicSamplesAvailable",
            "sonicChangeShortSpeed",
        ),
    ),
    (
        "pvmp3dec",
        "pvmp3dec",
        5,
        (
            "pvmp3_InitDecoder",
            "pvmp3_framedecoder",
            "pvmp3_decode_header",
            "pvmp3_alias_reduction",
            "pvmp3_dct_9",
            "pvmp3_dct_16",
            "pvmp3_mdct_18",
            "pvmp3_decode_huff_cw_tab0",
            "pvmp3_poly_phase_synthesis",
            "pvmp3_stereo_proc",
        ),
    ),
    (
        "pvmp4audiodecoder",
        "pvmp4audiodecoder",
        5,
        (
            "PVMP4AudioDecodeFrame",
            "PVMP4AudioDecoderConfig",
            "PVMP4AudioDecoderInitLibrary",
            "PVMP4AudioDecoderGetMemRequirements",
            "PVMP4AudioDecoderResetBuffer",
            "PVMP4SetAudioConfig",
            "PVMP4AudioDecoderDisableAacPlus",
        ),
    ),
    (
        "opencore-amrnb",
        "opencore-amr",
        6,
        (
            "GSMInitDecode",
            "GSMFrameDecode",
            "GSMDecodeFrameExit",
            "AMRDecode",
            "Decoder_amr_init",
            "Decoder_amr",
            "Speech_Decode_Frame_reset",
            "Bgn_scd",
            "Post_Filter",
            "D_plsf_3",
            "Lsp_Az",
        ),
    ),
    (
        "libplctag",
        "libplctag",
        16,
        (
            "plc_tag_create_ex",
            "plc_tag_destroy",
            "plc_tag_read",
            "plc_tag_write",
            "plc_tag_status",
            "plc_tag_shutdown",
            "plc_tag_get_size",
            "plc_tag_set_raw_bytes",
            "plc_tag_get_raw_bytes",
            "plc_tag_get_int8",
            "plc_tag_get_uint8",
            "plc_tag_get_int16",
            "plc_tag_get_uint16",
            "plc_tag_get_int32",
            "plc_tag_get_uint32",
            "plc_tag_get_float32",
            "plc_tag_set_float32",
        ),
    ),
]

GO_MAGIC = b"\xff Go buildinf:"


def _uvarint(data: bytes, at: int) -> tuple[int, int] | None:
    value = shift = 0
    for i in range(10):
        if at + i >= len(data):
            return None
        b = data[at + i]
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, at + i + 1
        shift += 7
    return None


def _go_string(data: bytes, at: int) -> tuple[str, int] | None:
    got = _uvarint(data, at)
    if got is None:
        return None
    size, at = got
    if size > 4 * 1024 * 1024 or at + size > len(data):
        return None
    return data[at : at + size].decode("utf-8", "replace"), at + size


class ELFDeepExtractor:
    """Multi-tier extractor combining ELF metadata, symbol versioning, and signatures."""

    def extract(self, filename: str, data: bytes) -> ELFExtractionResult | None:
        if len(data) < 16 or data[:4] != b"\x7fELF":
            return None

        result = ELFExtractionResult()
        clean_name = filename.rsplit("/", 1)[-1]
        result.canonical_name = clean_name

        # -------------------------------------------------------------
        # Layer 3 (Fast path): Android HAL Interface Versioning from Filename
        # e.g., android.hardware.camera.device@3.7.so -> 3.7
        #       android.hardware.audio.common-V4-ndk.so -> V4
        # -------------------------------------------------------------
        m_hidl = re.search(r"@(\d+\.\d+(?:\.\d+)?)(?:-.*)?\.so$", clean_name)
        if m_hidl:
            result.version = m_hidl.group(1)
            result.confidence = 0.95
            result.method = ExtractionMethod.MANIFEST_BINARY
            result.evidence = f"Android HIDL HAL interface @{result.version}"
            result.version_kind = "interface"
            result.purl = f"pkg:generic/{clean_name}@{result.version}"
            return result

        m_aidl = re.search(r"-V(\d+(?:\.\d+)?)(?:-[a-z0-9_]+)?(?:\.so)?$", clean_name)
        if m_aidl:
            result.version = f"V{m_aidl.group(1)}"
            result.confidence = 0.95
            result.method = ExtractionMethod.MANIFEST_BINARY
            result.evidence = f"Android AIDL HAL interface {result.version}"
            result.version_kind = "interface"
            result.purl = f"pkg:generic/{clean_name}@{result.version}"
            return result

        # -------------------------------------------------------------
        # Layer 2: .rodata Banner Signatures & Error Strings
        # -------------------------------------------------------------
        self._extract_rodata_signatures(clean_name, data, result)

        # -------------------------------------------------------------
        # Layer 2.2: Protobuf Integer Version Constant Extraction
        # -------------------------------------------------------------
        if not result.version:
            self._extract_protobuf_version(clean_name, data, result)

        # -------------------------------------------------------------
        # Layer 2.5: Anchored Version Signatures (format string + shape)
        # -------------------------------------------------------------
        if not result.version:
            self._extract_anchored_signatures(clean_name, data, result)

        # -------------------------------------------------------------
        # Layer 2.8: Go Runtime & Module Metadata
        # -------------------------------------------------------------
        if not result.version:
            self._extract_go_buildinfo(data, result)

        # -------------------------------------------------------------
        # Layer 1: ELF metadata and defined symbols, parsed in one pass
        # -------------------------------------------------------------
        defined_symbols = self._extract_elf_headers(data, result) if HAVE_ELFTOOLS else set()
        if HAVE_ELFTOOLS:
            result.defined_symbols = defined_symbols

        # -------------------------------------------------------------
        # Layer 3: Exported Symbol Milestones (Landmark APIs)
        # -------------------------------------------------------------
        if not result.version:
            self._extract_symbol_milestones(data, result, defined_symbols)

        # -------------------------------------------------------------
        # Layer 3.5: Multi-Symbol Set Containment
        # -------------------------------------------------------------
        if not result.version:
            self._extract_symbol_sets(clean_name, data, result, defined_symbols)

        # -------------------------------------------------------------
        # Layer 4: Cryptographic Constants & Magic Numbers
        # -------------------------------------------------------------
        if not result.version:
            self._extract_crypto_constants(data, result)

        return (
            result if result.version or result.facts or result.evidence or defined_symbols else None
        )

    def _extract_elf_headers(self, data: bytes, result: ELFExtractionResult) -> set[str]:
        """Record ABI and build metadata without promoting it to a release."""
        defined_symbols: set[str] = set()
        try:
            elffile = ELFFile(io.BytesIO(data))
            for section in elffile.iter_sections():
                if isinstance(section, DynamicSection):
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == "DT_SONAME":
                            result.facts.append(
                                {"name": "firmware:elf:soname", "value": tag.soname}
                            )
                        elif tag.entry.d_tag == "DT_NEEDED":
                            result.facts.append(
                                {"name": "firmware:elf:needed", "value": tag.needed}
                            )
                        elif tag.entry.d_tag in ("DT_RPATH", "DT_RUNPATH"):
                            path = getattr(tag, "runpath", "") or getattr(tag, "rpath", "")
                            result.facts.append({"name": "firmware:elf:runpath", "value": path})
                elif section.name == ".gnu.version_d":
                    for version, aux in section.iter_versions():
                        for entry in aux:
                            if entry.name:
                                result.facts.append(
                                    {"name": "firmware:elf:abi_version", "value": entry.name}
                                )
                elif section.name == ".comment":
                    result.toolchain = (
                        section.data().decode("ascii", errors="ignore").replace("\x00", " ").strip()
                    )
                elif section.name == ".note.android.ident":
                    raw = section.data()
                    at = raw.find(b"Android\x00")
                    if at >= 0 and at + 12 <= len(raw):
                        result.target_sdk = struct.unpack_from("<I", raw, at + 8)[0]
                if section.name in (".dynsym", ".symtab"):
                    for symbol in section.iter_symbols():
                        info = symbol["st_info"]
                        if (
                            symbol["st_shndx"] != "SHN_UNDEF"
                            and symbol.name
                            and info["bind"] in ("STB_GLOBAL", "STB_WEAK")
                            and info["type"] in ("STT_NOTYPE", "STT_FUNC", "STT_OBJECT")
                        ):
                            defined_symbols.add(symbol.name)
        except Exception:  # noqa: BLE001 - malformed ELF handling is fail-closed
            return defined_symbols
        return defined_symbols

    @staticmethod
    def _defined_symbols(data: bytes) -> set[str]:
        if not HAVE_ELFTOOLS:
            return set()
        symbols = set()
        try:
            elf = ELFFile(io.BytesIO(data))
            for section in elf.iter_sections():
                if section.name in (".dynsym", ".symtab"):
                    for sym in section.iter_symbols():
                        if sym["st_shndx"] != "SHN_UNDEF" and sym.name:
                            symbols.add(sym.name)
        except Exception:  # noqa: S110, BLE001 - identity extraction is best effort
            pass
        return symbols

    def _extract_rodata_signatures(self, filename: str, data: bytes, result: ELFExtractionResult):
        """Match .rodata banner signatures and error strings."""
        if result.version:
            return

        # Determine library key from filename
        lib_key = filename.lower()
        lib_key = lib_key.removeprefix("lib")
        so_idx = lib_key.find(".so")
        if so_idx > 0:
            lib_key = lib_key[:so_idx]
        if lib_key.startswith("pcre2-"):
            lib_key = "pcre2"

        patterns = KNOWN_RODATA_PATTERNS.get(lib_key)
        if not patterns:
            clean_name = filename.lower()
            clean_name = clean_name.removeprefix("lib")
            clean_name = clean_name.removesuffix(".so")
            patterns = KNOWN_RODATA_PATTERNS.get(clean_name)

        if not patterns:
            return

        search_chunk = data[: 4 * 1024 * 1024]
        for pattern, desc in patterns:
            if lib_key == "curl" and ".so" not in filename and desc.startswith("libcurl"):
                continue
            match = re.search(pattern, search_chunk)
            if match:
                if match.groups():
                    ver = match.group(1).decode("ascii", errors="replace")
                    result.version = ver
                    result.confidence = 0.90
                    result.method = ExtractionMethod.STRING_PATTERN
                    result.evidence = f"{desc}: {match.group(0).decode('ascii', errors='replace')}"
                    result.purl = f"pkg:generic/{filename}@{ver}"
                    return
                elif b"BoringSSL" in match.group(0):
                    result.version = ""
                    result.canonical_name = "boringssl"
                    result.confidence = 0.85
                    result.method = ExtractionMethod.STRING_PATTERN
                    result.evidence = "BoringSSL identifier in binary"
                    result.purl = "pkg:generic/boringssl"
                    return

    def _extract_protobuf_version(self, filename: str, data: bytes, result: ELFExtractionResult):
        # Arbitrary four-byte windows in instructions are not protobuf version
        # constants. Only a proven instruction-level data flow may establish one.
        return

    def _extract_symbol_milestones(self, data: bytes, result: ELFExtractionResult, defined=None):
        """Keep observed APIs as identity evidence, never as exact releases."""
        if defined is None:
            defined = self._defined_symbols(data)
        for sym, comp_name, min_ver, reason in LANDMARK_SYMBOLS:
            if sym in defined:
                result.facts.append({"name": "firmware:elf:defined_api", "value": sym})

    def _extract_crypto_constants(self, data: bytes, result: ELFExtractionResult):
        """Check for cryptographic magic numbers & lookup tables (S-Box, SHA256)."""
        if AES_SBOX_PREFIX in data:
            result.evidence = "Embedded AES S-Box table detected"
        elif CHACHA20_MAGIC in data:
            result.evidence = "ChaCha20 magic constant ('expand 32-byte k') detected"
        elif SHA256_IV in data:
            result.evidence = "SHA-256 initial constant vector detected"

    def _extract_anchored_signatures(self, filename: str, data: bytes, result: ELFExtractionResult):
        """Extract anchored version patterns where format string and version string are separate."""
        if result.version:
            return
        fn_lower = filename.lower()
        search_chunk = data[: 8 * 1024 * 1024]
        for name, canonical, anchors, shape in ANCHORED_PATTERNS:
            if name in fn_lower or any(a in search_chunk for a in anchors):
                anchor = next((a for a in anchors if a in search_chunk), None)
                if not anchor:
                    continue
                shape_re = re.compile(
                    rb"(?<![0-9A-Za-z._+-])(" + shape + rb"(?:-g?[0-9a-f]{7,12})?)(?=\x00)"
                )
                tokens = {
                    m.group(1).decode("ascii", errors="replace")
                    for m in shape_re.finditer(search_chunk)
                }
                if len(tokens) == 1:
                    raw_ver = tokens.pop()
                    ver = raw_ver
                    result.version = ver
                    result.canonical_name = canonical
                    result.confidence = 0.90
                    result.method = ExtractionMethod.STRING_PATTERN
                    result.evidence = f"Anchored signature '{anchor.decode('ascii', errors='replace')}' with version {ver}"
                    result.purl = f"pkg:generic/{canonical}@{ver}"
                    return

    def _extract_symbol_sets(
        self, filename: str, data: bytes, result: ELFExtractionResult, defined=None
    ):
        """Match whole NUL-delimited exported API symbol sets for stripped binaries."""
        if result.version:
            return
        if defined is None:
            defined = self._defined_symbols(data)
        for name, canonical, need, syms in SYMBOL_SETS:
            hits = 0
            for s in syms:
                if s in defined:
                    hits += 1
            if hits >= need:
                result.version = ""
                result.canonical_name = canonical
                result.confidence = 0.85
                result.method = ExtractionMethod.SYMBOL_TABLE
                result.evidence = f"Exported symbol set matched: {hits}/{len(syms)} APIs of {name}"
                result.purl = f"pkg:generic/{canonical}"
                return

    def _extract_go_buildinfo(self, data: bytes, result: ELFExtractionResult):
        """Extract Go runtime version and dependencies from embedded debug/buildinfo."""
        if result.version:
            return
        at = data.find(GO_MAGIC)
        if at >= 0 and at + 32 <= len(data) and data[at + 14] in (4, 8) and (data[at + 15] & 0x2):
            res = _go_string(data, at + 32)
            if res and res[0].startswith("go"):
                go_ver = res[0].replace("go", "")
                result.version = go_ver
                result.canonical_name = "golang"
                result.version_kind = "runtime"
                result.confidence = 0.98
                result.method = ExtractionMethod.MANIFEST_BINARY
                result.evidence = f"Go embedded buildinfo: {res[0]}"
                result.purl = f"pkg:golang/go@{go_ver}"
                return
