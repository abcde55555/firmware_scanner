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
from typing import Optional

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    HAVE_ELFTOOLS = True
except ImportError:
    HAVE_ELFTOOLS = False

from .models import VersionConfidence, ExtractionMethod


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


# Milestone symbols mapping for landmark API fingerprinting
LANDMARK_SYMBOLS: list[tuple[str, str, str, str]] = [
    ("EVP_MAC_CTX_new", "OpenSSL/BoringSSL", "3.0+", "EVP_MAC API introduced in OpenSSL 3.0+ / BoringSSL"),
    ("TLS_method", "OpenSSL", "1.1+", "TLS_method API introduced in OpenSSL 1.1.0"),
    ("deflatePending", "zlib", "1.2.11+", "deflatePending API introduced in zlib 1.2.11"),
    ("sqlite3_autocommit", "sqlite3", "3.37.0+", "sqlite3_autocommit API introduced in SQLite 3.37.0"),
    ("sqlite3_drop_modules", "sqlite3", "3.30.0+", "sqlite3_drop_modules API introduced in SQLite 3.30.0"),
    ("sqlite3_keyword_name", "sqlite3", "3.24.0+", "sqlite3_keyword_name API introduced in SQLite 3.24.0"),
]


# Known rodata patterns (library -> list of (regex, desc))
KNOWN_RODATA_PATTERNS: dict[str, list[tuple[bytes, str]]] = {
    "sqlite": [
        (rb'(?:SQLite version |^|\x00)(3\.\d{1,2}\.\d+)', "SQLite version string"),
    ],
    "png": [
        (rb'libpng version (\d+\.\d+\.\d+)', "libpng version string"),
        (rb'PNG Library (\d+\.\d+\.\d+)', "PNG Library version string"),
    ],
    "jpeg": [
        (rb'libjpeg-turbo version (\d+\.\d+\.\d+(?:\.\d+)?)', "libjpeg-turbo version string"),
        (rb'(\d+\.\d+)\x00.{0,16}JFIF', "JFIF version string"),
    ],
    "zlib": [
        (rb'deflate (\d+\.\d+\.\d+(?:\.\d+)?)', "zlib version string"),
        (rb'inflate (\d+\.\d+\.\d+)', "zlib version string"),
        (rb'(\d+\.\d+\.\d+(?:\.\d+)?)\x00.{0,8}deflate', "zlib deflate version"),
    ],
    "z": [
        (rb'deflate (\d+\.\d+\.\d+(?:\.\d+)?)', "zlib version string"),
        (rb'inflate (\d+\.\d+\.\d+)', "zlib version string"),
        (rb'(\d+\.\d+\.\d+(?:\.\d+)?)\x00.{0,8}deflate', "zlib deflate version"),
    ],
    "libz": [
        (rb'deflate (\d+\.\d+\.\d+(?:\.\d+)?)', "zlib version string"),
        (rb'inflate (\d+\.\d+\.\d+)', "zlib version string"),
        (rb'(\d+\.\d+\.\d+(?:\.\d+)?)\x00.{0,8}deflate', "zlib deflate version"),
    ],
    "expat": [
        (rb'expat_(\d+\.\d+\.\d+)', "expat version string"),
        (rb'(\d+\.\d+\.\d+)\x00.{0,16}expat', "expat version string"),
    ],
    "xml2": [
        (rb'(?:GITv|libxml2-)(\d+\.\d+\.\d+)', "libxml2 version string"),
        (rb'(\d+\.\d+\.\d+)\x00.{0,16}libxml', "libxml2 version string"),
    ],
    "lz4": [
        (rb'\x00(1\.\d{1,2}\.\d+)\x00(?:ERROR_)?', "lz4 version string"),
    ],
    "harfbuzz": [
        (rb'(\d{1,2}\.\d{1,2}\.\d{1,2})\x00end table', "HarfBuzz version string"),
        (rb'HarfBuzz (\d+\.\d+\.\d+)', "HarfBuzz version string"),
    ],
    "harfbuzz_ng": [
        (rb'(\d{1,2}\.\d{1,2}\.\d{1,2})\x00end table', "HarfBuzz version string"),
        (rb'HarfBuzz (\d+\.\d+\.\d+)', "HarfBuzz version string"),
    ],
    "pcre2": [
        (rb'(\d+\.\d+)\s+\d{4}-\d{2}-\d{2}', "PCRE2 release date version"),
    ],
    "pcre": [
        (rb'(\d+\.\d+)\s+\d{4}-\d{2}-\d{2}', "PCRE release date version"),
    ],
    "pcap": [
        (rb'libpcap version (\d+\.\d+\.\d+)', "libpcap version string"),
    ],
    "event": [
        (rb'(\d+\.\d+\.\d+)-stable', "libevent version string"),
    ],
    "bpf": [
        (rb'\x00(\d+\.\d+\.\d+)\x00Operation made no progress', "libbpf version string"),
    ],
    "ext2fs": [
        (rb'\x00(1\.\d{1,2}\.\d+)\x00Test_io', "libext2fs version string"),
        (rb'version of e2fsck!\x00(1\.\d+\.\d+)', "e2fsck version string"),
    ],
    "ext2_blkid": [
        (rb'\x00(1\.\d{1,2}\.\d+)\x00Test_io', "libext2fs version string"),
        (rb'version of e2fsck!\x00(1\.\d+\.\d+)', "e2fsck version string"),
    ],
    "curl": [
        (rb'libcurl/(\d+\.\d+\.\d+)', "libcurl version string"),
        (rb'curl (\d+\.\d+\.\d+)', "curl version string"),
    ],
    "toybox": [
        (rb'(\d+\.\d+\.\d+)-android', "Toybox Android version string"),
        (rb'toybox (\d+\.\d+\.\d+)', "Toybox version string"),
    ],
    "e2fsck": [
        (rb'version of e2fsck!\x00(\d+\.\d+\.\d+)', "e2fsck version string"),
        (rb'(\d+\.\d+\.\d+)\x00%12u non-contiguous', "e2fsck version string"),
        (rb'e2fsck (\d+\.\d+\.\d+)', "e2fsck version string"),
    ],
    "tune2fs": [
        (rb'\x00(1\.\d{1,2}\.\d+)\x00', "tune2fs version string"),
        (rb'version of e2fsck!\x00(\d+\.\d+\.\d+)', "tune2fs version string"),
    ],
    "resize2fs": [
        (rb'\x00(1\.\d{1,2}\.\d+)\x00', "resize2fs version string"),
        (rb'version of e2fsck!\x00(\d+\.\d+\.\d+)', "resize2fs version string"),
    ],
    "mke2fs": [
        (rb'\x00(1\.\d{1,2}\.\d+)\x00', "mke2fs version string"),
        (rb'version of e2fsck!\x00(\d+\.\d+\.\d+)', "mke2fs version string"),
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
        (rb'(\d+\.\d+\.\d+) \(legacy\)', "iptables version string"),
        (rb'iptables v(\d+\.\d+\.\d+)', "iptables version string"),
    ],
    "ip6tables": [
        (rb'(\d+\.\d+\.\d+) \(legacy\)', "ip6tables version string"),
        (rb'ip6tables v(\d+\.\d+\.\d+)', "ip6tables version string"),
    ],
    "bzip2": [
        (rb'(\d+\.\d+\.\d+), \d{1,2}-[A-Za-z]{3}-\d{4}', "bzip2 version string"),
        (rb'\x00(1\.\d+\.\d+)\x00(?:[^\x00]*?)Julian Seward', "bzip2 version string"),
        (rb'bzip2.*?Version (\d+\.\d+\.\d+)', "bzip2 version string"),
    ],
    "sh": [
        (rb'@\(#\)MIRBSD KSH (R\d+)', "MirBSD Korn Shell version"),
    ],
    "mksh": [
        (rb'@\(#\)MIRBSD KSH (R\d+)', "MirBSD Korn Shell version"),
    ],
    "bc": [
        (rb'divide by 0\x00(\d+\.\d+\.\d+)\x00', "bc version string"),
    ],
    "awk": [
        (rb'version (\d{8})', "awk version string"),
    ],
    "ssl": [
        (rb'OpenSSL (\d+\.\d+\.\d+[a-z]?)', "OpenSSL version string"),
        (rb'BoringSSL', "BoringSSL (unversioned AOSP fork)"),
    ],
    "crypto": [
        (rb'OpenSSL (\d+\.\d+\.\d+[a-z]?)', "OpenSSL version string"),
        (rb'BoringSSL', "BoringSSL (unversioned AOSP fork)"),
    ],
    "icuuc": [
        (rb'ICU (\d+\.\d+(?:\.\d+)?)', "ICU version string"),
        (rb'icudt(\d+)', "ICU data version"),
    ],
    "icui18n": [
        (rb'ICU (\d+\.\d+(?:\.\d+)?)', "ICU version string"),
    ],
    "opus": [
        (rb'libopus (\d+\.\d+(?:\.\d+)?)', "libopus version string"),
    ],
    "vpx": [
        (rb'libvpx v(\d+\.\d+\.\d+)', "libvpx version string"),
        (rb'v(\d+\.\d+\.\d+)\x00.{0,32}vpx', "libvpx version string"),
    ],
}


class ELFDeepExtractor:
    """Multi-tier extractor combining ELF metadata, symbol versioning, and signatures."""

    def extract(self, filename: str, data: bytes) -> Optional[ELFExtractionResult]:
        if len(data) < 16 or data[:4] != b'\x7fELF':
            return None

        result = ELFExtractionResult()
        clean_name = filename.rsplit('/', 1)[-1]
        result.canonical_name = clean_name

        # -------------------------------------------------------------
        # Layer 3 (Fast path): Android HAL Interface Versioning from Filename
        # e.g., android.hardware.camera.device@3.7.so -> 3.7
        #       android.hardware.audio.common-V4-ndk.so -> V4
        # -------------------------------------------------------------
        m_hidl = re.search(r'@(\d+\.\d+)(?:-.*)?\.so$', clean_name)
        if m_hidl:
            result.version = m_hidl.group(1)
            result.confidence = 0.95
            result.method = ExtractionMethod.MANIFEST_BINARY
            result.evidence = f"Android HIDL HAL interface @{result.version}"
            result.purl = f"pkg:generic/{clean_name}@{result.version}"
            return result

        m_aidl = re.search(r'-V(\d+)-(?:ndk|cpp)(?:\.so)?$', clean_name)
        if m_aidl:
            result.version = f"V{m_aidl.group(1)}"
            result.confidence = 0.95
            result.method = ExtractionMethod.MANIFEST_BINARY
            result.evidence = f"Android AIDL HAL interface {result.version}"
            result.purl = f"pkg:generic/{clean_name}@{result.version}"
            return result

        # -------------------------------------------------------------
        # Layer 1: ELF Dynamic Section (SONAME, RUNPATH) & Symbol Versions
        # -------------------------------------------------------------
        if HAVE_ELFTOOLS:
            self._extract_elf_headers(data, result)

        # -------------------------------------------------------------
        # Layer 2: .rodata Banner Signatures & Error Strings
        # -------------------------------------------------------------
        self._extract_rodata_signatures(clean_name, data, result)

        # -------------------------------------------------------------
        # Layer 3: Exported Symbol Milestones (Landmark APIs)
        # -------------------------------------------------------------
        if not result.version:
            self._extract_symbol_milestones(data, result)

        # -------------------------------------------------------------
        # Layer 4: Cryptographic Constants & Magic Numbers
        # -------------------------------------------------------------
        if not result.version:
            self._extract_crypto_constants(data, result)

        return result if result.version else None

    def _extract_elf_headers(self, data: bytes, result: ELFExtractionResult):
        """Extract SONAME, RUNPATH, symbol versions (.gnu.version_d/.gnu.version_r), .comment, and Android ident."""
        try:
            elffile = ELFFile(io.BytesIO(data))
            for section in elffile.iter_sections():
                # Dynamic section
                if isinstance(section, DynamicSection):
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == 'DT_SONAME':
                            soname = tag.soname
                            m = re.search(r'\.so\.(\d+(?:\.\d+)*)', soname)
                            if m and not result.version:
                                result.version = m.group(1)
                                result.confidence = 0.90
                                result.method = ExtractionMethod.BINARY_SIGNATURE
                                result.evidence = f"DT_SONAME version: {soname}"
                                result.purl = f"pkg:generic/{result.canonical_name}@{result.version}"
                        elif tag.entry.d_tag in ('DT_RPATH', 'DT_RUNPATH'):
                            path_str = getattr(tag, 'runpath', '') or getattr(tag, 'rpath', '')
                            m = re.search(r'/([a-zA-Z0-9_\-]+)[-_]v?(\d+\.\d+(?:\.\d+)?(?:[a-z]|[-_][a-z0-9]+)?)/', path_str)
                            if m and not result.version:
                                result.version = m.group(2)
                                result.confidence = 0.85
                                result.method = ExtractionMethod.STRING_PATTERN
                                result.evidence = f"Build path version: {m.group(0)}"
                                result.purl = f"pkg:generic/{m.group(1)}@{result.version}"

                # Symbol Version Definition (.gnu.version_d)
                elif section.name == '.gnu.version_d':
                    best_ver = self._extract_best_symbol_version(section)
                    if best_ver and not result.version:
                        result.version = best_ver[0]
                        result.confidence = 0.90
                        result.method = ExtractionMethod.SYMBOL_TABLE
                        result.evidence = f".gnu.version_d tag: {best_ver[1]}"
                        result.purl = f"pkg:generic/{result.canonical_name}@{result.version}"

                # Compiler and Toolchain (.comment)
                elif section.name == '.comment':
                    comment_text = section.data().decode('ascii', errors='ignore').replace('\x00', ' ').strip()
                    if comment_text:
                        result.toolchain = comment_text

                # Android Ident (.note.android.ident)
                elif section.name == '.note.android.ident':
                    raw = section.data()
                    if b'Android\x00' in raw:
                        idx = raw.find(b'Android\x00') + 8
                        if idx + 4 <= len(raw):
                            result.target_sdk = struct.unpack_from('<I', raw, idx)[0]
        except Exception:
            return

    def _extract_best_symbol_version(self, section) -> Optional[tuple[str, str]]:
        """Extract the highest version tag from .gnu.version_d."""
        tags = []
        try:
            for ver in section.iter_versions():
                vname = ver[0].name
                if vname:
                    tags.append(vname)
        except Exception:
            return None

        # Check OpenSSL tags (OPENSSL_1_1_1e, OPENSSL_3_0_0)
        openssl_tags = [t for t in tags if t.startswith('OPENSSL_')]
        if openssl_tags:
            # Sort by version
            openssl_tags.sort()
            latest = openssl_tags[-1]
            ver_part = latest.replace('OPENSSL_', '').replace('_', '.')
            return (ver_part, latest)

        # Check GLIBC tags (GLIBC_2.34)
        glibc_tags = [t for t in tags if t.startswith('GLIBC_')]
        if glibc_tags:
            glibc_tags.sort()
            latest = glibc_tags[-1]
            ver_part = latest.replace('GLIBC_', '')
            return (ver_part, latest)

        # Check ZLIB tags (ZLIB_1.2.9)
        zlib_tags = [t for t in tags if t.startswith('ZLIB_')]
        if zlib_tags:
            zlib_tags.sort()
            latest = zlib_tags[-1]
            ver_part = latest.replace('ZLIB_', '')
            return (ver_part, latest)

        # Check Libstdc++ tags (GLIBCXX_3.4.29)
        cxx_tags = [t for t in tags if t.startswith('GLIBCXX_')]
        if cxx_tags:
            cxx_tags.sort()
            latest = cxx_tags[-1]
            ver_part = latest.replace('GLIBCXX_', '')
            return (ver_part, latest)

        return None

    def _extract_rodata_signatures(self, filename: str, data: bytes, result: ELFExtractionResult):
        """Match .rodata banner signatures and error strings."""
        if result.version:
            return

        # Determine library key from filename
        lib_key = filename.lower()
        if lib_key.startswith('lib'):
            lib_key = lib_key[3:]
        so_idx = lib_key.find('.so')
        if so_idx > 0:
            lib_key = lib_key[:so_idx]

        patterns = KNOWN_RODATA_PATTERNS.get(lib_key)
        if not patterns:
            clean_name = filename.lower()
            if clean_name.startswith("lib"):
                clean_name = clean_name[3:]
            if clean_name.endswith(".so"):
                clean_name = clean_name[:-3]
            patterns = KNOWN_RODATA_PATTERNS.get(clean_name)

        if not patterns:
            fn_lower = filename.lower()
            for k, pats in KNOWN_RODATA_PATTERNS.items():
                if len(k) >= 3 and (k in lib_key or k in fn_lower):
                    patterns = pats
                    break

        if not patterns:
            return

        search_chunk = data[:4 * 1024 * 1024]
        for pattern, desc in patterns:
            match = re.search(pattern, search_chunk)
            if match:
                if match.groups():
                    ver = match.group(1).decode('ascii', errors='replace')
                    result.version = ver
                    result.confidence = 0.90
                    result.method = ExtractionMethod.STRING_PATTERN
                    result.evidence = f"{desc}: {match.group(0).decode('ascii', errors='replace')}"
                    result.purl = f"pkg:generic/{filename}@{ver}"
                    return
                elif b"BoringSSL" in match.group(0):
                    result.version = "BoringSSL"
                    result.confidence = 0.85
                    result.method = ExtractionMethod.STRING_PATTERN
                    result.evidence = "BoringSSL identifier in binary"
                    result.purl = f"pkg:generic/{filename}@BoringSSL"
                    return

    def _extract_symbol_milestones(self, data: bytes, result: ELFExtractionResult):
        """Check for landmark exported symbols indicating minimum version."""
        for sym, comp_name, min_ver, reason in LANDMARK_SYMBOLS:
            sym_bytes = sym.encode('ascii') + b'\x00'
            if sym_bytes in data:
                result.version = min_ver
                result.confidence = 0.80
                result.method = ExtractionMethod.SYMBOL_TABLE
                result.evidence = f"Landmark symbol: {reason}"
                result.purl = f"pkg:generic/{result.canonical_name}@{min_ver}"
                return

    def _extract_crypto_constants(self, data: bytes, result: ELFExtractionResult):
        """Check for cryptographic magic numbers & lookup tables (S-Box, SHA256)."""
        if AES_SBOX_PREFIX in data:
            result.evidence = "Embedded AES S-Box table detected"
        elif CHACHA20_MAGIC in data:
            result.evidence = "ChaCha20 magic constant ('expand 32-byte k') detected"
        elif SHA256_IV in data:
            result.evidence = "SHA-256 initial constant vector detected"
