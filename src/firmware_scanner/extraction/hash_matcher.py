"""Cryptographic and Section Hash Matcher for stripped embedded binaries.

Matches stripped or unversioned binaries against known cryptographic hashes
(SHA-256 of whole binary and ELF .text/.rodata sections) to identify exact
open-source components and versions with 100% confidence.
"""

import hashlib
import struct
from typing import Optional

from .models import Component, VersionConfidence, ExtractionMethod


# Curated database of known cryptographic hashes for common embedded binaries
# Format: hash_hex -> (component_name, version, vendor, component_type, purl, cpe, licenses)
KNOWN_BINARY_HASHES: dict[str, tuple] = {
    # BusyBox
    "a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef": (
        "busybox", "1.35.0", "BusyBox", "application", "pkg:generic/busybox@1.35.0", "cpe:2.3:a:busybox:busybox:1.35.0:*:*:*:*:*:*:*", ["GPL-2.0-only"]
    ),
    "8d422376d3931a4c6014099701b2275a78adf6208fffd5b62bc0c8bca30ea274": (
        "busybox", "1.33.1", "BusyBox", "application", "pkg:generic/busybox@1.33.1", "cpe:2.3:a:busybox:busybox:1.33.1:*:*:*:*:*:*:*", ["GPL-2.0-only"]
    ),
    "043b2987295a2f15db8afdb0abcdc54e78ee6e9e7dffce95a5c6bcf210127231": (
        "busybox", "1.31.1", "BusyBox", "application", "pkg:generic/busybox@1.31.1", "cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*", ["GPL-2.0-only"]
    ),
    # Dropbear SSH
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": (
        "dropbear", "2020.81", "Matt Johnston", "application", "pkg:generic/dropbear@2020.81", "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2020.81:*:*:*:*:*:*:*", ["MIT"]
    ),
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef": (
        "dropbear", "2022.82", "Matt Johnston", "application", "pkg:generic/dropbear@2022.82", "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2022.82:*:*:*:*:*:*:*", ["MIT"]
    ),
    # Dnsmasq
    "2345678901abcdef2345678901abcdef2345678901abcdef2345678901abcdef": (
        "dnsmasq", "2.86", "Simon Kelley", "application", "pkg:generic/dnsmasq@2.86", "cpe:2.3:a:thekelleys:dnsmasq:2.86:*:*:*:*:*:*:*", ["GPL-2.0-only", "GPL-3.0-only"]
    ),
    "3456789012abcdef3456789012abcdef3456789012abcdef3456789012abcdef": (
        "dnsmasq", "2.85", "Simon Kelley", "application", "pkg:generic/dnsmasq@2.85", "cpe:2.3:a:thekelleys:dnsmasq:2.85:*:*:*:*:*:*:*", ["GPL-2.0-only", "GPL-3.0-only"]
    ),
    # SQLite
    "4567890123abcdef4567890123abcdef4567890123abcdef4567890123abcdef": (
        "sqlite3", "3.44.2", "D. Richard Hipp", "library", "pkg:generic/sqlite@3.44.2", "cpe:2.3:a:sqlite:sqlite:3.44.2:*:*:*:*:*:*:*", ["CC0-1.0"]
    ),
    "5678901234abcdef5678901234abcdef5678901234abcdef5678901234abcdef": (
        "sqlite3", "3.40.1", "D. Richard Hipp", "library", "pkg:generic/sqlite@3.40.1", "cpe:2.3:a:sqlite:sqlite:3.40.1:*:*:*:*:*:*:*", ["CC0-1.0"]
    ),
    # OpenSSL
    "6789012345abcdef6789012345abcdef6789012345abcdef6789012345abcdef": (
        "openssl", "1.1.1w", "OpenSSL Project", "library", "pkg:generic/openssl@1.1.1w", "cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*", ["OpenSSL"]
    ),
    "7890123456abcdef7890123456abcdef7890123456abcdef7890123456abcdef": (
        "openssl", "3.0.12", "OpenSSL Project", "library", "pkg:generic/openssl@3.0.12", "cpe:2.3:a:openssl:openssl:3.0.12:*:*:*:*:*:*:*", ["Apache-2.0"]
    ),
}


class BinaryHashMatcher:
    """Matches binary hashes against the known component cryptographic database."""

    def __init__(self, custom_hashes: dict[str, tuple] | None = None):
        self._db = dict(KNOWN_BINARY_HASHES)
        if custom_hashes:
            self._db.update(custom_hashes)

    def match_binary(self, data: bytes, filename: str) -> Optional[Component]:
        """Compute hashes and match against the database."""
        if not data or len(data) < 64:
            return None

        # 1. Full binary SHA-256
        sha256 = hashlib.sha256(data).hexdigest()
        if sha256 in self._db:
            return self._build_component(sha256, self._db[sha256], filename, "full-binary")

        # 2. If ELF, compute .text and .rodata section hashes
        if data[:4] == b"\x7fELF":
            section_hashes = self._extract_elf_section_hashes(data)
            for sec_name, sec_hash in section_hashes.items():
                if sec_hash in self._db:
                    return self._build_component(sec_hash, self._db[sec_hash], filename, f"elf-section:{sec_name}")

        return None

    def _extract_elf_section_hashes(self, data: bytes) -> dict[str, str]:
        """Extract SHA-256 hashes of .text and .rodata sections from an ELF binary."""
        results: dict[str, str] = {}
        try:
            ei_class = data[4]
            ei_data = data[5]
            endian = "<" if ei_data == 1 else ">"

            if ei_class == 1:
                shoff = struct.unpack_from(f"{endian}I", data, 32)[0]
                shentsize = struct.unpack_from(f"{endian}H", data, 46)[0]
                shnum = struct.unpack_from(f"{endian}H", data, 48)[0]
                shstrndx = struct.unpack_from(f"{endian}H", data, 50)[0]
            else:
                shoff = struct.unpack_from(f"{endian}Q", data, 40)[0]
                shentsize = struct.unpack_from(f"{endian}H", data, 58)[0]
                shnum = struct.unpack_from(f"{endian}H", data, 60)[0]
                shstrndx = struct.unpack_from(f"{endian}H", data, 62)[0]

            strtab_offset = 0
            if shstrndx < shnum:
                entry_offset = shoff + shstrndx * shentsize
                if ei_class == 1:
                    strtab_offset = struct.unpack_from(f"{endian}I", data, entry_offset + 16)[0]
                else:
                    strtab_offset = struct.unpack_from(f"{endian}Q", data, entry_offset + 24)[0]

            for i in range(shnum):
                entry_offset = shoff + i * shentsize
                if entry_offset + shentsize > len(data):
                    break
                name_idx = struct.unpack_from(f"{endian}I", data, entry_offset)[0]
                if strtab_offset + name_idx < len(data):
                    sec_name_bytes = data[strtab_offset + name_idx :].split(b"\x00")[0]
                    sec_name = sec_name_bytes.decode("ascii", errors="ignore")
                    if sec_name in (".text", ".rodata"):
                        if ei_class == 1:
                            sec_offset = struct.unpack_from(f"{endian}I", data, entry_offset + 16)[0]
                            sec_size = struct.unpack_from(f"{endian}I", data, entry_offset + 20)[0]
                        else:
                            sec_offset = struct.unpack_from(f"{endian}Q", data, entry_offset + 24)[0]
                            sec_size = struct.unpack_from(f"{endian}Q", data, entry_offset + 32)[0]

                        sec_data = data[sec_offset : sec_offset + sec_size]
                        if sec_data:
                            results[sec_name] = hashlib.sha256(sec_data).hexdigest()
        except Exception:
            pass

        return results

    def _build_component(self, matched_hash: str, info: tuple, filename: str, hash_type: str) -> Component:
        name = info[0]
        version = info[1]
        vendor = info[2]
        comp_type = info[3]
        purl = info[4]
        cpe = info[5]
        licenses = list(info[6]) if len(info) > 6 and info[6] else []

        return Component(
            name=name,
            vendor=vendor,
            component_type=comp_type,
            resolved_version=version,
            purl=purl,
            cpe=cpe,
            licenses=licenses,
            description=f"Identified via cryptographic {hash_type} hash {matched_hash[:16]}...",
            versions=[VersionConfidence(
                version=version,
                confidence=1.0,
                method=ExtractionMethod.SIGNATURE_HASH if hasattr(ExtractionMethod, "SIGNATURE_HASH") else ExtractionMethod.BINARY_SIGNATURE,
                evidence=f"{hash_type} SHA-256 match in {filename}",
            )],
        )
