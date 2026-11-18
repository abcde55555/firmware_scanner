"""Match complete binary SHA-256 digests supplied by a trusted reference corpus.

An isolated .text or .rodata hash is useful candidate evidence, but cannot
establish the identity and release of the complete containing binary.
"""

import hashlib
import struct
from typing import Optional

from .models import Component, VersionConfidence, ExtractionMethod


# No unverifiable demonstration digests are bundled. Real entries must be
# accompanied by source/build provenance in the supplying reference corpus.
# Format: digest -> (name, version, vendor, type, purl, cpe, licenses)
KNOWN_BINARY_HASHES: dict[str, tuple] = {}


class BinaryHashMatcher:
    """Matches binary hashes against the known component cryptographic database."""

    def __init__(self, custom_hashes: dict[str, tuple] | None = None):
        self._db = dict(KNOWN_BINARY_HASHES)
        if custom_hashes:
            self._db.update(custom_hashes)

    def match_binary(self, data: bytes, filename: str) -> Optional[Component]:
        """Compute hashes and match against the database."""
        if not self._db or not data or len(data) < 64:
            return None

        # 1. Full binary SHA-256
        sha256 = hashlib.sha256(data).hexdigest()
        if sha256 in self._db:
            return self._build_component(sha256, self._db[sha256], filename, "full-binary")

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
