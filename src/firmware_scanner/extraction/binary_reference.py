"""Conservative, data-driven matching of third-party binary references.

This module deliberately does not infer component identity from undefined ELF
imports. Version claims come only from an explicitly configured upstream
banner; symbol-only rules report identity without claiming a version.
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BinaryReferenceMatch:
    name: str
    version: str = ""
    confidence: float = 0.0
    evidence: str = ""
    source: str = ""
    identity_only: bool = False


@lru_cache(maxsize=1)
def _load_catalog() -> dict[str, Any]:
    path = files("firmware_scanner.data").joinpath("binary_reference.json")
    return json.loads(path.read_text(encoding="utf-8"))


def openssl_compatibility_only(data: bytes, version: str) -> bool:
    """BoringSSL's OPENSSL_VERSION_TEXT advertises compatibility, not its release."""
    # https://boringssl.googlesource.com/boringssl/+/refs/heads/main/include/openssl/crypto.h
    if b'BoringSSL' not in data:
        return False
    try:
        encoded = version.encode('ascii')
    except UnicodeEncodeError:
        return False
    pattern = rb'OpenSSL\s+' + re.escape(encoded) + rb'(?![A-Za-z0-9._+-])'
    found = False
    for match in re.finditer(pattern, data, re.I):
        found = True
        if not re.match(rb'\s*\(compatible;\s*BoringSSL\)', data[match.end():match.end() + 96], re.I):
            return False
    return found


class BinaryReferenceMatcher:
    """Match curated upstream banners and defined ELF symbol combinations."""

    def __init__(self, catalog_path: str | Path | None = None):
        if catalog_path is None:
            self._catalog = _load_catalog()
        else:
            self._catalog = json.loads(Path(catalog_path).read_text(encoding="utf-8"))
        if self._catalog.get("schema_version") != 1:
            raise ValueError("Unsupported binary reference schema_version")
        self._rules = self._catalog.get("references", [])
        for rule in self._rules:
            if not rule.get("name") or not rule.get("source", "").startswith("https://"):
                raise ValueError("Each binary reference requires a name and HTTPS provenance")
            if rule.get("version_policy") not in {"banner", "identity_only"}:
                raise ValueError(f"Invalid version_policy for {rule.get('name')}")
            if rule.get("banner_regex"):
                re.compile(rule["banner_regex"], re.IGNORECASE)

    def match(self, data: bytes, filename: str = "") -> list[BinaryReferenceMatch]:
        if not isinstance(data, bytes) or not data:
            return []
        lowered = data.lower()
        text = None
        basename = Path(filename).name.lower()
        defined_symbols = self._defined_elf_symbols(data)
        matches: list[BinaryReferenceMatch] = []

        for rule in self._rules:
            name = rule["name"]
            filename_hint = any(hint.lower() in basename for hint in rule.get("filename_patterns", []))
            candidates: list[tuple[str, str, bool]] = []

            pattern = rule.get("banner_regex")
            prefix = re.match(r'[A-Za-z0-9 /_,:-]+', pattern or '')
            required = rule.get('required_literal') or (prefix.group(0) if prefix and len(prefix.group(0)) >= 3 else '')
            if pattern and (not required or required.lower().encode('ascii') in lowered):
                if text is None:
                    text = data.decode('latin-1')
                seen_versions: set[str] = set()
                for found in re.finditer(pattern, text, re.IGNORECASE):
                    if name == 'OpenSSL' and re.match(r'\s*\(compatible;\s*BoringSSL\)',
                                                     text[found.end():found.end() + 96], re.I):
                        continue
                    version = next((group for group in found.groups() if group is not None), "")
                    if version and version in seen_versions:
                        continue
                    if version:
                        seen_versions.add(version)
                    candidates.append(
                        (version, f"upstream banner matched: {found.group(0)}", not bool(version))
                    )
                    if len(candidates) >= 32:
                        break

            identity_banner = rule.get("identity_banner")
            if not candidates and identity_banner and identity_banner.lower().encode('ascii') in lowered:
                candidates.append(("", f"explicit identity banner: {identity_banner}", True))

            if not candidates:
                if name == 'OpenSSL' and b'boringssl' in lowered:
                    continue
                for group in rule.get("identity_symbols", []):
                    present = [symbol for symbol in group if symbol in defined_symbols]
                    if len(group) >= 2 and len(present) == len(group):
                        evidence = "defined ELF symbol combination: " + ", ".join(present)
                        candidates.append(("", evidence, True))
                        break

            for version, evidence, identity_only in candidates[:32]:
                if version:
                    confidence = 0.98 if filename_hint else 0.93
                else:
                    confidence = 0.91 if filename_hint else 0.82
                matches.append(
                    BinaryReferenceMatch(
                        name=name,
                        version=version,
                        confidence=confidence,
                        evidence=evidence,
                        source=rule["source"],
                        identity_only=identity_only or not version,
                    )
                )

        # A banner rule can overlap an identity-only API rule for the same
        # component. Keep the strongest evidence and avoid duplicate BOM rows.
        best: dict[tuple[str, str], BinaryReferenceMatch] = {}
        for match in matches:
            key = (match.name, match.version)
            current = best.get(key)
            if current is None or match.confidence > current.confidence:
                best[key] = match
        return sorted(best.values(), key=lambda item: (-item.confidence, item.name))

    @staticmethod
    def _defined_elf_symbols(data: bytes) -> set[str]:
        """Return globally/weakly bound, defined function/object names in ELF."""
        if len(data) < 16 or data[:4] != b"\x7fELF":
            return set()
        elf_class, encoding = data[4], data[5]
        if elf_class not in (1, 2) or encoding not in (1, 2):
            return set()
        endian = "<" if encoding == 1 else ">"
        try:
            if elf_class == 2:
                if len(data) < 64:
                    return set()
                shoff = struct.unpack_from(endian + "Q", data, 40)[0]
                shentsize, shnum = struct.unpack_from(endian + "HH", data, 58)
                section_format, section_size = endian + "IIQQQQIIQQ", 64
                symbol_format, symbol_size = endian + "IBBHQQ", 24
            else:
                if len(data) < 52:
                    return set()
                shoff = struct.unpack_from(endian + "I", data, 32)[0]
                shentsize, shnum = struct.unpack_from(endian + "HH", data, 46)
                section_format, section_size = endian + "IIIIIIIIII", 40
                symbol_format, symbol_size = endian + "IIIBBH", 16
            if shentsize < section_size or shnum == 0 or shoff + shentsize * shnum > len(data):
                return set()
            sections = [
                struct.unpack_from(section_format, data, shoff + index * shentsize)
                for index in range(shnum)
            ]
            names: set[str] = set()
            for section in sections:
                section_type = section[1]
                if section_type not in (2, 11):  # SHT_SYMTAB / SHT_DYNSYM
                    continue
                offset = section[4] if elf_class == 2 else section[4]
                size = section[5] if elf_class == 2 else section[5]
                link = section[6]
                entsize = section[9] if elf_class == 2 else section[9]
                if link >= len(sections) or entsize < symbol_size or offset + size > len(data):
                    continue
                strings_section = sections[link]
                strings_offset = strings_section[4]
                strings_size = strings_section[5]
                if strings_offset + strings_size > len(data):
                    continue
                strings = data[strings_offset : strings_offset + strings_size]
                for position in range(offset, offset + size - symbol_size + 1, entsize):
                    symbol = struct.unpack_from(symbol_format, data, position)
                    name_offset = symbol[0]
                    if elf_class == 2:
                        info, shndx = symbol[1], symbol[3]
                    else:
                        info, shndx = symbol[3], symbol[5]
                    binding, symbol_type = info >> 4, info & 0x0F
                    if not name_offset or shndx == 0 or binding not in (1, 2) or symbol_type not in (0, 1, 2):
                        continue
                    end = strings.find(b"\0", name_offset)
                    if name_offset < len(strings) and end > name_offset:
                        names.add(strings[name_offset:end].decode("utf-8", errors="replace"))
            return names
        except (IndexError, struct.error, OverflowError):
            return set()
