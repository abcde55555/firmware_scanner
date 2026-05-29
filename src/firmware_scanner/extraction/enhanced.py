"""Enhanced analysis: compressed section extraction, build metadata, compiler detection."""

import gzip
import struct
import re
from pathlib import Path

from ..extraction.models import FirmwareSection


# Magic bytes for compressed formats
GZIP_MAGIC = b"\x1f\x8b"
LZMA_MAGIC = b"\x5d\x00\x00"
XZ_MAGIC = b"\xfd7zXZ\x00"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
LZ4_MAGIC = b"\x04\x22\x4d\x18"
BZIP2_MAGIC = b"BZ"


def extract_compressed_sections(data: bytes) -> list[FirmwareSection]:
    """Find and decompress embedded compressed regions in firmware."""
    extracted: list[FirmwareSection] = []

    # Scan for gzip sections
    offset = 0
    while True:
        pos = data.find(GZIP_MAGIC, offset)
        if pos == -1:
            break
        try:
            decompressed = gzip.decompress(data[pos:pos + 1024 * 1024])
            if len(decompressed) > 64:
                extracted.append(FirmwareSection(
                    name=f"gzip_{pos:#x}",
                    offset=pos,
                    size=len(decompressed),
                    data=decompressed,
                    section_type="decompressed",
                ))
        except Exception:
            pass
        offset = pos + 2

    # Scan for LZMA sections
    offset = 0
    while True:
        pos = data.find(LZMA_MAGIC, offset)
        if pos == -1:
            break
        try:
            import lzma
            decompressed = lzma.decompress(data[pos:pos + 1024 * 1024])
            if len(decompressed) > 64:
                extracted.append(FirmwareSection(
                    name=f"lzma_{pos:#x}",
                    offset=pos,
                    size=len(decompressed),
                    data=decompressed,
                    section_type="decompressed",
                ))
        except Exception:
            pass
        offset = pos + 3

    # Scan for XZ sections
    offset = 0
    while True:
        pos = data.find(XZ_MAGIC, offset)
        if pos == -1:
            break
        try:
            import lzma
            decompressed = lzma.decompress(data[pos:pos + 2 * 1024 * 1024])
            if len(decompressed) > 64:
                extracted.append(FirmwareSection(
                    name=f"xz_{pos:#x}",
                    offset=pos,
                    size=len(decompressed),
                    data=decompressed,
                    section_type="decompressed",
                ))
        except Exception:
            pass
        offset = pos + 6

    return extracted


def extract_build_metadata(data: bytes) -> dict[str, str]:
    """Extract build metadata from firmware (compiler, build date, flags)."""
    metadata: dict[str, str] = {}
    text = data.decode("ascii", errors="ignore")

    # GCC version detection
    gcc_patterns = [
        r"GCC:\s*\(([^)]+)\)\s*([\d.]+)",
        r"gcc\s+version\s+([\d.]+)",
        r"arm-none-eabi-gcc.*?([\d.]+)",
        r"GCC\s+([\d.]+)",
    ]
    for pat in gcc_patterns:
        match = re.search(pat, text)
        if match:
            metadata["compiler"] = f"GCC {match.group(0)}"
            break

    # Clang/LLVM detection
    clang_patterns = [
        r"clang\s+version\s+([\d.]+)",
        r"LLVM\s+([\d.]+)",
        r"Apple\s+clang.*?([\d.]+)",
    ]
    for pat in clang_patterns:
        match = re.search(pat, text)
        if match:
            metadata["compiler"] = f"Clang {match.group(0)}"
            break

    # IAR detection
    iar_match = re.search(r"IAR\s+(?:ARM|RISC-V).*?[Vv]?([\d.]+)", text)
    if iar_match:
        metadata["compiler"] = f"IAR {iar_match.group(0)}"

    # Keil/ARMCC detection
    keil_match = re.search(r"ARM\s*Compiler\s*([\d.]+)", text)
    if keil_match:
        metadata["compiler"] = f"ARM Compiler {keil_match.group(1)}"

    # Build date
    date_patterns = [
        r"((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{4})",
        r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2})",
        r"Build:\s*(\d{8})",
    ]
    for pat in date_patterns:
        match = re.search(pat, text)
        if match:
            metadata["build_date"] = match.group(1)
            break

    # Build flags / optimization level
    opt_match = re.search(r"-O[0-3sg]", text)
    if opt_match:
        metadata["optimization"] = opt_match.group(0)

    # SDK version
    sdk_patterns = [
        (r"SDK\s+[Vv]?([\d.]+)", "sdk_version"),
        (r"BSP\s+[Vv]?([\d.]+)", "bsp_version"),
        (r"HAL\s+[Vv]?([\d.]+)", "hal_version"),
    ]
    for pat, key in sdk_patterns:
        match = re.search(pat, text)
        if match:
            metadata[key] = match.group(1)

    return metadata


def detect_nested_firmware(data: bytes) -> list[tuple[int, str]]:
    """Detect nested firmware images within the binary."""
    nested: list[tuple[int, str]] = []

    # ELF headers
    offset = 0
    while True:
        pos = data.find(b"\x7fELF", offset)
        if pos == -1 or pos == 0:
            break
        nested.append((pos, "ELF"))
        offset = pos + 4

    # ESP-IDF image magic
    for i in range(256, len(data) - 8, 4):
        if data[i] == 0xE9 and 1 <= data[i+1] <= 16:
            # Verify it looks like a real ESP header
            entry = struct.unpack_from("<I", data, i+4)[0]
            if 0x40000000 <= entry <= 0x40800000:
                nested.append((i, "ESP-IDF"))

    # U-Boot image header (magic 0x27051956)
    uboot_magic = b"\x27\x05\x19\x56"
    offset = 0
    while True:
        pos = data.find(uboot_magic, offset)
        if pos == -1:
            break
        nested.append((pos, "U-Boot"))
        offset = pos + 4

    return nested
