"""Tests for ArchDetector."""

import struct

import pytest

from firmware_scanner.arch.detector import ArchDetector
from firmware_scanner.arch.models import ArchInfo, CPUFamily, Endianness, FileType


class TestArchDetector:
    def test_detect_elf_arm(self, elf_binary_data):
        """Detect ARM architecture from ELF header."""
        detector = ArchDetector()
        result = detector.detect(elf_binary_data)

        assert isinstance(result, ArchInfo)
        # Should detect ARM from the ELF header (e_machine=40)
        assert result.cpu_family in (
            CPUFamily.ARM, CPUFamily.ARM_CORTEX_M,
            CPUFamily.ARM_CORTEX_A, CPUFamily.ARM_CORTEX_R,
        )
        assert result.confidence > 0.0

    def test_detect_elf_file_type(self, elf_binary_data):
        """Detect ELF file type from magic bytes."""
        detector = ArchDetector()
        result = detector.detect(elf_binary_data)

        assert result.file_type == FileType.ELF

    def test_detect_returns_arch_info_for_any_data(self):
        """Any input data returns a valid ArchInfo (never raises)."""
        detector = ArchDetector()
        # Sequential byte data - may still be detected as ARM by instruction probe
        data = bytes(range(256)) * 4
        result = detector.detect(data)

        assert isinstance(result, ArchInfo)
        # Should always return a valid result with confidence in [0, 1]
        assert 0.0 <= result.confidence <= 1.0
        assert result.file_type == FileType.RAW_BINARY

    def test_guess_endianness_little(self):
        """_guess_endianness detects little-endian pattern."""
        detector = ArchDetector()
        # Little-endian pattern: null bytes in high (odd) positions
        # e.g., 16-bit values like 0x0041 stored as [0x41, 0x00]
        data = b""
        for i in range(512):
            if i % 2 == 1:
                data += b"\x00"
            else:
                data += b"\x41"
        result = detector._guess_endianness(data)
        assert result == Endianness.LITTLE

    def test_guess_file_type_pe(self):
        """_guess_file_type returns PE for MZ header."""
        detector = ArchDetector()
        data = b"MZ" + b"\x00" * 100
        result = detector._guess_file_type(data)
        assert result == FileType.PE
