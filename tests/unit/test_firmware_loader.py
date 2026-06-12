"""Tests for FirmwareLoader."""

import tempfile
from pathlib import Path

import pytest

from firmware_scanner.core.config import AnalysisConfig
from firmware_scanner.core.errors import FirmwareLoadError
from firmware_scanner.firmware.loader import FirmwareLoader


class TestFirmwareLoader:
    def test_load_valid_file(self, elf_binary_file, default_config):
        """Loading a valid file returns data, sha256, and md5."""
        loader = FirmwareLoader(default_config)
        data, sha256, md5 = loader.load(elf_binary_file)

        assert len(data) > 0
        assert data[:4] == b"\x7fELF"
        assert len(sha256) == 64  # SHA256 hex digest length
        assert len(md5) == 32  # MD5 hex digest length

    def test_load_nonexistent_file(self, default_config):
        """Loading a non-existent file raises FirmwareLoadError."""
        loader = FirmwareLoader(default_config)
        with pytest.raises(FirmwareLoadError, match="File not found"):
            loader.load(Path("/nonexistent/firmware.bin"))

    def test_load_empty_file(self, tmp_path, default_config):
        """Loading an empty file raises FirmwareLoadError."""
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")
        loader = FirmwareLoader(default_config)
        with pytest.raises(FirmwareLoadError, match="Empty file"):
            loader.load(empty_file)

    def test_load_file_too_large(self, tmp_path, small_config):
        """Loading a file exceeding max_file_size raises FirmwareLoadError."""
        large_file = tmp_path / "large.bin"
        large_file.write_bytes(b"\x00" * 2048)  # Exceeds small_config max of 1024
        loader = FirmwareLoader(small_config)
        with pytest.raises(FirmwareLoadError, match="File too large"):
            loader.load(large_file)

    def test_load_directory_raises_error(self, tmp_path, default_config):
        """Loading a directory path raises FirmwareLoadError."""
        loader = FirmwareLoader(default_config)
        with pytest.raises(FirmwareLoadError, match="Not a regular file"):
            loader.load(tmp_path)
