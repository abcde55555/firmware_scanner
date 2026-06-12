"""Shared fixtures for firmware_scanner tests."""

import struct
import tempfile
from pathlib import Path

import pytest

from firmware_scanner.core.config import AnalysisConfig
from firmware_scanner.core.context import AnalysisContext


@pytest.fixture
def default_config():
    """Default AnalysisConfig for testing."""
    return AnalysisConfig()


@pytest.fixture
def small_config():
    """AnalysisConfig with a small max file size for testing size limits."""
    return AnalysisConfig(max_file_size=1024)


@pytest.fixture
def elf_binary_data():
    """Minimal ELF binary data (32-bit little-endian ARM)."""
    # ELF magic + class(32-bit) + data(little-endian) + version + OS/ABI
    e_ident = b"\x7fELF" + b"\x01\x01\x01\x00" + b"\x00" * 8
    # e_type=2 (EXEC), e_machine=40 (ARM), e_version=1
    elf_header = struct.pack("<HHI", 2, 40, 1)
    # Pad the rest to make a valid-looking binary
    data = e_ident + elf_header + b"\x00" * 200
    return data


@pytest.fixture
def elf_binary_file(elf_binary_data):
    """Temp file containing minimal ELF binary."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(elf_binary_data)
        f.flush()
        yield Path(f.name)
    Path(f.name).unlink(missing_ok=True)


@pytest.fixture
def freertos_firmware_data():
    """Binary data with FreeRTOS markers embedded."""
    base = b"\x00" * 128
    markers = b"xTaskCreate\x00vTaskDelay\x00FreeRTOS V10.4.3\x00"
    padding = b"\x00" * 256
    return base + markers + padding


@pytest.fixture
def openssl_firmware_data():
    """Binary data with OpenSSL version string embedded."""
    base = b"\x00" * 64
    version_str = b"OpenSSL 1.1.1k  25 Mar 2021\x00"
    padding = b"\x00" * 200
    return base + version_str + padding


@pytest.fixture
def freertos_context(freertos_firmware_data, tmp_path):
    """AnalysisContext populated with FreeRTOS firmware data."""
    fw_path = tmp_path / "freertos_fw.bin"
    fw_path.write_bytes(freertos_firmware_data)
    return AnalysisContext(
        firmware_path=fw_path,
        raw_data=freertos_firmware_data,
        file_hash_sha256="dummy_sha256",
        file_hash_md5="dummy_md5",
    )


@pytest.fixture
def empty_context(tmp_path):
    """AnalysisContext with minimal data (no RTOS markers)."""
    data = b"\x00" * 512
    fw_path = tmp_path / "empty_fw.bin"
    fw_path.write_bytes(data)
    return AnalysisContext(
        firmware_path=fw_path,
        raw_data=data,
        file_hash_sha256="dummy_sha256",
        file_hash_md5="dummy_md5",
    )
