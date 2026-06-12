"""Tests for AnalysisConfig."""

from pathlib import Path

import pytest

from firmware_scanner.core.config import AnalysisConfig


class TestAnalysisConfig:
    def test_default_values(self):
        """Default AnalysisConfig has expected values."""
        config = AnalysisConfig()
        assert config.timeout == 300
        assert config.max_file_size == 512 * 1024 * 1024
        assert config.verbose is False
        assert config.output_format == "cyclonedx"
        assert config.output_path is None
        assert config.extractors == []
        assert config.skip_extractors == []

    def test_custom_max_file_size(self):
        """AnalysisConfig accepts custom max_file_size."""
        config = AnalysisConfig(max_file_size=1024 * 1024)
        assert config.max_file_size == 1024 * 1024

    def test_android_defaults(self):
        """Android-related settings have correct defaults."""
        config = AnalysisConfig()
        assert config.android_max_apks == 200
        assert config.android_max_libs == 300
        assert config.android_max_total_files == 2000
        assert config.android_max_single_file == 64 * 1024 * 1024

    def test_output_path_as_path_object(self):
        """output_path accepts a Path object."""
        config = AnalysisConfig(output_path=Path("/tmp/output.json"))
        assert config.output_path == Path("/tmp/output.json")

    def test_rtos_and_arch_hints(self):
        """rtos_hint and arch_hint can be set."""
        config = AnalysisConfig(rtos_hint="freertos", arch_hint="arm-cortex-m")
        assert config.rtos_hint == "freertos"
        assert config.arch_hint == "arm-cortex-m"
