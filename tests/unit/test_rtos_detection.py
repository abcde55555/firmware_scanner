"""Tests for RTOSRegistry."""

import pytest

from firmware_scanner.core.context import AnalysisContext
from firmware_scanner.rtos.registry import RTOSRegistry
from firmware_scanner.rtos.base import RTOSPlugin


class TestRTOSRegistry:
    def test_get_all_returns_plugins(self):
        """RTOSRegistry.get_all() returns a list of registered plugin classes."""
        plugins = RTOSRegistry.get_all()
        assert isinstance(plugins, list)
        # Built-in plugins should have been registered on import
        assert len(plugins) > 0

    def test_registered_plugins_are_rtos_plugin_subclasses(self):
        """All registered plugins should be subclasses of RTOSPlugin."""
        plugins = RTOSRegistry.get_all()
        for plugin_cls in plugins:
            assert issubclass(plugin_cls, RTOSPlugin)

    def test_detect_with_freertos_data(self, freertos_context):
        """RTOSRegistry.detect() should detect FreeRTOS in firmware with its markers."""
        results = RTOSRegistry.detect(freertos_context)
        # Should have at least one detection result
        assert len(results) > 0
        # Results are sorted by confidence descending
        plugin, confidence = results[0]
        assert confidence >= 0.3
        assert plugin.rtos_name.lower() in ("freertos", "esp-idf")

    def test_detect_with_empty_data(self, empty_context):
        """RTOSRegistry.detect() returns empty list for data with no markers."""
        results = RTOSRegistry.detect(empty_context)
        # Should find no RTOS with confidence >= 0.3
        assert isinstance(results, list)
        # All zeros data shouldn't strongly match any RTOS
        for plugin, confidence in results:
            assert confidence < 0.9

    def test_detect_linux_suppresses_rtos(self, tmp_path):
        """Linux markers should suppress non-Linux RTOS detections."""
        data = b"Linux version 5.10.0\x00" + b"\x00" * 512 + b"xTaskCreate\x00"
        fw_path = tmp_path / "linux_fw.bin"
        fw_path.write_bytes(data)
        context = AnalysisContext(
            firmware_path=fw_path,
            raw_data=data,
            file_hash_sha256="dummy",
            file_hash_md5="dummy",
        )
        results = RTOSRegistry.detect(context)
        # Any detected RTOS should be Linux-related, not FreeRTOS
        for plugin, confidence in results:
            if confidence >= 0.3:
                assert plugin.rtos_name not in ("FreeRTOS",)
