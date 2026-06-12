"""Tests for DeepScanner."""

import pytest

from firmware_scanner.extraction.deep_scanner import (
    DeepScanner,
    StringHit,
    ComponentHit,
    PROXIMITY_WINDOW,
)
from firmware_scanner.core.context import AnalysisContext
from firmware_scanner.extraction.models import Component


class TestStringHit:
    def test_create_string_hit(self):
        """StringHit can be instantiated with offset and value."""
        hit = StringHit(offset=100, value="OpenSSL 1.1.1k")
        assert hit.offset == 100
        assert hit.value == "OpenSSL 1.1.1k"
        assert hit.section_name == ""

    def test_string_hit_with_section(self):
        """StringHit can have a section name."""
        hit = StringHit(offset=200, value="test", section_name=".rodata")
        assert hit.section_name == ".rodata"


class TestComponentHit:
    def test_create_component_hit(self):
        """ComponentHit can be instantiated with required fields."""
        hit = ComponentHit(
            name="OpenSSL",
            vendor="OpenSSL Project",
            component_type="library",
            offset=0x1000,
            matched_pattern="OpenSSL",
        )
        assert hit.name == "OpenSSL"
        assert hit.vendor == "OpenSSL Project"
        assert hit.offset == 0x1000
        assert hit.nearby_strings == []

    def test_component_hit_nearby_strings(self):
        """ComponentHit accumulates nearby strings."""
        hit = ComponentHit(
            name="mbedTLS",
            vendor="ARM",
            component_type="library",
            offset=0x2000,
            matched_pattern="mbedTLS",
            nearby_strings=["2.28.0", "TLS handshake"],
        )
        assert len(hit.nearby_strings) == 2
        assert "2.28.0" in hit.nearby_strings


class TestDeepScannerConstants:
    def test_proximity_window_value(self):
        """PROXIMITY_WINDOW constant is set to expected value."""
        assert PROXIMITY_WINDOW == 512

    def test_max_section_scan_size(self):
        """MAX_SECTION_SCAN_SIZE is 8MB."""
        from firmware_scanner.extraction.deep_scanner import MAX_SECTION_SCAN_SIZE
        assert MAX_SECTION_SCAN_SIZE == 8 * 1024 * 1024
