"""ESP-IDF application image parsing and metadata tests."""

from __future__ import annotations

import asyncio
import struct
from pathlib import Path

from firmware_scanner.core.context import AnalysisContext
from firmware_scanner.extraction.deep_scanner import ComponentDatabase, DeepScanner
from firmware_scanner.extraction.extractors.binary_signatures import BinarySignatureExtractor
from firmware_scanner.extraction.extractors.string_patterns import StringPatternExtractor
from firmware_scanner.extraction.models import ExtractionMethod
from firmware_scanner.firmware.formats.esp_idf import ESPIDFFormat
from firmware_scanner.rtos.plugins.esp_idf import ESPIDFPlugin


def _app_image(
    *,
    project_name: str = "https_request",
    app_version: str = "v5.4",
    idf_version: str = "v5.4",
) -> bytes:
    app_desc = bytearray(256)
    struct.pack_into("<I", app_desc, 0, 0xABCD5432)
    struct.pack_into("<I", app_desc, 4, 3)
    app_desc[0x10:0x30] = app_version.encode().ljust(32, b"\0")
    app_desc[0x30:0x50] = project_name.encode().ljust(32, b"\0")
    app_desc[0x50:0x60] = b"02:44:19".ljust(16, b"\0")
    app_desc[0x60:0x70] = b"Nov 23 2026".ljust(16, b"\0")
    app_desc[0x70:0x90] = idf_version.encode().ljust(32, b"\0")
    app_desc[0x90:0xB0] = bytes(range(32))

    header = bytearray(24)
    header[0:4] = b"\xe9\x01\x02\x10"
    struct.pack_into("<I", header, 4, 0x400813D4)
    segment_header = struct.pack("<II", 0x3F400020, len(app_desc))
    return bytes(header) + segment_header + bytes(app_desc)


def test_unpack_extracts_esp_app_descriptor_metadata() -> None:
    image = _app_image()

    result = ESPIDFFormat().unpack(image, Path("https_request.bin"))

    descriptor = result.metadata["esp_app_desc"]
    assert descriptor["project_name"] == "https_request"
    assert descriptor["app_version"] == "v5.4"
    assert descriptor["idf_version"] == "v5.4"
    assert descriptor["build_time"] == "02:44:19"
    assert descriptor["build_date"] == "Nov 23 2026"
    assert descriptor["secure_version"] == 3
    assert descriptor["elf_sha256"] == bytes(range(32)).hex()


def test_plugin_uses_app_descriptor_for_idf_and_project_versions() -> None:
    image = _app_image()
    result = ESPIDFFormat().unpack(image, Path("https_request.bin"))
    context = AnalysisContext(
        firmware_path=Path("https_request.bin"),
        raw_data=image,
        unpack_result=result,
    )

    components = asyncio.run(ESPIDFPlugin().analyze(context))
    by_name = {component.name: component for component in components}

    idf = by_name["ESP-IDF"]
    assert idf.resolved_version == "v5.4"
    assert idf.component_type == "framework"
    assert idf.versions[0].method == ExtractionMethod.BUILD_METADATA
    assert "idf_ver" in idf.versions[0].evidence

    application = by_name["https_request"]
    assert application.resolved_version == "v5.4"
    assert application.component_type == "application"
    assert application.versions[0].method == ExtractionMethod.BUILD_METADATA


def _scan_deep(data: bytes) -> list:
    context = AnalysisContext(
        firmware_path=Path("fixture.bin"),
        raw_data=data,
    )
    return DeepScanner(ComponentDatabase()).scan(context)


def test_esp_idf_http_user_agent_is_not_treated_as_idf_version() -> None:
    components = _scan_deep(
        b"esp_wifi_init\0esp_event_loop\0GET / HTTP/1.1\r\nUser-Agent: esp-idf/1.0 esp32\r\n\r\n"
    )

    versions = [
        claim.version
        for component in components
        if component.name == "ESP-IDF"
        for claim in component.versions
    ]
    assert "1.0" not in versions


def test_esp_idf_version_prefixed_http_user_agent_is_rejected() -> None:
    components = _scan_deep(
        b"esp_wifi_init\0esp_event_loop\0GET / HTTP/1.1\r\nUser-Agent: esp-idf/v5.4 esp32\r\n\r\n"
    )

    versions = [
        claim.version
        for component in components
        if component.name == "ESP-IDF"
        for claim in component.versions
    ]
    assert "5.4" not in versions


def test_esp_idf_release_banner_still_supplies_version() -> None:
    components = _scan_deep(b"ESP-IDF v5.4 build banner")

    esp_idf = next(component for component in components if component.name == "ESP-IDF")
    assert esp_idf.resolved_version == "5.4"


def test_esp_idf_extractors_classify_framework() -> None:
    context = AnalysisContext(
        firmware_path=Path("fixture.bin"),
        raw_data=b"esp_idf\0ESP_ERROR_CHECK\0ESP-IDF v5.4\0",
    )

    signature_components = asyncio.run(BinarySignatureExtractor().extract(context))
    string_components = asyncio.run(StringPatternExtractor().extract(context))

    signature = next(c for c in signature_components if c.name == "ESP-IDF")
    banner = next(c for c in string_components if c.name == "ESP-IDF")
    assert signature.component_type == "framework"
    assert banner.component_type == "framework"


def test_plugin_discovers_components_from_compiled_idf_source_paths() -> None:
    image = _app_image()
    result = ESPIDFFormat().unpack(image, Path("https_request.bin"))
    source_paths = (
        b"\0//IDF/components/esp_system/startup_funcs.c\0"
        b"\0//IDF/components/lwip/lwip/src/core/tcp.c\0"
        b"\0//IDF/components/mbedtls/port/bignum/esp_bignum.c\0"
        b"\0//IDF/examples/common_components/protocol_examples_common/connect.c\0"
    )
    context = AnalysisContext(
        firmware_path=Path("https_request.bin"),
        raw_data=image + source_paths,
        unpack_result=result,
    )

    components = asyncio.run(ESPIDFPlugin().analyze(context))
    by_name = {component.name: component for component in components}

    internal = by_name["component-esp-system"]
    assert internal.resolved_version == "v5.4"
    assert any(
        property_row["value"] == "//IDF/components/esp_system/startup_funcs.c"
        for property_row in internal.properties
        if property_row["name"] == "firmware:evidence:source_path"
    )
    assert by_name["component-protocol-examples-common"].resolved_version == "v5.4"
    assert "lwIP" in by_name
    assert "mbedTLS" in by_name
