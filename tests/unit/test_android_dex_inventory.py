"""Bounded DEX inventory tests for Android APK and framework archives."""

import io
import zipfile

from firmware_scanner.android.system_scanner import AndroidSystemScanner
from firmware_scanner.extraction.models import Component


class _Filesystem:
    def is_valid(self):
        return True

    def exists(self, path):
        return False

    def read_file(self, path, max_size=16 * 1024 * 1024):
        return None


def _uleb128(value):
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _dex(*strings, imported=(), literals=()):
    """Build DEX string/type/class tables; imported types have no class definition."""
    defined_count = len(strings)
    type_count = len(strings) + len(imported)
    strings = strings + tuple(imported) + tuple(literals)
    table_offset = 0x70
    type_offset = table_offset + 4 * len(strings)
    class_offset = type_offset + 4 * type_count
    data_offset = class_offset + 32 * defined_count
    string_data = bytearray()
    string_offsets = []
    for value in strings:
        encoded = value.encode("utf-8")
        string_offsets.append(data_offset + len(string_data))
        string_data.extend(_uleb128(len(value)))
        string_data.extend(encoded)
        string_data.append(0)

    result = bytearray(data_offset)
    result[:8] = b"dex\n039\0"
    result[0x24:0x28] = (0x70).to_bytes(4, "little")
    result[0x28:0x2C] = (0x12345678).to_bytes(4, "little")
    result[0x38:0x3C] = len(strings).to_bytes(4, "little")
    result[0x3C:0x40] = table_offset.to_bytes(4, "little")
    result[0x40:0x44] = type_count.to_bytes(4, "little")
    result[0x44:0x48] = type_offset.to_bytes(4, "little")
    result[0x60:0x64] = defined_count.to_bytes(4, "little")
    result[0x64:0x68] = class_offset.to_bytes(4, "little")
    for index, offset in enumerate(string_offsets):
        start = table_offset + index * 4
        result[start:start + 4] = offset.to_bytes(4, "little")
        if index < type_count:
            start = type_offset + index * 4
            result[start:start + 4] = index.to_bytes(4, "little")
    for index in range(defined_count):
        start = class_offset + index * 32
        result[start:start + 4] = index.to_bytes(4, "little")
    result.extend(string_data)
    result[0x20:0x24] = len(result).to_bytes(4, "little")
    return bytes(result)


def _archive(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buffer.getvalue()


def _analyze_apk(data):
    scanner = AndroidSystemScanner(_Filesystem())
    return scanner, scanner._analyze_apk_data(data, "/system/app/Example/Example.apk")


def test_apk_scans_component_found_only_in_classes2_dex():
    data = _archive([
        ("classes.dex", _dex("Lorg/example/app/Main;")),
        ("classes2.dex", _dex("Lcom/squareup/okhttp3/OkHttpClient;")),
    ])

    _, components = _analyze_apk(data)

    okhttp = [component for component in components if component.name == "OkHttp"]
    assert len(okhttp) == 1
    assert "classes2.dex" in okhttp[0].versions[0].evidence


def test_apk_merges_duplicate_dex_findings_and_keeps_each_path_evidence():
    data = _archive([
        ("classes.dex", _dex("Lcom/squareup/okhttp3/OkHttpClient;")),
        ("classes2.dex", _dex("Lcom/squareup/okhttp3/OkHttpClient;")),
    ])

    _, components = _analyze_apk(data)

    okhttp = [component for component in components if component.name == "OkHttp"]
    assert len(okhttp) == 1
    evidence = [version.evidence for version in okhttp[0].versions]
    assert any("classes.dex" in item for item in evidence)
    assert any("classes2.dex" in item for item in evidence)


def test_apk_warns_and_continues_after_oversized_and_total_budget_dex(monkeypatch):
    monkeypatch.setattr(AndroidSystemScanner, "_MAX_DEX_SIZE", 256)
    monkeypatch.setattr(AndroidSystemScanner, "_MAX_TOTAL_DEX_SIZE", 512)
    entries = [
        ("classes.dex", _dex("Lcom/squareup/okhttp3/OkHttpClient;")),
        ("classes2.dex", b"x" * 257),
        ("classes3.dex", _dex("Lcom/google/gson/Gson;")),
        ("classes4.dex", _dex("Lcom/google/gson/Gson;")),
        ("classes5.dex", _dex("Lcom/squareup/okhttp3/OkHttpClient;")),
    ]
    scanner, components = _analyze_apk(_archive(entries))

    assert any("OkHttp" == component.name for component in components)
    assert any("DEX" in warning and "classes2.dex" in warning for warning in scanner._coverage_warnings)
    assert any("DEX" in warning and "budget" in warning.lower() for warning in scanner._coverage_warnings)


def test_apk_limits_root_dex_entry_count(monkeypatch):
    monkeypatch.setattr(AndroidSystemScanner, "_MAX_DEX_ENTRIES", 1)
    scanner, components = _analyze_apk(_archive([
        ("classes.dex", _dex("Lorg/example/app/Main;")),
        ("classes2.dex", _dex("Lcom/google/gson/Gson;")),
    ]))

    assert not any(component.name == "Gson" for component in components)
    assert any("DEX entry count" in warning for warning in scanner._coverage_warnings)


def test_malformed_dex_does_not_hide_later_dex_or_native_entry(monkeypatch):
    data = _archive([
        ("classes.dex", b"dex\nmalformed"),
        ("classes2.dex", _dex("Lcom/google/gson/Gson;")),
        ("lib/arm64-v8a/libfixture.so", b"fixture native bytes"),
    ])
    scanner = AndroidSystemScanner(_Filesystem())

    class _Inventory:
        def extract(self, data, filename, path):
            return [Component(name="fixture-native", description=path)]

    monkeypatch.setattr(scanner, "_binary_inventory", lambda: _Inventory())
    components = scanner._analyze_apk_data(data, "/system/app/Example/Example.apk")

    assert any(component.name == "Gson" for component in components)
    native = next(component for component in components if component.name == "fixture-native")
    assert "libfixture.so" in native.description


def test_framework_jar_scans_all_root_dex_files(monkeypatch):
    jar = _archive([
        ("classes.dex", _dex("Lorg/example/app/Main;")),
        ("classes2.dex", _dex("Lcom/google/gson/Gson;")),
    ])

    class _Entry:
        name = "core.jar"
        is_file = True
        is_dir = False

    class _FrameworkFilesystem(_Filesystem):
        def exists(self, path):
            return path == "/system/framework"

        def list_directory(self, path):
            return [_Entry()]

        def read_file(self, path, max_size=16 * 1024 * 1024):
            return jar if path == "/system/framework/core.jar" else None

    scanner = AndroidSystemScanner(_FrameworkFilesystem())
    components = scanner._scan_framework_jars()

    gson = next(component for component in components if component.name == "Gson")
    assert "classes2.dex" in gson.versions[0].evidence


def test_framework_jar_uses_random_reads_when_filesystem_supports_them():
    jar = _archive([("classes2.dex", _dex("Lcom/google/gson/Gson;"))])

    class _Entry:
        name = "core.jar"

    class _RangeFilesystem(_Filesystem):
        def exists(self, path):
            return path == "/system/framework"

        def list_directory(self, path):
            return [_Entry()]

        def file_size(self, path):
            return len(jar)

        def read_file_range(self, path, offset, size):
            return jar[offset:offset + size]

        def read_file(self, path, max_size=16 * 1024 * 1024):
            raise AssertionError("complete JAR buffering is unnecessary")

    scanner = AndroidSystemScanner(_RangeFilesystem())
    components = scanner._scan_framework_jars()

    assert any(component.name == "Gson" for component in components)
    assert not scanner._coverage_warnings


def test_unbounded_numeric_dex_name_cannot_hide_a_valid_dex():
    _, components = _analyze_apk(_archive([
        ("classes" + "9" * 5000 + ".dex", _dex("Lorg/example/app/Main;")),
        ("classes2.dex", _dex("Lcom/google/gson/Gson;")),
    ]))

    assert any(component.name == "Gson" for component in components)


def test_referenced_library_is_not_reported_as_a_bundled_implementation():
    _, components = _analyze_apk(_archive([
        ("classes.dex", _dex("Lorg/example/app/Main;", imported=("Lcom/google/gson/Gson;",))),
    ]))
    assert not any(component.name == "Gson" for component in components)


def test_unknown_dex_version_is_empty_and_actual_okhttp_namespace_is_detected():
    _, components = _analyze_apk(_archive([
        ("classes.dex", _dex("Lokhttp3/OkHttpClient;", "Lcom/google/gson/Gson;")),
    ]))
    libraries = {component.name: component for component in components}
    assert libraries["OkHttp"].resolved_version == ""
    assert libraries["Gson"].resolved_version == ""


def test_library_name_in_diagnostic_text_cannot_donate_an_unrelated_version():
    from firmware_scanner.extraction.smart_analyzer import SmartSectionAnalyzer

    result = SmartSectionAnalyzer()._match_dex_strings(
        ["Lcom/google/gson/Gson;", "Gson is incompatible with application 99.7.1"], "classes.dex")
    assert result[0].resolved_version == ""


def test_own_release_banner_is_exported_for_a_defined_library():
    _, components = _analyze_apk(_archive([
        ("classes.dex", _dex("Lcom/google/gson/Gson;", literals=("Gson version 2.8.9",))),
    ]))
    gson = next(component for component in components if component.name == "Gson")
    assert gson.resolved_version == "2.8.9"
    assert "own release banner 2.8.9" in gson.versions[0].evidence


def test_crc_failure_still_consumes_archive_decompression_budget(monkeypatch):
    monkeypatch.setattr(AndroidSystemScanner, "_MAX_DEX_SIZE", 8)
    monkeypatch.setattr(AndroidSystemScanner, "_MAX_TOTAL_DEX_SIZE", 8)
    payload = _archive([("classes.dex", b"dex\n039\0"), ("classes2.dex", b"dex\n039\0")])
    scanner = AndroidSystemScanner(_Filesystem())
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for entry in archive.infolist():
            entry.CRC ^= 1
        attempts = []
        original = archive.open

        def record_open(entry, *args, **kwargs):
            attempts.append(entry.filename)
            return original(entry, *args, **kwargs)

        monkeypatch.setattr(archive, "open", record_open)
        assert scanner._extract_embedded_dex_components(archive, "fixture.apk") == []
    assert attempts == ["classes.dex"]
    assert any("budget" in warning and "classes2.dex" in warning for warning in scanner._coverage_warnings)


def test_class_definition_outside_declared_dex_file_is_not_an_implementation():
    data = bytearray(_dex("Lorg/example/app/Main;", imported=("Lcom/google/gson/Gson;",)))
    class_offset = int.from_bytes(data[0x64:0x68], "little")
    data[class_offset:class_offset + 4] = (1).to_bytes(4, "little")
    data[0x20:0x24] = class_offset.to_bytes(4, "little")
    _, components = _analyze_apk(_archive([("classes.dex", data)]))
    assert not any(component.name == "Gson" for component in components)


def test_dex_preserves_namespace_version_families_as_ranges():
    _, components = _analyze_apk(_archive([
        ("classes.dex", _dex("Lio/reactivex/rxjava3/core/Flowable;")),
    ]))
    rxjava = next(component for component in components if component.name == "RxJava")
    assert rxjava.resolved_version == "3.x"
    assert any(version.version == "3.x" for version in rxjava.versions)


def test_multiple_namespace_families_are_retained_without_selecting_a_release():
    _, components = _analyze_apk(_archive([
        ("classes.dex", _dex("Lio/reactivex/rxjava3/core/Flowable;", "Lio/reactivex/Flowable;")),
    ]))
    rxjava = next(component for component in components if component.name == "RxJava")
    assert rxjava.resolved_version == ""
    families = next(prop["value"] for prop in rxjava.properties if prop["name"] == "firmware:version:families")
    assert "2.x" in families and "3.x" in families
