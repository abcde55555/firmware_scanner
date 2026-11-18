"""Read-only, bounded native binary scanning for Android APEX payloads."""

from __future__ import annotations

import posixpath
import struct
import zipfile
import zlib
from dataclasses import dataclass, field

from firmware_scanner.android.erofs_reader import ErofsReader
from firmware_scanner.android.ext4_reader import Ext4Reader
from firmware_scanner.extraction.models import Component

MAX_PAYLOAD_BYTES = 512 * 1024 * 1024
MAX_ELF_BYTES = 64 * 1024 * 1024
MAX_FILES = 10_000
MAX_DIRECTORIES = 10_000
MAX_DEPTH = 24
MAX_APEX_NESTING = 3


class _BytesReader:
    """Seekable ZIP input backed by the original bytes without copying them."""

    def __init__(self, data: bytes):
        self._data = memoryview(data)
        self._position = 0

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            position = offset
        elif whence == 1:
            position = self._position + offset
        elif whence == 2:
            position = len(self._data) + offset
        else:
            raise ValueError("invalid seek mode")
        if position < 0:
            raise ValueError("negative seek position")
        self._position = position
        return position

    def tell(self) -> int:
        return self._position

    def seekable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = len(self._data) - self._position
        end = min(len(self._data), self._position + size)
        chunk = self._data[self._position:end].tobytes()
        self._position = end
        return chunk


@dataclass
class ApexPayloadScan:
    components: list[Component] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    analysed_files: int = 0


def scan_apex_payload(apex_data: bytes, apex_path: str, inventory) -> ApexPayloadScan:
    """Scan native ELF files from an APEX ZIP without extracting or executing them.

    The payload image is held as one bytes object while its read-only filesystem
    reader is active. Each candidate ELF is read and analyzed serially.
    """
    result = ApexPayloadScan()
    _scan_apex(apex_data, apex_path, apex_path, inventory, result, 0)
    return result


def _scan_apex(data: bytes, path: str, root_container: str, inventory,
               result: ApexPayloadScan, nesting: int) -> None:
    if nesting > MAX_APEX_NESTING:
        _warn(result, f"APEX nesting limit ({MAX_APEX_NESTING}) reached at {path}")
        return
    if len(data) > MAX_PAYLOAD_BYTES:
        _warn(result, f"APEX archive exceeds the 512 MiB input limit at {path}")
        return

    try:
        archive = zipfile.ZipFile(_BytesReader(data))
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        _warn(result, f"Invalid or corrupt APEX ZIP at {path}: {exc}")
        return

    with archive:
        infos = archive.infolist()
        names: dict[str, list[zipfile.ZipInfo]] = {}
        for info in infos:
            names.setdefault(info.filename, []).append(info)
        payloads = names.get("apex_payload.img", [])
        if len(payloads) > 1:
            _warn(result, f"Duplicate apex_payload.img entries in {path}; payload was not scanned")
            return

        if payloads:
            info = payloads[0]
            if info.file_size > MAX_PAYLOAD_BYTES:
                _warn(result, f"apex_payload.img exceeds the 512 MiB payload limit in {path}")
                return
            try:
                payload = archive.read(info)
            except (zipfile.BadZipFile, OSError, RuntimeError, EOFError, ValueError,
                    NotImplementedError, zlib.error) as exc:
                _warn(result, f"Corrupt apex_payload.img in {path}: {exc}")
                return
            if len(payload) != info.file_size:
                _warn(result, f"Truncated apex_payload.img in {path}")
                return
            _scan_filesystem(payload, path, root_container, inventory, result)
            return

        original_apex = names.get("original_apex", [])
        if len(original_apex) > 1:
            _warn(result, f"Duplicate original_apex entries in {path}; nested APEX was not scanned")
            return
        if original_apex:
            info = original_apex[0]
            if info.file_size > MAX_PAYLOAD_BYTES:
                _warn(result, f"original_apex exceeds the 512 MiB limit in {path}")
                return
            try:
                original = archive.read(info)
            except (zipfile.BadZipFile, OSError, RuntimeError, EOFError, ValueError,
                    NotImplementedError, zlib.error) as exc:
                _warn(result, f"Corrupt original_apex in {path}: {exc}")
                return
            if len(original) != info.file_size:
                _warn(result, f"Truncated original_apex in {path}")
                return
            _scan_apex(original, path + "!/original_apex", root_container,
                       inventory, result, nesting + 1)
            return

        _warn(result, f"No apex_payload.img or original_apex member found in {path}")


def _scan_filesystem(payload: bytes, apex_path: str, root_container: str,
                     inventory, result: ApexPayloadScan) -> None:
    # Validate with the actual parser, not a magic-only probe. Do not retain both
    # candidate readers: each failed reader is discarded before trying the next.
    reader = Ext4Reader(payload)
    filesystem = "ext4"
    if not reader.is_valid():
        del reader
        reader = ErofsReader(payload)
        filesystem = "EROFS"
    if not reader.is_valid():
        _warn(result, f"Unsupported, invalid or corrupt payload filesystem in {apex_path}")
        return
    try:
        if reader.file_size("/") <= 0:
            _warn(result, f"Truncated or corrupt {filesystem} payload root in {apex_path}")
            return
    except (OSError, ValueError, IndexError, struct.error) as exc:
        _warn(result, f"Corrupt {filesystem} payload root in {apex_path}: {exc}")
        return

    visited = 0
    visited_directories = 0
    analyzed_bytes = 0
    try:
        for directory, subdirs, filenames in reader.walk("/", max_depth=MAX_DEPTH):
            visited_directories += 1
            if visited_directories > MAX_DIRECTORIES:
                _warn(result, f"Filesystem directory-count limit ({MAX_DIRECTORIES}) reached in {apex_path}")
                return
            depth = len([part for part in directory.split("/") if part])
            if subdirs and depth >= MAX_DEPTH:
                _warn(result, f"Filesystem traversal depth limit ({MAX_DEPTH}) reached in {apex_path}")
            for filename in filenames:
                visited += 1
                if visited > MAX_FILES:
                    _warn(result, f"Filesystem file-count limit ({MAX_FILES}) reached in {apex_path}")
                    return
                if not isinstance(filename, str) or filename in ("", ".", "..") or "/" in filename or "\\" in filename:
                    _warn(result, f"Unsafe filesystem entry name skipped in {apex_path}")
                    continue
                inner_path = posixpath.normpath(posixpath.join(directory, filename))
                if not inner_path.startswith("/") or inner_path == "/.." or inner_path.startswith("/../"):
                    _warn(result, f"Unsafe filesystem path skipped in {apex_path}")
                    continue
                try:
                    size = reader.file_size(inner_path)
                except (OSError, ValueError, IndexError, struct.error) as exc:
                    _warn(result, f"Could not inspect {inner_path} in {apex_path}: {exc}")
                    continue
                if size <= 0:
                    continue
                if size > MAX_ELF_BYTES:
                    try:
                        prefix = reader.read_file(inner_path, max_size=4)
                    except (OSError, ValueError, IndexError, struct.error) as exc:
                        _warn(result, f"Could not inspect oversized file {inner_path} in {apex_path}: {exc}")
                        continue
                    if prefix and prefix.startswith(b"\x7fELF"):
                        _warn(result, f"Native ELF exceeds the 64 MiB file limit: {inner_path} in {apex_path}")
                    continue
                try:
                    prefix = reader.read_file(inner_path, max_size=4)
                except (OSError, ValueError, IndexError, struct.error) as exc:
                    _warn(result, f"Could not inspect {inner_path} in {apex_path}: {exc}")
                    continue
                if not prefix or not prefix.startswith(b"\x7fELF"):
                    continue
                if analyzed_bytes + size > MAX_PAYLOAD_BYTES:
                    _warn(result, f"Native analysis byte limit (512 MiB) reached in {apex_path}")
                    return
                try:
                    data = reader.read_file(inner_path, max_size=MAX_ELF_BYTES)
                except (OSError, ValueError, IndexError) as exc:
                    _warn(result, f"Could not read {inner_path} in {apex_path}: {exc}")
                    continue
                if data is None or len(data) < size:
                    _warn(result, f"Truncated filesystem file skipped: {inner_path} in {apex_path}")
                    continue
                if not data.startswith(b"\x7fELF"):
                    del data
                    continue

                location = apex_path + "!/apex_payload.img" + inner_path
                try:
                    if any(part in {'bin', 'sbin', 'xbin'} for part in inner_path.split('/')[:-1]):
                        components = inventory.extract(data, posixpath.basename(inner_path), location,
                                                       component_type='application')
                    else:
                        components = inventory.extract(data, posixpath.basename(inner_path), location)
                except Exception as exc:  # noqa: BLE001 -- report a failed ELF and continue its siblings
                    _warn(result, f"Native analysis failed for {inner_path} in {apex_path}: {exc}")
                    del data
                    continue
                for component in components or []:
                    _attach_provenance(component, root_container, location)
                    result.components.append(component)
                result.analysed_files += 1
                analyzed_bytes += size
                del data
            # Limit traversal; don't trust a reader to honor max_depth.
            if depth >= MAX_DEPTH:
                continue
    except (OSError, ValueError, IndexError, struct.error, RecursionError) as exc:
        _warn(result, f"Corrupt {filesystem} payload while traversing {apex_path}: {exc}")
        return


def _attach_provenance(component: Component, container: str, location: str) -> None:
    properties = component.properties
    required = (
        {"name": "firmware:evidence:container", "value": container},
        {"name": "firmware:evidence:location", "value": location},
    )
    for prop in required:
        if prop not in properties:
            properties.append(prop)


def _warn(result: ApexPayloadScan, message: str) -> None:
    if message not in result.warnings:
        result.warnings.append(message)
