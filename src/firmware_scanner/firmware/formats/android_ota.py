"""Android OTA format handlers.

Supports:
- payload.bin (A/B OTA updates with "CrAU" magic)
- Block-based OTA ZIP packages (system.new.dat + system.transfer.list)
"""

import struct
import zipfile
import io
from pathlib import Path

from ..formats.base import FirmwareFormat
from ..extension_api import ZipBasedFormat
from ...extraction.models import UnpackResult, FirmwareSection


PAYLOAD_MAGIC = b"CrAU"


class AndroidPayloadFormat(FirmwareFormat):
    """Handler for Android OTA payload.bin (A/B OTA updates).

    payload.bin format:
    - Magic: "CrAU" (4 bytes)
    - File format version: uint64 big-endian
    - Manifest size: uint64 big-endian
    - Manifest signature size: uint32 big-endian (v2+)
    - Manifest (protobuf-encoded DeltaArchiveManifest)
    - Manifest signature
    - Partition data blobs
    """

    @property
    def format_name(self) -> str:
        return "Android OTA Payload"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if len(data) < 24:
            return 0.0

        # Direct payload.bin
        if data[:4] == PAYLOAD_MAGIC:
            return 0.95

        # payload.bin inside a ZIP
        if data[:2] == b'PK' and path.suffix.lower() == '.zip':
            try:
                zf = zipfile.ZipFile(io.BytesIO(data[:65536]))
                names = zf.namelist()
                zf.close()
                if 'payload.bin' in names:
                    return 0.92
            except Exception:
                pass

        return 0.0

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        """Unpack payload.bin to extract partition info."""
        payload_data = data

        # If ZIP, extract payload.bin first
        if data[:2] == b'PK':
            try:
                zf = zipfile.ZipFile(io.BytesIO(data))
                if 'payload.bin' in zf.namelist():
                    payload_data = zf.read('payload.bin')
                zf.close()
            except Exception:
                return UnpackResult(metadata={"error": "Failed to read ZIP"})

        if payload_data[:4] != PAYLOAD_MAGIC:
            return UnpackResult(metadata={"error": "Invalid payload magic"})

        return self._parse_payload(payload_data)

    def _parse_payload(self, data: bytes) -> UnpackResult:
        """Parse payload.bin header and extract partition metadata."""
        sections: list[FirmwareSection] = []
        metadata: dict = {"format": "payload.bin"}

        if len(data) < 24:
            return UnpackResult(sections=sections, metadata=metadata)

        # Parse header
        version = struct.unpack_from('>Q', data, 4)[0]
        manifest_size = struct.unpack_from('>Q', data, 12)[0]

        metadata["payload_version"] = version

        header_size = 24
        if version >= 2 and len(data) >= 24:
            manifest_sig_size = struct.unpack_from('>I', data, 20)[0]
            header_size = 24
            metadata["manifest_signature_size"] = manifest_sig_size

        # Extract manifest (protobuf)
        manifest_offset = header_size
        manifest_end = manifest_offset + manifest_size

        if manifest_end > len(data):
            manifest_end = len(data)

        manifest_data = data[manifest_offset:manifest_end]

        # Parse protobuf manually (field 13 = partitions, repeated)
        partitions = self._parse_manifest_partitions(manifest_data)
        metadata["partitions"] = [p["name"] for p in partitions]

        # Data blobs start after manifest + signature
        if version >= 2:
            data_offset = header_size + manifest_size + struct.unpack_from('>I', data, 20)[0]
        else:
            data_offset = header_size + manifest_size

        # Create sections for each partition (metadata only, data may be huge)
        for part in partitions:
            part_name = part["name"]
            part_size = part.get("size", 0)

            # For each partition, try to extract initial chunk for identification
            part_data_offset = data_offset + part.get("data_offset", 0)
            chunk_size = min(part_size, 1024 * 1024)  # Max 1MB preview

            if part_data_offset + chunk_size <= len(data) and chunk_size > 0:
                chunk = data[part_data_offset:part_data_offset + chunk_size]
            else:
                chunk = b""

            sections.append(FirmwareSection(
                name=f"{part_name}.img",
                offset=part_data_offset,
                size=part_size,
                data=chunk,
                section_type="partition",
            ))

        return UnpackResult(sections=sections, metadata=metadata)

    def _parse_manifest_partitions(self, manifest_data: bytes) -> list[dict]:
        """Parse partition info from protobuf manifest using wire format.

        We only need partition names and sizes, so we do minimal protobuf
        decoding rather than requiring a compiled .proto file.
        """
        partitions: list[dict] = []
        offset = 0

        while offset < len(manifest_data):
            try:
                # Read field tag
                tag, consumed = self._read_varint(manifest_data, offset)
                offset += consumed
                field_number = tag >> 3
                wire_type = tag & 0x07

                if wire_type == 0:  # varint
                    _, consumed = self._read_varint(manifest_data, offset)
                    offset += consumed
                elif wire_type == 1:  # 64-bit
                    offset += 8
                elif wire_type == 2:  # length-delimited
                    length, consumed = self._read_varint(manifest_data, offset)
                    offset += consumed
                    field_data = manifest_data[offset:offset + length]

                    # Field 13 in DeltaArchiveManifest = partitions (repeated PartitionUpdate)
                    if field_number == 13:
                        part_info = self._parse_partition_update(field_data)
                        if part_info:
                            partitions.append(part_info)

                    offset += length
                elif wire_type == 5:  # 32-bit
                    offset += 4
                else:
                    break
            except (IndexError, ValueError):
                break

        return partitions

    def _parse_partition_update(self, data: bytes) -> dict | None:
        """Parse a PartitionUpdate message to extract partition name and size."""
        result: dict = {}
        offset = 0

        while offset < len(data):
            try:
                tag, consumed = self._read_varint(data, offset)
                offset += consumed
                field_number = tag >> 3
                wire_type = tag & 0x07

                if wire_type == 0:  # varint
                    value, consumed = self._read_varint(data, offset)
                    offset += consumed
                    if field_number == 3:  # new_partition_info might have size
                        result["size"] = value
                elif wire_type == 1:  # 64-bit
                    offset += 8
                elif wire_type == 2:  # length-delimited
                    length, consumed = self._read_varint(data, offset)
                    offset += consumed

                    # Field 1 = partition_name (string)
                    if field_number == 1:
                        try:
                            result["name"] = data[offset:offset + length].decode('utf-8')
                        except Exception:
                            pass
                    # Field 7 = new_partition_info (PartitionInfo message)
                    elif field_number == 7:
                        size = self._parse_partition_info_size(data[offset:offset + length])
                        if size:
                            result["size"] = size

                    offset += length
                elif wire_type == 5:  # 32-bit
                    offset += 4
                else:
                    break
            except (IndexError, ValueError):
                break

        return result if "name" in result else None

    def _parse_partition_info_size(self, data: bytes) -> int:
        """Parse PartitionInfo to extract size field."""
        offset = 0
        while offset < len(data):
            try:
                tag, consumed = self._read_varint(data, offset)
                offset += consumed
                field_number = tag >> 3
                wire_type = tag & 0x07

                if wire_type == 0:
                    value, consumed = self._read_varint(data, offset)
                    offset += consumed
                    if field_number == 1:  # size
                        return value
                elif wire_type == 1:
                    offset += 8
                elif wire_type == 2:
                    length, consumed = self._read_varint(data, offset)
                    offset += consumed + length
                elif wire_type == 5:
                    offset += 4
                else:
                    break
            except (IndexError, ValueError):
                break
        return 0

    @staticmethod
    def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
        """Read a protobuf varint. Returns (value, bytes_consumed)."""
        result = 0
        shift = 0
        consumed = 0

        while offset < len(data):
            byte = data[offset]
            offset += 1
            consumed += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
            if consumed > 10:
                break

        return result, consumed


class AndroidBlockOTAFormat(ZipBasedFormat):
    """Handler for block-based OTA ZIP packages.

    These contain:
    - system.new.dat (or system.new.dat.br for brotli-compressed)
    - system.transfer.list
    - system.patch.dat (optional, for incremental OTA)
    - META-INF/ with updater scripts
    """

    @property
    def format_name(self) -> str:
        return "Android Block OTA"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if data[:2] != b'PK':
            return 0.0

        try:
            zf = zipfile.ZipFile(io.BytesIO(data[:1024 * 1024]))
            names = zf.namelist()
            zf.close()

            # Look for block OTA signatures
            has_new_dat = any(n.endswith('.new.dat') or n.endswith('.new.dat.br') for n in names)
            has_transfer_list = any(n.endswith('.transfer.list') for n in names)
            has_meta = any(n.startswith('META-INF/') for n in names)

            if has_new_dat and has_transfer_list:
                return 0.93
            if has_new_dat and has_meta:
                return 0.80

        except Exception:
            pass

        return 0.0

    def _get_files_to_analyze(self, zf: zipfile.ZipFile) -> list[str]:
        """Select files for analysis from the OTA package."""
        targets = []
        for name in zf.namelist():
            lower = name.lower()
            # Transfer lists (contain partition layout info)
            if lower.endswith('.transfer.list'):
                targets.append(name)
            # Updater scripts
            elif 'updater-script' in lower or 'update-binary' in lower:
                targets.append(name)
            # Build metadata
            elif 'metadata' in lower and not lower.endswith(('.dat', '.dat.br')):
                targets.append(name)
            # Build properties inside OTA
            elif 'build.prop' in lower:
                targets.append(name)
            # Dynamic partitions metadata
            elif lower.endswith('dynamic_partitions_info.txt'):
                targets.append(name)
            # OTA metadata protobuf (contains version info)
            elif name == 'META-INF/com/android/metadata':
                targets.append(name)
            elif name == 'META-INF/com/android/metadata.pb':
                targets.append(name)
            # Payload properties
            elif name == 'payload_properties.txt':
                targets.append(name)
            # care_map (for A/B verification)
            elif 'care_map' in lower:
                targets.append(name)

        return targets
