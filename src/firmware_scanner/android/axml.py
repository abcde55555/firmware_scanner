"""Pure-Python Android binary XML (AXML) parser.

Parses compiled AndroidManifest.xml without requiring apktool or aapt.
Extracts package name, version info, permissions, and library dependencies.
"""

import struct
from dataclasses import dataclass, field


# Chunk types
CHUNK_TYPE_STRING_POOL = 0x0001
CHUNK_TYPE_XML = 0x0003
CHUNK_TYPE_RESOURCE_MAP = 0x0180
CHUNK_TYPE_START_NAMESPACE = 0x0100
CHUNK_TYPE_END_NAMESPACE = 0x0101
CHUNK_TYPE_START_TAG = 0x0102
CHUNK_TYPE_END_TAG = 0x0103
CHUNK_TYPE_TEXT = 0x0104

# Attribute value types
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

# Well-known Android attribute resource IDs
ATTR_PACKAGE = 0x01010003
ATTR_VERSION_CODE = 0x0101021b
ATTR_VERSION_NAME = 0x0101021c
ATTR_NAME = 0x01010003
ATTR_MIN_SDK_VERSION = 0x0101020c
ATTR_TARGET_SDK_VERSION = 0x01010270
ATTR_COMPILE_SDK_VERSION = 0x01010572

# Fallback attribute name strings for when resource IDs aren't available
ATTR_NAME_STRINGS = {
    "package": "package",
    "versionCode": "version_code",
    "versionName": "version_name",
    "minSdkVersion": "min_sdk",
    "targetSdkVersion": "target_sdk",
    "compileSdkVersion": "compile_sdk",
    "name": "name",
}


@dataclass
class AndroidManifestInfo:
    package_name: str = ""
    version_code: int = 0
    version_name: str = ""
    min_sdk_version: int = 0
    target_sdk_version: int = 0
    compile_sdk_version: int = 0
    permissions: list[str] = field(default_factory=list)
    uses_libraries: list[str] = field(default_factory=list)
    activities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)


@dataclass
class AXMLAttribute:
    namespace_uri: int
    name_idx: int
    raw_value_idx: int
    value_type: int
    value_data: int


class AXMLParser:
    """Parse Android binary XML format."""

    def __init__(self):
        self._strings: list[str] = []
        self._resource_ids: list[int] = []

    def get_manifest_info(self, data: bytes) -> AndroidManifestInfo:
        """Extract key information from a binary AndroidManifest.xml."""
        info = AndroidManifestInfo()

        if len(data) < 8:
            return info

        magic = struct.unpack_from('<H', data, 0)[0]
        if magic != CHUNK_TYPE_XML:
            return info

        self._strings = []
        self._resource_ids = []
        offset = 8  # skip XML chunk header (type + header_size + total_size)

        # Parse string pool
        if offset + 8 > len(data):
            return info
        chunk_type = struct.unpack_from('<H', data, offset)[0]
        if chunk_type == CHUNK_TYPE_STRING_POOL:
            pool_size = struct.unpack_from('<I', data, offset + 4)[0]
            self._parse_string_pool(data[offset:offset + pool_size])
            offset += pool_size

        # Parse resource ID map (optional)
        if offset + 8 <= len(data):
            chunk_type = struct.unpack_from('<H', data, offset)[0]
            if chunk_type == CHUNK_TYPE_RESOURCE_MAP:
                chunk_size = struct.unpack_from('<I', data, offset + 4)[0]
                self._parse_resource_map(data[offset:offset + chunk_size])
                offset += chunk_size

        # Parse XML tree events
        current_tag = ""
        while offset + 8 <= len(data):
            chunk_type = struct.unpack_from('<H', data, offset)[0]
            chunk_size = struct.unpack_from('<I', data, offset + 4)[0]

            if chunk_size < 8 or offset + chunk_size > len(data):
                break

            if chunk_type == CHUNK_TYPE_START_TAG:
                tag_name, attrs = self._parse_start_tag(data[offset:offset + chunk_size])
                current_tag = tag_name
                self._process_tag(info, tag_name, attrs)

            offset += chunk_size

        return info

    def _parse_string_pool(self, data: bytes):
        """Parse string pool chunk to extract all strings."""
        if len(data) < 28:
            return

        string_count = struct.unpack_from('<I', data, 8)[0]
        _style_count = struct.unpack_from('<I', data, 12)[0]
        flags = struct.unpack_from('<I', data, 16)[0]
        strings_offset = struct.unpack_from('<I', data, 20)[0]
        _styles_offset = struct.unpack_from('<I', data, 24)[0]

        is_utf8 = (flags & (1 << 8)) != 0

        # Read string offset table
        offsets = []
        for i in range(min(string_count, 100000)):
            if 28 + i * 4 + 4 > len(data):
                break
            str_offset = struct.unpack_from('<I', data, 28 + i * 4)[0]
            offsets.append(str_offset)

        # Read each string
        base = strings_offset + 28  # 28 = pool header size (type+size+string_count+etc)
        # Actually strings_offset is relative to chunk start
        base = strings_offset

        for str_offset in offsets:
            abs_offset = base + str_offset
            if abs_offset >= len(data):
                self._strings.append("")
                continue

            try:
                if is_utf8:
                    s = self._read_utf8_string(data, abs_offset)
                else:
                    s = self._read_utf16_string(data, abs_offset)
                self._strings.append(s)
            except Exception:
                self._strings.append("")

    def _read_utf8_string(self, data: bytes, offset: int) -> str:
        """Read a UTF-8 string from the string pool."""
        if offset + 2 > len(data):
            return ""
        # UTF-8 strings have two length prefixes: char count and byte count
        char_len = data[offset]
        offset += 1
        if char_len & 0x80:
            offset += 1  # skip high byte of two-byte char length

        byte_len = data[offset]
        offset += 1
        if byte_len & 0x80:
            byte_len = ((byte_len & 0x7F) << 8) | data[offset]
            offset += 1

        if offset + byte_len > len(data):
            byte_len = len(data) - offset

        return data[offset:offset + byte_len].decode('utf-8', errors='replace')

    def _read_utf16_string(self, data: bytes, offset: int) -> str:
        """Read a UTF-16LE string from the string pool."""
        if offset + 2 > len(data):
            return ""
        str_len = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if str_len & 0x8000:
            str_len = ((str_len & 0x7FFF) << 16) | struct.unpack_from('<H', data, offset)[0]
            offset += 2

        byte_count = str_len * 2
        if offset + byte_count > len(data):
            byte_count = len(data) - offset

        return data[offset:offset + byte_count].decode('utf-16-le', errors='replace')

    def _parse_resource_map(self, data: bytes):
        """Parse resource ID map chunk."""
        if len(data) < 12:
            return
        header_size = struct.unpack_from('<H', data, 2)[0]
        count = (len(data) - header_size) // 4
        for i in range(count):
            pos = header_size + i * 4
            if pos + 4 > len(data):
                break
            res_id = struct.unpack_from('<I', data, pos)[0]
            self._resource_ids.append(res_id)

    def _parse_start_tag(self, data: bytes) -> tuple[str, list[AXMLAttribute]]:
        """Parse START_TAG chunk and return (tag_name, attributes)."""
        if len(data) < 36:
            return ("", [])

        # START_TAG layout after common header (8 bytes):
        # 4: line number
        # 4: comment index
        # 4: namespace uri (string index, -1 if none)
        # 4: name (string index)
        # 2: attribute start offset
        # 2: attribute size
        # 2: attribute count
        # 2: id index
        # 2: class index
        # 2: style index
        header_size = struct.unpack_from('<H', data, 2)[0]
        name_idx = struct.unpack_from('<i', data, 20)[0]
        attr_count = struct.unpack_from('<H', data, 28)[0]

        tag_name = self._get_string(name_idx)

        attrs: list[AXMLAttribute] = []
        attr_offset = 36  # standard offset for attributes in START_TAG

        for i in range(min(attr_count, 100)):
            if attr_offset + 20 > len(data):
                break

            ns_uri = struct.unpack_from('<i', data, attr_offset)[0]
            attr_name_idx = struct.unpack_from('<i', data, attr_offset + 4)[0]
            raw_value_idx = struct.unpack_from('<i', data, attr_offset + 8)[0]
            value_type = struct.unpack_from('<B', data, attr_offset + 15)[0]
            value_data = struct.unpack_from('<i', data, attr_offset + 16)[0]

            attrs.append(AXMLAttribute(
                namespace_uri=ns_uri,
                name_idx=attr_name_idx,
                raw_value_idx=raw_value_idx,
                value_type=value_type,
                value_data=value_data,
            ))
            attr_offset += 20

        return (tag_name, attrs)

    def _process_tag(self, info: AndroidManifestInfo, tag_name: str, attrs: list[AXMLAttribute]):
        """Process a tag and its attributes to populate AndroidManifestInfo."""
        if tag_name == "manifest":
            for attr in attrs:
                attr_name = self._get_string(attr.name_idx)
                res_id = self._get_resource_id(attr.name_idx)

                if attr_name == "package" or res_id == ATTR_PACKAGE:
                    info.package_name = self._get_attr_string_value(attr)
                elif attr_name == "versionCode" or res_id == ATTR_VERSION_CODE:
                    if attr.value_type == TYPE_INT_DEC or attr.value_type == TYPE_INT_HEX:
                        info.version_code = attr.value_data
                elif attr_name == "versionName" or res_id == ATTR_VERSION_NAME:
                    info.version_name = self._get_attr_string_value(attr)
                elif attr_name == "compileSdkVersion" or res_id == ATTR_COMPILE_SDK_VERSION:
                    if attr.value_type in (TYPE_INT_DEC, TYPE_INT_HEX):
                        info.compile_sdk_version = attr.value_data

        elif tag_name == "uses-sdk":
            for attr in attrs:
                attr_name = self._get_string(attr.name_idx)
                res_id = self._get_resource_id(attr.name_idx)

                if attr_name == "minSdkVersion" or res_id == ATTR_MIN_SDK_VERSION:
                    if attr.value_type in (TYPE_INT_DEC, TYPE_INT_HEX):
                        info.min_sdk_version = attr.value_data
                elif attr_name == "targetSdkVersion" or res_id == ATTR_TARGET_SDK_VERSION:
                    if attr.value_type in (TYPE_INT_DEC, TYPE_INT_HEX):
                        info.target_sdk_version = attr.value_data

        elif tag_name == "uses-permission":
            for attr in attrs:
                attr_name = self._get_string(attr.name_idx)
                if attr_name == "name":
                    perm = self._get_attr_string_value(attr)
                    if perm:
                        info.permissions.append(perm)

        elif tag_name == "uses-library":
            for attr in attrs:
                attr_name = self._get_string(attr.name_idx)
                if attr_name == "name":
                    lib = self._get_attr_string_value(attr)
                    if lib:
                        info.uses_libraries.append(lib)

        elif tag_name == "activity":
            for attr in attrs:
                attr_name = self._get_string(attr.name_idx)
                if attr_name == "name":
                    name = self._get_attr_string_value(attr)
                    if name:
                        info.activities.append(name)

        elif tag_name == "service":
            for attr in attrs:
                attr_name = self._get_string(attr.name_idx)
                if attr_name == "name":
                    name = self._get_attr_string_value(attr)
                    if name:
                        info.services.append(name)

        elif tag_name == "receiver":
            for attr in attrs:
                attr_name = self._get_string(attr.name_idx)
                if attr_name == "name":
                    name = self._get_attr_string_value(attr)
                    if name:
                        info.receivers.append(name)

    def _get_string(self, idx: int) -> str:
        if idx < 0 or idx >= len(self._strings):
            return ""
        return self._strings[idx]

    def _get_resource_id(self, idx: int) -> int:
        if idx < 0 or idx >= len(self._resource_ids):
            return 0
        return self._resource_ids[idx]

    def _get_attr_string_value(self, attr: AXMLAttribute) -> str:
        if attr.value_type == TYPE_STRING:
            return self._get_string(attr.value_data)
        if attr.raw_value_idx >= 0:
            return self._get_string(attr.raw_value_idx)
        return ""
