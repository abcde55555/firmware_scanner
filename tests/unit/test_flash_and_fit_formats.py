"""Unit tests for CramFS, JFFS2, FIT Image / DTB, and Android Super Image formats."""

import io
import struct
import zlib
from pathlib import Path
import pytest

from firmware_scanner.firmware.cramfs_reader import CramFSReader, CRAMFS_MAGIC_LE
from firmware_scanner.firmware.jffs2_reader import JFFS2Reader, JFFS2_NODETYPE_DIRENT, JFFS2_NODETYPE_INODE, JFFS2_COMPR_NONE, JFFS2_COMPR_ZLIB
from firmware_scanner.firmware.fdt_parser import FDTParser, FDT_MAGIC, FDT_BEGIN_NODE, FDT_END_NODE, FDT_PROP, FDT_END
from firmware_scanner.firmware.formats.android_super import AndroidSuperImageFormat
from firmware_scanner.firmware.formats.flash_fs import CramFSFormat, JFFS2Format
from firmware_scanner.firmware.formats.fit_image import FITImageFormat
from firmware_scanner.android.super_img import LP_GEOMETRY_MAGIC, PRIMARY_GEOMETRY_OFFSET


def _create_mock_cramfs_image() -> bytes:
    buf = bytearray(4096)
    # Magic
    struct.pack_into("<I", buf, 0, CRAMFS_MAGIC_LE)
    # Size
    struct.pack_into("<I", buf, 4, 4096)
    # Flags
    struct.pack_into("<I", buf, 8, 0)
    # Future
    struct.pack_into("<I", buf, 12, 0)
    # Signature
    buf[16:32] = b"Compressed ROMFS"
    # Name
    buf[48:64] = b"mock_cramfs\x00" * 2

    # Root inode at offset 64 (12 bytes)
    # Mode: directory (0o040755), uid=0
    struct.pack_into("<HH", buf, 64, 0o040755, 0)
    # Size=24 bytes (one child entry: 12 bytes inode + 12 bytes name padded), gid=0
    struct.pack_into("<I", buf, 68, 24)
    # namelen=0, offset=76 >> 2 (points to child inode at offset 76)
    struct.pack_into("<I", buf, 72, (0 << 26) | (76 >> 2))

    # Child file inode at offset 76
    # Mode: regular file (0o100644), uid=0
    struct.pack_into("<HH", buf, 76, 0o100644, 0)
    # Size = 13 bytes
    struct.pack_into("<I", buf, 80, 13)
    # namelen = 2 (name length padded is 8 bytes: 'test.txt\x00...'), offset=200 >> 2
    struct.pack_into("<I", buf, 84, (2 << 26) | (200 >> 2))
    # Filename (8 bytes)
    buf[88:96] = b"test.txt"

    # Block pointer table at offset 200 (1 block of size 13)
    # End of block 0 is at offset 220
    struct.pack_into("<I", buf, 200, 204 + len(zlib.compress(b"Hello CramFS!")))
    compressed = zlib.compress(b"Hello CramFS!")
    buf[204 : 204 + len(compressed)] = compressed

    return bytes(buf)


def test_cramfs_reader_and_format():
    data = _create_mock_cramfs_image()
    reader = CramFSReader(data)
    assert reader.is_valid()
    assert reader.name == "mock_cramfs"

    files = reader.list_files()
    assert len(files) == 1
    assert files[0].name == "test.txt"
    content = reader.read_file(files[0])
    assert content == b"Hello CramFS!"

    # Format handler
    fmt = CramFSFormat()
    assert fmt.can_handle(data, Path("firmware.cramfs")) >= 0.9
    res = fmt.unpack(data, Path("firmware.cramfs"))
    assert len(res.sections) == 1
    assert res.sections[0].name == "test.txt"
    assert res.sections[0].data == b"Hello CramFS!"


def _create_mock_jffs2_image() -> bytes:
    buf = bytearray()
    magic = 0x1985

    # 1. DIRENT node for "passwd" (ino=2, pino=1)
    name = b"passwd"
    totlen = 40 + len(name)
    totlen_padded = (totlen + 3) & ~3
    node_bytes = bytearray(totlen_padded)
    struct.pack_into("<HHI", node_bytes, 0, magic, JFFS2_NODETYPE_DIRENT, totlen_padded)
    # pino=1, version=1, ino=2, mctime=0
    struct.pack_into("<IIII", node_bytes, 12, 1, 1, 2, 0)
    # nsize, type (1=file)
    struct.pack_into("BB", node_bytes, 28, len(name), 1)
    node_bytes[38 : 38 + len(name)] = name
    buf.extend(node_bytes)

    # 2. INODE node for "passwd" (ino=2)
    payload = b"root:x:0:0:root:/root:/bin/sh\n"
    totlen = 68 + len(payload)
    totlen_padded = (totlen + 3) & ~3
    inode_bytes = bytearray(totlen_padded)
    struct.pack_into("<HHI", inode_bytes, 0, magic, JFFS2_NODETYPE_INODE, totlen_padded)
    # ino=2, version=1, mode=0o100644
    struct.pack_into("<III", inode_bytes, 12, 2, 1, 0o100644)
    # isize=len(payload)
    struct.pack_into("<I", inode_bytes, 24, len(payload))
    # offset=0, csize=len(payload), dsize=len(payload)
    struct.pack_into("<III", inode_bytes, 40, 0, len(payload), len(payload))
    # comptype = NONE (0)
    inode_bytes[52] = JFFS2_COMPR_NONE
    inode_bytes[68 : 68 + len(payload)] = payload
    buf.extend(inode_bytes)

    return bytes(buf)


def test_jffs2_reader_and_format():
    data = _create_mock_jffs2_image()
    reader = JFFS2Reader(data)
    assert reader.is_valid()
    files = reader.list_files()
    assert len(files) == 1
    assert files[0].name == "passwd"
    content = reader.read_file(files[0])
    assert b"root:x:0:0" in content

    # Format handler
    fmt = JFFS2Format()
    assert fmt.can_handle(data, Path("flash.jffs2")) >= 0.85
    res = fmt.unpack(data, Path("flash.jffs2"))
    assert len(res.sections) == 1
    assert res.sections[0].name == "passwd"
    assert b"root:x:0:0" in res.sections[0].data


def _create_mock_fdt_image() -> bytes:
    # Build a minimal valid FDT binary with model and compatible properties
    struct_buf = bytearray()
    strings_buf = bytearray()

    def add_prop(name: str, value: bytes):
        nonlocal struct_buf, strings_buf
        nameoff = len(strings_buf)
        strings_buf.extend(name.encode("ascii") + b"\x00")
        struct_buf.extend(struct.pack(">III", FDT_PROP, len(value), nameoff))
        padded = value + b"\x00" * ((4 - (len(value) % 4)) % 4)
        struct_buf.extend(padded)

    # Root node
    struct_buf.extend(struct.pack(">I", FDT_BEGIN_NODE) + b"\x00\x00\x00\x00")
    add_prop("model", b"Sunxi A33 Test Board\x00")
    add_prop("compatible", b"allwinner,sun8i-a33\x00allwinner,sun8i\x00")
    struct_buf.extend(struct.pack(">I", FDT_END_NODE))
    struct_buf.extend(struct.pack(">I", FDT_END))

    off_struct = 48
    len_struct = len(struct_buf)
    off_strings = off_struct + len_struct
    len_strings = len(strings_buf)
    totalsize = off_strings + len_strings

    header = bytearray(48)
    struct.pack_into(">I", header, 0, FDT_MAGIC)
    struct.pack_into(">I", header, 4, totalsize)
    struct.pack_into(">I", header, 8, off_struct)
    struct.pack_into(">I", header, 12, off_strings)
    struct.pack_into(">I", header, 16, 40)  # rsvmap
    struct.pack_into(">I", header, 20, 17)  # version
    struct.pack_into(">I", header, 24, 16)  # last comp version

    return bytes(header + struct_buf + strings_buf)


def test_fdt_parser_and_fit_format():
    data = _create_mock_fdt_image()
    parser = FDTParser(data)
    assert parser.is_valid()
    hw_info = parser.get_hardware_info()
    assert hw_info["model"] == "Sunxi A33 Test Board"
    assert "allwinner,sun8i-a33" in hw_info["compatible"]

    fmt = FITImageFormat()
    assert fmt.can_handle(data, Path("test.dtb")) >= 0.85
    res = fmt.unpack(data, Path("test.dtb"))
    assert len(res.sections) == 1
    assert "device_tree_info.txt" in res.sections[0].name
    assert b"Sunxi A33 Test Board" in res.sections[0].data


def test_android_super_image_can_handle():
    buf = bytearray(8192)
    # Put LP_GEOMETRY_MAGIC at offset 4096
    struct.pack_into("<I", buf, PRIMARY_GEOMETRY_OFFSET, LP_GEOMETRY_MAGIC)
    fmt = AndroidSuperImageFormat()
    assert fmt.can_handle(bytes(buf), Path("super.img")) >= 0.90
