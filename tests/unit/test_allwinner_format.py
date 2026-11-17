"""Unit tests for AllwinnerImageFormat."""

import struct
from pathlib import Path
from firmware_scanner.firmware.formats.allwinner import AllwinnerImageFormat


def test_allwinner_can_handle():
    assert AllwinnerImageFormat.can_handle(b"IMAGEWTY" + b"\x00" * 100, Path("test.img")) == 0.98
    assert AllwinnerImageFormat.can_handle(b"ANDROID!" + b"\x00" * 100, Path("test.img")) == 0.0
    assert AllwinnerImageFormat.can_handle(b"\x7fELF" + b"\x00" * 100, Path("test.elf")) == 0.0


def test_allwinner_unpack_synthetic():
    # Build a minimal valid IMAGEWTY buffer
    # Global header: 1024 bytes
    # magic: IMAGEWTY (8)
    # version: 0x0300 (4), hdr_size: 96 (4), ram_base: 0x4d00000 (4), fmt_ver: 0x100234 (4), img_size: 4096 (4), img_hdr_size: 1024 (4)
    # offset 32: 12 integers, where offset 60 (index 7) is num_files = 1
    hdr = bytearray(1024)
    hdr[:8] = b"IMAGEWTY"
    struct.pack_into("<6I", hdr, 8, 0x0300, 96, 0x04D00000, 0x100234, 4096, 1024)
    struct.pack_into("<I", hdr, 60, 1)  # num_files = 1

    # File header: 1024 bytes at offset 1024
    fhdr = bytearray(1024)
    # maintype: COMMON (8)
    fhdr[8:14] = b"COMMON"
    # subtype: SYS_CONFIG100000 (16)
    fhdr[16:32] = b"SYS_CONFIG100000"
    # filename at 36
    fname = b"sys_config.fex\x00"
    fhdr[36 : 36 + len(fname)] = fname
    # stored_len, pad1, orig_len, pad2, offset
    cfg_content = b";A83 PAD\n[product]\nmachine = \"perf3_v1_0\"\n"
    data_off = 2048
    struct.pack_into("<5I", fhdr, 292, len(cfg_content), 0, len(cfg_content), 0, data_off)

    full_img = bytes(hdr) + bytes(fhdr) + cfg_content

    fmt = AllwinnerImageFormat()
    result = fmt.unpack(full_img, Path("test.img"))
    assert len(result.sections) == 1
    assert result.sections[0].name == "sys_config.fex"
    assert result.sections[0].section_type == "config"
    assert result.metadata.get("machine") == "perf3_v1_0"
