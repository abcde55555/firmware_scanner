"""Device Tree Blob (DTB) and U-Boot Flattened Image Tree (FIT) parser.

Parses FDT binaries (magic 0xd00dfeed) to extract hardware compatibility
metadata, chip models, and embedded images (kernel, initramfs, ramdisk).
"""

import gzip
import io
import lzma
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any, Optional

FDT_MAGIC = 0xD00DFEED

FDT_BEGIN_NODE = 0x00000001
FDT_END_NODE = 0x00000002
FDT_PROP = 0x00000003
FDT_NOP = 0x00000004
FDT_END = 0x00000009


@dataclass
class FITSubImage:
    node_name: str
    description: str = ""
    image_type: str = ""  # kernel, ramdisk, flat_dt, firmware
    arch: str = ""
    os: str = ""
    compression: str = "none"
    load_addr: int = 0
    entry_point: int = 0
    data: bytes = b""


@dataclass
class FDTNode:
    name: str
    properties: dict[str, Any] = field(default_factory=dict)
    children: dict[str, "FDTNode"] = field(default_factory=dict)


class FDTParser:
    """Parser for Device Tree Blobs (DTB) and U-Boot FIT Images."""

    def __init__(self, data: bytes):
        self.data = data
        self.totalsize = 0
        self.version = 0
        self.root: Optional[FDTNode] = None
        self._valid = False
        self.fit_images: list[FITSubImage] = []

        self._parse()

    def is_valid(self) -> bool:
        return self._valid

    def _parse(self) -> None:
        if len(self.data) < 32:
            return

        magic = struct.unpack_from(">I", self.data, 0)[0]
        if magic != FDT_MAGIC:
            return

        totalsize, off_dt_struct, off_dt_strings = struct.unpack_from(">III", self.data, 4)
        version = struct.unpack_from(">I", self.data, 20)[0]

        if totalsize > len(self.data) or off_dt_struct >= len(self.data) or off_dt_strings >= len(self.data):
            return

        self.totalsize = totalsize
        self.version = version
        self._valid = True

        strings_block = self.data[off_dt_strings:totalsize]
        self.root = self._parse_node_tree(off_dt_struct, strings_block)

        if self.root:
            self._extract_fit_images()

    def _parse_node_tree(self, struct_offset: int, strings_block: bytes) -> Optional[FDTNode]:
        pos = struct_offset
        node_stack: list[FDTNode] = []
        root: Optional[FDTNode] = None

        while pos + 4 <= len(self.data):
            token = struct.unpack_from(">I", self.data, pos)[0]
            pos += 4

            if token == FDT_BEGIN_NODE:
                null_pos = self.data.find(b"\x00", pos)
                if null_pos < 0:
                    break
                node_name = self.data[pos:null_pos].decode("ascii", errors="ignore")
                pos = (null_pos + 4) & ~3

                new_node = FDTNode(name=node_name)
                if not root:
                    root = new_node
                if node_stack:
                    node_stack[-1].children[node_name] = new_node
                node_stack.append(new_node)

            elif token == FDT_END_NODE:
                if node_stack:
                    node_stack.pop()

            elif token == FDT_PROP:
                prop_len, nameoff = struct.unpack_from(">II", self.data, pos)
                pos += 8
                prop_data = self.data[pos : pos + prop_len]
                pos = (pos + prop_len + 3) & ~3

                prop_name = ""
                if nameoff < len(strings_block):
                    null_idx = strings_block.find(b"\x00", nameoff)
                    if null_idx >= 0:
                        prop_name = strings_block[nameoff:null_idx].decode("ascii", errors="ignore")
                    else:
                        prop_name = strings_block[nameoff:].decode("ascii", errors="ignore")

                if node_stack and prop_name:
                    node_stack[-1].properties[prop_name] = prop_data

            elif token == FDT_NOP:
                continue

            elif token == FDT_END:
                break

        return root

    def get_hardware_info(self) -> dict[str, Any]:
        """Extract hardware model and compatible strings from DTB."""
        info = {
            "model": "",
            "compatible": [],
        }
        if not self.root:
            return info

        if "model" in self.root.properties:
            raw_model = self.root.properties["model"]
            info["model"] = raw_model.split(b"\x00")[0].decode("utf-8", errors="ignore")

        if "compatible" in self.root.properties:
            raw_compat = self.root.properties["compatible"]
            parts = [p.decode("ascii", errors="ignore") for p in raw_compat.split(b"\x00") if p]
            info["compatible"] = parts

        return info

    def _extract_fit_images(self) -> None:
        """Extract sub-images defined in FIT /images node."""
        if not self.root:
            return

        images_node = self.root.children.get("images")
        if not images_node:
            return

        for img_name, img_node in images_node.children.items():
            sub = FITSubImage(node_name=img_name)
            props = img_node.properties

            if "description" in props:
                sub.description = props["description"].split(b"\x00")[0].decode("utf-8", errors="ignore")
            if "type" in props:
                sub.image_type = props["type"].split(b"\x00")[0].decode("ascii", errors="ignore")
            if "arch" in props:
                sub.arch = props["arch"].split(b"\x00")[0].decode("ascii", errors="ignore")
            if "os" in props:
                sub.os = props["os"].split(b"\x00")[0].decode("ascii", errors="ignore")
            if "compression" in props:
                sub.compression = props["compression"].split(b"\x00")[0].decode("ascii", errors="ignore")

            raw_payload = props.get("data", b"")
            if raw_payload:
                # Decompress if compressed
                if sub.compression == "gzip":
                    try:
                        raw_payload = gzip.decompress(raw_payload)
                    except Exception:
                        try:
                            raw_payload = zlib.decompress(raw_payload)
                        except Exception:
                            pass
                elif sub.compression in ("lzma", "xz"):
                    try:
                        raw_payload = lzma.decompress(raw_payload)
                    except Exception:
                        pass

                sub.data = raw_payload

            self.fit_images.append(sub)
