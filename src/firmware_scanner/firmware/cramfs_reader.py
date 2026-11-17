"""Pure-Python CramFS (Compressed ROM File System) reader.

Extracts files and directories from CramFS images without requiring root
privileges or external tools. Supports both little-endian and big-endian images.
"""

import struct
import zlib
from dataclasses import dataclass
from typing import Optional

CRAMFS_MAGIC_LE = 0x28CD3D45
CRAMFS_MAGIC_BE = 0x453DCD28


@dataclass
class CramFSEntry:
    name: str
    path: str
    mode: int
    size: int
    uid: int
    gid: int
    offset: int
    is_dir: bool = False
    is_file: bool = False
    is_symlink: bool = False


class CramFSReader:
    """Reader for CramFS filesystem images."""

    def __init__(self, data: bytes):
        self.data = data
        self.endian = "<"
        self._valid = False
        self.size = 0
        self.flags = 0
        self.name = ""
        self.root_inode: Optional[CramFSEntry] = None
        self._entries: list[CramFSEntry] = []

        self._parse_superblock()

    def is_valid(self) -> bool:
        return self._valid

    def _parse_superblock(self) -> None:
        if len(self.data) < 64:
            return

        magic = struct.unpack("<I", self.data[:4])[0]
        if magic == CRAMFS_MAGIC_LE:
            self.endian = "<"
        elif magic == CRAMFS_MAGIC_BE:
            self.endian = ">"
        else:
            return

        size, flags, future = struct.unpack_from(f"{self.endian}III", self.data, 4)
        sig = self.data[16:32]
        if b"Compressed ROMFS" not in sig:
            # Some non-standard cramfs images don't have the exact signature string
            pass

        self.size = size
        self.flags = flags
        self.name = self.data[48:64].split(b"\x00")[0].decode("ascii", errors="ignore")

        # Root inode is at offset 64 (12 bytes)
        root = self._parse_inode(64, "", "")
        if root:
            self.root_inode = root
            self._valid = True
            self._scan_dir(root)

    def _parse_inode(self, offset: int, parent_path: str, filename: str) -> Optional[CramFSEntry]:
        if offset + 12 > len(self.data):
            return None

        mode, uid = struct.unpack_from(f"{self.endian}HH", self.data, offset)
        size_raw = struct.unpack_from(f"{self.endian}I", self.data, offset + 4)[0]
        size = size_raw & 0x00FFFFFF
        gid = (size_raw >> 24) & 0xFF

        namelen_offset = struct.unpack_from(f"{self.endian}I", self.data, offset + 8)[0]
        namelen = ((namelen_offset >> 26) & 0x3F) * 4
        block_offset = (namelen_offset & 0x03FFFFFF) << 2

        file_type = mode & 0o170000
        is_dir = file_type == 0o040000
        is_file = file_type == 0o100000
        is_symlink = file_type == 0o120000

        full_path = f"{parent_path.rstrip('/')}/{filename}" if filename else "/"

        return CramFSEntry(
            name=filename,
            path=full_path,
            mode=mode,
            size=size,
            uid=uid,
            gid=gid,
            offset=block_offset,
            is_dir=is_dir,
            is_file=is_file,
            is_symlink=is_symlink,
        )

    def _scan_dir(self, dir_entry: CramFSEntry) -> None:
        """Scan directory and parse all child inodes."""
        offset = dir_entry.offset
        end_offset = offset + dir_entry.size

        while offset < end_offset and offset + 12 <= len(self.data):
            namelen_offset = struct.unpack_from(f"{self.endian}I", self.data, offset + 8)[0]
            namelen = ((namelen_offset >> 26) & 0x3F) * 4
            if namelen == 0:
                break

            name_bytes = self.data[offset + 12 : offset + 12 + namelen]
            name = name_bytes.split(b"\x00")[0].decode("utf-8", errors="ignore")

            child = self._parse_inode(offset, dir_entry.path, name)
            if not child:
                break

            self._entries.append(child)
            if child.is_dir and child.size > 0 and child.offset != dir_entry.offset:
                self._scan_dir(child)

            offset += 12 + namelen

    def list_files(self) -> list[CramFSEntry]:
        """Return all regular files in the image."""
        return [e for e in self._entries if e.is_file]

    def read_file(self, entry: CramFSEntry, max_size: int = 16 * 1024 * 1024) -> bytes:
        """Decompress and read file data."""
        if not entry.is_file or entry.size == 0:
            return b""

        num_blocks = (entry.size + 4095) // 4096
        table_offset = entry.offset
        block_pointers = []

        for i in range(num_blocks):
            ptr_offset = table_offset + i * 4
            if ptr_offset + 4 > len(self.data):
                break
            ptr = struct.unpack_from(f"{self.endian}I", self.data, ptr_offset)[0]
            block_pointers.append(ptr)

        if not block_pointers:
            return b""

        curr_offset = table_offset + num_blocks * 4
        decompressed_chunks = []
        total_decompressed = 0

        for end_ptr in block_pointers:
            if end_ptr <= curr_offset or end_ptr > len(self.data):
                break
            chunk = self.data[curr_offset:end_ptr]
            curr_offset = end_ptr

            try:
                data = zlib.decompress(chunk)
            except Exception:
                # May be uncompressed block
                data = chunk

            decompressed_chunks.append(data)
            total_decompressed += len(data)
            if total_decompressed >= max_size:
                break

        full_content = b"".join(decompressed_chunks)
        return full_content[: entry.size]
