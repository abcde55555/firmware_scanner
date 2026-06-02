"""Pure-Python SquashFS v4 reader for firmware analysis.

Supports reading directory listings and extracting files from SquashFS v4
filesystems with gzip, LZMA, XZ, and LZO compression.
"""

import struct
import zlib
import lzma
from dataclasses import dataclass
from typing import Iterator


# SquashFS magic
SQUASHFS_MAGIC = 0x73717368  # 'hsqs' little-endian

# Compression types
COMP_GZIP = 1
COMP_LZMA = 2
COMP_LZO = 3
COMP_XZ = 4
COMP_LZ4 = 5
COMP_ZSTD = 6

# Inode types
SQFS_DIR_TYPE = 1
SQFS_REG_TYPE = 2
SQFS_SYMLINK_TYPE = 3
SQFS_BLKDEV_TYPE = 4
SQFS_CHRDEV_TYPE = 5
SQFS_FIFO_TYPE = 6
SQFS_SOCKET_TYPE = 7
SQFS_LDIR_TYPE = 8
SQFS_LREG_TYPE = 9
SQFS_LSYMLINK_TYPE = 10
SQFS_LBLKDEV_TYPE = 11
SQFS_LCHRDEV_TYPE = 12
SQFS_LFIFO_TYPE = 13
SQFS_LSOCKET_TYPE = 14

# Metadata block size
METADATA_BLOCK_SIZE = 8192
# Flag in metadata block header indicating uncompressed
METADATA_UNCOMPRESSED = 0x8000


@dataclass
class SquashFSSuperblock:
    magic: int
    inode_count: int
    modification_time: int
    block_size: int
    fragment_count: int
    compression: int
    block_log: int
    flags: int
    id_count: int
    version_major: int
    version_minor: int
    root_inode_ref: int
    bytes_used: int
    id_table_start: int
    xattr_table_start: int
    inode_table_start: int
    dir_table_start: int
    fragment_table_start: int
    export_table_start: int


@dataclass
class DirEntry:
    name: str
    inode_number: int
    inode_type: int
    is_dir: bool
    is_file: bool
    size: int = 0


class SquashFSReader:
    """Read-only SquashFS v4 filesystem reader."""

    def __init__(self, data: bytes):
        self._data = data
        self._sb: SquashFSSuperblock | None = None
        self._valid = False
        self._inode_cache: dict[int, dict] = {}
        self._parse_superblock()

    def is_valid(self) -> bool:
        return self._valid

    def _parse_superblock(self):
        if len(self._data) < 96:
            return
        magic = struct.unpack_from('<I', self._data, 0)[0]
        if magic != SQUASHFS_MAGIC:
            return

        self._sb = SquashFSSuperblock(
            magic=magic,
            inode_count=struct.unpack_from('<I', self._data, 4)[0],
            modification_time=struct.unpack_from('<I', self._data, 8)[0],
            block_size=struct.unpack_from('<I', self._data, 12)[0],
            fragment_count=struct.unpack_from('<I', self._data, 16)[0],
            compression=struct.unpack_from('<H', self._data, 20)[0],
            block_log=struct.unpack_from('<H', self._data, 22)[0],
            flags=struct.unpack_from('<H', self._data, 24)[0],
            id_count=struct.unpack_from('<H', self._data, 26)[0],
            version_major=struct.unpack_from('<H', self._data, 28)[0],
            version_minor=struct.unpack_from('<H', self._data, 30)[0],
            root_inode_ref=struct.unpack_from('<Q', self._data, 32)[0],
            bytes_used=struct.unpack_from('<Q', self._data, 40)[0],
            id_table_start=struct.unpack_from('<Q', self._data, 48)[0],
            xattr_table_start=struct.unpack_from('<Q', self._data, 56)[0],
            inode_table_start=struct.unpack_from('<Q', self._data, 64)[0],
            dir_table_start=struct.unpack_from('<Q', self._data, 72)[0],
            fragment_table_start=struct.unpack_from('<Q', self._data, 80)[0],
            export_table_start=struct.unpack_from('<Q', self._data, 88)[0],
        )

        if self._sb.version_major != 4:
            return
        if self._sb.compression not in (COMP_GZIP, COMP_LZMA, COMP_XZ, COMP_LZO, COMP_LZ4, COMP_ZSTD):
            return

        self._valid = True

    def _decompress(self, compressed: bytes) -> bytes:
        """Decompress a data block using the filesystem's compression type."""
        if not self._sb:
            return b""
        comp = self._sb.compression
        try:
            if comp == COMP_GZIP:
                return zlib.decompress(compressed, 15 + 32)
            elif comp == COMP_LZMA:
                return lzma.decompress(compressed)
            elif comp == COMP_XZ:
                return lzma.decompress(compressed)
            elif comp == COMP_LZO:
                try:
                    import lzo
                    return lzo.decompress(compressed, False, self._sb.block_size)
                except ImportError:
                    return b""
            elif comp == COMP_LZ4:
                try:
                    import lz4.block
                    return lz4.block.decompress(compressed, uncompressed_size=self._sb.block_size)
                except ImportError:
                    return b""
            elif comp == COMP_ZSTD:
                try:
                    import zstandard
                    return zstandard.ZstdDecompressor().decompress(compressed)
                except ImportError:
                    return b""
        except Exception:
            return b""
        return b""

    def _read_metadata_block(self, offset: int) -> tuple[bytes, int]:
        """Read and decompress a metadata block at offset.
        Returns (decompressed_data, next_offset)."""
        if offset + 2 > len(self._data):
            return b"", offset + 2
        header = struct.unpack_from('<H', self._data, offset)[0]
        is_uncompressed = bool(header & METADATA_UNCOMPRESSED)
        size = header & 0x7FFF

        if size == 0 or offset + 2 + size > len(self._data):
            return b"", offset + 2 + size

        raw = self._data[offset + 2:offset + 2 + size]
        if is_uncompressed:
            return raw, offset + 2 + size
        else:
            decompressed = self._decompress(raw)
            return decompressed, offset + 2 + size

    def _read_metadata_at(self, table_start: int, block_offset: int, byte_offset: int) -> bytes:
        """Read metadata at a specific block/byte offset within a metadata table.

        Handles cases where byte_offset spans multiple consecutive metadata blocks
        by reading and concatenating blocks until enough data is available.
        """
        abs_offset = table_start + block_offset
        accumulated = bytearray()
        current_offset = abs_offset

        # Read blocks until we have enough data past byte_offset
        # (typically 1 block suffices, but large inodes/directories may span blocks)
        max_blocks = 8
        for _ in range(max_blocks):
            block_data, next_offset = self._read_metadata_block(current_offset)
            if not block_data:
                break
            accumulated.extend(block_data)
            if len(accumulated) > byte_offset:
                return bytes(accumulated[byte_offset:])
            current_offset = next_offset

        if byte_offset < len(accumulated):
            return bytes(accumulated[byte_offset:])
        return b""

    def _read_inode(self, inode_ref: int) -> dict | None:
        """Read an inode given its reference (block_offset:byte_offset packed in u64)."""
        if inode_ref in self._inode_cache:
            return self._inode_cache[inode_ref]

        block_offset = (inode_ref >> 16) & 0xFFFFFFFF
        byte_offset = inode_ref & 0xFFFF

        meta = self._read_metadata_at(self._sb.inode_table_start, block_offset, byte_offset)
        if len(meta) < 16:
            return None

        inode_type = struct.unpack_from('<H', meta, 0)[0]
        permissions = struct.unpack_from('<H', meta, 2)[0]
        uid_idx = struct.unpack_from('<H', meta, 4)[0]
        gid_idx = struct.unpack_from('<H', meta, 6)[0]
        mtime = struct.unpack_from('<I', meta, 8)[0]
        inode_number = struct.unpack_from('<I', meta, 12)[0]

        result = {
            "type": inode_type,
            "permissions": permissions,
            "inode_number": inode_number,
            "mtime": mtime,
        }

        if inode_type == SQFS_DIR_TYPE:
            if len(meta) >= 28:
                result["dir_block_start"] = struct.unpack_from('<I', meta, 16)[0]
                result["hard_links"] = struct.unpack_from('<I', meta, 20)[0]
                result["file_size"] = struct.unpack_from('<H', meta, 24)[0]
                result["block_offset"] = struct.unpack_from('<H', meta, 26)[0]
                result["parent_inode"] = struct.unpack_from('<I', meta, 28)[0] if len(meta) >= 32 else 0
        elif inode_type == SQFS_LDIR_TYPE:
            if len(meta) >= 36:
                result["hard_links"] = struct.unpack_from('<I', meta, 16)[0]
                result["file_size"] = struct.unpack_from('<I', meta, 20)[0]
                result["dir_block_start"] = struct.unpack_from('<I', meta, 24)[0]
                result["parent_inode"] = struct.unpack_from('<I', meta, 28)[0]
                result["dir_index_count"] = struct.unpack_from('<H', meta, 32)[0]
                result["block_offset"] = struct.unpack_from('<H', meta, 34)[0]
                result["xattr_idx"] = struct.unpack_from('<I', meta, 36)[0] if len(meta) >= 40 else 0
        elif inode_type == SQFS_REG_TYPE:
            if len(meta) >= 32:
                result["blocks_start"] = struct.unpack_from('<I', meta, 16)[0]
                result["fragment_index"] = struct.unpack_from('<I', meta, 20)[0]
                result["fragment_offset"] = struct.unpack_from('<I', meta, 24)[0]
                result["file_size"] = struct.unpack_from('<I', meta, 28)[0]
                # Block sizes follow at offset 32
                num_blocks = (result["file_size"] + self._sb.block_size - 1) // self._sb.block_size if result["fragment_index"] == 0xFFFFFFFF else result["file_size"] // self._sb.block_size
                result["block_sizes"] = []
                off = 32
                for _ in range(num_blocks):
                    if off + 4 <= len(meta):
                        result["block_sizes"].append(struct.unpack_from('<I', meta, off)[0])
                        off += 4
        elif inode_type == SQFS_LREG_TYPE:
            if len(meta) >= 52:
                result["blocks_start"] = struct.unpack_from('<Q', meta, 16)[0]
                result["file_size"] = struct.unpack_from('<Q', meta, 24)[0]
                result["sparse"] = struct.unpack_from('<Q', meta, 32)[0]
                result["hard_links"] = struct.unpack_from('<I', meta, 40)[0]
                result["fragment_index"] = struct.unpack_from('<I', meta, 44)[0]
                result["fragment_offset"] = struct.unpack_from('<I', meta, 48)[0]
                result["xattr_idx"] = struct.unpack_from('<I', meta, 52)[0] if len(meta) >= 56 else 0
                num_blocks = (int(result["file_size"]) + self._sb.block_size - 1) // self._sb.block_size if result["fragment_index"] == 0xFFFFFFFF else int(result["file_size"]) // self._sb.block_size
                result["block_sizes"] = []
                off = 56
                for _ in range(num_blocks):
                    if off + 4 <= len(meta):
                        result["block_sizes"].append(struct.unpack_from('<I', meta, off)[0])
                        off += 4
        elif inode_type == SQFS_SYMLINK_TYPE or inode_type == SQFS_LSYMLINK_TYPE:
            if len(meta) >= 24:
                result["hard_links"] = struct.unpack_from('<I', meta, 16)[0]
                symlink_size = struct.unpack_from('<I', meta, 20)[0]
                if len(meta) >= 24 + symlink_size:
                    result["symlink_target"] = meta[24:24 + symlink_size].decode("utf-8", errors="replace")
                result["file_size"] = 0

        self._inode_cache[inode_ref] = result
        return result

    def _read_directory(self, inode: dict) -> list[DirEntry]:
        """Read directory entries from a directory inode."""
        entries: list[DirEntry] = []
        if not self._sb:
            return entries

        dir_block_start = inode.get("dir_block_start", 0)
        block_offset = inode.get("block_offset", 0)
        dir_size = inode.get("file_size", 0)
        if inode["type"] == SQFS_DIR_TYPE:
            dir_size -= 3  # Quirk: basic dir inode size field includes "." and ".."

        if dir_size <= 0:
            return entries

        # Read directory metadata
        meta = self._read_metadata_at(self._sb.dir_table_start, dir_block_start, block_offset)
        if not meta:
            return entries

        offset = 0
        bytes_read = 0

        while bytes_read < dir_size and offset + 12 <= len(meta):
            # Directory header: count(4) + start_block(4) + inode_number(4)
            count = struct.unpack_from('<I', meta, offset)[0]
            start_block = struct.unpack_from('<I', meta, offset + 4)[0]
            inode_number_base = struct.unpack_from('<I', meta, offset + 8)[0]
            offset += 12
            bytes_read += 12

            for _ in range(count + 1):
                if offset + 8 > len(meta):
                    break
                entry_offset = struct.unpack_from('<H', meta, offset)[0]
                entry_inode_offset = struct.unpack_from('<h', meta, offset + 2)[0]
                entry_type = struct.unpack_from('<H', meta, offset + 4)[0]
                name_size = struct.unpack_from('<H', meta, offset + 6)[0]
                offset += 8
                bytes_read += 8

                if offset + name_size + 1 > len(meta):
                    break
                name = meta[offset:offset + name_size + 1].decode("utf-8", errors="replace")
                offset += name_size + 1
                bytes_read += name_size + 1

                inode_ref = (start_block << 16) | entry_offset
                entry_inode_num = inode_number_base + entry_inode_offset

                is_dir = entry_type in (SQFS_DIR_TYPE, SQFS_LDIR_TYPE)
                is_file = entry_type in (SQFS_REG_TYPE, SQFS_LREG_TYPE)

                entries.append(DirEntry(
                    name=name,
                    inode_number=inode_ref,
                    inode_type=entry_type,
                    is_dir=is_dir,
                    is_file=is_file,
                ))

        return entries

    def list_directory(self, path: str) -> list[DirEntry]:
        """List files in a directory path."""
        if not self._valid or not self._sb:
            return []

        inode = self._resolve_path(path)
        if not inode:
            return []
        if inode["type"] not in (SQFS_DIR_TYPE, SQFS_LDIR_TYPE):
            return []

        return self._read_directory(inode)

    def _resolve_path(self, path: str) -> dict | None:
        """Resolve a path to its inode."""
        if not self._sb:
            return None

        # Start from root inode
        inode = self._read_inode(self._sb.root_inode_ref)
        if not inode:
            return None

        if path == "/" or path == "":
            return inode

        parts = [p for p in path.strip("/").split("/") if p]
        for part in parts:
            if inode["type"] not in (SQFS_DIR_TYPE, SQFS_LDIR_TYPE):
                return None
            entries = self._read_directory(inode)
            found = False
            for entry in entries:
                if entry.name == part:
                    inode = self._read_inode(entry.inode_number)
                    if not inode:
                        return None
                    found = True
                    break
            if not found:
                return None

        return inode

    def read_file(self, path: str, max_size: int = 16 * 1024 * 1024) -> bytes | None:
        """Read a file from the filesystem."""
        if not self._valid or not self._sb:
            return None

        inode = self._resolve_path(path)
        if not inode:
            return None
        if inode["type"] not in (SQFS_REG_TYPE, SQFS_LREG_TYPE):
            return None

        file_size = inode.get("file_size", 0)
        if file_size == 0 or file_size > max_size:
            return None

        return self._read_file_data(inode)

    def _read_file_data(self, inode: dict) -> bytes | None:
        """Read file data blocks for a regular file inode."""
        if not self._sb:
            return None

        file_size = inode.get("file_size", 0)
        blocks_start = inode.get("blocks_start", 0)
        block_sizes = inode.get("block_sizes", [])
        fragment_index = inode.get("fragment_index", 0xFFFFFFFF)
        fragment_offset = inode.get("fragment_offset", 0)

        result = bytearray()
        data_offset = blocks_start

        # Read data blocks
        for block_size_raw in block_sizes:
            is_uncompressed = bool(block_size_raw & (1 << 24))
            block_size = block_size_raw & 0x00FFFFFF

            if block_size == 0:
                # Sparse block
                result.extend(b'\x00' * self._sb.block_size)
            elif data_offset + block_size > len(self._data):
                break
            else:
                block_data = self._data[data_offset:data_offset + block_size]
                if is_uncompressed:
                    result.extend(block_data)
                else:
                    decompressed = self._decompress(block_data)
                    if decompressed:
                        result.extend(decompressed)
                    else:
                        break
                data_offset += block_size

        # Read fragment if present
        if fragment_index != 0xFFFFFFFF and len(result) < file_size:
            frag_data = self._read_fragment(fragment_index)
            if frag_data and fragment_offset < len(frag_data):
                remaining = file_size - len(result)
                result.extend(frag_data[fragment_offset:fragment_offset + remaining])

        return bytes(result[:file_size])

    def _read_fragment(self, fragment_index: int) -> bytes | None:
        """Read and decompress a fragment block."""
        if not self._sb or fragment_index >= self._sb.fragment_count:
            return None

        # Fragment table is a lookup table of block offsets
        # Each entry is 16 bytes: start(8) + size(4) + unused(4)
        frag_table_offset = self._sb.fragment_table_start
        # The fragment table itself is stored as metadata block pointers
        # Each pointer is 8 bytes pointing to a metadata block containing fragment entries
        entries_per_block = METADATA_BLOCK_SIZE // 16
        block_idx = fragment_index // entries_per_block
        entry_idx = fragment_index % entries_per_block

        # Read the fragment table pointer
        ptr_offset = frag_table_offset + block_idx * 8
        if ptr_offset + 8 > len(self._data):
            return None
        meta_block_offset = struct.unpack_from('<Q', self._data, ptr_offset)[0]

        # Read the metadata block containing fragment entries
        meta, _ = self._read_metadata_block(meta_block_offset)
        if not meta or entry_idx * 16 + 16 > len(meta):
            return None

        # Parse fragment entry
        frag_start = struct.unpack_from('<Q', meta, entry_idx * 16)[0]
        frag_size_raw = struct.unpack_from('<I', meta, entry_idx * 16 + 8)[0]

        is_uncompressed = bool(frag_size_raw & (1 << 24))
        frag_size = frag_size_raw & 0x00FFFFFF

        if frag_start + frag_size > len(self._data):
            return None

        frag_data = self._data[frag_start:frag_start + frag_size]
        if is_uncompressed:
            return frag_data
        return self._decompress(frag_data)

    def exists(self, path: str) -> bool:
        return self._resolve_path(path) is not None

    def file_size(self, path: str) -> int:
        inode = self._resolve_path(path)
        if inode:
            return inode.get("file_size", 0)
        return 0

    def walk(self, root: str = "/", max_depth: int = 5) -> Iterator[tuple[str, list[DirEntry]]]:
        """Walk the filesystem tree yielding (path, entries) tuples."""
        if not self._valid:
            return

        stack = [(root, 0)]
        while stack:
            path, depth = stack.pop()
            if depth > max_depth:
                continue
            entries = self.list_directory(path)
            if entries:
                yield path, entries
                for entry in entries:
                    if entry.is_dir:
                        child_path = f"{path.rstrip('/')}/{entry.name}"
                        stack.append((child_path, depth + 1))
