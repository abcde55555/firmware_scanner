"""Pure-Python read-only EROFS filesystem parser.

EROFS (Enhanced Read-Only File System) is used in Android 12+ for system
partitions. It offers better compression and performance than ext4 for
read-only images.

Supports:
- Flat plain inodes (uncompressed)
- Inline data for small files
- LZ4-compressed data blocks (requires lz4 package)

Limitations:
- LZMA compression not supported without external tools
- No EROFS over FUSE support
"""

import struct
from dataclasses import dataclass
from typing import Iterator

try:
    import lz4.block as lz4_block
    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False


EROFS_MAGIC = 0xE0F5E1E2
EROFS_SUPER_OFFSET = 1024

# Inode formats
EROFS_INODE_FLAT_PLAIN = 0
EROFS_INODE_FLAT_COMPRESSION = 1
EROFS_INODE_FLAT_INLINE = 2
EROFS_INODE_COMPRESSED_FULL = 3
EROFS_INODE_COMPRESSED_COMPACT = 4

# File types (same as ext4)
FT_REG_FILE = 1
FT_DIR = 2
FT_SYMLINK = 7

S_IFREG = 0o100000
S_IFDIR = 0o040000
S_IFLNK = 0o120000

EROFS_INODE_COMPACT_SIZE = 32
EROFS_INODE_EXTENDED_SIZE = 64


@dataclass
class ErofsSuperblock:
    magic: int = 0
    checksum: int = 0
    feature_compat: int = 0
    block_size_bits: int = 12
    block_size: int = 4096
    root_nid: int = 0
    inos: int = 0
    blocks: int = 0
    meta_blkaddr: int = 0
    xattr_blkaddr: int = 0


@dataclass
class ErofsInode:
    format: int = 0
    mode: int = 0
    nid: int = 0
    size: int = 0
    nlink: int = 0
    data_layout: int = 0
    raw_blkaddr: int = 0
    inode_size: int = 0
    xattr_count: int = 0


@dataclass
class DirEntry:
    name: str
    nid: int
    file_type: int

    @property
    def is_dir(self) -> bool:
        return self.file_type == FT_DIR

    @property
    def is_file(self) -> bool:
        return self.file_type == FT_REG_FILE

    @property
    def is_symlink(self) -> bool:
        return self.file_type == FT_SYMLINK


class ErofsReader:
    """Read-only EROFS filesystem parser."""

    def __init__(self, data: bytes):
        self._data = data
        self._sb = ErofsSuperblock()
        self._valid = False
        self._parse_superblock()

    def is_valid(self) -> bool:
        return self._valid

    def _parse_superblock(self):
        if len(self._data) < EROFS_SUPER_OFFSET + 128:
            return

        sb_data = self._data[EROFS_SUPER_OFFSET:EROFS_SUPER_OFFSET + 128]
        magic = struct.unpack_from('<I', sb_data, 0)[0]
        if magic != EROFS_MAGIC:
            return

        self._sb.magic = magic
        self._sb.checksum = struct.unpack_from('<I', sb_data, 4)[0]
        self._sb.feature_compat = struct.unpack_from('<I', sb_data, 8)[0]
        self._sb.block_size_bits = struct.unpack_from('<B', sb_data, 12)[0]

        if self._sb.block_size_bits < 9 or self._sb.block_size_bits > 16:
            self._sb.block_size_bits = 12

        self._sb.block_size = 1 << self._sb.block_size_bits
        self._sb.root_nid = struct.unpack_from('<H', sb_data, 14)[0]
        self._sb.inos = struct.unpack_from('<Q', sb_data, 16)[0]
        self._sb.blocks = struct.unpack_from('<I', sb_data, 28)[0]
        self._sb.meta_blkaddr = struct.unpack_from('<I', sb_data, 32)[0]
        self._sb.xattr_blkaddr = struct.unpack_from('<I', sb_data, 36)[0]

        self._valid = True

    def _nid_to_offset(self, nid: int) -> int:
        """Convert node ID (NID) to byte offset in the image."""
        return self._sb.meta_blkaddr * self._sb.block_size + nid * 32

    def _read_inode(self, nid: int) -> ErofsInode | None:
        """Read inode at given NID."""
        offset = self._nid_to_offset(nid)
        if offset + 32 > len(self._data):
            return None

        # Read compact header first
        inode_data = self._data[offset:offset + 64]
        if len(inode_data) < 32:
            return None

        inode = ErofsInode()
        inode.nid = nid

        # First 2 bytes: format | data_layout
        format_field = struct.unpack_from('<H', inode_data, 0)[0]
        inode.format = (format_field >> 12) & 0x1  # 0=compact, 1=extended
        inode.data_layout = format_field & 0x07

        if inode.format == 0:
            # Compact inode (32 bytes)
            inode.inode_size = EROFS_INODE_COMPACT_SIZE
            inode.mode = struct.unpack_from('<H', inode_data, 2)[0]
            inode.nlink = struct.unpack_from('<H', inode_data, 4)[0]
            inode.size = struct.unpack_from('<I', inode_data, 6)[0]
            inode.raw_blkaddr = struct.unpack_from('<I', inode_data, 18)[0]
            inode.xattr_count = struct.unpack_from('<H', inode_data, 14)[0]
        else:
            # Extended inode (64 bytes)
            if offset + 64 > len(self._data):
                return None
            inode.inode_size = EROFS_INODE_EXTENDED_SIZE
            inode.mode = struct.unpack_from('<H', inode_data, 2)[0]
            inode.nlink = struct.unpack_from('<I', inode_data, 8)[0]
            inode.size = struct.unpack_from('<Q', inode_data, 12)[0]
            inode.raw_blkaddr = struct.unpack_from('<I', inode_data, 22)[0]
            inode.xattr_count = struct.unpack_from('<H', inode_data, 4)[0]

        return inode

    def _get_data_offset(self, inode: ErofsInode) -> int:
        """Get the data start offset for an inode."""
        if inode.data_layout in (EROFS_INODE_FLAT_INLINE, EROFS_INODE_FLAT_COMPRESSION):
            # Inline data: stored right after the inode + xattrs
            inode_offset = self._nid_to_offset(inode.nid)
            xattr_size = inode.xattr_count * 4 if inode.xattr_count else 0
            return inode_offset + inode.inode_size + xattr_size
        else:
            # Data in separate blocks
            return inode.raw_blkaddr * self._sb.block_size

    def _read_file_data(self, inode: ErofsInode, max_size: int = 16 * 1024 * 1024) -> bytes:
        """Read file content from inode."""
        read_size = min(inode.size, max_size)
        if read_size == 0:
            return b""

        if inode.data_layout == EROFS_INODE_FLAT_INLINE:
            offset = self._get_data_offset(inode)
            return self._data[offset:offset + read_size]

        elif inode.data_layout == EROFS_INODE_FLAT_PLAIN:
            offset = inode.raw_blkaddr * self._sb.block_size
            return self._data[offset:offset + read_size]

        elif inode.data_layout in (EROFS_INODE_FLAT_COMPRESSION,
                                    EROFS_INODE_COMPRESSED_FULL,
                                    EROFS_INODE_COMPRESSED_COMPACT):
            return self._read_compressed_data(inode, read_size)

        return b""

    def _read_compressed_data(self, inode: ErofsInode, max_size: int) -> bytes:
        """Read LZ4-compressed file data."""
        if not HAS_LZ4:
            return b""

        data_offset = inode.raw_blkaddr * self._sb.block_size
        result = bytearray()

        # Read compressed blocks
        offset = data_offset
        while len(result) < max_size and offset < len(self._data):
            remaining = max_size - len(result)
            # Try to decompress one block
            block_end = min(offset + self._sb.block_size * 2, len(self._data))
            compressed = self._data[offset:block_end]

            try:
                decompressed = lz4_block.decompress(
                    compressed,
                    uncompressed_size=min(self._sb.block_size, remaining)
                )
                result.extend(decompressed[:remaining])
                offset += len(compressed)
            except Exception:
                # If decompression fails, try reading as plain data
                plain = self._data[offset:offset + min(self._sb.block_size, remaining)]
                result.extend(plain)
                offset += self._sb.block_size
                break

        return bytes(result[:max_size])

    def _read_directory(self, inode: ErofsInode) -> list[DirEntry]:
        """Read directory entries from an inode."""
        entries: list[DirEntry] = []
        dir_data = self._read_file_data(inode, max_size=min(inode.size, 4 * 1024 * 1024))

        if not dir_data:
            return entries

        offset = 0
        while offset + 12 <= len(dir_data):
            # EROFS dirent: nid(8) + nameoff(2) + file_type(1) + reserved(1)
            nid = struct.unpack_from('<Q', dir_data, offset)[0]
            nameoff = struct.unpack_from('<H', dir_data, offset + 8)[0]
            file_type = struct.unpack_from('<B', dir_data, offset + 10)[0]

            if nid == 0 and nameoff == 0:
                break

            # Name is at the specified offset relative to the block start
            # In EROFS, directory entries are fixed-size headers followed by names
            # The nameoff points to where the name starts
            name_start = nameoff
            # Find end of name (next entry's nameoff or end of data)
            next_offset = offset + 12
            if next_offset + 12 <= len(dir_data):
                next_nameoff = struct.unpack_from('<H', dir_data, next_offset + 8)[0]
                if next_nameoff > name_start:
                    name_end = next_nameoff
                else:
                    name_end = name_start + 255
            else:
                name_end = min(name_start + 255, len(dir_data))

            if name_start < len(dir_data):
                name_bytes = dir_data[name_start:name_end]
                # Name is null-terminated
                null_pos = name_bytes.find(b'\x00')
                if null_pos >= 0:
                    name_bytes = name_bytes[:null_pos]
                name = name_bytes.decode('utf-8', errors='replace').strip('\x00')

                if name and name not in ('.', '..'):
                    entries.append(DirEntry(name=name, nid=nid, file_type=file_type))

            offset += 12

        return entries

    def _resolve_path(self, path: str) -> int | None:
        """Resolve a filesystem path to a NID."""
        parts = [p for p in path.strip('/').split('/') if p]
        current_nid = self._sb.root_nid

        for part in parts:
            inode = self._read_inode(current_nid)
            if inode is None or not (inode.mode & S_IFDIR):
                return None

            entries = self._read_directory(inode)
            found = False
            for entry in entries:
                if entry.name == part:
                    current_nid = entry.nid
                    found = True
                    break

            if not found:
                return None

        return current_nid

    def list_directory(self, path: str) -> list[DirEntry]:
        """List entries in a directory at the given path."""
        if not self._valid:
            return []

        nid = self._resolve_path(path)
        if nid is None:
            return []

        inode = self._read_inode(nid)
        if inode is None or not (inode.mode & S_IFDIR):
            return []

        return self._read_directory(inode)

    def read_file(self, path: str, max_size: int = 16 * 1024 * 1024) -> bytes | None:
        """Read file content at the given path."""
        if not self._valid:
            return None

        nid = self._resolve_path(path)
        if nid is None:
            return None

        inode = self._read_inode(nid)
        if inode is None or (inode.mode & S_IFDIR):
            return None

        return self._read_file_data(inode, max_size)

    def file_size(self, path: str) -> int:
        """Get file size without reading content."""
        if not self._valid:
            return 0
        nid = self._resolve_path(path)
        if nid is None:
            return 0
        inode = self._read_inode(nid)
        return inode.size if inode else 0

    def walk(self, root: str = "/", max_depth: int = 10) -> Iterator[tuple[str, list[str], list[str]]]:
        """Walk the filesystem tree (like os.walk)."""
        if not self._valid:
            return
        yield from self._walk_recursive(root, 0, max_depth)

    def _walk_recursive(self, path: str, depth: int, max_depth: int) -> Iterator[tuple[str, list[str], list[str]]]:
        if depth > max_depth:
            return

        entries = self.list_directory(path)
        dirs: list[str] = []
        files: list[str] = []

        for entry in entries:
            if entry.is_dir:
                dirs.append(entry.name)
            else:
                files.append(entry.name)

        yield (path, dirs, files)

        for d in dirs:
            child_path = f"{path.rstrip('/')}/{d}"
            yield from self._walk_recursive(child_path, depth + 1, max_depth)

    def exists(self, path: str) -> bool:
        """Check if a path exists in the filesystem."""
        if not self._valid:
            return False
        return self._resolve_path(path) is not None
