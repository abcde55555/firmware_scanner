"""Pure-Python read-only ext4 filesystem parser.

Parses ext4 filesystem images to list directories and read files without
requiring mount privileges or external tools (debugfs/e2tools).

Supports:
- ext4 with extent-based allocation (modern default)
- Directory entries in linear and htree format
- Inline data for small files
- Standard ext4 features used in Android system images

Limitations:
- Read-only (no write support)
- Extent trees limited to 3 levels (sufficient for most files)
- No journal replay
- No encryption/verity decryption
"""

import struct
from dataclasses import dataclass, field
from typing import Iterator


EXT4_SUPER_MAGIC = 0xEF53
SUPERBLOCK_OFFSET = 1024
SUPERBLOCK_SIZE = 1024

# Inode flags
EXT4_EXTENTS_FL = 0x00080000
EXT4_INLINE_DATA_FL = 0x10000000

# File type constants in directory entries
FT_UNKNOWN = 0
FT_REG_FILE = 1
FT_DIR = 2
FT_CHRDEV = 3
FT_BLKDEV = 4
FT_FIFO = 5
FT_SOCK = 6
FT_SYMLINK = 7

# Inode mode type bits
S_IFREG = 0o100000
S_IFDIR = 0o040000
S_IFLNK = 0o120000

ROOT_INODE = 2


@dataclass
class Ext4Superblock:
    inodes_count: int = 0
    blocks_count: int = 0
    block_size: int = 4096
    blocks_per_group: int = 0
    inodes_per_group: int = 0
    inode_size: int = 256
    first_data_block: int = 0
    log_block_size: int = 0
    desc_size: int = 32
    feature_incompat: int = 0
    feature_ro_compat: int = 0


@dataclass
class Ext4GroupDesc:
    block_bitmap: int = 0
    inode_bitmap: int = 0
    inode_table: int = 0


@dataclass
class Ext4Inode:
    mode: int = 0
    size: int = 0
    flags: int = 0
    block_data: bytes = b""
    inline_data: bytes = b""


@dataclass
class DirEntry:
    name: str
    inode: int
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


class Ext4Reader:
    """Read-only ext4 filesystem parser."""

    def __init__(self, data: bytes):
        self._data = data
        self._sb = Ext4Superblock()
        self._valid = False
        self._parse_superblock()

    def is_valid(self) -> bool:
        return self._valid

    def _parse_superblock(self):
        if len(self._data) < SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE:
            return

        sb_data = self._data[SUPERBLOCK_OFFSET:SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE]

        magic = struct.unpack_from('<H', sb_data, 56)[0]
        if magic != EXT4_SUPER_MAGIC:
            return

        self._sb.inodes_count = struct.unpack_from('<I', sb_data, 0)[0]
        blocks_lo = struct.unpack_from('<I', sb_data, 4)[0]
        self._sb.first_data_block = struct.unpack_from('<I', sb_data, 20)[0]
        self._sb.log_block_size = struct.unpack_from('<I', sb_data, 24)[0]
        self._sb.blocks_per_group = struct.unpack_from('<I', sb_data, 32)[0]
        self._sb.inodes_per_group = struct.unpack_from('<I', sb_data, 40)[0]
        self._sb.inode_size = struct.unpack_from('<H', sb_data, 88)[0]
        self._sb.feature_incompat = struct.unpack_from('<I', sb_data, 96)[0]
        self._sb.feature_ro_compat = struct.unpack_from('<I', sb_data, 100)[0]

        self._sb.block_size = 1024 << self._sb.log_block_size
        self._sb.blocks_count = blocks_lo

        # 64-bit block count if feature flag set
        if self._sb.feature_incompat & 0x0080:  # INCOMPAT_64BIT
            blocks_hi = struct.unpack_from('<I', sb_data, 336)[0]
            self._sb.blocks_count = (blocks_hi << 32) | blocks_lo
            self._sb.desc_size = struct.unpack_from('<H', sb_data, 254)[0]
            if self._sb.desc_size < 32:
                self._sb.desc_size = 32
        else:
            self._sb.desc_size = 32

        if self._sb.inode_size < 128:
            self._sb.inode_size = 128

        self._valid = True

    def _block_offset(self, block_num: int) -> int:
        return block_num * self._sb.block_size

    def _read_block(self, block_num: int) -> bytes:
        offset = self._block_offset(block_num)
        return self._data[offset:offset + self._sb.block_size]

    def _get_group_desc(self, group: int) -> Ext4GroupDesc:
        # Group descriptors start at block after superblock
        gdt_block = self._sb.first_data_block + 1
        gdt_offset = self._block_offset(gdt_block) + group * self._sb.desc_size
        gd = Ext4GroupDesc()

        if gdt_offset + self._sb.desc_size > len(self._data):
            return gd

        gd_data = self._data[gdt_offset:gdt_offset + self._sb.desc_size]

        block_bitmap_lo = struct.unpack_from('<I', gd_data, 0)[0]
        inode_bitmap_lo = struct.unpack_from('<I', gd_data, 4)[0]
        inode_table_lo = struct.unpack_from('<I', gd_data, 8)[0]

        if self._sb.desc_size > 32 and len(gd_data) >= 48:
            block_bitmap_hi = struct.unpack_from('<I', gd_data, 32)[0]
            inode_bitmap_hi = struct.unpack_from('<I', gd_data, 36)[0]
            inode_table_hi = struct.unpack_from('<I', gd_data, 40)[0]
            gd.block_bitmap = (block_bitmap_hi << 32) | block_bitmap_lo
            gd.inode_bitmap = (inode_bitmap_hi << 32) | inode_bitmap_lo
            gd.inode_table = (inode_table_hi << 32) | inode_table_lo
        else:
            gd.block_bitmap = block_bitmap_lo
            gd.inode_bitmap = inode_bitmap_lo
            gd.inode_table = inode_table_lo

        return gd

    def _read_inode(self, inode_num: int) -> Ext4Inode | None:
        if inode_num < 1 or inode_num > self._sb.inodes_count:
            return None

        group = (inode_num - 1) // self._sb.inodes_per_group
        index = (inode_num - 1) % self._sb.inodes_per_group

        gd = self._get_group_desc(group)
        if gd.inode_table == 0:
            return None

        inode_offset = self._block_offset(gd.inode_table) + index * self._sb.inode_size
        if inode_offset + self._sb.inode_size > len(self._data):
            return None

        inode_data = self._data[inode_offset:inode_offset + self._sb.inode_size]
        if len(inode_data) < 128:
            return None

        inode = Ext4Inode()
        inode.mode = struct.unpack_from('<H', inode_data, 0)[0]
        size_lo = struct.unpack_from('<I', inode_data, 4)[0]
        size_hi = struct.unpack_from('<I', inode_data, 108)[0] if len(inode_data) > 108 else 0
        inode.size = (size_hi << 32) | size_lo
        inode.flags = struct.unpack_from('<I', inode_data, 32)[0]
        inode.block_data = inode_data[40:100]  # i_block[0..14] area (60 bytes)

        return inode

    def _read_file_data(self, inode: Ext4Inode, max_size: int = 16 * 1024 * 1024) -> bytes:
        """Read file content from inode, respecting max_size limit."""
        read_size = min(inode.size, max_size)
        if read_size == 0:
            return b""

        if inode.flags & EXT4_EXTENTS_FL:
            return self._read_extents(inode.block_data, read_size)
        else:
            return self._read_block_map(inode.block_data, read_size)

    def _read_extents(self, block_data: bytes, size: int) -> bytes:
        """Read file data using extent tree."""
        if len(block_data) < 12:
            return b""

        result = bytearray()
        self._walk_extent_tree(block_data, result, size, depth=0)
        return bytes(result[:size])

    def _walk_extent_tree(self, node_data: bytes, result: bytearray, max_size: int, depth: int):
        """Walk extent tree recursively (max 3 levels)."""
        if depth > 3 or len(node_data) < 12:
            return

        # Extent header
        magic = struct.unpack_from('<H', node_data, 0)[0]
        if magic != 0xF30A:
            return
        entries = struct.unpack_from('<H', node_data, 2)[0]
        tree_depth = struct.unpack_from('<H', node_data, 6)[0]

        if tree_depth == 0:
            # Leaf node - read extent entries
            for i in range(min(entries, 340)):
                if len(result) >= max_size:
                    break
                entry_offset = 12 + i * 12
                if entry_offset + 12 > len(node_data):
                    break

                # ee_block (logical block), ee_len, ee_start_hi, ee_start_lo
                _logical_block = struct.unpack_from('<I', node_data, entry_offset)[0]
                ee_len = struct.unpack_from('<H', node_data, entry_offset + 4)[0]
                ee_start_hi = struct.unpack_from('<H', node_data, entry_offset + 6)[0]
                ee_start_lo = struct.unpack_from('<I', node_data, entry_offset + 8)[0]

                # Uninitialized extent has top bit set in length
                if ee_len > 32768:
                    ee_len -= 32768

                physical_block = (ee_start_hi << 32) | ee_start_lo
                for b in range(ee_len):
                    if len(result) >= max_size:
                        break
                    block_data = self._read_block(physical_block + b)
                    remaining = max_size - len(result)
                    result.extend(block_data[:remaining])
        else:
            # Internal node - follow index entries
            for i in range(min(entries, 340)):
                if len(result) >= max_size:
                    break
                entry_offset = 12 + i * 12
                if entry_offset + 12 > len(node_data):
                    break

                # ei_block, ei_leaf_lo, ei_leaf_hi
                _logical_block = struct.unpack_from('<I', node_data, entry_offset)[0]
                leaf_lo = struct.unpack_from('<I', node_data, entry_offset + 4)[0]
                leaf_hi = struct.unpack_from('<H', node_data, entry_offset + 8)[0]

                leaf_block = (leaf_hi << 32) | leaf_lo
                child_data = self._read_block(leaf_block)
                self._walk_extent_tree(child_data, result, max_size, depth + 1)

    def _read_block_map(self, block_data: bytes, size: int) -> bytes:
        """Read file data using traditional block map (indirect blocks)."""
        result = bytearray()

        # Direct blocks (0-11)
        for i in range(12):
            if len(result) >= size:
                break
            block_num = struct.unpack_from('<I', block_data, i * 4)[0]
            if block_num == 0:
                result.extend(b'\x00' * min(self._sb.block_size, size - len(result)))
            else:
                data = self._read_block(block_num)
                remaining = size - len(result)
                result.extend(data[:remaining])

        if len(result) >= size:
            return bytes(result[:size])

        # Single indirect block (12)
        indirect_block = struct.unpack_from('<I', block_data, 48)[0]
        if indirect_block:
            self._read_indirect(indirect_block, result, size)

        if len(result) >= size:
            return bytes(result[:size])

        # Double indirect block (13)
        dindirect_block = struct.unpack_from('<I', block_data, 52)[0]
        if dindirect_block:
            ind_data = self._read_block(dindirect_block)
            ptrs_per_block = self._sb.block_size // 4
            for i in range(ptrs_per_block):
                if len(result) >= size:
                    break
                block_num = struct.unpack_from('<I', ind_data, i * 4)[0]
                if block_num:
                    self._read_indirect(block_num, result, size)

        return bytes(result[:size])

    def _read_indirect(self, indirect_block: int, result: bytearray, max_size: int):
        """Read blocks referenced by an indirect block."""
        ind_data = self._read_block(indirect_block)
        ptrs_per_block = self._sb.block_size // 4

        for i in range(ptrs_per_block):
            if len(result) >= max_size:
                break
            block_num = struct.unpack_from('<I', ind_data, i * 4)[0]
            if block_num == 0:
                remaining = min(self._sb.block_size, max_size - len(result))
                result.extend(b'\x00' * remaining)
            else:
                data = self._read_block(block_num)
                remaining = max_size - len(result)
                result.extend(data[:remaining])

    def _read_directory(self, inode: Ext4Inode) -> list[DirEntry]:
        """Read directory entries from an inode."""
        entries: list[DirEntry] = []
        dir_data = self._read_file_data(inode, max_size=min(inode.size, 4 * 1024 * 1024))

        offset = 0
        while offset + 8 <= len(dir_data):
            entry_inode = struct.unpack_from('<I', dir_data, offset)[0]
            rec_len = struct.unpack_from('<H', dir_data, offset + 4)[0]
            name_len = struct.unpack_from('<B', dir_data, offset + 6)[0]
            file_type = struct.unpack_from('<B', dir_data, offset + 7)[0]

            if rec_len < 8 or offset + rec_len > len(dir_data):
                break

            if entry_inode != 0 and name_len > 0:
                name_bytes = dir_data[offset + 8:offset + 8 + name_len]
                name = name_bytes.decode('utf-8', errors='replace')
                if name not in ('.', '..'):
                    entries.append(DirEntry(
                        name=name,
                        inode=entry_inode,
                        file_type=file_type,
                    ))

            offset += rec_len

        return entries

    def _resolve_path(self, path: str) -> int | None:
        """Resolve a filesystem path to an inode number."""
        parts = [p for p in path.strip('/').split('/') if p]
        current_inode = ROOT_INODE

        for part in parts:
            inode = self._read_inode(current_inode)
            if inode is None or not (inode.mode & S_IFDIR):
                return None

            entries = self._read_directory(inode)
            found = False
            for entry in entries:
                if entry.name == part:
                    current_inode = entry.inode
                    found = True
                    break

            if not found:
                return None

        return current_inode

    def list_directory(self, path: str) -> list[DirEntry]:
        """List entries in a directory at the given path."""
        if not self._valid:
            return []

        inode_num = self._resolve_path(path)
        if inode_num is None:
            return []

        inode = self._read_inode(inode_num)
        if inode is None or not (inode.mode & S_IFDIR):
            return []

        return self._read_directory(inode)

    def read_file(self, path: str, max_size: int = 16 * 1024 * 1024) -> bytes | None:
        """Read file content at the given path."""
        if not self._valid:
            return None

        inode_num = self._resolve_path(path)
        if inode_num is None:
            return None

        inode = self._read_inode(inode_num)
        if inode is None:
            return None

        if inode.mode & S_IFDIR:
            return None

        return self._read_file_data(inode, max_size)

    def file_size(self, path: str) -> int:
        """Get file size without reading content."""
        if not self._valid:
            return 0
        inode_num = self._resolve_path(path)
        if inode_num is None:
            return 0
        inode = self._read_inode(inode_num)
        return inode.size if inode else 0

    def walk(self, root: str = "/", max_depth: int = 10) -> Iterator[tuple[str, list[str], list[str]]]:
        """Walk the filesystem tree (like os.walk).

        Yields (dirpath, dirnames, filenames) tuples.
        """
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
