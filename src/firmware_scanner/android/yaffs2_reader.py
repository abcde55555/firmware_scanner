"""YAFFS2 raw dump filesystem reader.

Parses YAFFS2 raw image dumps (without OOB/spare data) where each 4KB page is
either an object header or a file data chunk. Object headers have a specific
structure: 4-byte type, 4-byte parent_id, 2-byte 0xFFFF marker, then the name.

File data pages are stored contiguously after the object header page.
"""

import struct
from dataclasses import dataclass, field


# YAFFS2 object types
YAFFS_OBJECT_TYPE_UNKNOWN = 0
YAFFS_OBJECT_TYPE_FILE = 1
YAFFS_OBJECT_TYPE_SYMLINK = 2
YAFFS_OBJECT_TYPE_DIRECTORY = 3
YAFFS_OBJECT_TYPE_HARDLINK = 4
YAFFS_OBJECT_TYPE_SPECIAL = 5

YAFFS_HEADER_MARKER = 0xFFFF
PAGE_SIZE = 4096


@dataclass
class Yaffs2Entry:
    obj_type: int
    name: str
    offset: int  # offset of the header page in the image
    parent_offset: int = 0  # offset of parent directory header
    data_offset: int = 0  # offset of first data page
    data_size: int = 0  # total file data size (computed from contiguous pages)
    is_dir: bool = False
    is_file: bool = False


@dataclass
class DirEntry:
    name: str
    is_dir: bool
    is_file: bool


class Yaffs2Reader:
    """Read-only access to YAFFS2 raw dump images (without OOB data).

    Supports the common dump format where:
    - Each page is exactly 4096 bytes
    - Object headers contain: type(4) + parent_id(4) + marker(2) + name(variable)
    - File data pages follow the header contiguously until the next header
    """

    def __init__(self, data: bytes, page_size: int = PAGE_SIZE):
        self._data = data
        self._page_size = page_size
        self._entries: list[Yaffs2Entry] = []
        self._dir_tree: dict[str, list[Yaffs2Entry]] = {}
        self._path_map: dict[str, Yaffs2Entry] = {}
        self._valid = False
        self._parse()

    def is_valid(self) -> bool:
        return self._valid

    def exists(self, path: str) -> bool:
        path = self._normalize_path(path)
        return path in self._path_map

    def list_directory(self, path: str) -> list[DirEntry]:
        path = self._normalize_path(path)
        if path not in self._dir_tree:
            return []
        return [
            DirEntry(name=e.name, is_dir=e.is_dir, is_file=e.is_file)
            for e in self._dir_tree[path]
        ]

    def read_file(self, path: str, max_size: int = 32 * 1024 * 1024) -> bytes | None:
        path = self._normalize_path(path)
        entry = self._path_map.get(path)
        if not entry or not entry.is_file:
            return None
        if entry.data_size == 0:
            return None
        read_size = min(entry.data_size, max_size)
        # Read data pages, skipping any interleaved YAFFS2 headers
        return self._read_data_pages(entry.data_offset, read_size)

    def file_size(self, path: str) -> int:
        path = self._normalize_path(path)
        entry = self._path_map.get(path)
        if not entry or not entry.is_file:
            return 0
        return entry.data_size

    def walk(self, root: str = "/", max_depth: int = 10):
        """Yield (dirpath, dirnames, filenames) similar to os.walk."""
        root = self._normalize_path(root)
        yield from self._walk_recursive(root, 0, max_depth)

    def get_all_files(self) -> list[tuple[str, Yaffs2Entry]]:
        """Return all file entries with their full paths."""
        return [(path, entry) for path, entry in self._path_map.items() if entry.is_file]

    def _read_data_pages(self, start_offset: int, region_size: int) -> bytes:
        """Read file data from a region, skipping any interleaved YAFFS2 headers."""
        data = self._data
        page_size = self._page_size
        end_offset = start_offset + region_size
        chunks: list[bytes] = []

        offset = start_offset
        while offset < end_offset:
            if self._is_header_page(data, offset):
                offset += page_size
                continue
            chunk_end = min(offset + page_size, end_offset)
            chunks.append(data[offset:chunk_end])
            offset += page_size

        return b''.join(chunks)

    def _walk_recursive(self, dirpath: str, depth: int, max_depth: int):
        if depth > max_depth:
            return
        children = self._dir_tree.get(dirpath, [])
        dirs = [e.name for e in children if e.is_dir]
        files = [e.name for e in children if e.is_file]
        yield dirpath, dirs, files
        for d in dirs:
            child_path = f"{dirpath.rstrip('/')}/{d}"
            yield from self._walk_recursive(child_path, depth + 1, max_depth)

    def _normalize_path(self, path: str) -> str:
        path = path.replace("\\", "/")
        if not path.startswith("/"):
            path = "/" + path
        while "//" in path:
            path = path.replace("//", "/")
        if path != "/" and path.endswith("/"):
            path = path[:-1]
        return path

    def _parse(self):
        """Parse the YAFFS2 image by scanning pages for object headers."""
        data = self._data
        page_size = self._page_size

        if len(data) < page_size * 2:
            return

        # Phase 1: Find all object headers with parent_id
        headers: list[tuple[int, int, int, str]] = []  # (offset, type, parent_id, name)
        for offset in range(0, len(data) - 10, page_size):
            if not self._is_header_page(data, offset):
                continue
            entry_type = struct.unpack_from('<I', data, offset)[0]
            parent_id = struct.unpack_from('<I', data, offset + 4)[0]
            name_end = data.find(b'\x00', offset + 10, offset + 266)
            if name_end <= offset + 10:
                name = ""
            else:
                try:
                    name = data[offset + 10:name_end].decode('ascii', errors='replace')
                except Exception:
                    name = ""
            headers.append((offset, entry_type, parent_id, name))

        if len(headers) < 3:
            return

        # Validate: first entry should be the root directory with parent_id=1
        if headers[0][1] != YAFFS_OBJECT_TYPE_DIRECTORY:
            return

        self._valid = True

        # Phase 2: Build object ID -> entry mapping
        # YAFFS2 object IDs: root = 1, subsequent objects get IDs starting at 257
        id_to_entry: dict[int, Yaffs2Entry] = {}

        for idx, (offset, entry_type, parent_id, name) in enumerate(headers):
            obj_id = 1 if idx == 0 else 256 + idx

            entry = Yaffs2Entry(
                obj_type=entry_type,
                name=name,
                offset=offset,
                parent_offset=0,
                is_dir=(entry_type == YAFFS_OBJECT_TYPE_DIRECTORY),
                is_file=(entry_type == YAFFS_OBJECT_TYPE_FILE),
            )

            if entry.is_file:
                data_start = offset + page_size
                # Find end: next header or end of image
                if idx + 1 < len(headers):
                    data_end = headers[idx + 1][0]
                else:
                    data_end = len(data)
                entry.data_offset = data_start
                entry.data_size = data_end - data_start

            id_to_entry[obj_id] = entry
            self._entries.append(entry)

        # Phase 3: Build directory tree using parent IDs
        # Map each object ID to its parent's path
        id_to_path: dict[int, str] = {1: "/"}
        self._dir_tree["/"] = []
        self._path_map["/"] = id_to_entry[1]

        # First pass: resolve all directory paths (BFS-like, iterate until stable)
        # Since parent dirs always appear before children in YAFFS2 dumps
        for idx, (offset, entry_type, parent_id, name) in enumerate(headers):
            obj_id = 1 if idx == 0 else 256 + idx
            if obj_id == 1:
                continue

            entry = id_to_entry[obj_id]
            parent_path = id_to_path.get(parent_id, "/")
            entry_path = f"{parent_path.rstrip('/')}/{name}"

            id_to_path[obj_id] = entry_path
            self._path_map[entry_path] = entry

            if entry.is_dir:
                self._dir_tree[entry_path] = []

            self._dir_tree.setdefault(parent_path, []).append(entry)

    def _is_header_page(self, data: bytes, offset: int) -> bool:
        """Check if a page at the given offset is a YAFFS2 object header."""
        if offset + 10 > len(data):
            return False
        entry_type = struct.unpack_from('<I', data, offset)[0]
        if entry_type not in (YAFFS_OBJECT_TYPE_FILE, YAFFS_OBJECT_TYPE_SYMLINK,
                              YAFFS_OBJECT_TYPE_DIRECTORY, YAFFS_OBJECT_TYPE_HARDLINK,
                              YAFFS_OBJECT_TYPE_SPECIAL):
            return False
        marker = struct.unpack_from('<H', data, offset + 8)[0]
        if marker != YAFFS_HEADER_MARKER:
            return False
        # Validate: name should be printable ASCII or empty
        name_byte = data[offset + 10]
        if name_byte == 0:
            return True  # Root directory has empty name
        return 32 <= name_byte < 127

def is_yaffs2_image(data: bytes) -> bool:
    """Quick check if data looks like a YAFFS2 raw dump."""
    if len(data) < PAGE_SIZE * 3:
        return False

    # First page should be root directory header
    entry_type = struct.unpack_from('<I', data, 0)[0]
    if entry_type != YAFFS_OBJECT_TYPE_DIRECTORY:
        return False
    marker = struct.unpack_from('<H', data, 8)[0]
    if marker != YAFFS_HEADER_MARKER:
        return False

    # Second page should also be a valid entry
    entry_type2 = struct.unpack_from('<I', data, PAGE_SIZE)[0]
    marker2 = struct.unpack_from('<H', data, PAGE_SIZE + 8)[0]
    if marker2 != YAFFS_HEADER_MARKER:
        return False
    if entry_type2 not in (1, 2, 3, 4, 5):
        return False

    return True
