"""Android super.img LP (Logical Partition) metadata parser.

Parses the LP metadata from Android super.img to locate embedded
partition images (system, vendor, product, etc.).

Reference: AOSP system/core/fs_mgr/liblp/
"""

import struct
from dataclasses import dataclass, field


LP_METADATA_MAGIC = 0x67446C70  # "gDlp" (little-endian: "pldG")
LP_GEOMETRY_MAGIC = 0x616C4467  # "alDg" (little-endian: "gDla")

LP_PARTITION_ATTR_READONLY = (1 << 0)
LP_PARTITION_ATTR_SLOT_SUFFIXED = (1 << 1)
LP_PARTITION_ATTR_UPDATED = (1 << 2)
LP_PARTITION_ATTR_DISABLED = (1 << 3)

PRIMARY_GEOMETRY_OFFSET = 4096


@dataclass
class LPGeometry:
    struct_size: int = 0
    metadata_max_size: int = 0
    metadata_slot_count: int = 0
    logical_block_size: int = 4096


@dataclass
class LPPartition:
    name: str = ""
    attributes: int = 0
    first_extent_index: int = 0
    num_extents: int = 0
    group_index: int = 0


@dataclass
class LPExtent:
    num_sectors: int = 0
    target_type: int = 0  # 0=linear, 1=zero
    target_data: int = 0  # physical sector for linear
    target_source: int = 0


@dataclass
class LPGroup:
    name: str = ""
    maximum_size: int = 0


@dataclass
class LPPartitionInfo:
    """Resolved partition info with absolute offset and size."""
    name: str
    offset: int
    size: int
    group_name: str = ""
    is_readonly: bool = True


class SuperImageParser:
    """Parse Android super.img LP metadata."""

    def __init__(self):
        self._geometry: LPGeometry | None = None
        self._partitions: list[LPPartition] = []
        self._extents: list[LPExtent] = []
        self._groups: list[LPGroup] = []
        self._block_size: int = 4096

    def parse(self, data: bytes) -> list[LPPartitionInfo]:
        """Parse super.img and return list of partitions with offsets and sizes."""
        from .sparse import SparseImageParser

        # Check if this is a sparse image wrapping the super partition
        sparse_parser = SparseImageParser()
        if sparse_parser.is_sparse(data):
            # Extract the geometry region (first few MB)
            raw_header = sparse_parser.extract_region(data, 0, 8 * 1024 * 1024)
            return self._parse_raw_super(raw_header, data, is_sparse=True)

        return self._parse_raw_super(data, data, is_sparse=False)

    def _parse_raw_super(self, header_data: bytes, full_data: bytes, is_sparse: bool) -> list[LPPartitionInfo]:
        """Parse LP metadata from raw (non-sparse) data."""
        # Find geometry
        geometry = self._parse_geometry(header_data)
        if not geometry:
            return []

        self._geometry = geometry
        self._block_size = geometry.logical_block_size

        # Metadata follows geometry
        metadata_offset = PRIMARY_GEOMETRY_OFFSET + 4096  # geometry is one 4K block
        if metadata_offset + geometry.metadata_max_size > len(header_data):
            # Try alternate location
            metadata_offset = PRIMARY_GEOMETRY_OFFSET + 4096 * 2
            if metadata_offset + 256 > len(header_data):
                return []

        # Parse metadata header
        result = self._parse_metadata(header_data, metadata_offset)
        if not result:
            return []

        # Resolve partitions to offsets
        return self._resolve_partitions(full_data, is_sparse)

    def _parse_geometry(self, data: bytes) -> LPGeometry | None:
        """Parse LP geometry structure."""
        offset = PRIMARY_GEOMETRY_OFFSET
        if offset + 4096 > len(data):
            return None

        magic = struct.unpack_from('<I', data, offset)[0]
        if magic != LP_GEOMETRY_MAGIC:
            # Try scanning for the magic
            for try_offset in (0x1000, 0x2000, 0x3000, 0x4000):
                if try_offset + 64 > len(data):
                    continue
                if struct.unpack_from('<I', data, try_offset)[0] == LP_GEOMETRY_MAGIC:
                    offset = try_offset
                    magic = LP_GEOMETRY_MAGIC
                    break
            if magic != LP_GEOMETRY_MAGIC:
                return None

        geo = LPGeometry()
        geo.struct_size = struct.unpack_from('<I', data, offset + 4)[0]
        # Skip SHA-256 checksum (32 bytes at offset+8)
        geo.metadata_max_size = struct.unpack_from('<I', data, offset + 40)[0]
        geo.metadata_slot_count = struct.unpack_from('<I', data, offset + 44)[0]
        geo.logical_block_size = struct.unpack_from('<I', data, offset + 48)[0]

        if geo.logical_block_size == 0:
            geo.logical_block_size = 4096
        if geo.metadata_max_size == 0:
            geo.metadata_max_size = 65536

        return geo

    def _parse_metadata(self, data: bytes, offset: int) -> bool:
        """Parse LP metadata (partition table, extents, groups)."""
        if offset + 92 > len(data):
            return False

        magic = struct.unpack_from('<I', data, offset)[0]
        if magic != LP_METADATA_MAGIC:
            # Scan forward for metadata magic
            for scan in range(0, 8192, 4):
                if offset + scan + 4 > len(data):
                    break
                if struct.unpack_from('<I', data, offset + scan)[0] == LP_METADATA_MAGIC:
                    offset += scan
                    break
            else:
                return False
            if struct.unpack_from('<I', data, offset)[0] != LP_METADATA_MAGIC:
                return False

        # Metadata header
        header_size = struct.unpack_from('<H', data, offset + 4)[0]
        # Skip SHA-256 (32 bytes)

        # Table descriptors (partitions, extents, groups, block_devices)
        # Each descriptor: offset(4) + num_entries(4) + entry_size(4)
        tables_offset = offset + 36

        # Partitions table
        part_offset = struct.unpack_from('<I', data, tables_offset)[0]
        part_count = struct.unpack_from('<I', data, tables_offset + 4)[0]
        part_entry_size = struct.unpack_from('<I', data, tables_offset + 8)[0]

        # Extents table
        ext_offset = struct.unpack_from('<I', data, tables_offset + 12)[0]
        ext_count = struct.unpack_from('<I', data, tables_offset + 16)[0]
        ext_entry_size = struct.unpack_from('<I', data, tables_offset + 20)[0]

        # Groups table
        grp_offset = struct.unpack_from('<I', data, tables_offset + 24)[0]
        grp_count = struct.unpack_from('<I', data, tables_offset + 28)[0]
        grp_entry_size = struct.unpack_from('<I', data, tables_offset + 32)[0]

        body_offset = offset + header_size

        # Parse partitions
        self._partitions = []
        for i in range(min(part_count, 64)):
            entry_start = body_offset + part_offset + i * part_entry_size
            if entry_start + 52 > len(data):
                break
            part = self._parse_partition_entry(data, entry_start, part_entry_size)
            if part:
                self._partitions.append(part)

        # Parse extents
        self._extents = []
        for i in range(min(ext_count, 256)):
            entry_start = body_offset + ext_offset + i * ext_entry_size
            if entry_start + 24 > len(data):
                break
            ext = self._parse_extent_entry(data, entry_start)
            if ext:
                self._extents.append(ext)

        # Parse groups
        self._groups = []
        for i in range(min(grp_count, 32)):
            entry_start = body_offset + grp_offset + i * grp_entry_size
            if entry_start + 48 > len(data):
                break
            grp = self._parse_group_entry(data, entry_start)
            if grp:
                self._groups.append(grp)

        return len(self._partitions) > 0

    def _parse_partition_entry(self, data: bytes, offset: int, entry_size: int) -> LPPartition | None:
        """Parse a single partition table entry."""
        if offset + 40 > len(data):
            return None

        part = LPPartition()
        # Name: 36 bytes at start
        name_bytes = data[offset:offset + 36]
        null_pos = name_bytes.find(b'\x00')
        if null_pos >= 0:
            name_bytes = name_bytes[:null_pos]
        part.name = name_bytes.decode('ascii', errors='ignore')

        part.attributes = struct.unpack_from('<I', data, offset + 36)[0]
        part.first_extent_index = struct.unpack_from('<I', data, offset + 40)[0]
        part.num_extents = struct.unpack_from('<I', data, offset + 44)[0]
        part.group_index = struct.unpack_from('<I', data, offset + 48)[0]

        return part

    def _parse_extent_entry(self, data: bytes, offset: int) -> LPExtent | None:
        """Parse a single extent entry."""
        if offset + 24 > len(data):
            return None

        ext = LPExtent()
        ext.num_sectors = struct.unpack_from('<Q', data, offset)[0]
        ext.target_type = struct.unpack_from('<I', data, offset + 8)[0]
        ext.target_data = struct.unpack_from('<Q', data, offset + 12)[0]
        ext.target_source = struct.unpack_from('<I', data, offset + 20)[0]

        return ext

    def _parse_group_entry(self, data: bytes, offset: int) -> LPGroup | None:
        """Parse a single group entry."""
        if offset + 48 > len(data):
            return None

        grp = LPGroup()
        name_bytes = data[offset:offset + 36]
        null_pos = name_bytes.find(b'\x00')
        if null_pos >= 0:
            name_bytes = name_bytes[:null_pos]
        grp.name = name_bytes.decode('ascii', errors='ignore')
        grp.maximum_size = struct.unpack_from('<Q', data, offset + 40)[0]

        return grp

    def _resolve_partitions(self, full_data: bytes, is_sparse: bool) -> list[LPPartitionInfo]:
        """Resolve partition entries to absolute offsets using extents."""
        results: list[LPPartitionInfo] = []

        for part in self._partitions:
            if not part.name or part.num_extents == 0:
                continue
            if part.attributes & LP_PARTITION_ATTR_DISABLED:
                continue

            # Calculate total size and first physical offset from extents
            total_size = 0
            first_offset = 0

            for i in range(part.num_extents):
                ext_idx = part.first_extent_index + i
                if ext_idx >= len(self._extents):
                    break

                ext = self._extents[ext_idx]
                sector_size = 512
                extent_size = ext.num_sectors * sector_size

                if ext.target_type == 0:  # linear
                    if i == 0:
                        first_offset = ext.target_data * sector_size
                    total_size += extent_size

            if total_size == 0:
                continue

            group_name = ""
            if part.group_index < len(self._groups):
                group_name = self._groups[part.group_index].name

            results.append(LPPartitionInfo(
                name=part.name,
                offset=first_offset,
                size=total_size,
                group_name=group_name,
                is_readonly=bool(part.attributes & LP_PARTITION_ATTR_READONLY),
            ))

        return results

    def extract_partition(self, data: bytes, partition: LPPartitionInfo) -> bytes:
        """Extract a partition's raw data from the super image."""
        from .sparse import SparseImageParser

        sparse_parser = SparseImageParser()
        if sparse_parser.is_sparse(data):
            return sparse_parser.extract_region(data, partition.offset, partition.size)

        end = partition.offset + partition.size
        if end > len(data):
            return data[partition.offset:]
        return data[partition.offset:end]
