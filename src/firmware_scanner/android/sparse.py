"""Pure-Python Android sparse image parser.

Converts Android sparse images (magic 0xED26FF3A) to raw without external tools.
Supports streaming to avoid materializing multi-GB images in memory.
"""

import struct
from dataclasses import dataclass
from typing import Iterator


SPARSE_MAGIC = 0xED26FF3A
CHUNK_TYPE_RAW = 0xCAC1
CHUNK_TYPE_FILL = 0xCAC2
CHUNK_TYPE_DONT_CARE = 0xCAC3
CHUNK_TYPE_CRC32 = 0xCAC4

SPARSE_HEADER_SIZE = 28
CHUNK_HEADER_SIZE = 12


@dataclass
class SparseHeader:
    magic: int
    major_version: int
    minor_version: int
    file_hdr_size: int
    chunk_hdr_size: int
    block_size: int
    total_blocks: int
    total_chunks: int
    image_checksum: int


@dataclass
class ChunkInfo:
    chunk_type: int
    chunk_blocks: int
    total_bytes: int
    data_offset: int


class SparseImageParser:
    """Parse Android sparse image format and convert to raw."""

    @staticmethod
    def is_sparse(data: bytes) -> bool:
        if len(data) < 4:
            return False
        return struct.unpack_from('<I', data, 0)[0] == SPARSE_MAGIC

    def parse_header(self, data: bytes) -> SparseHeader | None:
        if len(data) < SPARSE_HEADER_SIZE:
            return None
        fields = struct.unpack_from('<IHHHHIIIi', data, 0)
        if fields[0] != SPARSE_MAGIC:
            return None
        return SparseHeader(
            magic=fields[0],
            major_version=fields[1],
            minor_version=fields[2],
            file_hdr_size=fields[3],
            chunk_hdr_size=fields[4],
            block_size=fields[5],
            total_blocks=fields[6],
            total_chunks=fields[7],
            image_checksum=fields[8],
        )

    def get_raw_size(self, data: bytes) -> int:
        header = self.parse_header(data)
        if not header:
            return 0
        return header.total_blocks * header.block_size

    def to_raw_streaming(self, data: bytes) -> Iterator[tuple[int, bytes]]:
        """Yield (output_offset, chunk_data) pairs for streaming conversion.

        Does not allocate the full raw image. Callers can seek to specific
        offsets or write sequentially.
        """
        header = self.parse_header(data)
        if not header:
            return

        offset = header.file_hdr_size
        output_offset = 0

        for _ in range(header.total_chunks):
            if offset + header.chunk_hdr_size > len(data):
                break

            chunk_type, _, chunk_blocks, total_bytes = struct.unpack_from(
                '<HHIi', data, offset
            )
            data_start = offset + header.chunk_hdr_size
            chunk_raw_size = chunk_blocks * header.block_size

            if chunk_type == CHUNK_TYPE_RAW:
                raw_data = data[data_start:data_start + chunk_raw_size]
                yield (output_offset, raw_data)

            elif chunk_type == CHUNK_TYPE_FILL:
                fill_value = data[data_start:data_start + 4]
                fill_data = fill_value * (chunk_raw_size // 4)
                yield (output_offset, fill_data)

            elif chunk_type == CHUNK_TYPE_DONT_CARE:
                yield (output_offset, b'\x00' * chunk_raw_size)

            elif chunk_type == CHUNK_TYPE_CRC32:
                pass

            output_offset += chunk_raw_size
            offset += header.chunk_hdr_size + (total_bytes - header.chunk_hdr_size)

    def to_raw(self, data: bytes, max_output_size: int = 4 * 1024 * 1024 * 1024) -> bytes | None:
        """Convert sparse image to raw bytes.

        Returns None if output would exceed max_output_size.
        For large images, prefer to_raw_streaming().
        """
        raw_size = self.get_raw_size(data)
        if raw_size == 0 or raw_size > max_output_size:
            return None

        output = bytearray(raw_size)
        for offset, chunk_data in self.to_raw_streaming(data):
            end = offset + len(chunk_data)
            if end > raw_size:
                chunk_data = chunk_data[:raw_size - offset]
                end = raw_size
            output[offset:end] = chunk_data

        return bytes(output)

    def extract_region(self, data: bytes, target_offset: int, size: int) -> bytes:
        """Extract a specific byte range from sparse image without full conversion."""
        result = bytearray(size)
        target_end = target_offset + size

        for chunk_offset, chunk_data in self.to_raw_streaming(data):
            chunk_end = chunk_offset + len(chunk_data)
            if chunk_end <= target_offset:
                continue
            if chunk_offset >= target_end:
                break

            src_start = max(0, target_offset - chunk_offset)
            src_end = min(len(chunk_data), target_end - chunk_offset)
            dst_start = max(0, chunk_offset - target_offset)

            result[dst_start:dst_start + (src_end - src_start)] = chunk_data[src_start:src_end]

        return bytes(result)
