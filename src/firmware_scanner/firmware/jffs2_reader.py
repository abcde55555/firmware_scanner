"""Pure-Python JFFS2 (Journalling Flash File System v2) reader.

Scans JFFS2 nodes, resolves directory trees, and reassembles compressed file
chunks into complete files without requiring external kernel modules or mtdblock.
"""

import struct
import zlib
from dataclasses import dataclass, field
from typing import Optional

JFFS2_MAGIC_BITMASK = 0x1985

JFFS2_NODETYPE_DIRENT = 0xE001
JFFS2_NODETYPE_INODE = 0xE002
JFFS2_NODETYPE_CLEANMARKER = 0x2003

JFFS2_COMPR_NONE = 0x00
JFFS2_COMPR_ZERO = 0x01
JFFS2_COMPR_RTIME = 0x02
JFFS2_COMPR_RUBINMIPS = 0x03
JFFS2_COMPR_COPY = 0x04
JFFS2_COMPR_DYNRUBIN = 0x05
JFFS2_COMPR_ZLIB = 0x06
JFFS2_COMPR_LZO = 0x07


def _decompress_rtime(data: bytes, dest_len: int) -> bytes:
    """RTIME decompression algorithm used by JFFS2."""
    out = bytearray()
    pos = 0
    positions = [0] * 256
    while pos < len(data) and len(out) < dest_len:
        val = data[pos]
        pos += 1
        repeat = val
        if repeat == 0:
            if pos >= len(data):
                break
            val = data[pos]
            pos += 1
            out.append(val)
        else:
            back_pos = positions[val]
            for _ in range(repeat):
                if back_pos < len(out):
                    out.append(out[back_pos])
                    back_pos += 1
                else:
                    break
        positions[val] = len(out) - 1
    return bytes(out[:dest_len])


@dataclass
class JFFS2FileChunk:
    offset: int
    dsize: int
    csize: int
    comptype: int
    data: bytes
    version: int


@dataclass
class JFFS2File:
    ino: int
    name: str
    path: str
    pino: int
    is_dir: bool = False
    is_file: bool = False
    is_symlink: bool = False
    total_size: int = 0
    chunks: list[JFFS2FileChunk] = field(default_factory=list)


class JFFS2Reader:
    """Scans and extracts files from a JFFS2 flash image."""

    def __init__(self, data: bytes):
        self.data = data
        self.endian = "<"
        self._valid = False
        self.files: dict[int, JFFS2File] = {}
        self.root_ino = 1

        self._detect_and_scan()

    def is_valid(self) -> bool:
        return self._valid

    def _detect_and_scan(self) -> None:
        if len(self.data) < 16:
            return

        # Check endianness
        if self.data[:2] == b"\x85\x19":
            self.endian = "<"
            self._valid = True
        elif self.data[:2] == b"\x19\x85":
            self.endian = ">"
            self._valid = True
        else:
            # Scan first 64KB for magic
            for i in range(0, min(len(self.data) - 4, 65536), 4):
                if self.data[i : i + 2] == b"\x85\x19":
                    self.endian = "<"
                    self._valid = True
                    break
                elif self.data[i : i + 2] == b"\x19\x85":
                    self.endian = ">"
                    self._valid = True
                    break

        if not self._valid:
            return

        self._scan_nodes()
        self._resolve_paths()

    def _scan_nodes(self) -> None:
        pos = 0
        data_len = len(self.data)
        magic_bytes = b"\x85\x19" if self.endian == "<" else b"\x19\x85"

        dirents: list[dict] = []

        while pos + 12 < data_len:
            if self.data[pos : pos + 2] != magic_bytes:
                # Seek to next 4-byte boundary matching magic
                next_pos = self.data.find(magic_bytes, pos + 1)
                if next_pos < 0 or next_pos + 12 >= data_len:
                    break
                pos = next_pos

            magic, nodetype, totlen = struct.unpack_from(f"{self.endian}HHI", self.data, pos)
            if totlen < 12 or pos + totlen > data_len:
                pos += 4
                continue

            if nodetype == JFFS2_NODETYPE_DIRENT and totlen >= 40:
                pino, version, ino, mctime = struct.unpack_from(f"{self.endian}IIII", self.data, pos + 12)
                nsize, ftype = struct.unpack_from("BB", self.data, pos + 28)
                if pos + 38 + nsize <= data_len:
                    name_bytes = self.data[pos + 38 : pos + 38 + nsize]
                    name = name_bytes.decode("utf-8", errors="ignore")
                    dirents.append({
                        "pino": pino,
                        "ino": ino,
                        "name": name,
                        "type": ftype,
                        "version": version,
                    })

            elif nodetype == JFFS2_NODETYPE_INODE and totlen >= 68:
                ino, version, mode = struct.unpack_from(f"{self.endian}III", self.data, pos + 12)
                isize = struct.unpack_from(f"{self.endian}I", self.data, pos + 24)[0]
                offset, csize, dsize = struct.unpack_from(f"{self.endian}III", self.data, pos + 40)
                comptype = self.data[pos + 52]

                chunk_payload = self.data[pos + 68 : pos + 68 + csize]
                if ino not in self.files:
                    self.files[ino] = JFFS2File(
                        ino=ino,
                        name=f"ino_{ino}",
                        path="",
                        pino=1,
                        is_file=True,
                        total_size=isize,
                    )

                f_obj = self.files[ino]
                if isize > f_obj.total_size:
                    f_obj.total_size = isize

                f_obj.chunks.append(JFFS2FileChunk(
                    offset=offset,
                    dsize=dsize,
                    csize=csize,
                    comptype=comptype,
                    data=chunk_payload,
                    version=version,
                ))

            # Pad to 4-byte boundary
            pos += (totlen + 3) & ~3

        # Apply latest dirents to name files
        # Sort by version so later dirent updates win
        dirents.sort(key=lambda d: d["version"])
        for d in dirents:
            ino = d["ino"]
            if ino in self.files:
                self.files[ino].name = d["name"]
                self.files[ino].pino = d["pino"]
                if d["type"] == 4:
                    self.files[ino].is_dir = True
                    self.files[ino].is_file = False
                elif d["type"] == 1:
                    self.files[ino].is_file = True

    def _resolve_paths(self) -> None:
        """Construct full filesystem paths using parent inode relationships."""
        name_map = {ino: f.name for ino, f in self.files.items()}
        pino_map = {ino: f.pino for ino, f in self.files.items()}

        for ino, f in self.files.items():
            parts = [f.name]
            curr_pino = f.pino
            visited = {ino}
            while curr_pino > 1 and curr_pino in name_map and curr_pino not in visited:
                visited.add(curr_pino)
                parts.append(name_map[curr_pino])
                curr_pino = pino_map.get(curr_pino, 1)

            f.path = "/" + "/".join(reversed(parts))

    def list_files(self) -> list[JFFS2File]:
        """Return all regular files."""
        return [f for f in self.files.values() if f.is_file and f.total_size > 0]

    def read_file(self, file_obj: JFFS2File, max_size: int = 16 * 1024 * 1024) -> bytes:
        """Assemble and decompress all file chunks."""
        if not file_obj.chunks:
            return b""

        # Sort chunks by file offset, and then by version (latest version wins)
        chunks = sorted(file_obj.chunks, key=lambda c: (c.offset, c.version))
        buf = bytearray(file_obj.total_size)

        for chunk in chunks:
            decompressed: Optional[bytes] = None
            if chunk.comptype == JFFS2_COMPR_NONE:
                decompressed = chunk.data[: chunk.dsize]
            elif chunk.comptype == JFFS2_COMPR_ZERO:
                decompressed = b"\x00" * chunk.dsize
            elif chunk.comptype == JFFS2_COMPR_ZLIB:
                try:
                    decompressed = zlib.decompress(chunk.data)
                except Exception:
                    decompressed = chunk.data[: chunk.dsize]
            elif chunk.comptype == JFFS2_COMPR_RTIME:
                decompressed = _decompress_rtime(chunk.data, chunk.dsize)
            else:
                decompressed = chunk.data[: chunk.dsize]

            if decompressed:
                end_off = min(chunk.offset + len(decompressed), len(buf))
                copy_len = end_off - chunk.offset
                if copy_len > 0:
                    buf[chunk.offset : end_off] = decompressed[:copy_len]

        return bytes(buf[:max_size])
