"""Binary data utilities."""

import hashlib
import math
from collections import Counter


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def find_strings(data: bytes, min_length: int = 4) -> list[tuple[int, str]]:
    """Extract printable ASCII strings with their offsets."""
    results = []
    current = []
    start_offset = 0

    for i, byte in enumerate(data):
        if 0x20 <= byte <= 0x7E:
            if not current:
                start_offset = i
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                results.append((start_offset, "".join(current)))
            current = []

    if len(current) >= min_length:
        results.append((start_offset, "".join(current)))

    return results


def read_u32_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def read_u32_be(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big")


def read_u16_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def read_u16_be(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")
