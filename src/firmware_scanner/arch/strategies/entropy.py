"""Entropy-based analysis for detecting code/data/compressed sections."""

import math
from collections import Counter


CHUNK_SIZE = 1024


def compute_section_entropy(data: bytes, chunk_size: int = CHUNK_SIZE) -> list[tuple[int, float]]:
    """Return list of (offset, entropy) for each chunk."""
    results = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        entropy = _entropy(chunk)
        results.append((i, entropy))
    return results


def find_code_regions(data: bytes, chunk_size: int = CHUNK_SIZE) -> list[tuple[int, int]]:
    """Find likely code regions based on entropy profile (5.0-7.0 range)."""
    regions: list[tuple[int, int]] = []
    in_code = False
    start = 0

    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        entropy = _entropy(chunk)

        is_code = 4.5 <= entropy <= 7.0

        if is_code and not in_code:
            start = i
            in_code = True
        elif not is_code and in_code:
            if i - start >= chunk_size * 4:
                regions.append((start, i))
            in_code = False

    if in_code and len(data) - start >= chunk_size * 4:
        regions.append((start, len(data)))

    return regions


def _entropy(data: bytes) -> float:
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
