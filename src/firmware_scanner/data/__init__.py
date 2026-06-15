"""Data file loading utilities for firmware_scanner."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_DATA_DIR = Path(__file__).parent


@lru_cache(maxsize=1)
def load_component_signatures() -> list[dict]:
    """Load component signature database from JSON."""
    sig_file = _DATA_DIR / "signatures" / "components.json"
    if sig_file.exists():
        return json.loads(sig_file.read_text(encoding="utf-8"))
    return []


@lru_cache(maxsize=1)
def load_version_patterns() -> list[dict]:
    """Load version pattern database from JSON."""
    pat_file = _DATA_DIR / "signatures" / "version_patterns.json"
    if pat_file.exists():
        return json.loads(pat_file.read_text(encoding="utf-8"))
    return []


@lru_cache(maxsize=1)
def load_dex_packages() -> dict[str, tuple[str, str, str]]:
    """Load DEX package to component mapping from JSON."""
    dex_file = _DATA_DIR / "signatures" / "dex_packages.json"
    if dex_file.exists():
        raw = json.loads(dex_file.read_text(encoding="utf-8"))
        return {k: tuple(v) for k, v in raw.items()}
    return {}
