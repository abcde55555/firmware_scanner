"""Local cache for OSV vulnerability query results."""

import hashlib
import json
import time
from pathlib import Path


CACHE_TTL_SECONDS = 86400  # 24 hours
MAX_CACHE_ENTRIES = 10000


def get_cache_dir() -> Path:
    cache_dir = Path.home() / ".firmware-scanner" / "vuln-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "entries").mkdir(exist_ok=True)
    return cache_dir


def cache_key(purl: str = "", name: str = "", version: str = "") -> str:
    raw = purl if purl else f"{name.lower().strip()}@{version.strip()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def is_entry_stale(entry_data: dict) -> bool:
    fetched_at = entry_data.get("fetched_at", 0)
    return (time.time() - fetched_at) > CACHE_TTL_SECONDS


def read_cached(cache_dir: Path, key: str) -> dict | None:
    entry_path = cache_dir / "entries" / f"{key}.json"
    if not entry_path.exists():
        return None
    try:
        data = json.loads(entry_path.read_text(encoding="utf-8"))
        if is_entry_stale(data):
            return None
        return data
    except (json.JSONDecodeError, OSError):
        return None


def read_cached_stale(cache_dir: Path, key: str) -> dict | None:
    """Read cached entry even if stale (fallback for offline mode)."""
    entry_path = cache_dir / "entries" / f"{key}.json"
    if not entry_path.exists():
        return None
    try:
        return json.loads(entry_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def write_cache(cache_dir: Path, key: str, vulns: list[dict], query: dict | None = None) -> None:
    entry_path = cache_dir / "entries" / f"{key}.json"
    data = {
        "fetched_at": time.time(),
        "vulns": vulns,
    }
    if query:
        data["query"] = query
    try:
        entry_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass
    _evict_if_needed(cache_dir)


def _evict_if_needed(cache_dir: Path) -> None:
    entries_dir = cache_dir / "entries"
    entries = list(entries_dir.glob("*.json"))
    if len(entries) <= MAX_CACHE_ENTRIES:
        return
    entries.sort(key=lambda p: p.stat().st_mtime)
    to_remove = len(entries) - MAX_CACHE_ENTRIES
    for path in entries[:to_remove]:
        try:
            path.unlink()
        except OSError:
            pass


def get_cache_age_hours(cache_dir: Path) -> float | None:
    meta_path = cache_dir / "meta.json"
    if not meta_path.exists():
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        last_refresh = meta.get("last_refresh", 0)
        return (time.time() - last_refresh) / 3600
    except (json.JSONDecodeError, OSError):
        return None


def update_cache_meta(cache_dir: Path) -> None:
    meta_path = cache_dir / "meta.json"
    meta = {"last_refresh": time.time()}
    try:
        meta_path.write_text(json.dumps(meta), encoding="utf-8")
    except OSError:
        pass


def list_cached_entries(cache_dir: Path) -> list[dict]:
    """List all cached entries that have stored query info for re-fetching."""
    entries_dir = cache_dir / "entries"
    if not entries_dir.exists():
        return []
    queries = []
    for path in entries_dir.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            query = data.get("query")
            if query:
                queries.append(query)
        except (json.JSONDecodeError, OSError):
            pass
    return queries


def clear_cache(cache_dir: Path) -> int:
    """Remove all cached entries. Returns count of removed entries."""
    entries_dir = cache_dir / "entries"
    if not entries_dir.exists():
        return 0
    count = 0
    for path in entries_dir.glob("*.json"):
        try:
            path.unlink()
            count += 1
        except OSError:
            pass
    meta_path = cache_dir / "meta.json"
    if meta_path.exists():
        try:
            meta_path.unlink()
        except OSError:
            pass
    return count
