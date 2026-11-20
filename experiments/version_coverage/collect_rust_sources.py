"""Collect bounded Rust source reference candidates; this is not a version recognizer."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

import tomllib

WARNING = "reference candidates, not binary exact versions"
ANDROID_PIN_DEFAULT = "c991cad10330f37e93d82926bd6dae7f4f6647f6"
ANDROID_BASE = "https://android.googlesource.com/platform/external/rust/android-crates-io"
INDEX_BASE = "https://index.crates.io"
ARCHIVE_BASE = "https://static.crates.io/crates"
TIMEOUT_SECONDS = 20
RETRIES = 2
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_INDEX_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
MAX_EXTRACTED_BYTES = 32 * 1024 * 1024
MAX_TAR_MEMBERS = 100_000
MAX_TAR_DECLARED_BYTES = 256 * 1024 * 1024
CRATE_RE = re.compile(r"^[A-Za-z0-9_-]{1,100}$")
STABLE_VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class DownloadBudget:
    def __init__(self, limit: int):
        self.limit = limit
        self.used = 0

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _valid_crate(crate: str) -> str:
    if not CRATE_RE.fullmatch(crate):
        raise ValueError(f"invalid crate name: {crate!r}")
    return crate


def normalize_package_name(name: str) -> str:
    return name.lower().replace("_", "-")


def sparse_index_path(name: str) -> str:
    name = _valid_crate(name).lower()
    if len(name) == 1:
        return f"1/{name}"
    if len(name) == 2:
        return f"2/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def sparse_index_url(crate: str) -> str:
    return f"{INDEX_BASE}/{sparse_index_path(crate)}"


def android_manifest_url(crate: str, pin: str) -> str:
    _valid_crate(crate)
    if not re.fullmatch(r"[0-9a-fA-F]{40}", pin):
        raise ValueError("pin must be a 40-character Git commit")
    return f"{ANDROID_BASE}/+/" + pin + f"/crates/{urllib.parse.quote(crate, safe='')}/Cargo.toml?format=TEXT"


def android_source_url(crate: str, pin: str, source_file: str) -> str:
    return (f"{ANDROID_BASE}/+/{pin}/crates/{urllib.parse.quote(crate, safe='')}/"
            f"{urllib.parse.quote(source_file, safe='/')}?format=TEXT")


def _read_limited(response, limit: int, budget: DownloadBudget) -> bytes:
    allowed = min(limit, budget.remaining)
    if allowed <= 0:
        raise ValueError("total download budget exhausted")
    data = response.read(allowed)
    budget.used += len(data)
    content_length = getattr(response, "headers", {}).get("Content-Length") if hasattr(response, "headers") else None
    declared_length = int(content_length) if content_length is not None else None
    if declared_length is not None and declared_length > allowed:
        if allowed < limit:
            raise ValueError("total download budget exhausted")
        raise ValueError(f"response exceeds {limit} byte limit")
    if (len(data) == allowed and allowed < limit
            and declared_length != len(data)):
        raise ValueError("total download budget exhausted")
    return data


def fetch_url(url: str, *, limit: int, budget: DownloadBudget, retries: int = RETRIES,
              retry_delay: float = 0.25, opener=None) -> bytes:
    opener = opener or urllib.request.urlopen
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "firmware-scanner-rust-source-reference/1"})
            with opener(request, timeout=TIMEOUT_SECONDS) as response:
                return _read_limited(response, limit, budget)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            last_error = exc
            if attempt + 1 < retries and budget.remaining:
                time.sleep(retry_delay * (attempt + 1))
    raise RuntimeError(f"network/download error for {url}: {type(last_error).__name__}: {last_error}")


def decode_manifest(raw: bytes) -> tuple[dict, bytes]:
    try:
        decoded = base64.b64decode(raw, validate=True)
        manifest = tomllib.loads(decoded.decode("utf-8"))
        package = manifest["package"]
        name, version = package["name"], package["version"]
    except (ValueError, UnicodeError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"invalid Android Cargo.toml response: {exc}") from exc
    if not isinstance(name, str) or not isinstance(version, str):
        raise TypeError("manifest [package] name/version must be strings")
    return {"package_name": name, "declared_version": version}, decoded


def parse_index(raw: bytes, expected_name: str) -> list[dict]:
    records = []
    normalized = normalize_package_name(expected_name)
    for line_no, line in enumerate(raw.splitlines(), 1):
        if not line:
            continue
        try:
            row = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid sparse index JSON at line {line_no}: {exc}") from exc
        if normalize_package_name(str(row.get("name", ""))) != normalized:
            raise ValueError(f"sparse index package mismatch at line {line_no}")
        version = row.get("vers")
        checksum = row.get("cksum")
        if isinstance(version, str) and STABLE_VERSION_RE.fullmatch(version):
            if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
                raise ValueError(f"invalid checksum for indexed version {version}")
            records.append({"vers": version, "cksum": checksum, "yanked": bool(row.get("yanked", False))})
    return records


def _version_key(version: str) -> tuple[int, int, int]:
    match = STABLE_VERSION_RE.fullmatch(version)
    if not match:
        raise ValueError(f"not a stable X.Y.Z version: {version}")
    return tuple(int(part) for part in match.groups())


def select_versions(records: list[dict], pin_version: str, radius: int = 2) -> list[tuple[str, str]]:
    if radius < 0 or radius > 20:
        raise ValueError("radius must be between 0 and 20")
    _version_key(pin_version)
    by_version = {}
    for row in records:
        version = row.get("vers")
        if not isinstance(version, str) or not STABLE_VERSION_RE.fullmatch(version):
            continue
        checksum = row.get("cksum")
        if isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum):
            by_version[version] = row
    if pin_version not in by_version:
        return []
    ordered = sorted(by_version, key=_version_key)
    eligible = [v for v in ordered if v == pin_version or not by_version[v].get("yanked", False)]
    pin_index = eligible.index(pin_version)
    chosen = eligible[max(0, pin_index - radius):pin_index + radius + 1]
    return [(v, by_version[v]["cksum"]) for v in chosen]


def _safe_relative_path(path: str) -> str:
    if not isinstance(path, str):
        raise TypeError("archive path must be a string")
    if not path or "\\" in path or "\x00" in path:
        raise ValueError(f"unsafe archive path: {path!r}")
    pure = PurePosixPath(path)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError(f"unsafe archive path: {path!r}")
    return pure.as_posix()


def _safe_source_path(path: str) -> str:
    safe = _safe_relative_path(path)
    if PurePosixPath(safe).suffix != ".rs":
        raise ValueError(f"unsafe archive path: {path!r}")
    return safe


def read_archive_sources(archive_bytes: bytes, crate: str, version: str,
                         wanted: set[str]) -> dict[str, bytes]:
    import io
    crate = _valid_crate(crate)
    expected_root = f"{crate}-{version}/"
    safe_wanted = {_safe_source_path(name) for name in wanted}
    found: dict[str, bytes] = {}
    extracted_bytes = 0
    declared_bytes = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            for count, member in enumerate(archive, 1):
                if count > MAX_TAR_MEMBERS:
                    raise ValueError("archive member count exceeds limit")
                declared_bytes += max(member.size, 0)
                if declared_bytes > MAX_TAR_DECLARED_BYTES:
                    raise ValueError("archive declared content exceeds limit")
                name = member.name
                if name.startswith("/") or "\\" in name or "\x00" in name:
                    raise ValueError(f"unsafe archive path: {name!r}")
                parts = name.split("/")
                if any(part in (".", "..") for part in parts):
                    raise ValueError(f"unsafe archive path: {name!r}")
                if member.isdir() and name.rstrip("/") == f"{crate}-{version}":
                    continue
                if not name.startswith(expected_root):
                    raise ValueError(f"archive root must be {crate}-{version}/")
                relative = name[len(expected_root):]
                if member.isdir():
                    if not relative or any(not part for part in relative.rstrip("/").split("/")):
                        continue
                    continue
                _safe_relative_path(relative)
                if member.issym() or member.islnk() or not member.isfile():
                    raise ValueError(f"non-regular archive member: {name}")
                if relative not in safe_wanted:
                    continue
                if member.size > MAX_SOURCE_FILE_BYTES:
                    raise ValueError(f"source file exceeds {MAX_SOURCE_FILE_BYTES} byte limit: {relative}")
                if extracted_bytes + member.size > MAX_EXTRACTED_BYTES:
                    raise ValueError("extracted source total exceeds limit")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError(f"unable to read archive member: {relative}")
                content = stream.read(MAX_SOURCE_FILE_BYTES + 1)
                if len(content) != member.size or len(content) > MAX_SOURCE_FILE_BYTES:
                    raise ValueError(f"invalid or oversized archive member: {relative}")
                found[relative] = content
                extracted_bytes += len(content)
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ValueError(f"invalid crate archive: {exc}") from exc
    return found


def _atomic_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _cache_archive(path: Path, expected_sha256: str) -> bytes | None:
    try:
        content = path.read_bytes()
    except OSError:
        return None
    if _sha256(content) != expected_sha256:
        path.unlink(missing_ok=True)
        return None
    return content


def _extract_cache_files(content: bytes, crate: str, version: str, wanted: set[str],
                         output_dir: Path, errors: list[str], base_record: dict) -> tuple[dict, list[str]]:
    try:
        files = read_archive_sources(content, crate, version, wanted)
        metadata = {}
        missing = sorted(wanted - files.keys())
        for source_file, file_bytes in files.items():
            relative_path = Path("sources") / crate / version / Path(source_file)
            _atomic_bytes(output_dir / relative_path, file_bytes)
            metadata[source_file] = {"path": relative_path.as_posix(), "sha256": _sha256(file_bytes)}
            pinned = base_record.get("pinned_files", {}).get(source_file)
            if pinned:
                metadata[source_file]["pinned_comparison"] = {
                    "pinned_sha256": pinned["sha256"],
                    "upstream_matches_pinned": pinned["sha256"] == metadata[source_file]["sha256"],
                }
        return metadata, missing
    except ValueError as exc:
        errors.append(f"archive extraction error: {exc}")
        return {}, []


def _collect_one(crate: str, wanted: set[str], output_dir: Path, *, pin: str, radius: int,
                 budget: DownloadBudget, retries: int, retry_delay: float, opener=None) -> dict:
    crate = _valid_crate(crate)
    wanted = {_safe_source_path(name) for name in wanted}
    record = {
        "crate_path": crate, "package_name": None, "declared_version": None,
        "manifest": {"url": android_manifest_url(crate, pin), "sha256": None},
        "index": {"url": sparse_index_url(crate), "sha256": None},
        "pinned_files": {}, "versions": [], "errors": [],
    }
    manifest_url = record["manifest"]["url"]
    index_url = record["index"]["url"]
    try:
        raw_manifest = fetch_url(manifest_url, limit=MAX_MANIFEST_BYTES, budget=budget,
                                 retries=retries, retry_delay=retry_delay, opener=opener)
        record["manifest"]["raw_sha256"] = _sha256(raw_manifest)
        manifest, decoded = decode_manifest(raw_manifest)
        record["manifest"]["sha256"] = _sha256(decoded)
        record["manifest"]["decoded_sha256"] = _sha256(decoded)
        record.update(manifest)
        index_url = sparse_index_url(record["package_name"])
        record["index"]["url"] = index_url
    except (RuntimeError, ValueError, TypeError) as exc:
        record["errors"].append(str(exc))
        return record

    try:
        raw_index = fetch_url(index_url, limit=MAX_INDEX_BYTES, budget=budget,
                              retries=retries, retry_delay=retry_delay, opener=opener)
        record["index"]["sha256"] = _sha256(raw_index)
        index_rows = parse_index(raw_index, record["package_name"])
    except (RuntimeError, ValueError) as exc:
        record["errors"].append(str(exc))
        index_rows = []

    selected = select_versions(index_rows, record["declared_version"], radius) if index_rows else []
    if not selected:
        if index_rows:
            record["errors"].append(
                f"pin version {record['declared_version']} is absent from stable registry index; no version guessed"
            )
        return record

    for source_file in sorted(wanted):
        url = android_source_url(crate, pin, source_file)
        try:
            raw = fetch_url(url, limit=MAX_SOURCE_FILE_BYTES + 4096, budget=budget,
                            retries=retries, retry_delay=retry_delay, opener=opener)
            decoded = base64.b64decode(raw, validate=True)
            if len(decoded) > MAX_SOURCE_FILE_BYTES:
                raise ValueError(f"pinned source exceeds {MAX_SOURCE_FILE_BYTES} byte limit")
            relative = Path("sources") / crate / "android-pin" / Path(source_file)
            _atomic_bytes(output_dir / relative, decoded)
            record["pinned_files"][source_file] = {
                "path": relative.as_posix(), "sha256": _sha256(decoded), "url": url,
                "raw_sha256": _sha256(raw), "decoded_sha256": _sha256(decoded),
            }
        except (RuntimeError, ValueError) as exc:
            record["errors"].append(f"pinned source {source_file}: {exc}")

    cache_dir = output_dir / ".cache" / "crates"
    for version, index_checksum in selected:
        package_name = record["package_name"]
        quoted_name = urllib.parse.quote(package_name, safe="")
        archive_url = f"{ARCHIVE_BASE}/{quoted_name}/{quoted_name}-{version}.crate"
        cache_path = cache_dir / f"{package_name}-{version}.crate"
        archive_bytes = _cache_archive(cache_path, index_checksum)
        version_record = {
            "version": version, "archive_url": archive_url, "archive_sha256": None,
            "index_checksum": index_checksum, "files": {}, "missing_files": [], "errors": [],
        }
        if archive_bytes is None:
            try:
                archive_bytes = fetch_url(archive_url, limit=MAX_ARCHIVE_BYTES, budget=budget,
                                         retries=retries, retry_delay=retry_delay, opener=opener)
            except RuntimeError as exc:
                version_record["errors"].append(str(exc))
                record["versions"].append(version_record)
                continue
            _atomic_bytes(cache_path, archive_bytes)
        digest = _sha256(archive_bytes)
        version_record["archive_sha256"] = digest
        if digest != index_checksum:
            version_record["errors"].append(
                f"archive SHA-256 mismatch: expected index {index_checksum}, got {digest}"
            )
            record["versions"].append(version_record)
            continue
        version_record["files"], version_record["missing_files"] = _extract_cache_files(
            archive_bytes, package_name, version, wanted, output_dir, version_record["errors"], record,
        )
        record["versions"].append(version_record)
    return record


def collect_from_locations(locations: dict[str, set[str]], crates: list[str], output_dir: Path,
                           *, radius: int = 2, pin: str = ANDROID_PIN_DEFAULT,
                           retries: int = RETRIES, retry_delay: float = 0.25,
                           total_budget: int = 256 * 1024 * 1024, opener=None) -> dict:
    if not 0 <= radius <= 20:
        raise ValueError("radius must be between 0 and 20")
    if retries < 1 or retries > 2:
        raise ValueError("retries must be 1 or 2")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    budget = DownloadBudget(total_budget)
    corpus_path = output_dir / "corpus.json"
    if corpus_path.exists():
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        if corpus.get("warning") != WARNING or not isinstance(corpus.get("crates"), list):
            raise ValueError("existing corpus has an incompatible schema")
        for old in corpus["crates"]:
            old_url = old.get("manifest", {}).get("url", "")
            expected_url = android_manifest_url(old["crate_path"], pin)
            stale_failed_attempt = bool(old.get("errors")) and f"/+/{pin}/" in old_url
            if old_url != expected_url and not stale_failed_attempt:
                raise ValueError("existing corpus uses a different Android pin")
        previous_budget = corpus.get("download_budget", {})
        if previous_budget and previous_budget.get("limit_bytes") != total_budget:
            raise ValueError("resumed corpus uses a different total download budget")
        budget.used = int(previous_budget.get("used_bytes", 0))
        if budget.used > total_budget:
            raise ValueError("existing corpus already exceeds the requested download budget")
    else:
        corpus = {"crates": [], "warning": WARNING}
        _atomic_json(corpus_path, corpus)
    for crate in crates:
        crate_record = _collect_one(crate, locations.get(crate, set()), output_dir, pin=pin,
                                    radius=radius, budget=budget, retries=retries,
                                    retry_delay=retry_delay, opener=opener)
        corpus["crates"] = [row for row in corpus["crates"] if row.get("crate_path") != crate]
        corpus["crates"].append(crate_record)
        corpus["download_budget"] = {"limit_bytes": total_budget, "used_bytes": budget.used}
        _atomic_json(corpus_path, corpus)
        print(f"collected {crate}: {len(crate_record['versions'])} versions, "
              f"{len(crate_record['errors'])} crate errors; corpus={corpus_path}", file=sys.stderr)
    return corpus


def read_locations(path: Path) -> dict[str, set[str]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = data.get("rows") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise TypeError("locations JSON must contain a rows array")
    result: dict[str, set[str]] = {}
    for row in rows:
        for location in row.get("locations", []):
            crate, source_file = location.get("crate"), location.get("source_file")
            if isinstance(crate, str) and isinstance(source_file, str):
                result.setdefault(crate, set()).add(_safe_source_path(source_file))
    return result


def collect(locations_path: Path, crates: list[str], output_dir: Path, *, radius: int = 2,
            pin: str = ANDROID_PIN_DEFAULT, retries: int = RETRIES,
            retry_delay: float = 0.25, total_budget: int = 256 * 1024 * 1024,
            opener=None) -> dict:
    locations = read_locations(locations_path)
    return collect_from_locations(locations, crates, output_dir, radius=radius, pin=pin,
                                  retries=retries, retry_delay=retry_delay,
                                  total_budget=total_budget, opener=opener)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--locations", required=True, type=Path)
    parser.add_argument("--crates", required=True, help="comma-separated crate paths, at most 10")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--radius", type=int, default=2)
    parser.add_argument("--pin", default=ANDROID_PIN_DEFAULT)
    parser.add_argument("--total-budget-mib", type=int, default=256)
    args = parser.parse_args()
    crates = [item.strip() for item in args.crates.split(",") if item.strip()]
    if not crates or len(crates) > 10 or len(set(crates)) != len(crates):
        parser.error("provide 1-10 unique crate names")
    if args.total_budget_mib < 1 or args.total_budget_mib > 2048:
        parser.error("--total-budget-mib must be between 1 and 2048")
    result = collect(args.locations, crates, args.output_dir, radius=args.radius, pin=args.pin,
                     total_budget=args.total_budget_mib * 1024 * 1024)
    print(json.dumps({"corpus": str(args.output_dir / "corpus.json"),
                      "crates": len(result["crates"]),
                      "errors": sum(len(row["errors"]) + sum(len(v["errors"]) for v in row["versions"])
                                     for row in result["crates"]),
                      "download_budget": result.get("download_budget")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
