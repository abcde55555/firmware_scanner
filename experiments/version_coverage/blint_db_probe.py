"""Probe AppThreat blint-db against unknown-version direct ELF observations.

The runner never executes target binaries and opens both firmware and database
read-only. It deliberately reports package/build versions as candidates, since
those are not necessarily upstream-library releases.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import mmap
import os
import resource
import shutil
import sqlite3
import time
from collections import defaultdict
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

CORPUS = Path("reports/version-corpus-20261118/scan")
DEFAULT_OUT = Path("reports/existing-databases-20261119/blintdb-probe.json")
TABLES = ("SchemaMeta", "Projects", "Builds", "Binaries", "Symbols")
GIB = 1024**3
CHUNK_SIZE = 4 * 1024 * 1024


def sha256_file(path: Path) -> str:
    """Hash a large file without materializing it in memory."""
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def merged_coverage(ranges: list[tuple[int, int]], size: int) -> list[tuple[int, int]]:
    """Merge non-empty half-open byte ranges and clip them to the layer."""
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        start, end = max(0, start), min(size, end)
        if start >= end:
            continue
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


def missing_ranges(coverage: list[tuple[int, int]], size: int) -> list[tuple[int, int]]:
    """Return half-open byte ranges not covered by an ordered range list."""
    gaps: list[tuple[int, int]] = []
    cursor = 0
    for start, end in coverage:
        if start > cursor:
            gaps.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < size:
        gaps.append((cursor, size))
    return gaps


def download_db_layer(manifest_path: Path, output_dir: Path, budget_bytes: int = 6 * GIB) -> Path:
    """Fetch and assemble a pinned raw-SQLite OCI layer from resumable ranges."""
    metadata = json.loads(manifest_path.read_text())
    repo = metadata["repository"]
    manifest = metadata["manifest"]
    layer = next(x for x in manifest["layers"] if x.get("annotations", {}).get("org.opencontainers.image.title") == "blint.db")
    size, digest = int(layer["size"]), layer["digest"]
    if size > budget_bytes:
        raise ValueError(f"database layer {size} bytes exceeds download budget {budget_bytes}")
    output_dir.mkdir(parents=True, exist_ok=True)
    disk = shutil.disk_usage(output_dir)
    minimum_free = size + 2 * GIB
    if disk.free < minimum_free:
        raise OSError(f"insufficient free disk: need {minimum_free} bytes for assembly and headroom")
    token_url = "https://ghcr.io/token?scope=" + quote(f"repository:{repo}:pull")
    with urlopen(Request(token_url, headers={"User-Agent": "blintdb-version-coverage-probe/1.0"}), timeout=30) as response:
        token = json.load(response)["token"]
    blob_url = f"https://ghcr.io/v2/{repo}/blobs/{digest}"
    db_path = output_dir / "blint.db"
    temporary_db = output_dir / "blint.db.partial"
    chunk_dir = output_dir / ".blintdb-v4-chunks"
    chunk_dir.mkdir(exist_ok=True)

    expected = digest.removeprefix("sha256:")
    if db_path.exists():
        if db_path.stat().st_size == size and sha256_file(db_path) == expected:
            return db_path
        raise ValueError("existing blint.db size or SHA-256 does not match the pinned OCI layer")

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    ghcr_opener = build_opener(NoRedirect)

    def fetch(bounds: tuple[int, int]) -> Path:
        """Fetch an exact half-open range into a reusable cache file."""
        start, end = bounds
        part = chunk_dir / f"gap-{start:012d}-{end:012d}.part"
        expected_size = end - start
        if part.exists() and part.stat().st_size == expected_size:
            return part
        headers = {"Authorization": f"Bearer {token}", "Range": f"bytes={start}-{end - 1}",
                   "User-Agent": "blintdb-version-coverage-probe/1.0"}
        for attempt in range(5):
            try:
                try:
                    response = ghcr_opener.open(Request(blob_url, headers=headers), timeout=90)
                except HTTPError as exc:
                    if exc.code not in (301, 302, 303, 307, 308) or not exc.headers.get("Location"):
                        raise
                    response = urlopen(Request(
                        exc.headers["Location"],
                        headers={"Range": f"bytes={start}-{end - 1}"},
                    ), timeout=120)
                with response:
                    content_range = response.headers.get("Content-Range", "")
                    if response.status != 206 or not content_range.startswith(f"bytes {start}-{end - 1}/{size}"):
                        raise OSError(f"invalid range response for {start}-{end}: status={response.status}, Content-Range={content_range!r}")
                    data = response.read(expected_size + 1)
                    if len(data) != expected_size:
                        raise OSError(f"short range {start}-{end}: received {len(data)} bytes")
                tmp = part.with_suffix(".tmp")
                tmp.write_bytes(data)
                tmp.replace(part)
                return part
            except (OSError, TimeoutError):
                if attempt == 4:
                    raise
                time.sleep(2 ** attempt)
        raise RuntimeError(f"unreachable range retry state: {start}-{end}")

    cached_parts = sorted(
        (part for part in chunk_dir.glob("*.part") if part.name[:4] not in {"gap-"}),
        key=lambda part: int(part.name[:-5]),
    )
    intervals = []
    for part in cached_parts:
        start = int(part.name[:-5])
        intervals.append((start, min(size, start + part.stat().st_size)))
    coverage = merged_coverage(intervals, size)
    gaps = missing_ranges(coverage, size)
    with temporary_db.open("wb") as target:
        target.truncate(size)
        for part in cached_parts:
            start = int(part.name[:-5])
            with part.open("rb") as source:
                target.seek(start)
                remaining = min(part.stat().st_size, size - start)
                while remaining:
                    block = source.read(min(8 * 1024 * 1024, remaining))
                    if not block:
                        break
                    target.write(block)
                    remaining -= len(block)
        if gaps:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(fetch, bounds) for bounds in gaps]
                for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
                    part = future.result()
                    _, start_text, _end_text = part.stem.split("-")
                    target.seek(int(start_text))
                    with part.open("rb") as source:
                        shutil.copyfileobj(source, target, length=8 * 1024 * 1024)
                    print(f"BLint database gap ranges: {index}/{len(gaps)}", flush=True)
        target.flush()
        os.fsync(target.fileno())
    actual = sha256_file(temporary_db)
    if temporary_db.stat().st_size != size or actual != expected:
        raise ValueError(f"OCI layer verification failed: size={temporary_db.stat().st_size}/{size}, sha256={actual}/{expected}")
    with temporary_db.open("rb") as header:
        is_raw_sqlite = header.read(16) == b'SQLite format 3\x00'
    if not is_raw_sqlite:
        raise ValueError("pinned OCI layer is not the expected raw SQLite database")
    temporary_db.replace(db_path)
    verification = {
        'repository': repo, 'tag': metadata['tag'],
        'manifest_digest': metadata['docker_content_digest'], 'layer_digest': digest,
        'layer_bytes': size, 'layer_sha256_verified': actual,
        'database_path': str(db_path), 'database_bytes': size,
        'database_sha256': actual, 'payload_format': 'raw-sqlite',
    }
    (output_dir / "blintdb-download-verification.json").write_text(json.dumps(verification, indent=2) + "\n")
    for part in chunk_dir.glob("*.part"):
        part.unlink()
    chunk_dir.rmdir()
    return db_path


def _table_columns(connection: sqlite3.Connection) -> dict[str, set[str]]:
    names = {r[0] for r in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    return {name: {r[1] for r in connection.execute(
        f'PRAGMA table_info("{name}")'
    )} for name in names}


def validate_schema(connection: sqlite3.Connection) -> dict[str, str]:
    """Reject incomplete/unknown databases before treating a query as zero-hit."""
    tables = _table_columns(connection)
    missing = [name for name in TABLES if name not in tables]
    if missing:
        raise ValueError(f"required blint-db tables missing: {', '.join(missing)}")
    required = {
        "Projects": {"project_id", "name"},
        "Builds": {"build_id", "project_id"},
        "Binaries": {"binary_id", "build_id"},
        "Symbols": {"binary_id", "name"},
    }
    for table, columns in required.items():
        absent = columns - tables[table]
        if absent:
            raise ValueError(f"unsupported blint-db schema: {table} lacks {sorted(absent)}")
    meta_columns = tables["SchemaMeta"]
    cursor = connection.execute("SELECT * FROM SchemaMeta")
    meta_names = [d[0] for d in cursor.description]
    rows = cursor.fetchall()
    version = "unknown"
    for row in rows:
        values = dict(zip(meta_names, row))
        if "schema_version" in values:
            version = str(values["schema_version"])
        elif "key" in values and str(values["key"]).lower() in {"schema_version", "schema-version"}:
            version = str(values.get("value", "unknown"))
    if not meta_columns:
        raise ValueError("unsupported blint-db schema: SchemaMeta has no columns")
    return {"schema_version": version, "tables": ",".join(TABLES)}


def query_symbol_candidates(connection: sqlite3.Connection, symbol_names: set[str]) -> list[dict]:
    """Apply blint-db's distinct-symbol count baseline and preserve all candidates."""
    if not symbol_names:
        return []
    columns = _table_columns(connection)
    symbol_columns = columns["Symbols"]
    has_raw = "raw_name" in symbol_columns
    names = sorted(symbol_names)
    hits: dict[int, set[str]] = defaultdict(set)
    for start in range(0, len(names), 400):
        batch = names[start:start + 400]
        placeholders = ",".join("?" for _ in batch)
        predicates = [f"name IN ({placeholders})"]
        args: list[str] = list(batch)
        if has_raw:
            predicates.append(f"raw_name IN ({placeholders})")
            args.extend(batch)
        query_args = args
        for binary_id, name in connection.execute(
            "SELECT DISTINCT binary_id, name FROM Symbols "
            f"WHERE {' OR '.join(predicates)}", query_args
        ):
            hits[int(binary_id)].add(str(name))
    if not hits:
        return []
    project_columns = columns["Projects"]
    build_columns = columns["Builds"]
    binary_columns = columns["Binaries"]
    select = ["b.binary_id", "p.name AS project_name"]
    for col, alias, prefix in (
        ("purl", "purl", project_columns), ("ecosystem", "ecosystem", project_columns),
        ("metadata_json", "project_metadata_json", project_columns),
        ("source_sbom_json", "source_sbom_json", project_columns),
        ("target_arch", "target_arch", build_columns), ("target_triplet", "target_triplet", build_columns),
        ("llvm_target_tuple", "llvm_target_tuple", build_columns),
        ("sha256", "binary_sha256", binary_columns), ("name", "binary_name", binary_columns),
    ):
        if col in prefix:
            table_alias = {"purl":"p", "ecosystem":"p", "metadata_json":"p", "source_sbom_json":"p",
                           "target_arch":"bu", "target_triplet":"bu", "llvm_target_tuple":"bu",
                           "sha256":"b", "name":"b"}[col]
            select.append(f"{table_alias}.{col} AS {alias}")
    sql = ("SELECT " + ", ".join(select) + " FROM Binaries b "
           "JOIN Builds bu ON bu.build_id=b.build_id "
           "JOIN Projects p ON p.project_id=bu.project_id WHERE b.binary_id IN (" +
           ",".join("?" for _ in hits) + ")")
    rows = connection.execute(sql, list(hits)).fetchall()
    colnames = [d[0] for d in connection.execute(sql, list(hits)).description]
    results = []
    for raw_row in rows:
        row = dict(zip(colnames, raw_row))
        matched = sorted(hits[int(row["binary_id"])])
        versions: set[str] = set()
        if row.get("purl"):
            versions.add(str(row["purl"]))
        for field in ("project_metadata_json", "source_sbom_json"):
            try:
                obj = json.loads(row.get(field) or "{}")
            except (TypeError, json.JSONDecodeError):
                continue
            stack = [obj]
            while stack:
                item = stack.pop()
                if isinstance(item, dict):
                    if item.get("version") and (item.get("name") == row["project_name"] or field == "project_metadata_json"):
                        versions.add(str(item["version"]))
                    stack.extend(item.values())
                elif isinstance(item, list):
                    stack.extend(item)
        results.append({
            "binary_id": row["binary_id"], "project_name": row["project_name"],
            "version_candidates": sorted(versions), "target_arch": row.get("target_arch"),
            "target_triplet": row.get("target_triplet"), "llvm_target_tuple": row.get("llvm_target_tuple"),
            "ecosystem": row.get("ecosystem"), "binary_name": row.get("binary_name"),
            "binary_sha256": row.get("binary_sha256"), "matched_symbols": len(matched),
            "symbol_evidence": matched,
            "version_semantics": "package/project/build candidate; not asserted as upstream library release",
        })
    return sorted(results, key=lambda x: (-x["matched_symbols"], x["project_name"], str(x["version_candidates"])))


def defined_elf_symbols(data: bytes | mmap.mmap) -> set[str]:
    """Return named, defined ELF symbols, excluding undefined imports."""
    import io

    from elftools.elf.elffile import ELFFile
    elf = ELFFile(io.BytesIO(data))
    found: set[str] = set()
    for section in elf.iter_sections():
        if section.__class__.__name__ != "SymbolTableSection":
            continue
        for symbol in section.iter_symbols():
            if symbol.name and symbol["st_shndx"] != "SHN_UNDEF":
                found.add(symbol.name)
    return found


def eligible_observations(paths: list[Path]) -> list[dict]:
    rows = []
    for path in paths:
        image_info = json.loads((path.parent / "input.json").read_text())
        for row in json.loads(path.read_text()):
            if "!" in row.get("location", "") or not row.get("sha256"):
                continue
            claims = row.get("claims", [])
            host_claim = claims[0] if claims else {}
            versions = [host_claim.get("version")]
            versions.extend(v.get("version") for v in host_claim.get("versions", []))
            if not any(v for v in versions):
                rows.append({**row, "corpus": path.parent.name, "image": image_info["path"]})
    return rows


def run_probe(database: Path, observations: list[dict], image_override: Path | None = None) -> dict:
    from firmware_scanner.android.ext4_reader import Ext4Reader

    started = time.monotonic()
    results = []
    schema = None
    per_image: dict[str, dict[str, dict]] = defaultdict(dict)
    for row in observations:
        image = str(image_override or row["image"])
        per_image[image].setdefault(row["sha256"], row)
    with sqlite3.connect(f"file:{quote(str(database.resolve()))}?mode=ro", uri=True) as conn:
        conn.execute("PRAGMA trusted_schema=OFF")
        schema = validate_schema(conn)
        for image_name, target_rows in per_image.items():
            image = Path(image_name)
            with image.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                fs = Ext4Reader(mapped)
                if not fs.is_valid():
                    raise ValueError(f"not an ext4 filesystem: {image}")
                for row in target_rows.values():
                    item = {"location": row["location"], "corpus": row["corpus"], "image": image_name,
                            "observation_sha256": row["sha256"]}
                    try:
                        data = fs.read_file(row["location"], max_size=128 * 1024 * 1024)
                        digest = hashlib.sha256(data).hexdigest()
                        if digest != row["sha256"]:
                            raise ValueError("readback SHA-256 differs from observation")
                        symbols = defined_elf_symbols(data)
                        candidates = query_symbol_candidates(conn, symbols)
                        item.update(status="queried", actual_sha256=digest, defined_symbol_count=len(symbols),
                                    candidates=candidates)
                    except Exception as exc:  # noqa: BLE001 - retain per-file failures in the evidence report
                        item.update(status="error", error=f"{type(exc).__name__}: {exc}")
                    results.append(item)
    target_symbol_total = sum(r.get("defined_symbol_count", 0) for r in results)
    matched_symbol_evidence = sum(c.get("matched_symbols", 0) for r in results for c in r.get("candidates", []))
    matched_target_symbols = sum(bool(r.get("candidates")) for r in results)
    matched_symbol_total = sum(len({name for candidate in r.get("candidates", [])
                                   for name in candidate.get("symbol_evidence", [])}) for r in results)
    return {
        "database": str(database), "database_sha256": sha256_file(database),
        "database_schema": schema,
        "image_sha256_by_path": {name: sha256_file(Path(name)) for name in per_image},
        "observation_total": len(observations), "unique_sha256": len({r["sha256"] for r in observations}),
        "unique_target_paths_processed": len(results),
        "direct_elf_targets_queried": sum(r.get("status") == "queried" for r in results),
        "matched_targets": sum(bool(r.get("candidates")) for r in results),
        "candidate_rows": sum(len(r.get("candidates", [])) for r in results),
        "matched_symbol_evidence_count": matched_symbol_evidence,
        "defined_symbol_count_total": target_symbol_total,
        "matched_distinct_target_symbols": matched_symbol_total,
        "matched_targets_with_symbol_evidence": matched_target_symbols,
        "target_symbol_coverage": round(matched_symbol_total / target_symbol_total, 6) if target_symbol_total else 0,
        "target_file_coverage": round(matched_target_symbols / len(results), 6) if results else 0,
        "ambiguous_targets": sum(len({(c["project_name"], tuple(c["version_candidates"]))
                                      for c in r.get("candidates", [])}) > 1 for r in results),
        "rows": results,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "scope": "direct ext4 ELF paths only; nested/archive members excluded",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--download-db", action="store_true", help="download and digest-check the selected public v4 DB layer")
    parser.add_argument("--image", type=Path)
    parser.add_argument("--corpus", type=Path, nargs="+", default=[CORPUS / "allwinner/file-observations.json", CORPUS / "system/file-observations.json"])
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    started = time.monotonic()
    observations = eligible_observations(args.corpus)
    result = {"observation_total": len(observations), "unique_sha256": len({r["sha256"] for r in observations}),
              "source_observation_sha256": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in args.corpus},
              "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "pyelftools_version": __import__("elftools").__version__, "rows": [],
              "scope": "direct ext4 ELF paths only; nested/archive members excluded",
              "database_manifest": "reports/existing-databases-20261119/blintdb-manifest.json"}
    code = 0
    if args.download_db:
        args.database = download_db_layer(args.output.parent / "blintdb-manifest.json", args.output.parent)
        result["downloaded_database_layer"] = str(args.output.parent / "blintdb-v4-arm64-layer.tar")
        result["downloaded_database"] = str(args.database)
    if args.database:
        result.update(run_probe(args.database, observations, args.image))
    else:
        result.update(status="database-not-supplied", note="Pass --database or --download-db to run the pinned BLintDB probe.")
        code = 2
    result["exit_code"] = code
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    result["max_rss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
