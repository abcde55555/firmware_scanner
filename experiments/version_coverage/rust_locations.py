"""Reproduce the bounded product Rust-location parser against actual image files."""
from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import mmap
from pathlib import Path

from firmware_scanner.extraction.rust_locations import (
    MAX_ELF_BYTES,
    decode_android_rela,
    decode_relr,
    extract_locations,
)

__all__ = ["decode_android_rela", "decode_relr", "extract_locations"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("candidates", type=Path)
    parser.add_argument("observations", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    candidates = json.loads(args.candidates.read_text())["observations"]
    candidates = [row for row in candidates if any(
        source["project_path"] == "external/rust/android-crates-io" for source in row["source_candidates"]
    )]
    known = {row["location"]: row for row in json.loads(args.observations.read_text())}
    from firmware_scanner.android.ext4_reader import Ext4Reader

    rows = []
    with args.image.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as image:
        reader = Ext4Reader(image)
        if not reader.is_valid():
            raise ValueError("input is not ext4")
        for row in candidates:
            location = row["locations"][0]
            record = {"identity": row["identity"], "location": location}
            try:
                if "!" in location or not 0 < reader.file_size(location) <= MAX_ELF_BYTES:
                    raise ValueError("unsupported nested, missing, empty or oversized path")
                data = reader.read_file(location, max_size=MAX_ELF_BYTES)
                digest = hashlib.sha256(data).hexdigest()
                if digest != known[location]["sha256"]:
                    raise ValueError("target SHA differs from scan observation")
                record.update(sha256=digest, size=len(data), **extract_locations(data))
            except (ValueError, OSError, KeyError) as exc:
                record.update(status="read-error", locations=[], error=f"{type(exc).__name__}: {exc}")
            rows.append(record)
    result = {"candidate_source_sha256": hashlib.sha256(args.candidates.read_bytes()).hexdigest(),
              "parser_sha256": hashlib.sha256(Path(inspect.getfile(extract_locations)).read_bytes()).hexdigest(),
              "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "observation_source_sha256": hashlib.sha256(args.observations.read_bytes()).hexdigest(),
              "files": len(rows), "read_errors": sum(x["status"] == "read-error" for x in rows),
              "invalid": sum(x["status"] == "invalid" for x in rows),
              "files_with_locations": sum(bool(x["locations"]) for x in rows),
              "files_with_referenced_locations": sum(any(q["code_references"] for q in x["locations"]) for x in rows),
              "files_with_core_panic_context": sum(any(q["corroborated_calls"] for q in x["locations"]) for x in rows),
              "location_records": sum(len(x["locations"]) for x in rows), "rows": rows,
              "warning": "experimental features only; all component versions remain unchanged"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}))


if __name__ == "__main__":
    main()
