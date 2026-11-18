"""Run local CVE Binary Tool checkers on real ext4 files, without a CVE DB.

This is an independent candidate scout, not a version oracle. Run using the
Python environment that contains cve-bin-tool, with this repository's src on
PYTHONPATH. Input locations are a JSON list of paths or objects with a location
or path key. Direct files and one ZIP member level are supported explicitly.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import mmap
import re
import time
import zipfile
from importlib.metadata import version
from pathlib import Path

from cve_bin_tool.checkers import Checker
from cve_bin_tool.version_scanner import VersionScanner

from firmware_scanner.android.archive_reader import FilesystemFile
from firmware_scanner.android.ext4_reader import Ext4Reader

_LIMIT = 64 * 1024 * 1024


def _read(reader, location):
    parts = location.split("!/")
    if len(parts) == 1:
        size = reader.file_size(location)
        if size is None or not 0 < size <= _LIMIT:
            raise ValueError("missing file or file exceeds 64 MiB budget")
        data = reader.read_file(location, max_size=_LIMIT)
    elif len(parts) == 2:
        with FilesystemFile(reader, parts[0]) as stream, zipfile.ZipFile(stream) as archive:
            info = archive.getinfo(parts[1])
            if not 0 < info.file_size <= _LIMIT:
                raise ValueError("ZIP member exceeds 64 MiB budget")
            data = archive.read(info)
            size = info.file_size
    else:
        raise ValueError("nested archive location unsupported by this experiment")
    if not data or len(data) != size or not data.startswith(b"\x7fELF"):
        raise ValueError("incomplete read or non-ELF input")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("locations", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    requested = json.loads(args.locations.read_text())
    locations = sorted({item if isinstance(item, str) else item.get("location", item.get("path"))
                        for item in requested})
    classes = VersionScanner.load_checkers()
    checkers = {name: cls() for name, cls in classes.items()}
    checker_hashes = {name: hashlib.sha256(Path(inspect.getfile(cls)).read_bytes()).hexdigest()
                      for name, cls in classes.items()}
    result = {
        "method": "CVE Binary Tool get_version checkers; ASCII strings >=3; no CVE DB, network or target execution",
        "tool_version": version("cve-bin-tool"), "checker_count": len(checkers),
        "checker_source_sha256": checker_hashes,
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "helper_source_sha256": {
            cls.__name__: hashlib.sha256(Path(inspect.getfile(cls)).read_bytes()).hexdigest()
            for cls in (Checker, VersionScanner, Ext4Reader, FilesystemFile)
        },
        "image": str(args.image.resolve()), "image_size": args.image.stat().st_size,
        "locations_sha256": hashlib.sha256(args.locations.read_bytes()).hexdigest(),
        "observations": [], "skipped": [],
    }
    started = time.monotonic()
    with args.image.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as image:
        result["image_sha256"] = hashlib.sha256(image).hexdigest()
        reader = Ext4Reader(image)
        if not reader.is_valid():
            raise SystemExit("input is not an ext4 partition")
        for index, location in enumerate(locations, 1):
            try:
                data = _read(reader, location)
            except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
                result["skipped"].append({"location": location, "reason": str(error)})
                continue
            strings = "\n".join(match.group().decode("ascii")
                                for match in re.finditer(rb"[\x20-\x7e]{3,}", data))
            hits, errors = [], []
            for name, checker in checkers.items():
                try:
                    found = checker.get_version(strings, location)
                    candidates = [found] if isinstance(found, dict) else found
                    for hit in candidates:
                        if not hit.get("is_or_contains"):
                            continue
                        evidence = [match.group(0)[:512] for pattern in checker.VERSION_PATTERNS
                                    if (match := pattern.search(strings)) is not None]
                        hits.append({"checker": name, "candidate": hit,
                                     "version_pattern_matches": evidence[:8]})
                except (ValueError, TypeError, KeyError, IndexError, AttributeError) as error:
                    errors.append({"checker": name, "error": repr(error)})
            result["observations"].append({"location": location, "size": len(data),
                                           "sha256": hashlib.sha256(data).hexdigest(),
                                           "candidates": hits, "checker_errors": errors})
            if index % 20 == 0:
                print(json.dumps({"processed": index, "total": len(locations)}), flush=True)
    result["seconds"] = round(time.monotonic() - started, 3)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"read": len(result["observations"]), "skipped": len(result["skipped"]),
                      "with_candidates": sum(bool(item["candidates"]) for item in result["observations"]),
                      "seconds": result["seconds"]}), flush=True)


if __name__ == "__main__":
    main()
