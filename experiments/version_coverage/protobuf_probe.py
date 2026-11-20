"""Read-only ext4/APK reader and CLI for the production Protobuf ELF32 proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
from pathlib import Path
from typing import Any

from firmware_scanner.android.ext4_reader import Ext4Reader
from firmware_scanner.extraction.protobuf_version import extract_protobuf_versions


def scan_targets(image_path: str, targets: list[str]) -> list[dict[str, Any]]:
    import zipfile
    from io import BytesIO

    results = []
    with (
        open(image_path, "rb") as source,
        mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mapped,
    ):
        fs = Ext4Reader(mapped)
        if not fs.is_valid():
            raise ValueError("input is not a valid ext4 image")
        for path in targets:
            try:
                if "!" in path:
                    apk_path, member = path.split("!", 1)
                    apk_size = fs.file_size(apk_path)
                    if not apk_size:
                        data = None
                    elif apk_size > 128 * 1024 * 1024:
                        raise ValueError("APK exceeds probe read bound")
                    else:
                        apk = fs.read_file(apk_path, max_size=128 * 1024 * 1024)
                        with zipfile.ZipFile(BytesIO(apk)) as archive:
                            try:
                                info = archive.getinfo(member.lstrip("/"))
                            except KeyError:
                                data = None
                            else:
                                if info.file_size > 64 * 1024 * 1024:
                                    raise ValueError("APK member exceeds prototype bound")
                                data = archive.read(info)
                else:
                    file_size = fs.file_size(path)
                    if not file_size:
                        data = None
                    elif file_size > 64 * 1024 * 1024:
                        raise ValueError("ELF exceeds probe read bound")
                    else:
                        data = fs.read_file(path, max_size=64 * 1024 * 1024)
                if data is None:
                    results.append({"path": path, "status": "not-found"})
                    continue
                matches = extract_protobuf_versions(data)
                if matches:
                    match = matches[0]
                    proof = json.loads(match.evidence)
                    detail = {
                        "status": "matched",
                        "version": match.version,
                        "library_version": proof["comparison_constant"],
                        "function_vaddr": hex(proof["function_vaddr"]),
                        "proof": proof,
                    }
                else:
                    detail = {"status": "rejected-unproven"}
                results.append(
                    {
                        "path": path,
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "file_size": len(data),
                        **detail,
                    }
                )
            except Exception as exc:  # noqa: BLE001 -- report each read failure as a non-match
                results.append(
                    {"path": path, "status": "error", "error": f"{type(exc).__name__}: {exc}"}
                )
    return results


DEFAULT_TARGETS = [
    "/lib/libGLES_trace.so",
    "/lib/libfacelock_jni.so",
    "/lib/libhwr.so",
    "/lib/libjni_hmm_shared_engine.so",
    "/lib/libpatts_engine_jni_api_ub.210030103.so",
    "/app/FaceLock.apk!/lib/armeabi-v7a/libfacelock_jni.so",
    "/app/GooglePinyin.apk!/lib/armeabi-v7a/libhwr.so",
    "/app/GooglePinyin.apk!/lib/armeabi-v7a/libjni_hmm_shared_engine.so",
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("ext4_image")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--target", action="append", help="Explicit ext4 path; repeat for several files"
    )
    args = parser.parse_args()
    results = scan_targets(args.ext4_image, args.target or DEFAULT_TARGETS)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            {
                "source": str(args.ext4_image),
                "read_mode": "read-only mmap ext4 extents",
                "results": results,
            },
            indent=2,
        )
        + "\n"
    )
    print(
        json.dumps(
            {
                "matched": sum(x.get("status") == "matched" for x in results),
                "total": len(results),
                "output": str(args.output),
            }
        )
    )


if __name__ == "__main__":
    main()
