#!/usr/bin/env python3
"""Regenerate or check the packaged firmware-scanner rule lock."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from firmware_scanner.core.rules_manifest import build_rule_lock


DEFAULT_DATA_ROOT = Path("src/firmware_scanner/data")
DEFAULT_RELEASE = "builtin-2026.11.19.3"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--release", default=DEFAULT_RELEASE)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    lock_path = args.data_root / "rules.lock.json"
    generated = build_rule_lock(args.data_root, args.release)
    rendered = json.dumps(generated, indent=2) + "\n"
    if args.check:
        current = lock_path.read_text(encoding="utf-8") if lock_path.exists() else ""
        if current != rendered:
            raise SystemExit("rules.lock.json is stale")
        return 0
    lock_path.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
