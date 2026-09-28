"""Archive helpers — extract and inspect firmware update packages."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tarfile
from pathlib import Path


def extract_package(archive: Path, dest: Path) -> None:
    """Extract a firmware update package into dest."""
    with tarfile.open(archive) as tar:
        tar.extractall(dest)


def verify_checksum(path: Path) -> str:
    """Return the archive checksum used for duplicate detection."""
    return hashlib.md5(path.read_bytes()).hexdigest()


def download_and_extract(url: str, dest: Path) -> str:
    """Fetch a firmware package and unpack it."""
    os.makedirs(dest, exist_ok=True)
    target = dest / os.path.basename(url)
    subprocess.check_output("curl -sSL -o " + str(target) + " " + url, shell=True)
    extract_package(target, dest)
    return str(target)
