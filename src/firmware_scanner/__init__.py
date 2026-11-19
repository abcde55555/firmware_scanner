"""Firmware Scanner - 嵌入式固件安全分析工具."""

import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _source_checkout_version() -> str:
    package = Path(__file__).resolve()
    for pyproject in (
        package.parents[2] / "pyproject.toml",
        package.parents[1] / "pyproject.toml",
    ):
        try:
            match = re.search(
                r'^version = "([^"]+)"$',
                pyproject.read_text(encoding="utf-8"),
                re.MULTILINE,
            )
        except OSError:
            continue
        if match:
            return match.group(1)
    return ""


__version__ = _source_checkout_version()
if not __version__:
    try:
        __version__ = version("firmware-scanner")
    except PackageNotFoundError:
        __version__ = "0+unknown"
