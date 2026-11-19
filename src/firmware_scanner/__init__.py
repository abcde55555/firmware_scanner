"""Firmware Scanner - 嵌入式固件安全分析工具."""
from importlib.metadata import version, PackageNotFoundError
import re
from pathlib import Path


def _source_checkout_version() -> str:
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    try:
        match = re.search(
            r'^version = "([^"]+)"$',
            pyproject.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
    except OSError:
        return ""
    return match.group(1) if match else ""


__version__ = _source_checkout_version()
if not __version__:
    try:
        __version__ = version("firmware-scanner")
    except PackageNotFoundError:
        __version__ = "0+unknown"
