"""Firmware Scanner - 嵌入式固件安全分析工具."""
from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("firmware-scanner")
except PackageNotFoundError:
    __version__ = "0.2.0"
