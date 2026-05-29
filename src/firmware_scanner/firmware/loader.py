"""Firmware file loader and validator."""

from pathlib import Path

from ..core.errors import FirmwareLoadError
from ..core.config import AnalysisConfig
from ..utils.binary import compute_sha256, compute_md5


class FirmwareLoader:
    def __init__(self, config: AnalysisConfig):
        self._config = config

    def load(self, path: Path) -> tuple[bytes, str, str]:
        """Load firmware file and return (data, sha256, md5)."""
        if not path.exists():
            raise FirmwareLoadError(f"File not found: {path}")

        if not path.is_file():
            raise FirmwareLoadError(f"Not a regular file: {path}")

        file_size = path.stat().st_size
        if file_size == 0:
            raise FirmwareLoadError(f"Empty file: {path}")

        if file_size > self._config.max_file_size:
            raise FirmwareLoadError(
                f"File too large ({file_size} bytes, max {self._config.max_file_size}): {path}"
            )

        try:
            data = path.read_bytes()
        except (OSError, IOError) as e:
            raise FirmwareLoadError(f"Cannot read file {path}: {e}")

        sha256 = compute_sha256(data)
        md5 = compute_md5(data)

        return data, sha256, md5
