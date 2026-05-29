"""Abstract base class for firmware format handlers."""

from abc import ABC, abstractmethod
from pathlib import Path

from ...extraction.models import UnpackResult


class FirmwareFormat(ABC):
    @classmethod
    @abstractmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        """Return confidence 0.0-1.0 that this handler can parse the data."""
        ...

    @abstractmethod
    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        """Unpack firmware into analyzable sections."""
        ...

    @property
    @abstractmethod
    def format_name(self) -> str:
        ...
