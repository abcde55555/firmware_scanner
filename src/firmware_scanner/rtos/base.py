"""Abstract base class for RTOS analysis plugins."""

from abc import ABC, abstractmethod
from ..core.context import AnalysisContext
from ..extraction.models import Component


class RTOSPlugin(ABC):
    @property
    @abstractmethod
    def rtos_name(self) -> str:
        ...

    @property
    @abstractmethod
    def vendor(self) -> str:
        ...

    @abstractmethod
    def detect(self, context: AnalysisContext) -> float:
        """Return confidence 0.0-1.0 that this RTOS is present."""
        ...

    @abstractmethod
    async def analyze(self, context: AnalysisContext) -> list[Component]:
        """Perform RTOS-specific deep analysis."""
        ...

    @abstractmethod
    def get_version_patterns(self) -> list[str]:
        ...

    @abstractmethod
    def get_known_symbols(self) -> list[str]:
        ...
