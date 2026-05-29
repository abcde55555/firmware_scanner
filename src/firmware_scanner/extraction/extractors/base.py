"""Abstract base class for component extractors."""

from abc import ABC, abstractmethod
from ...core.context import AnalysisContext
from ..models import Component


class BaseExtractor(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def is_available(self) -> bool:
        ...

    @abstractmethod
    async def extract(self, context: AnalysisContext) -> list[Component]:
        ...

    @property
    def priority(self) -> int:
        return 50
