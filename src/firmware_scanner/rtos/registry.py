"""RTOS plugin registry and detection orchestrator."""

from ..core.context import AnalysisContext
from .base import RTOSPlugin


class RTOSRegistry:
    _plugins: list[type[RTOSPlugin]] = []

    @classmethod
    def register(cls, plugin_class: type[RTOSPlugin]) -> type[RTOSPlugin]:
        cls._plugins.append(plugin_class)
        return plugin_class

    @classmethod
    def get_all(cls) -> list[type[RTOSPlugin]]:
        return cls._plugins.copy()

    @classmethod
    def detect(cls, context: AnalysisContext) -> list[tuple[RTOSPlugin, float]]:
        """Run detection across all plugins, return sorted by confidence."""
        results: list[tuple[RTOSPlugin, float]] = []
        for plugin_cls in cls._plugins:
            try:
                plugin = plugin_cls()
                confidence = plugin.detect(context)
                if confidence > 0.1:
                    results.append((plugin, confidence))
            except Exception:
                continue
        results.sort(key=lambda x: x[1], reverse=True)
        return results


def _load_builtin_plugins():
    """Import all built-in plugins to trigger registration."""
    from .plugins import (  # noqa: F401
        freertos,
        zephyr,
        rt_thread,
        esp_idf,
        vxworks,
        threadx,
        nuttx,
        liteos,
        ucos,
    )


_load_builtin_plugins()
