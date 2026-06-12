"""RTOS plugin registry and detection orchestrator."""

import logging

from ..core.context import AnalysisContext
from .base import RTOSPlugin

logger = logging.getLogger(__name__)


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

        # Check for Linux/Android markers — suppress RTOS if found
        data = context.raw_data[:8 * 1024 * 1024]  # Check first 8MB
        is_linux = (
            b"Linux version " in data
            or b"ro.build.version.release=" in data
            or b"AndroidManifest" in data
            or b"OpenWrt" in data
        )

        for plugin_cls in cls._plugins:
            try:
                plugin = plugin_cls()
                confidence = plugin.detect(context)
                if confidence >= 0.3:
                    # Suppress RTOS detections for Linux/Android firmware
                    if is_linux and plugin.rtos_name not in ("Linux", "OpenWrt"):
                        continue
                    results.append((plugin, confidence))
            except Exception as e:  # noqa: BLE001
                logger.debug(f"Non-critical operation failed: {e}")
                continue
        results.sort(key=lambda x: x[1], reverse=True)
        return results


def _load_builtin_plugins():
    """Import all built-in plugins to trigger registration."""
    from .plugins import (  # noqa: F401
        linux,
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
