"""Plugin extension system for adding custom scanners, signatures, and analysis tools."""

import importlib
import json
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..core.context import AnalysisContext
from ..extraction.models import Component
from ..extraction.deep_scanner import SignatureEntry, VersionPatternEntry, ComponentDatabase


@runtime_checkable
class AnalyzerPlugin(Protocol):
    """Protocol for analyzer plugins."""

    @property
    def name(self) -> str:
        ...

    @property
    def version(self) -> str:
        ...

    def get_signatures(self) -> list[SignatureEntry]:
        ...

    def get_version_patterns(self) -> list[VersionPatternEntry]:
        ...

    async def analyze(self, context: AnalysisContext) -> list[Component]:
        ...


class PluginManager:
    """Manages loading and executing analysis plugins."""

    def __init__(self):
        self._plugins: list[AnalyzerPlugin] = []
        self._plugin_dirs: list[Path] = []

    def register_plugin(self, plugin: AnalyzerPlugin) -> None:
        self._plugins.append(plugin)

    def add_plugin_dir(self, path: Path) -> None:
        """Add a directory to scan for plugins."""
        if path.exists() and path.is_dir():
            self._plugin_dirs.append(path)

    def load_plugins(self) -> None:
        """Discover and load plugins from registered directories."""
        for plugin_dir in self._plugin_dirs:
            self._load_from_dir(plugin_dir)

    def load_signature_file(self, path: Path) -> list[SignatureEntry]:
        """Load additional signatures from a JSON file."""
        entries = []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for item in data.get("signatures", []):
                entries.append(SignatureEntry(
                    pattern=item["pattern"],
                    name=item["name"],
                    vendor=item.get("vendor", ""),
                    component_type=item.get("type", "library"),
                ))
            for item in data.get("version_patterns", []):
                # These go separately
                pass
        except Exception:
            pass
        return entries

    def load_version_patterns_file(self, path: Path) -> list[VersionPatternEntry]:
        """Load additional version patterns from a JSON file."""
        entries = []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for item in data.get("version_patterns", []):
                entries.append(VersionPatternEntry(
                    pattern=item["pattern"],
                    name=item["name"],
                    vendor=item.get("vendor", ""),
                    component_type=item.get("type", "library"),
                ))
        except Exception:
            pass
        return entries

    def enrich_database(self, db: ComponentDatabase) -> None:
        """Add all plugin signatures/patterns to the component database."""
        for plugin in self._plugins:
            try:
                db.add_signatures(plugin.get_signatures())
                db.add_version_patterns(plugin.get_version_patterns())
            except Exception:
                continue

        # Load from signature files in plugin dirs
        for plugin_dir in self._plugin_dirs:
            for json_file in plugin_dir.glob("*.json"):
                sigs = self.load_signature_file(json_file)
                if sigs:
                    db.add_signatures(sigs)
                patterns = self.load_version_patterns_file(json_file)
                if patterns:
                    db.add_version_patterns(patterns)

    async def run_all_plugins(self, context: AnalysisContext) -> list[Component]:
        """Run analyze() on all registered plugins."""
        components: list[Component] = []
        for plugin in self._plugins:
            try:
                result = await plugin.analyze(context)
                components.extend(result)
            except Exception:
                continue
        return components

    def get_loaded_plugins(self) -> list[dict]:
        """Return info about loaded plugins."""
        return [{"name": p.name, "version": p.version} for p in self._plugins]

    def _load_from_dir(self, plugin_dir: Path) -> None:
        """Load Python plugins from a directory."""
        for py_file in plugin_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    f"rtos_plugin_{py_file.stem}", py_file
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    # Look for a class implementing AnalyzerPlugin
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (
                            isinstance(attr, type)
                            and attr_name != "AnalyzerPlugin"
                            and isinstance(attr(), AnalyzerPlugin)
                        ):
                            self._plugins.append(attr())
            except Exception:
                continue
