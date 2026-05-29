"""User configuration file management and dependency detection."""

import json
import shutil
import platform
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_DIR = Path.home() / ".rtos-analyzer"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"

DEFAULT_CONFIG = {
    "tools": {
        "radare2_path": "",
        "ghidra_path": "",
        "binwalk_path": "",
    },
    "analysis": {
        "deep_scan": True,
        "max_threads": 4,
        "timeout": 300,
        "max_file_size_mb": 512,
    },
    "output": {
        "default_format": "cyclonedx",
        "include_evidence": True,
        "min_confidence": 0.3,
    },
    "plugins": {
        "plugin_dirs": [],
        "disabled_extractors": [],
    },
}


class UserConfig:
    """Manages user configuration with graceful defaults."""

    def __init__(self, config_path: Path | None = None):
        self._path = config_path or DEFAULT_CONFIG_FILE
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                self._data = json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:
                self._data = DEFAULT_CONFIG.copy()
        else:
            self._data = DEFAULT_CONFIG.copy()

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(self._data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def get(self, section: str, key: str, default: Any = None) -> Any:
        return self._data.get(section, {}).get(key, default)

    def set(self, section: str, key: str, value: Any) -> None:
        if section not in self._data:
            self._data[section] = {}
        self._data[section][key] = value

    @property
    def radare2_path(self) -> str:
        return self.get("tools", "radare2_path", "")

    @property
    def ghidra_path(self) -> str:
        return self.get("tools", "ghidra_path", "")

    @property
    def binwalk_path(self) -> str:
        return self.get("tools", "binwalk_path", "")

    @property
    def max_threads(self) -> int:
        return self.get("analysis", "max_threads", 4)

    @property
    def deep_scan(self) -> bool:
        return self.get("analysis", "deep_scan", True)

    @property
    def disabled_extractors(self) -> list[str]:
        return self.get("plugins", "disabled_extractors", [])

    @property
    def plugin_dirs(self) -> list[str]:
        return self.get("plugins", "plugin_dirs", [])

    @property
    def config_path(self) -> Path:
        return self._path


class DependencyChecker:
    """Check availability of all external tools and report status."""

    def check_all(self) -> dict[str, dict[str, Any]]:
        """Return status of all dependencies."""
        results = {}

        # Python packages
        results["capstone"] = self._check_python_package("capstone")
        results["lief"] = self._check_python_package("lief")
        results["intelhex"] = self._check_python_package("intelhex")
        results["pyhidra"] = self._check_python_package_safe("pyhidra")
        results["r2pipe"] = self._check_python_package("r2pipe")

        # External tools
        results["radare2"] = self._check_tool("r2", alt_names=["radare2"])
        results["ghidra"] = self._check_ghidra()
        results["binwalk"] = self._check_tool("binwalk")

        return results

    def _check_python_package(self, name: str) -> dict[str, Any]:
        try:
            mod = __import__(name)
            version = getattr(mod, "__version__", getattr(mod, "version", "unknown"))
            return {"available": True, "version": str(version), "type": "python_package"}
        except ImportError:
            return {"available": False, "version": None, "type": "python_package"}

    def _check_python_package_safe(self, name: str) -> dict[str, Any]:
        """Check package without triggering side effects (like Ghidra env check)."""
        try:
            import importlib.util
            spec = importlib.util.find_spec(name)
            if spec is not None:
                return {"available": True, "version": "installed (not loaded)", "type": "python_package",
                        "note": "Requires GHIDRA_INSTALL_DIR env variable to function"}
            return {"available": False, "version": None, "type": "python_package"}
        except Exception:
            return {"available": False, "version": None, "type": "python_package"}

    def _check_tool(self, name: str, alt_names: list[str] | None = None) -> dict[str, Any]:
        path = shutil.which(name)
        if path:
            return {"available": True, "path": path, "type": "external_tool"}
        if alt_names:
            for alt in alt_names:
                path = shutil.which(alt)
                if path:
                    return {"available": True, "path": path, "type": "external_tool"}
        return {"available": False, "path": None, "type": "external_tool"}

    def _check_ghidra(self) -> dict[str, Any]:
        import os
        ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR", "")
        if ghidra_dir and Path(ghidra_dir).exists():
            return {"available": True, "path": ghidra_dir, "type": "external_tool"}
        # Check common locations
        common_paths = [
            Path.home() / "ghidra",
            Path("/opt/ghidra"),
            Path("C:/ghidra"),
            Path("C:/Program Files/ghidra"),
        ]
        for p in common_paths:
            if p.exists() and (p / "support").exists():
                return {"available": True, "path": str(p), "type": "external_tool"}
        return {"available": False, "path": None, "type": "external_tool",
                "note": "Set GHIDRA_INSTALL_DIR or configure in config.json"}


def init_config() -> UserConfig:
    """Initialize config file on first run. Returns the config."""
    config = UserConfig()
    if not config.config_path.exists():
        config.save()
    return config


def print_dependency_report(results: dict[str, dict[str, Any]]) -> str:
    """Format dependency check results as a readable report."""
    lines = ["Dependency Status Report", "=" * 50, ""]

    required = ["capstone", "lief", "intelhex"]
    optional = ["r2pipe", "pyhidra", "radare2", "ghidra", "binwalk"]

    lines.append("Required Dependencies:")
    for name in required:
        info = results.get(name, {})
        status = "OK" if info.get("available") else "MISSING"
        version = info.get("version", "")
        lines.append(f"  [{status:7s}] {name:15s} {version}")

    lines.append("")
    lines.append("Optional Dependencies (empty config = skip, no errors):")
    for name in optional:
        info = results.get(name, {})
        status = "OK" if info.get("available") else "not found"
        detail = info.get("path") or info.get("version") or ""
        note = info.get("note", "")
        line = f"  [{status:10s}] {name:15s} {detail}"
        if note:
            line += f"  ({note})"
        lines.append(line)

    lines.append("")
    lines.append(f"Config file: {DEFAULT_CONFIG_FILE}")
    lines.append("(Set tool paths in config to enable optional features)")

    return "\n".join(lines)
