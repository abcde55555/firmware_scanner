"""Scan telemetry logging for optimization analysis.

Collects per-stage timing, component counts, and pipeline metadata,
then writes structured JSON logs for post-hoc analysis.
"""

import json
import re
import time
from datetime import datetime
from pathlib import Path


class ScanLog:
    """Accumulates scan telemetry and persists to structured JSON."""

    def __init__(self):
        self._meta: dict = {}
        self._config: dict = {}
        self._stages: dict = {}
        self._stage_starts: dict = {}
        self._results: dict = {}
        self._start_time = time.perf_counter()
        self._timestamp = datetime.now()

    def set_meta(self, firmware_path: str, size: int, sha256: str, md5: str):
        self._meta = {
            "scanner_version": "0.1.0",
            "timestamp": self._timestamp.isoformat(timespec="seconds"),
            "firmware_path": str(firmware_path),
            "firmware_name": Path(firmware_path).name,
            "firmware_size": size,
            "sha256": sha256,
            "md5": md5,
        }

    def set_config(self, config, deep_scan: bool = True, plugin_dir=None):
        self._config = {
            "max_file_size_mb": config.max_file_size // (1024 * 1024),
            "deep_scan": deep_scan,
            "extractors": config.extractors,
            "skip_extractors": config.skip_extractors,
            "plugin_dir": str(plugin_dir) if plugin_dir else None,
            "rtos_hint": config.rtos_hint or None,
            "arch_hint": config.arch_hint or None,
        }

    def start_stage(self, name: str):
        self._stage_starts[name] = time.perf_counter()

    def end_stage(self, name: str, **results):
        elapsed_ms = 0
        if name in self._stage_starts:
            elapsed_ms = int((time.perf_counter() - self._stage_starts[name]) * 1000)
        stage_data = {"duration_ms": elapsed_ms}
        stage_data.update(results)
        self._stages[name] = stage_data

    def set_final_results(self, components_before_dedup: int, final_components: list):
        comp_summaries = []
        for c in final_components:
            methods = list(set(v.method.value for v in c.versions))
            max_conf = max((v.confidence for v in c.versions), default=0)
            comp_summaries.append({
                "name": c.name,
                "version": c.resolved_version or None,
                "vendor": c.vendor or None,
                "methods": methods,
                "confidence": round(max_conf, 2),
            })
        self._results = {
            "total_before_dedup": components_before_dedup,
            "total_after_dedup": len(final_components),
            "components": comp_summaries,
        }

    def save(self, log_dir: Path):
        """Write full telemetry JSON and append to scan index."""
        log_dir = Path(log_dir)
        scans_dir = log_dir / "scans"
        scans_dir.mkdir(parents=True, exist_ok=True)

        total_duration = round(time.perf_counter() - self._start_time, 2)

        full_record = {
            "meta": self._meta,
            "config": self._config,
            "pipeline": self._stages,
            "results": self._results,
            "total_duration_s": total_duration,
        }

        # Generate filename
        ts_str = self._timestamp.strftime("%Y%m%d_%H%M%S")
        name_slug = _slugify(self._meta.get("firmware_name", "unknown"))
        sha_prefix = self._meta.get("sha256", "000000")[:6]
        filename = f"{ts_str}_{name_slug}_{sha_prefix}.json"

        # Write full telemetry
        scan_path = scans_dir / filename
        scan_path.write_text(json.dumps(full_record, indent=2, ensure_ascii=False), encoding="utf-8")

        # Append to index
        index_entry = {
            "timestamp": self._meta.get("timestamp", ""),
            "firmware": self._meta.get("firmware_name", ""),
            "size_bytes": self._meta.get("firmware_size", 0),
            "sha256": self._meta.get("sha256", ""),
            "format": self._stages.get("format_detection", {}).get("format", "Unknown"),
            "os_detected": self._stages.get("rtos_detection", {}).get("detected", "Unknown"),
            "total_components": self._results.get("total_after_dedup", 0),
            "scan_duration_s": total_duration,
            "log_file": f"scans/{filename}",
        }

        index_path = log_dir / "scan_index.jsonl"
        with open(index_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(index_entry, ensure_ascii=False) + "\n")

        return scan_path


def _slugify(name: str) -> str:
    """Convert filename to safe slug for log filenames."""
    name = name.rsplit(".", 1)[0] if "." in name else name
    name = re.sub(r"[^\w\-]", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    return name[:40].lower()
