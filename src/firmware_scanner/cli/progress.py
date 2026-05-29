"""Progress tracking with ETA calculation for Windows-compatible terminals."""

import sys
import time
from dataclasses import dataclass, field


@dataclass
class StageInfo:
    name: str
    total_steps: int = 0
    current_step: int = 0
    start_time: float = 0.0
    weight: float = 1.0  # relative weight for overall progress


class ProgressTracker:
    """Tracks analysis progress across multiple stages with ETA calculation."""

    def __init__(self, verbose: bool = True):
        self._verbose = verbose
        self._stages: list[StageInfo] = []
        self._current_stage_idx: int = -1
        self._overall_start: float = 0.0
        self._stage_weights: dict[str, float] = {
            "load": 0.05,
            "unpack": 0.05,
            "arch_detect": 0.05,
            "rtos_detect": 0.05,
            "extraction": 0.20,
            "deep_scan": 0.45,
            "resolve": 0.10,
            "sbom": 0.05,
        }

    def start(self) -> None:
        self._overall_start = time.time()

    def begin_stage(self, name: str, total_steps: int = 1) -> None:
        stage = StageInfo(
            name=name,
            total_steps=max(total_steps, 1),
            start_time=time.time(),
            weight=self._stage_weights.get(name, 0.1),
        )
        self._stages.append(stage)
        self._current_stage_idx = len(self._stages) - 1
        if self._verbose:
            self._print_stage_start(name)

    def update(self, step: int = 0, detail: str = "") -> None:
        if self._current_stage_idx < 0:
            return
        stage = self._stages[self._current_stage_idx]
        stage.current_step = step
        if self._verbose:
            self._print_progress(stage, detail)

    def finish_stage(self, detail: str = "") -> None:
        if self._current_stage_idx < 0:
            return
        stage = self._stages[self._current_stage_idx]
        stage.current_step = stage.total_steps
        elapsed = time.time() - stage.start_time
        if self._verbose:
            self._print_stage_done(stage, elapsed, detail)

    def get_overall_progress(self) -> float:
        """Return 0.0-1.0 overall progress based on weighted stages."""
        if not self._stages:
            return 0.0
        total_weight = sum(s.weight for s in self._stages)
        completed_weight = sum(
            s.weight * (s.current_step / s.total_steps)
            for s in self._stages
        )
        remaining_weight = sum(
            v for k, v in self._stage_weights.items()
            if k not in [s.name for s in self._stages]
        )
        return completed_weight / (total_weight + remaining_weight) if (total_weight + remaining_weight) > 0 else 0.0

    def get_eta_seconds(self) -> float:
        """Estimate remaining time based on current progress rate."""
        if not self._stages or self._overall_start == 0:
            return 0.0
        elapsed = time.time() - self._overall_start
        progress = self.get_overall_progress()
        if progress <= 0.01:
            return 0.0
        total_estimated = elapsed / progress
        return max(total_estimated - elapsed, 0.0)

    def format_eta(self) -> str:
        eta = self.get_eta_seconds()
        if eta <= 0:
            return ""
        if eta < 60:
            return f"ETA: {eta:.0f}s"
        return f"ETA: {eta/60:.1f}m"

    def _print_stage_start(self, name: str) -> None:
        overall = self.get_overall_progress()
        eta_str = self.format_eta()
        pct = f"{overall*100:.0f}%"
        prefix = f"[{pct:>4s}]"
        eta_part = f"  ({eta_str})" if eta_str else ""
        sys.stdout.write(f"{prefix} {name}...{eta_part}\n")
        sys.stdout.flush()

    def _print_progress(self, stage: StageInfo, detail: str) -> None:
        if stage.total_steps <= 1:
            return
        pct = stage.current_step / stage.total_steps * 100
        overall = self.get_overall_progress()
        eta_str = self.format_eta()
        bar_width = 30
        filled = int(bar_width * stage.current_step / stage.total_steps)
        bar = "#" * filled + "-" * (bar_width - filled)
        detail_str = f" {detail}" if detail else ""
        eta_part = f"  {eta_str}" if eta_str else ""
        line = f"       [{bar}] {pct:5.1f}% ({stage.current_step}/{stage.total_steps}){detail_str}{eta_part}"
        sys.stdout.write(f"\r{line}")
        sys.stdout.flush()
        if stage.current_step >= stage.total_steps:
            sys.stdout.write("\n")
            sys.stdout.flush()

    def _print_stage_done(self, stage: StageInfo, elapsed: float, detail: str) -> None:
        detail_str = f" - {detail}" if detail else ""
        sys.stdout.write(f"       Done in {elapsed:.1f}s{detail_str}\n")
        sys.stdout.flush()

    def print_summary(self) -> None:
        if not self._overall_start:
            return
        total_time = time.time() - self._overall_start
        sys.stdout.write(f"\n[100%] Analysis complete in {total_time:.1f}s\n")
        sys.stdout.flush()
