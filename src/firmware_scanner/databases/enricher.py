"""Attach external database evidence without promoting candidate versions."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from ..extraction.models import Component
from .blintdb import BLintDatabase
from .manifest import load_database_manifest
from .nsrl import NSRLDatabase


@dataclass
class DatabaseStats:
    files_queried: int = 0
    nsrl_matched_files: int = 0
    nsrl_distribution_rows: int = 0
    blint_candidate_files: int = 0
    blint_candidate_rows: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "files_queried": self.files_queried,
            "nsrl_matched_files": self.nsrl_matched_files,
            "nsrl_distribution_rows": self.nsrl_distribution_rows,
            "blint_candidate_files": self.blint_candidate_files,
            "blint_candidate_rows": self.blint_candidate_rows,
            "errors": list(self.errors),
        }


class DatabaseEnricher:
    def __init__(
        self,
        *,
        blint: BLintDatabase | None = None,
        nsrl: NSRLDatabase | None = None,
    ):
        self.blint = blint
        self.nsrl = nsrl
        self.stats = DatabaseStats()

    @classmethod
    def from_paths(
        cls,
        *,
        blint_path: Path | None = None,
        nsrl_path: Path | None = None,
        verify_hash: bool = True,
    ) -> DatabaseEnricher:
        blint = None
        nsrl = None
        if blint_path:
            blint_path = Path(blint_path)
            manifest = load_database_manifest(
                "blintdb",
                blint_path,
                verify_hash=verify_hash,
            )
            blint = BLintDatabase(blint_path, manifest, verify_hash=False)
        if nsrl_path:
            nsrl_path = Path(nsrl_path)
            manifest = load_database_manifest(
                "nsrl",
                nsrl_path,
                verify_hash=verify_hash,
            )
            nsrl = NSRLDatabase(nsrl_path, manifest, verify_hash=False)
        return cls(blint=blint, nsrl=nsrl)

    def enrich(
        self,
        component: Component,
        data: bytes,
        filename: str,
        location: str,
    ) -> None:
        if not data.startswith(b"\x7fELF"):
            return
        self.stats.files_queried += 1
        digest = hashlib.sha256(data).hexdigest()
        if self.nsrl is not None:
            try:
                matches = self.nsrl.lookup(digest, len(data))
            except Exception as exc:  # noqa: BLE001 - retain file-scoped DB evidence errors
                self.stats.errors.append(f"NSRL lookup failed for {location}: {type(exc).__name__}")
            else:
                if matches:
                    self.stats.nsrl_matched_files += 1
                    self.stats.nsrl_distribution_rows += len(matches)
                    self._append_property(component, "firmware:nsrl:file-matched", "true")
                    self._append_property(component, "firmware:nsrl:database-release", self.nsrl.manifest.release)
                    self._append_property(
                        component,
                        "firmware:nsrl:distributions",
                        json.dumps(matches[:20], sort_keys=True, ensure_ascii=False),
                    )
        if self.blint is not None and not component.resolved_version:
            try:
                candidates = self.blint.candidates(data, filename)
            except Exception as exc:  # noqa: BLE001 - retain file-scoped DB evidence errors
                self.stats.errors.append(f"BLintDB lookup failed for {location}: {type(exc).__name__}")
            else:
                if candidates:
                    self.stats.blint_candidate_files += 1
                    self.stats.blint_candidate_rows += len(candidates)
                    self._append_property(component, "firmware:blintdb:candidate-count", str(len(candidates)))
                    self._append_property(component, "firmware:blintdb:database-release", self.blint.manifest.release)
                    self._append_property(
                        component,
                        "firmware:blintdb:candidates",
                        json.dumps(candidates, sort_keys=True, ensure_ascii=False),
                    )

    def close(self) -> None:
        if self.blint is not None:
            self.blint.close()
        if self.nsrl is not None:
            self.nsrl.close()

    @staticmethod
    def _append_property(component: Component, name: str, value: str) -> None:
        row = {"name": name, "value": value}
        if row not in component.properties:
            component.properties.append(row)
