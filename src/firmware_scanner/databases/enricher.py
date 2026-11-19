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
    nsrl_queried_files: int = 0
    nsrl_matched_files: int = 0
    nsrl_distribution_rows: int = 0
    blint_queried_files: int = 0
    blint_candidate_files: int = 0
    blint_candidate_rows: int = 0
    blint_reviewed_components: int = 0
    blint_identity_confirmations: int = 0
    blint_reference_version_agreements: int = 0
    blint_reference_version_mismatches: int = 0
    blint_reference_version_not_comparable: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "files_queried": self.files_queried,
            "nsrl_queried_files": self.nsrl_queried_files,
            "nsrl_matched_files": self.nsrl_matched_files,
            "nsrl_distribution_rows": self.nsrl_distribution_rows,
            "blint_queried_files": self.blint_queried_files,
            "blint_candidate_files": self.blint_candidate_files,
            "blint_candidate_rows": self.blint_candidate_rows,
            "blint_reviewed_components": self.blint_reviewed_components,
            "blint_identity_confirmations": self.blint_identity_confirmations,
            "blint_reference_version_agreements": self.blint_reference_version_agreements,
            "blint_reference_version_mismatches": self.blint_reference_version_mismatches,
            "blint_reference_version_not_comparable": (self.blint_reference_version_not_comparable),
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
            self.stats.nsrl_queried_files += 1
            try:
                matches = self.nsrl.lookup(digest, len(data))
            except Exception as exc:  # noqa: BLE001 - retain file-scoped DB evidence errors
                self.stats.errors.append(f"NSRL lookup failed for {location}: {type(exc).__name__}")
            else:
                if matches:
                    self.stats.nsrl_matched_files += 1
                    self.stats.nsrl_distribution_rows += len(matches)
                    self._append_property(component, "firmware:nsrl:file-matched", "true")
                    self._append_property(
                        component, "firmware:nsrl:database-release", self.nsrl.manifest.release
                    )
                    self._append_property(
                        component,
                        "firmware:nsrl:distributions",
                        json.dumps(matches[:20], sort_keys=True, ensure_ascii=False),
                    )
        if self.blint is not None:
            self.stats.blint_queried_files += 1
            try:
                candidates = self.blint.candidates(data, filename)
            except Exception as exc:  # noqa: BLE001 - retain file-scoped DB evidence errors
                self.stats.errors.append(
                    f"BLintDB lookup failed for {location}: {type(exc).__name__}"
                )
            else:
                if candidates:
                    self.stats.blint_candidate_files += 1
                    self.stats.blint_candidate_rows += len(candidates)
                    self._append_property(
                        component, "firmware:blintdb:candidate-count", str(len(candidates))
                    )
                    self._append_property(
                        component, "firmware:blintdb:database-release", self.blint.manifest.release
                    )
                    self._append_property(
                        component,
                        "firmware:blintdb:candidates",
                        json.dumps(candidates, sort_keys=True, ensure_ascii=False),
                    )

    def reconcile(self, components: list[Component]) -> None:
        """Compare final component versions with BLint reference candidates."""
        from ..extraction.binary_inventory import identity_key

        reviewed = set()
        confirmed = set()
        compared: dict[tuple, bool] = {}
        not_comparable = set()
        for component in components:
            raw_candidates = next(
                (
                    str(prop.get("value", ""))
                    for prop in component.properties
                    if prop.get("name") == "firmware:blintdb:candidates"
                ),
                "",
            )
            if not raw_candidates:
                continue
            try:
                candidates = json.loads(raw_candidates)
            except (ValueError, TypeError):
                continue
            if not isinstance(candidates, list) or not candidates:
                continue

            target_identity = identity_key(component.name)
            component_key = (
                target_identity,
                component.name.casefold(),
                component.resolved_version,
            )
            reviewed.add(component_key)
            candidate_identities = set()
            confirmed_projects = set()
            confirmed_components = set()
            reference_versions = set()
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue
                project_name = str(candidate.get("project_name", ""))
                if project_name:
                    candidate_identities.add(identity_key(project_name))
                    if identity_key(project_name) == target_identity:
                        confirmed_projects.add(project_name)
                for item in candidate.get("unique_component_versions", []):
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("name", ""))
                    version = str(item.get("version", "")).strip()
                    if name:
                        candidate_identities.add(identity_key(name))
                        if identity_key(name) == target_identity:
                            confirmed_components.add(name)
                    if version and identity_key(name) == target_identity:
                        reference_versions.add(version)

            if target_identity in candidate_identities:
                confirmed.add(component_key)
                self._set_property(
                    component,
                    "firmware:blintdb:identity-confirmed",
                    json.dumps(
                        {
                            "projects": sorted(confirmed_projects),
                            "components": sorted(confirmed_components),
                        },
                        sort_keys=True,
                    ),
                )

            if not component.resolved_version or not reference_versions:
                continue
            resolution_state = next(
                (
                    str(prop.get("value", ""))
                    for prop in component.properties
                    if prop.get("name") == "firmware:version:resolution-state"
                ),
                "",
            )
            if resolution_state != "exact":
                not_comparable.add(component_key)
                self._set_property(
                    component,
                    "firmware:blintdb:reference-version-comparison",
                    json.dumps(
                        {
                            "comparison_status": "not-comparable",
                            "reason": (
                                "target is not an exact release; parent-package "
                                "or source-revision versions are not compared"
                            ),
                            "target_resolution_state": resolution_state,
                            "target_version": component.resolved_version,
                            "reference_versions": sorted(reference_versions),
                            "decision": "diagnostic-only-no-version-overwrite",
                        },
                        sort_keys=True,
                    ),
                )
                continue
            agreement = component.resolved_version in reference_versions
            comparison = {
                "comparison_status": "comparable",
                "target_version": component.resolved_version,
                "reference_versions": sorted(reference_versions),
                "agreement": agreement,
                "decision": "diagnostic-only-no-version-overwrite",
            }
            self._set_property(
                component,
                "firmware:blintdb:reference-version-comparison",
                json.dumps(comparison, sort_keys=True),
            )
            compared[component_key] = agreement
        self.stats.blint_reviewed_components = len(reviewed)
        self.stats.blint_identity_confirmations = len(confirmed)
        self.stats.blint_reference_version_agreements = sum(compared.values())
        self.stats.blint_reference_version_mismatches = sum(
            not agreement for agreement in compared.values()
        )
        self.stats.blint_reference_version_not_comparable = len(not_comparable)

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

    @staticmethod
    def _set_property(component: Component, name: str, value: str) -> None:
        component.properties = [prop for prop in component.properties if prop.get("name") != name]
        component.properties.append({"name": name, "value": value})
