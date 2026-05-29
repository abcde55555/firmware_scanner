"""Extraction orchestrator with cross-validation logic."""

from collections import defaultdict

from ..core.context import AnalysisContext, AnalysisError
from .models import Component, VersionConfidence, ExtractionMethod
from .extractors.base import BaseExtractor
from .extractors.string_patterns import StringPatternExtractor
from .extractors.symbol_table import SymbolTableExtractor
from .extractors.disassembly import DisassemblyExtractor
from .extractors.binary_signatures import BinarySignatureExtractor
from .extractors.radare2_ext import Radare2Extractor
from .extractors.ghidra_ext import GhidraExtractor
from .extractors.manifest_scanner import ManifestScannerExtractor


METHOD_WEIGHTS: dict[ExtractionMethod, float] = {
    ExtractionMethod.GHIDRA: 0.95,
    ExtractionMethod.RADARE2: 0.90,
    ExtractionMethod.SYMBOL_TABLE: 0.85,
    ExtractionMethod.DISASSEMBLY: 0.75,
    ExtractionMethod.BINARY_SIGNATURE: 0.80,
    ExtractionMethod.STRING_PATTERN: 0.60,
    ExtractionMethod.RTOS_PLUGIN: 0.85,
}


class ExtractionOrchestrator:
    def __init__(
        self,
        r2_path: str = "r2",
        ghidra_path: str = "",
        enabled_extractors: list[str] | None = None,
        skip_extractors: list[str] | None = None,
    ):
        self._extractors: list[BaseExtractor] = self._build_extractors(
            r2_path, ghidra_path, enabled_extractors, skip_extractors
        )

    def _build_extractors(
        self,
        r2_path: str,
        ghidra_path: str,
        enabled: list[str] | None,
        skipped: list[str] | None,
    ) -> list[BaseExtractor]:
        all_extractors: list[BaseExtractor] = [
            ManifestScannerExtractor(),
            StringPatternExtractor(),
            SymbolTableExtractor(),
            DisassemblyExtractor(),
            BinarySignatureExtractor(),
            Radare2Extractor(r2_path),
            GhidraExtractor(ghidra_path),
        ]

        if enabled:
            all_extractors = [e for e in all_extractors if e.name in enabled]
        if skipped:
            all_extractors = [e for e in all_extractors if e.name not in skipped]

        all_extractors.sort(key=lambda e: e.priority, reverse=True)
        return all_extractors

    async def run_all(self, context: AnalysisContext) -> list[Component]:
        raw_components: list[Component] = []

        for extractor in self._extractors:
            if not extractor.is_available():
                context.warnings.append(f"Extractor '{extractor.name}' unavailable, skipping")
                continue
            try:
                results = await extractor.extract(context)
                raw_components.extend(results)
            except Exception as e:
                context.errors.append(
                    AnalysisError(
                        stage=f"extraction.{extractor.name}",
                        message=str(e),
                        fatal=False,
                    )
                )

        return self._cross_validate(raw_components)

    def _cross_validate(self, components: list[Component]) -> list[Component]:
        """Merge duplicates, resolve versions via weighted voting."""
        groups: dict[str, list[Component]] = defaultdict(list)
        for comp in components:
            key = self._normalize_name(comp.name)
            groups[key].append(comp)

        final: list[Component] = []
        for key, group in groups.items():
            merged = self._merge_group(group)
            final.append(merged)

        final.sort(key=lambda c: c.name.lower())
        return final

    def _merge_group(self, group: list[Component]) -> Component:
        """Merge multiple detections of the same component."""
        base = group[0]
        all_versions: list[VersionConfidence] = []

        for comp in group:
            for vc in comp.versions:
                weighted_conf = vc.confidence * METHOD_WEIGHTS.get(vc.method, 0.5)
                all_versions.append(vc.model_copy(update={"confidence": weighted_conf}))

        # Vote on best version
        version_scores: dict[str, float] = defaultdict(float)
        version_methods: dict[str, set] = defaultdict(set)

        for vc in all_versions:
            if vc.version and vc.version != "detected":
                version_scores[vc.version] += vc.confidence
                version_methods[vc.version].add(vc.method)

        # Multi-source bonus
        for version, methods in version_methods.items():
            if len(methods) >= 2:
                version_scores[version] *= 1.2
            if len(methods) >= 3:
                version_scores[version] *= 1.1

        best_version = ""
        if version_scores:
            best_version = max(version_scores, key=version_scores.get)
        elif all_versions:
            best_version = "detected (version unknown)"

        # Pick best vendor/type from highest-confidence source
        best_vendor = base.vendor
        best_type = base.component_type
        for comp in group:
            if comp.vendor and not best_vendor:
                best_vendor = comp.vendor
            if comp.component_type != "library":
                best_type = comp.component_type

        # Generate PURL
        purl = self._generate_purl(base.name, best_version, best_vendor)

        return Component(
            name=base.name,
            vendor=best_vendor,
            versions=all_versions,
            resolved_version=best_version,
            component_type=best_type,
            purl=purl,
            licenses=base.licenses,
            description=base.description,
        )

    def _normalize_name(self, name: str) -> str:
        return name.lower().replace("-", "").replace("_", "").replace(" ", "").replace("/", "")

    def _generate_purl(self, name: str, version: str, vendor: str) -> str:
        if not version or version.startswith("detected"):
            return ""
        name_slug = name.lower().replace(" ", "-").replace("/", "-")
        return f"pkg:generic/{name_slug}@{version}"
