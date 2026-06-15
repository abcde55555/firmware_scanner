"""Deep scanner engine - exhaustive per-section analysis with proximity-based version detection."""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterator, Callable

from ..core.context import AnalysisContext
from ..data import load_component_signatures, load_version_patterns
from ..extraction.models import Component, VersionConfidence, ExtractionMethod
from ..extraction.emba_rules import scan_binary_with_rules
from ..utils.binary import find_strings

logger = logging.getLogger(__name__)


@dataclass
class StringHit:
    offset: int
    value: str
    section_name: str = ""


@dataclass
class ComponentHit:
    name: str
    vendor: str
    component_type: str
    offset: int
    matched_pattern: str
    section_name: str = ""
    nearby_strings: list[str] = field(default_factory=list)


PROXIMITY_WINDOW = 512  # bytes around a component hit to search for version
MAX_SECTION_SCAN_SIZE = 8 * 1024 * 1024  # 8MB max per section for pattern scanning
SCAN_TIMEOUT_PER_SECTION = 30  # seconds


class DeepScanner:
    """Exhaustive firmware scanner that analyzes every section and performs
    proximity-based version detection around each component signature hit."""

    def __init__(self, component_db: "ComponentDatabase", max_threads: int = 4,
                 progress_callback: Callable[[int, int, str], None] | None = None):
        self._db = component_db
        self._max_threads = max_threads
        self._progress_callback = progress_callback

    def scan(self, context: AnalysisContext) -> list[Component]:
        """Perform deep scan across all firmware sections using thread pool."""
        sections_to_scan = self._get_sections(context)
        total_sections = len(sections_to_scan)

        all_hits: list[ComponentHit] = []
        completed = 0

        if self._progress_callback:
            self._progress_callback(0, total_sections, "Starting deep scan...")

        # Multi-threaded section scanning
        with ThreadPoolExecutor(max_workers=self._max_threads) as executor:
            futures = {}
            for section_name, section_data in sections_to_scan:
                future = executor.submit(self._scan_one_section, section_data, section_name)
                futures[future] = section_name

            for future in as_completed(futures, timeout=SCAN_TIMEOUT_PER_SECTION * total_sections):
                section_name = futures[future]
                completed += 1
                try:
                    hits = future.result(timeout=SCAN_TIMEOUT_PER_SECTION)
                    all_hits.extend(hits)
                except TimeoutError:
                    pass
                except Exception as e:  # noqa: BLE001
                    logger.debug(f"Non-critical operation failed: {e}")
                if self._progress_callback:
                    self._progress_callback(completed, total_sections, f"Scanned: {section_name}")

        # Phase 4: Resolve versions from nearby strings (uses raw_data, single-threaded)
        if self._progress_callback:
            self._progress_callback(total_sections, total_sections, "Resolving versions...")

        components = self._resolve_components(all_hits, context)

        # Phase 5: Run EMBA static rules on all sections for additional detections
        if self._progress_callback:
            self._progress_callback(total_sections, total_sections, "Running EMBA rules...")
        existing_names = {c.name.lower() for c in components}
        for section_name, section_data in sections_to_scan:
            if len(section_data) < 64:
                continue
            emba_components = scan_binary_with_rules(section_data, section_name)
            for ec in emba_components:
                if ec.name.lower() not in existing_names:
                    components.append(ec)
                    existing_names.add(ec.name.lower())

        return components

    def _scan_one_section(self, section_data: bytes, section_name: str) -> list[ComponentHit]:
        """Scan a single section - designed to run in a thread."""
        # Limit large sections to avoid hanging
        scan_data = section_data[:MAX_SECTION_SCAN_SIZE]
        hits = self._scan_section(scan_data, section_name)
        # For each hit, extract nearby strings for version detection
        strings_in_section = find_strings(scan_data, min_length=4)
        for hit in hits:
            hit.nearby_strings = self._get_nearby_strings(
                hit.offset, strings_in_section, scan_data
            )
        return hits

    def _get_sections(self, context: AnalysisContext) -> list[tuple[str, bytes]]:
        """Get all analyzable data sections from the firmware."""
        sections: list[tuple[str, bytes]] = []

        # Always include the full raw data as a section
        sections.append(("raw_firmware", context.raw_data))

        # Add unpacked sections
        if context.unpack_result:
            for section in context.unpack_result.sections:
                if section.data and len(section.data) > 16:
                    sections.append((section.name, section.data))

        return sections

    def _scan_section(self, data: bytes, section_name: str) -> list[ComponentHit]:
        """Scan a section for all known component signatures."""
        hits: list[ComponentHit] = []

        for entry in self._db.get_all_signatures():
            pattern_bytes = entry.pattern.encode("ascii", errors="ignore")
            # Skip very short patterns (too many false positives)
            if len(pattern_bytes) < 5:
                continue
            # For patterns under 8 bytes, require word boundary (not inside another word)
            require_boundary = len(pattern_bytes) < 8
            offset = 0
            while True:
                pos = data.find(pattern_bytes, offset)
                if pos == -1:
                    break
                # Word boundary check: byte before must not be alphanumeric
                if require_boundary and pos > 0:
                    prev_byte = data[pos - 1]
                    if (0x30 <= prev_byte <= 0x39) or (0x41 <= prev_byte <= 0x5A) or (0x61 <= prev_byte <= 0x7A) or prev_byte == 0x5F:
                        offset = pos + len(pattern_bytes)
                        continue
                hits.append(ComponentHit(
                    name=entry.name,
                    vendor=entry.vendor,
                    component_type=entry.component_type,
                    offset=pos,
                    matched_pattern=entry.pattern,
                    section_name=section_name,
                ))
                offset = pos + len(pattern_bytes)

        # Also scan with regex patterns for version-embedded strings
        text = data.decode("ascii", errors="ignore")
        for entry in self._db.get_all_version_patterns():
            for match in re.finditer(entry.pattern, text):
                hits.append(ComponentHit(
                    name=entry.name,
                    vendor=entry.vendor,
                    component_type=entry.component_type,
                    offset=match.start(),
                    matched_pattern=match.group(0),
                    section_name=section_name,
                    nearby_strings=[match.group(0)],
                ))

        return hits

    def _get_nearby_strings(
        self, offset: int, all_strings: list[tuple[int, str]], data: bytes
    ) -> list[str]:
        """Get strings within PROXIMITY_WINDOW bytes of the hit."""
        nearby = []
        window_start = max(0, offset - PROXIMITY_WINDOW)
        window_end = offset + PROXIMITY_WINDOW

        for str_offset, str_value in all_strings:
            if window_start <= str_offset <= window_end:
                nearby.append(str_value)

        return nearby

    def _resolve_components(
        self, hits: list[ComponentHit], context: AnalysisContext
    ) -> list[Component]:
        """Merge hits and resolve versions using all available evidence."""
        # Group hits by component name
        groups: dict[str, list[ComponentHit]] = {}
        for hit in hits:
            key = hit.name.lower()
            if key not in groups:
                groups[key] = []
            groups[key].append(hit)

        components: list[Component] = []
        for key, group in groups.items():
            # Check if any hit came from a version pattern (high confidence, one is enough)
            has_version_hit = any(h.nearby_strings and h.matched_pattern == h.nearby_strings[0] for h in group)
            if not has_version_hit:
                # For pure signature hits, require at least 2 distinct patterns
                unique_patterns = set(h.matched_pattern for h in group)
                if len(unique_patterns) < 2:
                    continue
            comp = self._merge_hits(group, context)
            if comp:
                components.append(comp)

        return components

    def _merge_hits(self, hits: list[ComponentHit], context: AnalysisContext) -> Component | None:
        if not hits:
            return None

        base = hits[0]
        # Collect all nearby strings for version extraction
        all_nearby = []
        for hit in hits:
            all_nearby.extend(hit.nearby_strings)

        # Try to extract version from nearby strings
        version = self._extract_version_from_context(base.name, all_nearby, context.raw_data)

        # Calculate confidence based on number of hits and methods
        unique_sections = set(h.section_name for h in hits)
        confidence = min(0.4 + len(hits) * 0.05 + len(unique_sections) * 0.1, 0.95)
        if version:
            confidence = min(confidence + 0.15, 0.95)

        evidence_parts = []
        unique_patterns = set(h.matched_pattern for h in hits)
        evidence_parts.append(f"Matched: {', '.join(list(unique_patterns)[:3])}")
        evidence_parts.append(f"Hits: {len(hits)} across {len(unique_sections)} sections")

        return Component(
            name=base.name,
            vendor=base.vendor,
            component_type=base.component_type,
            resolved_version=version or "detected (version unknown)",
            versions=[VersionConfidence(
                version=version or "detected",
                confidence=confidence,
                method=ExtractionMethod.STRING_PATTERN,
                evidence=" | ".join(evidence_parts),
            )],
            purl=f"pkg:generic/{base.name.lower().replace(' ', '-')}@{version}" if version else "",
        )

    def _extract_version_from_context(
        self, component_name: str, nearby_strings: list[str], raw_data: bytes
    ) -> str:
        """Try multiple strategies to extract version for a component."""
        # Strategy 1: Look in nearby strings for version patterns
        version = self._find_version_in_strings(nearby_strings, component_name)
        if version:
            return version

        # Strategy 2: Search globally for "ComponentName vX.Y.Z" patterns
        version = self._search_global_version(component_name, raw_data)
        if version:
            return version

        # Strategy 3: Look for version defines (e.g., COMPONENT_VERSION "X.Y.Z")
        version = self._search_version_defines(component_name, raw_data)
        if version:
            return version

        return ""

    def _find_version_in_strings(self, strings: list[str], comp_name: str) -> str:
        """Search nearby strings for version number patterns."""
        version_re = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[-_.]\w+)?)")

        for s in strings:
            # Direct version match in the string
            if comp_name.lower() in s.lower():
                match = version_re.search(s)
                if match:
                    v = match.group(1)
                    if self._is_plausible_version(v):
                        return v

        # Second pass: look for standalone version patterns
        for s in strings:
            if re.match(r"^[Vv]?\d+\.\d+\.\d+", s):
                v = version_re.search(s).group(1)
                if self._is_plausible_version(v):
                    return v

        return ""

    def _search_global_version(self, comp_name: str, data: bytes) -> str:
        """Search entire firmware for component name + version pattern."""
        text = data.decode("ascii", errors="ignore")
        # Try common patterns
        patterns = [
            rf"{re.escape(comp_name)}\s+[Vv]?(\d+\.\d+(?:\.\d+)?)",
            rf"{re.escape(comp_name)}[/\-_](\d+\.\d+(?:\.\d+)?)",
            rf"{re.escape(comp_name)}\s+version\s+(\d+\.\d+(?:\.\d+)?)",
        ]
        for pat in patterns:
            match = re.search(pat, text, re.IGNORECASE)
            if match:
                v = match.group(1)
                if self._is_plausible_version(v):
                    return v
        return ""

    def _search_version_defines(self, comp_name: str, data: bytes) -> str:
        """Search for C-style version defines."""
        text = data.decode("ascii", errors="ignore")
        name_upper = comp_name.upper().replace(" ", "_").replace("-", "_")
        patterns = [
            rf"{name_upper}_VERSION\s+\"(\d+\.\d+(?:\.\d+)?)\"",
            rf"{name_upper}_VERSION_STRING\s+\"(\d+\.\d+(?:\.\d+)?)\"",
            rf"{name_upper}_VER\s+\"(\d+\.\d+(?:\.\d+)?)\"",
            rf"{name_upper}_VERSION_MAJOR\s+(\d+)",
        ]
        for pat in patterns:
            match = re.search(pat, text)
            if match:
                return match.group(1)

        # Try to combine MAJOR.MINOR.PATCH
        major_pat = rf"{name_upper}_VERSION_MAJOR\s+(\d+)"
        minor_pat = rf"{name_upper}_VERSION_MINOR\s+(\d+)"
        patch_pat = rf"{name_upper}_VERSION_PATCH\s+(\d+)"

        major_m = re.search(major_pat, text)
        minor_m = re.search(minor_pat, text)
        if major_m and minor_m:
            patch_m = re.search(patch_pat, text)
            patch = patch_m.group(1) if patch_m else "0"
            return f"{major_m.group(1)}.{minor_m.group(1)}.{patch}"

        return ""

    def _is_plausible_version(self, version: str) -> bool:
        """Check if a version string is plausible (not a date, IP, or protocol number)."""
        parts = version.split(".")
        if len(parts) < 2:
            return False
        try:
            major = int(parts[0])
            if major > 999:  # Likely a date or IP
                return False
            # Reject IEEE 802.x network protocol numbers (e.g., "802.1", "802.11")
            if 800 <= major <= 899:
                return False
            return True
        except ValueError:
            return False


@dataclass
class SignatureEntry:
    pattern: str
    name: str
    vendor: str
    component_type: str


@dataclass
class VersionPatternEntry:
    pattern: str
    name: str
    vendor: str
    component_type: str


class ComponentDatabase:
    """Database of known component signatures and version patterns."""

    def __init__(self):
        self._signatures: list[SignatureEntry] = []
        self._version_patterns: list[VersionPatternEntry] = []
        self._load_builtin()

    def add_signatures(self, entries: list[SignatureEntry]) -> None:
        self._signatures.extend(entries)

    def add_version_patterns(self, entries: list[VersionPatternEntry]) -> None:
        self._version_patterns.extend(entries)

    def get_all_signatures(self) -> list[SignatureEntry]:
        return self._signatures

    def get_all_version_patterns(self) -> list[VersionPatternEntry]:
        return self._version_patterns

    def _load_builtin(self) -> None:
        """Load the massive built-in signature database."""
        self._signatures = _BUILTIN_SIGNATURES.copy()
        self._version_patterns = _BUILTIN_VERSION_PATTERNS.copy()


# =============================================================================
# BUILT-IN SIGNATURE DATABASE (loaded from JSON)
# =============================================================================


def _get_builtin_signatures() -> list["SignatureEntry"]:
    """Load and prepare builtin signatures from JSON."""
    raw = load_component_signatures()
    return [
        SignatureEntry(
            pattern=entry["pattern"],
            name=entry["name"],
            vendor=entry["vendor"],
            component_type=entry["component_type"],
        )
        for entry in raw
    ]


def _get_builtin_version_patterns() -> list["VersionPatternEntry"]:
    """Load and prepare builtin version patterns from JSON."""
    raw = load_version_patterns()
    return [
        VersionPatternEntry(
            pattern=entry["pattern"],
            name=entry["name"],
            vendor=entry["vendor"],
            component_type=entry["component_type"],
        )
        for entry in raw
    ]


_BUILTIN_SIGNATURES: list[SignatureEntry] = _get_builtin_signatures()
_BUILTIN_VERSION_PATTERNS: list[VersionPatternEntry] = _get_builtin_version_patterns()
