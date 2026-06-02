"""EMBA-compatible static version detection rule engine.

Loads EMBA's bin_version_identifiers rules (529 components) and applies them
to binary data to extract component versions via regex pattern matching.
"""

import json
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from functools import lru_cache
from typing import Callable

from .models import Component, VersionConfidence, ExtractionMethod


@dataclass
class EmbaRule:
    identifier: str
    vendor: str
    product: str
    licenses: list[str]
    grep_patterns: list[re.Pattern] = field(default_factory=list)
    version_extractors: list[Callable[[str], tuple[str, str, str] | None]] = field(default_factory=list)
    strict_patterns: list[re.Pattern] = field(default_factory=list)
    affected_paths: list[str] = field(default_factory=list)


_RULES_CACHE: list[EmbaRule] | None = None


def get_rules() -> list[EmbaRule]:
    """Get the singleton loaded rule set."""
    global _RULES_CACHE
    if _RULES_CACHE is None:
        _RULES_CACHE = _load_bundled_rules()
    return _RULES_CACHE


def _load_bundled_rules() -> list[EmbaRule]:
    """Load rules from the bundled emba_rules.json."""
    rules_path = Path(__file__).parent.parent / "data" / "emba_rules.json"
    if not rules_path.exists():
        return []
    data = json.loads(rules_path.read_text(encoding="utf-8"))
    return [_parse_rule(r) for r in data if r.get("grep_commands") or r.get("strict_grep_commands")]


def _parse_rule(raw: dict) -> EmbaRule:
    """Parse a raw JSON rule dict into an EmbaRule with compiled patterns."""
    identifier = raw.get("identifier", "")
    vendors = raw.get("vendor_names", ["NA"])
    products = raw.get("product_names", [identifier])
    vendor = vendors[0] if vendors and vendors[0] != "NA" else identifier
    product = products[0] if products else identifier

    # Compile grep patterns
    grep_patterns = []
    for cmd in raw.get("grep_commands", []):
        try:
            regex = _convert_grep_to_regex(cmd)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                grep_patterns.append(re.compile(regex))
        except re.error:
            pass

    # Compile strict patterns
    strict_patterns = []
    for cmd in raw.get("strict_grep_commands", []):
        try:
            regex = _convert_grep_to_regex(cmd)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                strict_patterns.append(re.compile(regex))
        except re.error:
            pass

    # Build version extractors from sed commands
    version_extractors = []
    for sed_cmd in raw.get("version_extraction", []):
        extractor = _convert_sed_to_extractor(sed_cmd)
        if extractor:
            version_extractors.append(extractor)

    affected_paths = [p for p in raw.get("affected_paths", ["NA"]) if p != "NA"]

    return EmbaRule(
        identifier=identifier,
        vendor=vendor,
        product=product,
        licenses=raw.get("licenses", []),
        grep_patterns=grep_patterns,
        version_extractors=version_extractors,
        strict_patterns=strict_patterns,
        affected_paths=affected_paths,
    )


def _convert_grep_to_regex(grep_cmd: str) -> str:
    """Convert EMBA grep-style pattern to Python regex.

    EMBA uses grep -E (extended regex) with double-backslash escaping for
    literal spaces: 'BusyBox\\ v[0-9]' means 'BusyBox v[0-9]' in regex.
    """
    # Replace \\ followed by a space → literal space
    # EMBA JSON stores: "BusyBox\\ v[0-9]" which in the file is: BusyBox\ v[0-9]
    # After JSON parse, Python sees: "BusyBox\\ v[0-9]" → literal backslash + space
    # We need to convert this to just a space in regex
    result = grep_cmd.replace("\\ ", " ")
    # Also handle \\/ → /
    result = result.replace("\\/", "/")
    # EMBA uses lazy quantifiers (+?) in version groups like ([0-9](\.[0-9]+)+?)
    # In sed (full-line substitution), lazy doesn't matter. In Python re.search,
    # lazy stops too early (e.g., "1.36" instead of "1.36.1"). Convert to greedy.
    result = result.replace("]+)+?)", "]+)+)")
    # Strip ^ and $ anchors — our text_block joins strings with \n, and without
    # MULTILINE these anchors only match start/end of the entire block. Removing
    # them is safe since each extracted string is independent.
    if result.startswith("^"):
        result = result[1:]
    if result.endswith("$"):
        result = result[:-1]
    return result


# Regex to parse sed -r 's/pattern/replacement/' commands
_SED_PATTERN = re.compile(r"sed\s+-r\s+'s/(.*?)/(.*?)/'")


def _convert_sed_to_extractor(sed_cmd: str) -> Callable[[str], tuple[str, str, str] | None] | None:
    """Convert a sed extraction command to a Python function.

    EMBA sed commands look like:
      sed -r 's/.*OpenSSL\\ ([0-9](\\.[0-9]+)+?).*/:openssl:openssl:\\1/'
    Output format is :vendor:product:version
    """
    m = _SED_PATTERN.search(sed_cmd)
    if not m:
        return None

    sed_pattern_raw = m.group(1)
    sed_replacement = m.group(2)

    # Convert sed pattern (same grep-style escaping)
    try:
        py_pattern = re.compile(_convert_grep_to_regex(sed_pattern_raw))
    except re.error:
        return None

    # Parse replacement to extract vendor, product, and version group reference
    # Format: :vendor:product:\1  or  ::product:\1
    parts = sed_replacement.split(":")
    # parts = ['', vendor, product, '\\1'] or ['', '', product, '\\1\\2']
    if len(parts) < 4:
        return None

    vendor_str = parts[1] if parts[1] else ""
    product_str = parts[2] if parts[2] else ""

    def extractor(line: str, _pat=py_pattern, _vendor=vendor_str, _product=product_str) -> tuple[str, str, str] | None:
        match = _pat.search(line)
        if not match:
            return None
        # Reconstruct version from capture groups
        # EMBA uses \1, \2, \3 etc. We just take group(1) as the primary version
        try:
            version = match.group(1)
            if not version:
                return None
            # Sometimes additional groups are appended (e.g., letter suffix)
            # Try to reconstruct from replacement pattern
            # Simple approach: if replacement has \1\2 or \1\3, concatenate groups
            if "\\2" in sed_replacement or "\\3" in sed_replacement:
                full_ver = ""
                for i in range(1, match.lastindex + 1 if match.lastindex else 2):
                    g = match.group(i)
                    if g:
                        full_ver += g
                # But many \2 refs are just sub-groups of \1. Use group(1) if it
                # already contains a reasonable version
                if "." in version or len(version) >= 3:
                    pass  # version from group(1) is good
                elif full_ver and "." in full_ver:
                    version = full_ver
            return (_vendor, _product, version)
        except (IndexError, AttributeError):
            return None

    return extractor


def scan_binary_with_rules(
    data: bytes,
    filename: str = "",
    rules: list[EmbaRule] | None = None,
    max_strings: int = 50000,
) -> list[Component]:
    """Scan binary data against all EMBA rules and return detected components.

    Extracts ASCII strings from the data and matches them against grep patterns.
    On match, applies version extractors to determine the exact version.
    """
    if rules is None:
        rules = get_rules()

    if not rules or not data:
        return []

    # Extract printable ASCII strings (min 6 chars to reduce noise)
    strings = _extract_strings(data, min_length=6, max_count=max_strings)
    if not strings:
        return []

    # Join all strings with newlines for efficient multi-pattern matching
    text_block = "\n".join(strings)

    components: list[Component] = []
    filename_lower = filename.lower()

    for rule in rules:
        patterns_to_check = rule.grep_patterns

        if rule.strict_patterns and rule.affected_paths:
            if any(ap.lower() in filename_lower for ap in rule.affected_paths):
                patterns_to_check = list(patterns_to_check) + rule.strict_patterns

        if not patterns_to_check:
            continue

        # Search text block for pattern matches
        matched_line = None
        for pat in patterns_to_check:
            m = pat.search(text_block)
            if m:
                # Extract the full line containing the match
                start = text_block.rfind("\n", 0, m.start()) + 1
                end = text_block.find("\n", m.end())
                if end == -1:
                    end = len(text_block)
                matched_line = text_block[start:end]
                break

        if not matched_line:
            continue

        # Extract version using sed extractors
        version = ""
        vendor = rule.vendor
        product = rule.product

        for extractor in rule.version_extractors:
            result = extractor(matched_line)
            if result:
                vendor = result[0] or rule.vendor
                product = result[1] or rule.product
                version = result[2]
                break

        if not version:
            version = _fallback_version_extract(matched_line)

        if not version:
            continue

        # Filter out obvious false positives
        if _is_false_positive(rule.identifier, version, matched_line):
            continue

        components.append(Component(
            name=product,
            vendor=vendor,
            component_type="library",
            resolved_version=version,
            versions=[VersionConfidence(
                version=version,
                confidence=0.80,
                method=ExtractionMethod.STATIC_RULE,
                evidence=f"EMBA rule '{rule.identifier}': {matched_line[:80]}",
            )],
            licenses=rule.licenses[:1] if rule.licenses else [],
            purl=f"pkg:generic/{vendor}/{product}@{version}" if vendor and product else "",
        ))

    # Run supplementary patterns for libraries missing from EMBA rules
    existing_names = {c.name.lower() for c in components}
    for supp in scan_supplementary_patterns(text_block):
        if supp.name.lower() not in existing_names:
            components.append(supp)
            existing_names.add(supp.name.lower())

    return components


# Version patterns that indicate false positives
_FP_VERSION_RE = re.compile(r"^\d{5,}$")  # Pure large numbers like "65536"
_FP_CONTEXT_WORDS = re.compile(
    r"\b(must be|limit|maximum|minimum|greater|less than|at least|up to|"
    r"buffer size|block size|timeout|max[_ ]|min[_ ]|size[= ]|length)\b",
    re.IGNORECASE,
)


def _is_false_positive(identifier: str, version: str, evidence: str) -> bool:
    """Detect common EMBA rule false positives."""
    # Pure large integer versions (likely constants/sizes, not software versions)
    if _FP_VERSION_RE.match(version):
        return True
    # Version is suspiciously large for a single component (e.g., 65536, 32768)
    try:
        major = int(version.split(".")[0])
        if major > 999:
            return True
    except (ValueError, IndexError):
        pass
    # Evidence contains context suggesting a configuration/log value, not a version string
    if _FP_CONTEXT_WORDS.search(evidence):
        return True
    # Version that looks like a memory address or hex constant
    if version.startswith("0x") or (len(version) >= 6 and version.isalnum() and not version[0].isdigit()):
        return True
    return False


# Supplementary patterns for common libraries missing from EMBA rules
_SUPPLEMENTARY_PATTERNS = [
    (re.compile(r"(?:User-Agent:\s*)?curl/(\d+\.\d+\.\d+)"), "haxx", "curl", "library"),
    (re.compile(r"mbedtls[/-](\d+\.\d+\.\d+)"), "arm", "mbedtls", "library"),
    (re.compile(r"mbed TLS (\d+\.\d+\.\d+)"), "arm", "mbedtls", "library"),
    (re.compile(r"lwIP[/ ](\d+\.\d+\.\d+)"), "savannah", "lwip", "library"),
    (re.compile(r"cJSON v?(\d+\.\d+\.\d+)"), "", "cjson", "library"),
    (re.compile(r"FreeRTOS[/ ]?[Vv]?(\d+\.\d+\.\d+)"), "freertos", "freertos", "operating-system"),
    (re.compile(r"wolfSSL[/ ](\d+\.\d+\.\d+)"), "wolfssl", "wolfssl", "library"),
    (re.compile(r"libuv[/ ](\d+\.\d+\.\d+)"), "", "libuv", "library"),
    (re.compile(r"mosquitto[/ ](\d+\.\d+\.\d+)"), "eclipse", "mosquitto", "library"),
    (re.compile(r"libwebsockets[/-](\d+\.\d+\.\d+)"), "", "libwebsockets", "library"),
    (re.compile(r"(?:lib)?jansson[/ -](\d+\.\d+\.\d+)"), "", "jansson", "library"),
    (re.compile(r"(?:lib)?event[/-](\d+\.\d+\.\d+)"), "", "libevent", "library"),
    (re.compile(r"ffmpeg[/ ](\d+\.\d+\.\d+)"), "ffmpeg", "ffmpeg", "library"),
    (re.compile(r"libav(?:codec|format|util)[/ ](\d+\.\d+\.\d+)"), "ffmpeg", "ffmpeg", "library"),
    (re.compile(r"(?:lib)?sqlite[/ ](\d+\.\d+\.\d+)"), "", "sqlite", "library"),
    (re.compile(r"dropbear[_ ]v?(\d+\.\d+)"), "", "dropbear", "application"),
    (re.compile(r"(?:lib)?uClibc[/-](\d+\.\d+\.\d+(?:\.\d+)?)"), "", "uclibc", "library"),
]


def scan_supplementary_patterns(text_block: str) -> list[Component]:
    """Match supplementary patterns not covered by EMBA rules."""
    components = []
    seen = set()
    for pattern, vendor, product, comp_type in _SUPPLEMENTARY_PATTERNS:
        if product in seen:
            continue
        m = pattern.search(text_block)
        if m:
            version = m.group(1)
            seen.add(product)
            components.append(Component(
                name=product,
                vendor=vendor,
                component_type=comp_type,
                resolved_version=version,
                versions=[VersionConfidence(
                    version=version,
                    confidence=0.85,
                    method=ExtractionMethod.STATIC_RULE,
                    evidence=f"pattern: {m.group(0)[:60]}",
                )],
                purl=f"pkg:generic/{vendor}/{product}@{version}" if vendor else f"pkg:generic/{product}@{version}",
            ))
    return components


def _extract_strings(data: bytes, min_length: int = 6, max_count: int = 50000) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    # Only scan first 4MB for performance
    scan_data = data[:4 * 1024 * 1024]
    # Use regex on bytes for fast extraction (much faster than byte-by-byte Python loop)
    pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_length)
    strings = []
    for m in pattern.finditer(scan_data):
        strings.append(m.group().decode("ascii"))
        if len(strings) >= max_count:
            break
    return strings


_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+){0,3}(?:[a-z]\d?)?)")


def _fallback_version_extract(line: str) -> str:
    """Try to extract a version number from a matched line as fallback."""
    m = _VERSION_RE.search(line)
    if m:
        ver = m.group(1)
        # Sanity check: version shouldn't be a date or too short
        if len(ver) >= 3 and not ver.startswith("20"):
            return ver
    return ""
