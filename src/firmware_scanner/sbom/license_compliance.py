"""SPDX License normalization, risk classification, and compatibility audit engine.

Audits firmware components against open-source license compliance rules:
- Normalizes varied raw license declarations to official SPDX License Identifiers.
- Classifies licenses by copyleft risk (Permissive, Weak Copyleft, Strong Copyleft, Network Copyleft).
- Detects licensing conflicts, copyleft contamination risks, and GPL incompatibilities.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..extraction.models import Component


class LicenseRiskCategory(str, Enum):
    PERMISSIVE = "Permissive"
    WEAK_COPYLEFT = "Weak Copyleft"
    STRONG_COPYLEFT = "Strong Copyleft"
    NETWORK_COPYLEFT = "Network Copyleft"
    COMMERCIAL = "Commercial / Proprietary"
    UNKNOWN = "Unknown / Unspecified"


class ComplianceSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


# Mapping from raw license strings/aliases to canonical SPDX Identifier
_SPDX_NORMALIZATION_MAP: dict[str, str] = {
    # GPL family
    "gpl": "GPL-2.0-or-later",
    "gplv2": "GPL-2.0-only",
    "gpl 2.0": "GPL-2.0-only",
    "gpl-2.0": "GPL-2.0-only",
    "gplv2+": "GPL-2.0-or-later",
    "gpl-2.0+": "GPL-2.0-or-later",
    "gpl 2.0 or later": "GPL-2.0-or-later",
    "gnu general public license v2": "GPL-2.0-only",
    "gnu general public license, version 2": "GPL-2.0-only",
    "gplv3": "GPL-3.0-only",
    "gpl 3.0": "GPL-3.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gplv3+": "GPL-3.0-or-later",
    "gpl-3.0+": "GPL-3.0-or-later",
    "gpl 3.0 or later": "GPL-3.0-or-later",
    "gnu general public license v3": "GPL-3.0-only",

    # LGPL family
    "lgpl": "LGPL-2.1-or-later",
    "lgplv2": "LGPL-2.0-only",
    "lgplv2.1": "LGPL-2.1-only",
    "lgpl 2.1": "LGPL-2.1-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgplv2.1+": "LGPL-2.1-or-later",
    "lgpl-2.1+": "LGPL-2.1-or-later",
    "lgplv3": "LGPL-3.0-only",
    "lgpl 3.0": "LGPL-3.0-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "lgplv3+": "LGPL-3.0-or-later",

    # AGPL
    "agpl": "AGPL-3.0-only",
    "agplv3": "AGPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "agpl 3.0": "AGPL-3.0-only",
    "affero gpl": "AGPL-3.0-only",

    # Apache
    "apache": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "asl 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",

    # BSD
    "bsd": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "modified bsd": "BSD-3-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "simplified bsd": "BSD-2-Clause",

    # MIT
    "mit": "MIT",
    "mit license": "MIT",

    # Others
    "mpl 2.0": "MPL-2.0",
    "mpl-2.0": "MPL-2.0",
    "isc": "ISC",
    "zlib": "Zlib",
    "openssl": "OpenSSL",
    "ssleay": "SSLeay",
    "public domain": "CC0-1.0",
    "proprietary": "Proprietary",
    "commercial": "Proprietary",
}

# License Risk Category mapping
_LICENSE_RISK_MAP: dict[str, LicenseRiskCategory] = {
    # Permissive
    "MIT": LicenseRiskCategory.PERMISSIVE,
    "Apache-2.0": LicenseRiskCategory.PERMISSIVE,
    "BSD-3-Clause": LicenseRiskCategory.PERMISSIVE,
    "BSD-2-Clause": LicenseRiskCategory.PERMISSIVE,
    "ISC": LicenseRiskCategory.PERMISSIVE,
    "Zlib": LicenseRiskCategory.PERMISSIVE,
    "OpenSSL": LicenseRiskCategory.PERMISSIVE,
    "CC0-1.0": LicenseRiskCategory.PERMISSIVE,

    # Weak Copyleft
    "LGPL-2.0-only": LicenseRiskCategory.WEAK_COPYLEFT,
    "LGPL-2.1-only": LicenseRiskCategory.WEAK_COPYLEFT,
    "LGPL-2.1-or-later": LicenseRiskCategory.WEAK_COPYLEFT,
    "LGPL-3.0-only": LicenseRiskCategory.WEAK_COPYLEFT,
    "LGPL-3.0-or-later": LicenseRiskCategory.WEAK_COPYLEFT,
    "MPL-2.0": LicenseRiskCategory.WEAK_COPYLEFT,

    # Strong Copyleft
    "GPL-2.0-only": LicenseRiskCategory.STRONG_COPYLEFT,
    "GPL-2.0-or-later": LicenseRiskCategory.STRONG_COPYLEFT,
    "GPL-3.0-only": LicenseRiskCategory.STRONG_COPYLEFT,
    "GPL-3.0-or-later": LicenseRiskCategory.STRONG_COPYLEFT,

    # Network Copyleft
    "AGPL-3.0-only": LicenseRiskCategory.NETWORK_COPYLEFT,
    "AGPL-3.0-or-later": LicenseRiskCategory.NETWORK_COPYLEFT,
    "SSPL-1.0": LicenseRiskCategory.NETWORK_COPYLEFT,

    # Proprietary
    "Proprietary": LicenseRiskCategory.COMMERCIAL,
}


# Direct canonical SPDX IDs (case-insensitive lookup)
_SPDX_CANONICAL_MAP: dict[str, str] = {k.lower(): k for k in _LICENSE_RISK_MAP.keys()}

# Aliases sorted by length descending to match most specific alias first
_SORTED_SPDX_ALIASES = sorted(_SPDX_NORMALIZATION_MAP.items(), key=lambda x: len(x[0]), reverse=True)


def normalize_license(raw_license: str) -> str:
    """Normalize raw license string to official SPDX License Identifier."""
    if not raw_license:
        return "Unknown"
    clean = raw_license.strip().lower()

    # 1. Exact match against known canonical SPDX IDs
    if clean in _SPDX_CANONICAL_MAP:
        return _SPDX_CANONICAL_MAP[clean]

    # 2. Exact match against known aliases
    if clean in _SPDX_NORMALIZATION_MAP:
        return _SPDX_NORMALIZATION_MAP[clean]

    # 3. Word-boundary substring match with longest alias first
    for alias, spdx_id in _SORTED_SPDX_ALIASES:
        # Require word boundary so 'gpl' does not match inside 'agpl' or 'lgpl'
        pattern = r'(?<![a-z0-9])' + re.escape(alias) + r'(?![a-z0-9])'
        if re.search(pattern, clean):
            return spdx_id

    # If it already looks like an SPDX identifier, return with cleaned casing
    return raw_license.strip()


def classify_license(spdx_id: str) -> LicenseRiskCategory:
    """Classify an SPDX license identifier into a risk category."""
    return _LICENSE_RISK_MAP.get(spdx_id, LicenseRiskCategory.UNKNOWN)


@dataclass
class ComplianceIssue:
    severity: ComplianceSeverity
    title: str
    description: str
    affected_components: list[str] = field(default_factory=list)


@dataclass
class LicenseAuditReport:
    total_components: int = 0
    licensed_components: int = 0
    unlicensed_components: int = 0
    licenses_found: dict[str, int] = field(default_factory=dict)
    risk_summary: dict[str, int] = field(default_factory=dict)
    compliance_issues: list[ComplianceIssue] = field(default_factory=list)
    is_compliant: bool = True


def audit_firmware_licenses(components: list[Component]) -> LicenseAuditReport:
    """Audit firmware components for open-source license compliance and conflicts."""
    report = LicenseAuditReport(total_components=len(components))

    has_gpl3 = False
    has_agpl = False
    has_gpl2_only = False
    has_apache2 = False
    has_proprietary = False

    gpl3_comps: list[str] = []
    agpl_comps: list[str] = []
    gpl2_comps: list[str] = []
    apache2_comps: list[str] = []
    prop_comps: list[str] = []

    for comp in components:
        raw_lics = comp.licenses
        if not raw_lics:
            report.unlicensed_components += 1
            continue

        report.licensed_components += 1
        for raw_lic in raw_lics:
            spdx_id = normalize_license(raw_lic)
            report.licenses_found[spdx_id] = report.licenses_found.get(spdx_id, 0) + 1

            cat = classify_license(spdx_id)
            report.risk_summary[cat.value] = report.risk_summary.get(cat.value, 0) + 1

            if "AGPL" in spdx_id:
                has_agpl = True
                agpl_comps.append(comp.name)
            elif spdx_id.startswith("GPL-3.0"):
                has_gpl3 = True
                gpl3_comps.append(comp.name)
            elif spdx_id == "GPL-2.0-only":
                has_gpl2_only = True
                gpl2_comps.append(comp.name)
            elif spdx_id == "Apache-2.0":
                has_apache2 = True
                apache2_comps.append(comp.name)
            elif spdx_id == "Proprietary":
                has_proprietary = True
                prop_comps.append(comp.name)

    # Compliance Rule 1: AGPL-3.0 Network Trigger Risk
    if has_agpl:
        report.compliance_issues.append(ComplianceIssue(
            severity=ComplianceSeverity.HIGH,
            title="AGPL-3.0 Network Copyleft Obligation",
            description="Firmware includes AGPL-3.0 licensed software. Providing network services triggers mandatory source code disclosure for the entire application stack.",
            affected_components=agpl_comps,
        ))

    # Compliance Rule 2: GPL-3.0 in Commercial / Hardware Firmware
    if has_gpl3 and has_proprietary:
        report.compliance_issues.append(ComplianceIssue(
            severity=ComplianceSeverity.CRITICAL,
            title="GPL-3.0 Copyleft Contamination Risk",
            description="GPL-3.0 components detected alongside proprietary commercial software. Combining or linking proprietary modules may obligate opening the proprietary source code.",
            affected_components=gpl3_comps,
        ))

    # Compliance Rule 3: GPL-2.0-only vs Apache-2.0 Incompatibility
    if has_gpl2_only and has_apache2:
        report.compliance_issues.append(ComplianceIssue(
            severity=ComplianceSeverity.WARNING,
            title="GPL-2.0-only and Apache-2.0 Incompatibility",
            description="Components with GPL-2.0-only and Apache-2.0 licenses detected. The Free Software Foundation (FSF) considers Apache-2.0 patent clauses incompatible with pure GPL-2.0-only when statically linked.",
            affected_components=gpl2_comps + apache2_comps,
        ))

    if any(i.severity in (ComplianceSeverity.HIGH, ComplianceSeverity.CRITICAL) for i in report.compliance_issues):
        report.is_compliant = False

    return report
