"""Vulnerability scanning module - CVE matching via OSV API."""

from .models import Vulnerability, VulnScanResult, ComponentVulnResult, Severity
from .matcher import VulnMatcher

__all__ = [
    "Vulnerability",
    "VulnScanResult",
    "ComponentVulnResult",
    "Severity",
    "VulnMatcher",
]
