"""JSON vulnerability report generator."""

from .models import VulnScanResult


def generate_vuln_json(result: VulnScanResult) -> str:
    return result.model_dump_json(indent=2)
