"""CycloneDX 1.6 VEX report generator."""

from typing import Any
from .models import VulnScanResult, Severity
from ..extraction.models import Component


def generate_cyclonedx_vex(result: VulnScanResult, components: list[Component] | None = None) -> str:
    """Generate CycloneDX 1.6 SBOM with VEX (vulnerabilities) section."""
    from ..sbom.cyclonedx import CycloneDXGenerator

    cdx_vulns: list[dict[str, Any]] = []

    for cr in result.results:
        bom_ref = cr.purl or f"pkg:generic/{cr.component_name}@{cr.component_version}"
        for v in cr.vulnerabilities:
            source_name = "NVD" if v.id.startswith("CVE") else "OSV"
            vuln_entry: dict[str, Any] = {
                "id": v.id,
                "source": {"name": source_name},
                "references": [{"id": r.url, "source": {"name": r.type or "URL", "url": r.url}} for r in v.references[:5]],
                "affects": [{"ref": bom_ref}],
            }
            if v.summary:
                vuln_entry["description"] = v.summary
            elif v.details:
                vuln_entry["description"] = v.details[:300]

            ratings = []
            if v.cvss_score is not None:
                rating: dict[str, Any] = {
                    "score": v.cvss_score,
                    "severity": v.severity.value,
                }
                if v.cvss_vector:
                    rating["vector"] = v.cvss_vector
                    rating["method"] = "CVSSv31" if "3.1" in v.cvss_vector else "CVSSv3"
                ratings.append(rating)
            elif v.severity != Severity.UNKNOWN:
                ratings.append({"severity": v.severity.value})

            if ratings:
                vuln_entry["ratings"] = ratings

            # VEX Analysis
            vuln_entry["analysis"] = {
                "state": "exploitable" if v.severity in (Severity.CRITICAL, Severity.HIGH) else "in_triage",
                "detail": f"Affected versions: {v.affected_versions}" if v.affected_versions else "Pending verification",
            }

            cdx_vulns.append(vuln_entry)

    gen = CycloneDXGenerator()
    comp_list = list(components) if components else []
    if not comp_list:
        for cr in result.results:
            comp_list.append(
                Component(
                    name=cr.component_name,
                    component_type="library",
                    resolved_version=cr.component_version,
                    purl=cr.purl,
                    cpe=cr.cpe,
                )
            )

    bom = gen.generate(
        components=comp_list,
        firmware_path=result.firmware_path or "firmware",
        firmware_hash_sha256=result.firmware_sha256 or "",
        vulnerabilities=cdx_vulns,
    )
    return gen.to_json(bom)
