"""CycloneDX 1.6 VEX report generator."""

from typing import Any
from .models import VulnScanResult, Severity
from .threat_intel import determine_vex_status
from ..extraction.models import Component


def generate_cyclonedx_vex(
    result: VulnScanResult,
    components: list[Component] | None = None,
    build_info: dict[str, Any] | None = None,
    spec_version: str = "1.6",
) -> str:
    """Generate CycloneDX SBOM with VEX (vulnerabilities) section."""
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

            # Context-Aware VEX Analysis & Threat Intel
            vex_state, vex_justification, priority = determine_vex_status(
                v.id, v.severity.value, v.cvss_score
            )
            vuln_entry["analysis"] = {
                "state": vex_state,
                "detail": f"{vex_justification} (Affected versions: {v.affected_versions or 'all'})",
            }

            # Properties for CISA KEV, EPSS, and CNVD/CNNVD
            vuln_props = [
                {"name": "remediation:priority", "value": priority},
                {"name": "cisa:kev", "value": "true" if v.is_cisa_kev else "false"},
            ]
            if v.epss_score is not None:
                vuln_props.append({"name": "epss:score", "value": f"{v.epss_score:.5f}"})
            if v.epss_percentile is not None:
                vuln_props.append({"name": "epss:percentile", "value": f"{v.epss_percentile:.5f}"})
            if v.cnvd_id:
                vuln_props.append({"name": "cnvd:id", "value": v.cnvd_id})
            if v.cnnvd_id:
                vuln_props.append({"name": "cnnvd:id", "value": v.cnnvd_id})

            vuln_entry["properties"] = vuln_props

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
        build_info=build_info,
        spec_version=spec_version,
        vulnerabilities=cdx_vulns,
    )
    return gen.to_json(bom)
