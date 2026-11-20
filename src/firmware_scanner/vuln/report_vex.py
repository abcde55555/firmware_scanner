"""CycloneDX 1.6 VEX report generator."""

from typing import Any

from ..extraction.models import Component
from .models import Severity, VulnScanResult
from .threat_intel import determine_vex_status


def generate_cyclonedx_vex(
    result: VulnScanResult,
    components: list[Component] | None = None,
    build_info: dict[str, Any] | None = None,
    spec_version: str = "1.6",
) -> str:
    """Generate CycloneDX SBOM with VEX (vulnerabilities) section."""
    from ..sbom.cyclonedx import CycloneDXGenerator

    cdx_vulns: dict[tuple[str, str], dict[str, Any]] = {}
    severity_rank = {
        Severity.UNKNOWN: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }

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

            key = (v.id, source_name)
            existing = cdx_vulns.get(key)
            if existing is None:
                vuln_entry["_score"] = v.cvss_score or 0
                vuln_entry["_rank"] = severity_rank.get(v.severity, 0)
                cdx_vulns[key] = vuln_entry
                continue

            affected_refs = {
                item["ref"] for item in existing.get("affects", []) if item.get("ref")
            }
            if bom_ref not in affected_refs:
                existing.setdefault("affects", []).append({"ref": bom_ref})
            known_refs = {
                (item.get("id"), item.get("source", {}).get("url"))
                for item in existing.get("references", [])
            }
            for reference in vuln_entry.get("references", []):
                identity = (
                    reference.get("id"),
                    reference.get("source", {}).get("url"),
                )
                if identity not in known_refs:
                    existing.setdefault("references", []).append(reference)
                    known_refs.add(identity)

            candidate_rank = severity_rank.get(v.severity, 0)
            candidate_score = v.cvss_score or 0
            if (candidate_rank, candidate_score) > (
                existing.get("_rank", 0),
                existing.get("_score", 0),
            ):
                for field in ("description", "ratings", "analysis", "_rank", "_score"):
                    if field in vuln_entry:
                        existing[field] = vuln_entry[field]

    cdx_vuln_list = []
    for entry in cdx_vulns.values():
        entry.pop("_rank", None)
        entry.pop("_score", None)
        cdx_vuln_list.append(entry)

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
        vulnerabilities=cdx_vuln_list,
    )
    return gen.to_json(bom)
