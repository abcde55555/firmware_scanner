"""CycloneDX 1.5 SBOM generation."""

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from ..extraction.models import Component


class CycloneDXGenerator:
    SPEC_VERSION = "1.5"

    def generate(
        self,
        components: list[Component],
        firmware_path: str,
        firmware_hash_sha256: str,
        firmware_hash_md5: str = "",
        arch_info: str = "",
        detected_rtos: str = "",
        analysis_warnings: list[str] | None = None,
    ) -> dict[str, Any]:
        bom: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": self.SPEC_VERSION,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": self._build_metadata(
                firmware_path, firmware_hash_sha256, firmware_hash_md5, arch_info, detected_rtos
            ),
            "components": [self._component_to_cdx(c) for c in components if c.resolved_version],
        }

        if analysis_warnings:
            bom["properties"] = [
                {"name": "analysis:warnings", "value": "; ".join(analysis_warnings[:10])}
            ]

        return bom

    def _build_metadata(
        self,
        firmware_path: str,
        sha256: str,
        md5: str,
        arch_info: str,
        detected_rtos: str,
    ) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "firmware-scanner",
                        "version": "0.1.0",
                        "publisher": "Firmware Security Team",
                    }
                ]
            },
            "component": {
                "type": "firmware",
                "name": firmware_path,
                "hashes": [{"alg": "SHA-256", "content": sha256}],
            },
        }

        if md5:
            metadata["component"]["hashes"].append({"alg": "MD5", "content": md5})

        props = []
        if arch_info:
            props.append({"name": "firmware:architecture", "value": arch_info})
        if detected_rtos:
            props.append({"name": "firmware:rtos", "value": detected_rtos})
        if props:
            metadata["properties"] = props

        return metadata

    def _component_to_cdx(self, comp: Component) -> dict[str, Any]:
        cdx_type = self._map_component_type(comp.component_type)

        cdx_comp: dict[str, Any] = {
            "type": cdx_type,
            "name": comp.name,
            "version": comp.resolved_version,
        }

        if comp.vendor:
            cdx_comp["publisher"] = comp.vendor

        if comp.purl:
            cdx_comp["purl"] = comp.purl

        if comp.cpe:
            cdx_comp["cpe"] = comp.cpe

        if comp.licenses:
            cdx_comp["licenses"] = [{"license": {"id": lic}} for lic in comp.licenses]

        if comp.description:
            cdx_comp["description"] = comp.description

        # Evidence from analysis
        evidence_props = []
        if comp.versions:
            methods = sorted(set(v.method.value for v in comp.versions))
            max_confidence = max((v.confidence for v in comp.versions), default=0)
            evidence_props.append({"name": "analysis:confidence", "value": f"{max_confidence:.2f}"})
            evidence_props.append({"name": "analysis:methods", "value": ",".join(methods)})

            # Include top evidence strings
            evidences = [v.evidence for v in comp.versions if v.evidence][:3]
            if evidences:
                evidence_props.append({"name": "analysis:evidence", "value": " | ".join(evidences)})

        if evidence_props:
            cdx_comp["properties"] = evidence_props

        return cdx_comp

    def _map_component_type(self, comp_type: str) -> str:
        mapping = {
            "operating-system": "operating-system",
            "library": "library",
            "firmware": "firmware",
            "framework": "framework",
            "device": "device",
        }
        return mapping.get(comp_type, "library")

    def to_json(self, bom: dict[str, Any], indent: int = 2) -> str:
        return json.dumps(bom, indent=indent, ensure_ascii=False)
