"""SPDX 3.0.1 SBOM generation in JSON-LD format."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..extraction.models import Component
from firmware_scanner import __version__


class SPDX3Generator:
    SPEC_VERSION = "3.0.1"
    CONTEXT_URL = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

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
        """Generate an SPDX 3.0.1 JSON-LD Document graph."""
        doc_uuid = str(uuid.uuid4())
        created_time = datetime.now(timezone.utc).isoformat()
        clean_fw_name = Path(firmware_path).name or "firmware"

        creation_info_id = f"urn:spdx:creationinfo:{doc_uuid}"
        tool_id = f"urn:spdx:tool:firmware-scanner-{__version__}"
        doc_id = f"urn:spdx:doc:{doc_uuid}"
        root_package_id = f"urn:spdx:pkg:firmware-{doc_uuid}"

        graph: list[dict[str, Any]] = []

        # 1. CreationInfo
        creation_info: dict[str, Any] = {
            "type": "CreationInfo",
            "spdxId": creation_info_id,
            "specVersion": self.SPEC_VERSION,
            "created": created_time,
            "createdBy": [tool_id],
        }
        graph.append(creation_info)

        # 2. Tool definition
        tool_elem: dict[str, Any] = {
            "type": "Tool",
            "spdxId": tool_id,
            "creationInfo": creation_info_id,
            "name": "firmware-scanner",
            "software_packageVersion": __version__,
        }
        graph.append(tool_elem)

        # 3. Root SpdxDocument
        spdx_doc: dict[str, Any] = {
            "type": "SpdxDocument",
            "spdxId": doc_id,
            "creationInfo": creation_info_id,
            "name": f"SPDX 3.0.1 Document for {clean_fw_name}",
            "profileConformance": ["core", "software"],
            "rootElement": [root_package_id],
        }
        if analysis_warnings:
            spdx_doc["summary"] = "; ".join(analysis_warnings[:10])
        graph.append(spdx_doc)

        # 4. Root Firmware Package
        root_hashes: list[dict[str, Any]] = [
            {
                "type": "Hash",
                "algorithm": "sha256",
                "hashValue": firmware_hash_sha256.lower(),
            }
        ]
        if firmware_hash_md5:
            root_hashes.append(
                {
                    "type": "Hash",
                    "algorithm": "md5",
                    "hashValue": firmware_hash_md5.lower(),
                }
            )

        root_pkg: dict[str, Any] = {
            "type": "software_Package",
            "spdxId": root_package_id,
            "creationInfo": creation_info_id,
            "name": clean_fw_name,
            "primaryPurpose": "firmware",
            "verifiedUsing": root_hashes,
        }
        if arch_info or detected_rtos:
            desc_parts = []
            if arch_info:
                desc_parts.append(f"Architecture: {arch_info}")
            if detected_rtos:
                desc_parts.append(f"OS/RTOS: {detected_rtos}")
            root_pkg["description"] = " | ".join(desc_parts)

        graph.append(root_pkg)

        # 5. Relationship: Document describes root package
        doc_rel: dict[str, Any] = {
            "type": "Relationship",
            "spdxId": f"urn:spdx:rel:doc-{doc_uuid}",
            "creationInfo": creation_info_id,
            "relationshipType": "describes",
            "from": doc_id,
            "to": [root_package_id],
        }
        graph.append(doc_rel)

        # 6. Components and their relationships to root
        for idx, comp in enumerate(components):
            pkg_uuid = str(uuid.uuid4())
            pkg_id = f"urn:spdx:pkg:{pkg_uuid}"

            pkg_elem: dict[str, Any] = {
                "type": "software_Package",
                "spdxId": pkg_id,
                "creationInfo": creation_info_id,
                "name": comp.name,
                "primaryPurpose": self._map_primary_purpose(comp.component_type),
            }

            if comp.resolved_version and comp.resolved_version != "detected":
                pkg_elem["software_packageVersion"] = comp.resolved_version

            if comp.vendor:
                pkg_elem["suppliedBy"] = comp.vendor
            if comp.purl:
                pkg_elem["software_packageUrl"] = comp.purl
            if comp.cpe:
                pkg_elem["externalIdentifier"] = [
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "cpe23Type",
                        "identifier": comp.cpe,
                    }
                ]
            if comp.description:
                pkg_elem["description"] = comp.description

            graph.append(pkg_elem)

            # Relationship: Root firmware contains component
            rel_elem: dict[str, Any] = {
                "type": "Relationship",
                "spdxId": f"urn:spdx:rel:{pkg_uuid}",
                "creationInfo": creation_info_id,
                "relationshipType": "contains",
                "from": root_package_id,
                "to": [pkg_id],
            }
            graph.append(rel_elem)

        return {
            "@context": self.CONTEXT_URL,
            "@graph": graph,
        }

    def _map_primary_purpose(self, comp_type: str) -> str:
        mapping = {
            "operating-system": "operatingSystem",
            "operating_system": "operatingSystem",
            "library": "library",
            "application": "application",
            "firmware": "firmware",
            "framework": "framework",
            "device": "device",
            "patch": "patch",
            "filesystem": "filesystemImage",
        }
        return mapping.get(comp_type, "library")

    def to_json(self, bom: dict[str, Any], indent: int = 2) -> str:
        return json.dumps(bom, indent=indent, ensure_ascii=False)
