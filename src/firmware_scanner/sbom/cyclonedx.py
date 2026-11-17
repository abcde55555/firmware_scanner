"""CycloneDX SBOM generation with enterprise platform and ATV-SBOM metadata compatibility."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from firmware_scanner import __version__
from ..extraction.models import Component


class CycloneDXGenerator:
    DEFAULT_SPEC_VERSION = "1.6"

    def generate(
        self,
        components: list[Component],
        firmware_path: str,
        firmware_hash_sha256: str,
        firmware_hash_md5: str = "",
        arch_info: str = "",
        detected_rtos: str = "",
        analysis_warnings: list[str] | None = None,
        vulnerabilities: list[dict[str, Any]] | None = None,
        build_info: dict[str, Any] | None = None,
        spec_version: str = "1.6",
    ) -> dict[str, Any]:
        meta = self._build_metadata(
            firmware_path,
            firmware_hash_sha256,
            firmware_hash_md5,
            arch_info,
            detected_rtos,
            build_info=build_info,
        )

        bom: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": spec_version,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": meta,
            "components": [
                self._component_to_cdx(c, spec_version=spec_version) for c in components
            ],
        }

        if vulnerabilities:
            bom["vulnerabilities"] = vulnerabilities

        return bom

    def _build_metadata(
        self,
        firmware_path: str,
        sha256: str,
        md5: str,
        arch_info: str,
        detected_rtos: str,
        build_info: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        info = build_info or {}
        now_iso = datetime.now(timezone.utc).isoformat()
        all_props = info.get("all_properties") or {}

        # 1. Target product name
        target_product = (
            info.get("target_product")
            or all_props.get("ro.build.product")
            or all_props.get("ro.product.device")
            or all_props.get("ro.product.system.device")
            or all_props.get("ro.product.system.name")
            or (Path(firmware_path).stem if firmware_path else "")
            or "waydroid_tv_x86_64"
        )

        # 2. Build ID / version
        build_id = (
            info.get("build_id")
            or all_props.get("ro.build.id")
            or all_props.get("ro.system.build.id")
            or all_props.get("ro.build.display.id")
            or info.get("version")
            or "1.0.0"
        )

        # 3. Build Date
        build_date = (
            info.get("build_date")
            or all_props.get("ro.build.date")
            or all_props.get("ro.system.build.date")
            or all_props.get("ro.build.date.utc")
            or now_iso
        )

        # 4. Chip model
        chip_model = (
            info.get("chip_model")
            or all_props.get("ro.board.platform")
            or all_props.get("ro.hardware")
            or all_props.get("ro.product.cpu.abi")
            or all_props.get("ro.product.board")
            or (arch_info.split()[0] if arch_info else "x86_64")
        )

        metadata: dict[str, Any] = {
            "timestamp": now_iso,
            # Top-level required fields for ATV-SBOM platforms
            "name": target_product,
            "version": build_id,
            "type": "firmware",
            "lifecycles": [
                {
                    "phase": "build"
                }
            ],
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "firmware-scanner",
                        "version": __version__,
                        "publisher": "Firmware Security Team",
                    }
                ]
            },
            "component": {
                "bom-ref": f"firmware-{target_product}-{build_id}",
                "type": "firmware",
                "name": target_product,
                "version": build_id,
                "hashes": [{"alg": "SHA-256", "content": sha256}],
            },
        }

        if md5:
            metadata["component"]["hashes"].append({"alg": "MD5", "content": md5})

        props = [
            # Mandatory ASRock ATV-SBOM platform properties
            {"name": "asrock:chip-model", "value": str(chip_model)},
            {"name": "asrock:build-date", "value": str(build_date)},
            {"name": "asrock:build-id", "value": str(build_id)},
            {"name": "asrock:target-product", "value": str(target_product)},
        ]

        if arch_info:
            props.append({"name": "firmware:architecture", "value": arch_info})
        if detected_rtos:
            props.append({"name": "firmware:rtos", "value": detected_rtos})
        if info.get("version"):
            props.append({"name": "android:version", "value": str(info["version"])})
        if info.get("security_patch"):
            props.append({"name": "android:security_patch", "value": str(info["security_patch"])})
        if info.get("build_fingerprint"):
            props.append({"name": "android:build_fingerprint", "value": str(info["build_fingerprint"])})

        metadata["properties"] = props
        # Also populate properties on metadata.component for platforms inspecting the root component
        metadata["component"]["properties"] = list(props)
        return metadata

    def _component_to_cdx(self, comp: Component, spec_version: str = "1.5") -> dict[str, Any]:
        cdx_type = self._map_component_type(comp.component_type, spec_version=spec_version)

        ver = comp.resolved_version or ""
        bom_ref = comp.purl or (f"pkg:generic/{comp.name}@{ver}" if ver else f"pkg:generic/{comp.name}")

        cdx_comp: dict[str, Any] = {
            "bom-ref": bom_ref,
            "type": cdx_type,
            "name": comp.name,
        }

        # For Maven components, separate group and name per CycloneDX specification
        if comp.purl and comp.purl.startswith("pkg:maven/"):
            try:
                purl_body = comp.purl.split("pkg:maven/", 1)[1].split("?", 1)[0]
                path_part = purl_body.split("@", 1)[0] if "@" in purl_body else purl_body
                if "/" in path_part:
                    grp, art = path_part.rsplit("/", 1)
                    cdx_comp["group"] = grp
                    cdx_comp["name"] = art
            except Exception:
                pass
        elif ":" in comp.name and not comp.name.startswith(("cpe:", "pkg:", "framework/")):
            parts = comp.name.split(":", 1)
            if all(parts):
                cdx_comp["group"] = parts[0]
                cdx_comp["name"] = parts[1]

        if comp.resolved_version and comp.resolved_version != "detected":
            cdx_comp["version"] = comp.resolved_version
        elif spec_version == "1.5":
            # For CycloneDX 1.5 enterprise platforms (e.g. atv-sbom-3), every component
            # must have a non-empty version so platforms do not drop unversioned components.
            cdx_comp["version"] = "unknown"

        if comp.vendor:
            cdx_comp["publisher"] = comp.vendor

        if comp.purl:
            cdx_comp["purl"] = comp.purl

        if comp.cpe:
            cdx_comp["cpe"] = comp.cpe

        if comp.licenses:
            cdx_lics = []
            for lic in comp.licenses:
                if any(op in lic for op in (" AND ", " OR ", " WITH ", " ")):
                    cdx_lics.append({"expression": lic})
                elif lic.lower() in ("proprietary", "unknown", "custom", "commercial"):
                    cdx_lics.append({"license": {"name": lic}})
                else:
                    cdx_lics.append({"license": {"id": lic}})
            cdx_comp["licenses"] = cdx_lics

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

        combined_props = []
        # If in 1.5 mode and original type was crypto or ml model, record it in properties
        if spec_version == "1.5" and comp.component_type in ("cryptographic-asset", "machine-learning-model"):
            combined_props.append({"name": "cdx:extendedType", "value": comp.component_type})

        if getattr(comp, "properties", None):
            combined_props.extend(comp.properties)
        combined_props.extend(evidence_props)
        if combined_props:
            cdx_comp["properties"] = combined_props

        if spec_version >= "1.6":
            if getattr(comp, "crypto_properties", None):
                cdx_comp["cryptoProperties"] = comp.crypto_properties

            if getattr(comp, "model_card", None):
                cdx_comp["modelCard"] = comp.model_card

        return cdx_comp

    def _map_component_type(self, comp_type: str, spec_version: str = "1.5") -> str:
        if spec_version == "1.5":
            if comp_type == "cryptographic-asset":
                return "library"
            elif comp_type == "machine-learning-model":
                return "file"

        mapping = {
            "operating-system": "operating-system",
            "library": "library",
            "application": "application",
            "firmware": "firmware",
            "framework": "framework",
            "device": "device",
            "file": "file",
            "cryptographic-asset": "cryptographic-asset",
            "machine-learning-model": "machine-learning-model",
        }
        return mapping.get(comp_type, "library")

    def to_json(self, bom: dict[str, Any], indent: int = 2) -> str:
        return json.dumps(bom, indent=indent, ensure_ascii=False)
