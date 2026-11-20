"""Parse CycloneDX and SPDX SBOM JSON files into Component list for vulnerability scanning."""

import json
from pathlib import Path

from ..extraction.models import Component


def is_sbom_file(path: Path) -> bool:
    """Check if a file is a supported SBOM JSON (CycloneDX or SPDX)."""
    if path.suffix.lower() != ".json":
        return False
    try:
        with open(path, encoding="utf-8") as f:
            head = f.read(4096)
        if '"bomFormat"' in head and '"CycloneDX"' in head:
            return True
        if '"spdxVersion"' in head:
            return True
        if '"@context"' in head and 'spdx' in head.lower():
            return True
        return False
    except (OSError, UnicodeDecodeError):
        return False


def parse_sbom_to_components(path: Path) -> tuple[list[Component], dict]:
    """Parse an SBOM JSON (CycloneDX 1.5/1.6 or SPDX 2.3/3.0.1) and return (components, metadata).

    metadata includes firmware_path and firmware_sha256 if available.
    """
    with open(path, encoding="utf-8") as f:
        bom = json.load(f)

    meta: dict = {}

    # Check for SPDX 3.0.1 (JSON-LD graph)
    if "@graph" in bom:
        components = []
        for elem in bom.get("@graph", []):
            elem_type = elem.get("type", "")
            if elem_type in ("software_Package", "Package", "SoftwarePackage"):
                name = elem.get("name", "")
                if not name:
                    continue
                purpose = elem.get("primaryPurpose", "library")

                # If this is the root firmware package, store in metadata
                if purpose in ("firmware", "filesystemImage") and "firmware_path" not in meta:
                    meta["firmware_path"] = name
                    for h in elem.get("verifiedUsing", []):
                        if h.get("algorithm", "").lower() == "sha256":
                            meta["firmware_sha256"] = h.get("hashValue", "")
                    continue

                version = elem.get("software_packageVersion") or elem.get("packageVersion") or ""
                purl = elem.get("software_packageUrl") or elem.get("purl") or ""
                supplied_by = elem.get("suppliedBy", "")

                components.append(Component(
                    name=name,
                    vendor=supplied_by if isinstance(supplied_by, str) else "",
                    resolved_version=version,
                    component_type=purpose,
                    purl=purl,
                    description=elem.get("description", ""),
                ))
        return components, meta

    # Check for SPDX 2.x
    if "spdxVersion" in bom and "packages" in bom:
        components = []
        for pkg in bom.get("packages", []):
            name = pkg.get("name", "")
            version = pkg.get("versionInfo", "")
            if not name or not version or version in ("UNKNOWN", "NOASSERTION"):
                continue
            purl = ""
            for ref in pkg.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator", "")
                    break
            components.append(Component(
                name=name,
                resolved_version=version,
                component_type="library",
                purl=purl,
            ))
        return components, meta

    # CycloneDX structure (1.5 / 1.6)
    bom_metadata = bom.get("metadata", {})
    component_meta = bom_metadata.get("component", {})
    if component_meta:
        meta["firmware_path"] = component_meta.get("name", "")

    for h in component_meta.get("hashes", []):
        if h.get("alg", "").upper() == "SHA-256":
            meta["firmware_sha256"] = h.get("content", "")
            break

    meta["raw_metadata"] = bom_metadata
    build_info = {}
    for p in bom_metadata.get("properties", []):
        pname = p.get("name", "")
        pval = p.get("value", "")
        if pname == "asrock:chip-model":
            build_info["chip_model"] = pval
        elif pname == "asrock:build-date":
            build_info["build_date"] = pval
        elif pname == "asrock:build-id":
            build_info["build_id"] = pval
        elif pname == "asrock:target-product":
            build_info["target_product"] = pval
    if not build_info.get("target_product") and bom_metadata.get("name"):
        build_info["target_product"] = bom_metadata["name"]
    if not build_info.get("build_id") and bom_metadata.get("version"):
        build_info["build_id"] = bom_metadata["version"]
    meta["build_info"] = build_info

    components = []
    for comp_data in bom.get("components", []):
        name = comp_data.get("name", "")
        version = comp_data.get("version", "")
        if not name:
            continue

        purl = comp_data.get("purl", "")
        cpe = str(comp_data.get("cpe", "") or "")
        for ext_ref in comp_data.get("externalReferences", []):
            if not cpe and ext_ref.get("type") == "cpe":
                cpe = ext_ref.get("url", "")
                break

        comp_type = comp_data.get("type", "library")
        publisher = comp_data.get("publisher", "")
        licenses_list = []
        for lic in comp_data.get("licenses", []):
            license_obj = lic.get("license", {})
            lid = license_obj.get("id", "") or license_obj.get("name", "")
            if lid:
                licenses_list.append(lid)
        properties = [
            {
                "name": str(prop.get("name", "")),
                "value": str(prop.get("value", "")),
            }
            for prop in comp_data.get("properties", [])
            if isinstance(prop, dict) and prop.get("name")
        ]

        components.append(Component(
            name=name,
            vendor=publisher,
            resolved_version=version,
            component_type=comp_type,
            purl=purl,
            cpe=cpe,
            licenses=licenses_list,
            properties=properties,
        ))

    return components, meta

