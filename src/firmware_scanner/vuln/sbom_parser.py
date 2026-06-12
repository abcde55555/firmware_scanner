"""Parse CycloneDX SBOM JSON files into Component list for vulnerability scanning."""

import json
from pathlib import Path

from ..extraction.models import Component


def is_sbom_file(path: Path) -> bool:
    """Check if a file is a CycloneDX SBOM JSON."""
    if path.suffix.lower() != ".json":
        return False
    try:
        with open(path, encoding="utf-8") as f:
            # Read just enough to detect the format without loading entire file
            head = f.read(4096)
        return '"bomFormat"' in head and '"CycloneDX"' in head
    except (OSError, UnicodeDecodeError):
        return False


def parse_sbom_to_components(path: Path) -> tuple[list[Component], dict]:
    """Parse a CycloneDX SBOM JSON and return (components, metadata).

    metadata includes firmware_path and firmware_sha256 if available.
    """
    with open(path, encoding="utf-8") as f:
        bom = json.load(f)

    meta: dict = {}
    # Extract metadata from CycloneDX structure
    bom_metadata = bom.get("metadata", {})
    component_meta = bom_metadata.get("component", {})
    if component_meta:
        meta["firmware_path"] = component_meta.get("name", "")

    # Look for SHA-256 in metadata hashes
    for h in component_meta.get("hashes", []):
        if h.get("alg", "").upper() == "SHA-256":
            meta["firmware_sha256"] = h.get("content", "")
            break

    # Parse components
    components = []
    for comp_data in bom.get("components", []):
        name = comp_data.get("name", "")
        version = comp_data.get("version", "")
        if not name:
            continue

        purl = comp_data.get("purl", "")
        cpe = ""
        # Extract CPE from externalReferences or properties
        for ext_ref in comp_data.get("externalReferences", []):
            if ext_ref.get("type") == "cpe":
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

        components.append(Component(
            name=name,
            vendor=publisher,
            resolved_version=version,
            component_type=comp_type,
            purl=purl,
            cpe=cpe,
            licenses=licenses_list,
        ))

    return components, meta
