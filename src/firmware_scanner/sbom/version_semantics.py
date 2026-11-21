"""Separate release versions from internal source-revision identifiers."""

from __future__ import annotations

from ..extraction.models import Component

_SOURCE_REVISION_STATES = {
    "estimated-source-revision",
    "estimated-aosp-source-revision",
}


def component_release_version(component: Component) -> str:
    """Return a release-like version suitable for standardized SBOM fields."""
    version = component.resolved_version.strip()
    if not version or version == "detected" or version.startswith("git:"):
        return ""
    state = next(
        (
            str(prop.get("value", ""))
            for prop in component.properties
            if prop.get("name") == "firmware:version:resolution-state"
        ),
        "",
    )
    return "" if state in _SOURCE_REVISION_STATES else version


def component_package_url(component: Component) -> str:
    """Remove an internal git sentinel from a package URL version component."""
    purl = component.purl.strip()
    if "@git:" in purl:
        return purl.split("@", 1)[0]
    return purl
