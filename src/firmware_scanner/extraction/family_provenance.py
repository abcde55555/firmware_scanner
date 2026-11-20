"""Propagate releases across components known to ship from one source package."""

from __future__ import annotations

from collections import defaultdict

from .models import Component, ExtractionMethod, VersionConfidence


_FAMILY_PATTERNS = {
    "e2fsprogs": (
        "libext2fs",
        "libext2_blkid",
        "libext2_com_err",
        "libext2_e2p",
        "libext2_profile",
        "libext2_quota",
        "libext2_uuid",
        "e2fsck",
        "mke2fs",
        "resize2fs",
        "tune2fs",
    ),
    "icu": (
        "libicu",
        "libicuuc",
        "libicui18n",
    ),
}


def _family(name: str) -> str:
    base = name.rsplit("/", 1)[-1].lower()
    base = base.split(".so", 1)[0]
    for family, names in _FAMILY_PATTERNS.items():
        if base in names:
            return family
    return ""


def _version_state(component: Component) -> str:
    return next(
        (
            str(prop.get("value", ""))
            for prop in component.properties
            if prop.get("name") == "firmware:version:resolution-state"
        ),
        "",
    )


def apply_family_version_provenance(components: list[Component]) -> dict:
    """Fill unknown siblings from one unambiguous same-source release."""
    grouped: dict[str, list[Component]] = defaultdict(list)
    for component in components:
        family = _family(component.name)
        if family:
            grouped[family].append(component)

    inherited = 0
    family_rows = []
    for family, members in sorted(grouped.items()):
        donors = [
            component
            for component in members
            if component.resolved_version and _version_state(component) in {"exact", "estimated"}
        ]
        versions = {component.resolved_version for component in donors}
        if len(versions) != 1:
            continue
        donor = donors[0]
        version = next(iter(versions))
        for component in members:
            if component.resolved_version:
                continue
            component.resolved_version = version
            component.purl = (
                f"{component.purl.split('@', 1)[0]}@{version}" if component.purl else component.purl
            )
            component.versions.append(
                VersionConfidence(
                    version=version,
                    confidence=0.8,
                    method=ExtractionMethod.VERSION_ESTIMATE,
                    evidence=(
                        f"{family} shared-source family version inherited from "
                        f"{donor.name} ({version})"
                    ),
                )
            )
            component.properties = [
                prop
                for prop in component.properties
                if prop.get("name") != "firmware:version:resolution-state"
            ]
            component.properties.extend(
                [
                    {
                        "name": "firmware:version:resolution-state",
                        "value": "estimated",
                    },
                    {
                        "name": "firmware:version:family",
                        "value": family,
                    },
                ]
            )
            inherited += 1
            family_rows.append(
                {
                    "name": component.name,
                    "family": family,
                    "version": version,
                    "donor": donor.name,
                }
            )
    return {
        "versions_inherited": inherited,
        "rows": family_rows,
        "scope": "same-source package family; inherited versions remain estimates",
    }
