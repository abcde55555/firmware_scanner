"""Resolve independently confirmed upstream component identity."""

import json

from .models import Component


def confirmed_upstream_identity(component: Component) -> str:
    """Return a BLint-confirmed component name, otherwise the raw component name."""
    raw = next(
        (
            str(prop.get("value", ""))
            for prop in component.properties
            if prop.get("name") == "firmware:blintdb:identity-confirmed"
        ),
        "",
    )
    if not raw:
        return component.name
    try:
        identity = json.loads(raw)
    except (ValueError, TypeError):
        return component.name
    if not isinstance(identity, dict):
        return component.name
    for key in ("components", "projects"):
        values = identity.get(key, [])
        if not isinstance(values, list):
            continue
        candidates = [str(value).strip() for value in values if str(value).strip()]
        if candidates:
            return candidates[0]
    return component.name
