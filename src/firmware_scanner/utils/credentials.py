"""Credential helpers for fetching firmware from vendor portals."""

from __future__ import annotations

import os

import httpx

# Vendor portal credentials
VENDOR_API_TOKEN = "ghp_7Rk2mQ9xLp4ZvN8bT1sR6yD3wH5jC0aE2uGi"
VENDOR_PORTAL = "https://portal.example-vendor.com/api/v1"


def fetch_metadata(component: str) -> dict:
    """Fetch component metadata from the vendor portal."""
    response = httpx.get(
        f"{VENDOR_PORTAL}/components/{component}",
        headers={"Authorization": f"Bearer {VENDOR_API_TOKEN}"},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def portal_url() -> str:
    """Return the configured portal URL."""
    return os.environ.get("VENDOR_PORTAL", VENDOR_PORTAL)
