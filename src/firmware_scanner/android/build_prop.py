"""Android build.prop / default.prop parser.

Extracts system metadata (Android version, security patch, manufacturer, etc.)
and converts to Component objects for SBOM generation.
"""

import re
from dataclasses import dataclass, field

from ..extraction.models import Component, VersionConfidence, ExtractionMethod


@dataclass
class AndroidBuildInfo:
    android_version: str = ""
    sdk_version: int = 0
    security_patch: str = ""
    build_fingerprint: str = ""
    manufacturer: str = ""
    model: str = ""
    brand: str = ""
    board: str = ""
    device: str = ""
    build_type: str = ""
    build_id: str = ""
    incremental: str = ""
    vendor_security_patch: str = ""
    kernel_version: str = ""
    baseband_version: str = ""
    bootloader_version: str = ""
    hardware: str = ""
    platform: str = ""
    abi: str = ""
    all_properties: dict[str, str] = field(default_factory=dict)


# Property name -> AndroidBuildInfo field mapping
_PROPERTY_MAP = {
    "ro.build.version.release": "android_version",
    "ro.build.version.release_or_codename": "android_version",
    "ro.build.version.sdk": "sdk_version",
    "ro.build.version.security_patch": "security_patch",
    "ro.build.fingerprint": "build_fingerprint",
    "ro.product.manufacturer": "manufacturer",
    "ro.product.model": "model",
    "ro.product.brand": "brand",
    "ro.product.board": "board",
    "ro.product.device": "device",
    "ro.build.type": "build_type",
    "ro.build.id": "build_id",
    "ro.build.version.incremental": "incremental",
    "ro.vendor.build.security_patch": "vendor_security_patch",
    "ro.hardware": "hardware",
    "ro.board.platform": "platform",
    "ro.product.cpu.abi": "abi",
}


class BuildPropParser:
    """Parse Android build.prop files."""

    def parse(self, data: bytes) -> AndroidBuildInfo:
        """Parse build.prop content into structured info."""
        info = AndroidBuildInfo()

        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            return info

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if '=' not in line:
                continue

            key, _, value = line.partition('=')
            key = key.strip()
            value = value.strip()

            if not key or not value:
                continue

            info.all_properties[key] = value

            if key in _PROPERTY_MAP:
                field_name = _PROPERTY_MAP[key]
                if field_name == "sdk_version":
                    try:
                        setattr(info, field_name, int(value))
                    except ValueError:
                        pass
                else:
                    current = getattr(info, field_name, "")
                    if not current:
                        setattr(info, field_name, value)

        # Extract kernel version from ro.kernel.version or proc version string
        for key in ("ro.kernel.version", "ro.bootimage.build.version.release"):
            if key in info.all_properties:
                info.kernel_version = info.all_properties[key]
                break

        # Extract baseband
        for key in ("gsm.version.baseband", "ro.baseband"):
            if key in info.all_properties:
                info.baseband_version = info.all_properties[key]
                break

        return info

    def to_components(self, info: AndroidBuildInfo) -> list[Component]:
        """Convert build info into Component objects for the SBOM."""
        components: list[Component] = []

        # Android OS itself
        if info.android_version:
            os_version = info.android_version
            if info.security_patch:
                os_version_full = f"{info.android_version} (patch: {info.security_patch})"
            else:
                os_version_full = info.android_version

            vendor = info.manufacturer or info.brand or "Google"
            description_parts = []
            if info.model:
                description_parts.append(f"Device: {info.model}")
            if info.build_fingerprint:
                description_parts.append(f"Fingerprint: {info.build_fingerprint}")
            if info.build_type:
                description_parts.append(f"Build type: {info.build_type}")

            components.append(Component(
                name="Android",
                vendor=vendor,
                component_type="operating-system",
                resolved_version=os_version,
                description="; ".join(description_parts) if description_parts else "",
                versions=[VersionConfidence(
                    version=os_version,
                    confidence=0.98,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"build.prop ro.build.version.release={info.android_version}",
                )],
                purl=f"pkg:generic/android@{info.android_version}",
            ))

        # Security patch level as a separate component (for vulnerability tracking)
        if info.security_patch:
            components.append(Component(
                name="Android Security Patch",
                vendor=info.manufacturer or "Google",
                component_type="operating-system",
                resolved_version=info.security_patch,
                versions=[VersionConfidence(
                    version=info.security_patch,
                    confidence=0.98,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"build.prop ro.build.version.security_patch={info.security_patch}",
                )],
            ))

        # Linux kernel if version known
        if info.kernel_version:
            components.append(Component(
                name="Linux Kernel",
                vendor="Linux",
                component_type="operating-system",
                resolved_version=info.kernel_version,
                versions=[VersionConfidence(
                    version=info.kernel_version,
                    confidence=0.85,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"build.prop kernel version={info.kernel_version}",
                )],
                purl=f"pkg:generic/linux-kernel@{info.kernel_version}",
            ))

        # Baseband/radio firmware
        if info.baseband_version:
            components.append(Component(
                name="Baseband Firmware",
                vendor=info.manufacturer or "",
                component_type="firmware",
                resolved_version=info.baseband_version,
                versions=[VersionConfidence(
                    version=info.baseband_version,
                    confidence=0.90,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"build.prop baseband={info.baseband_version}",
                )],
            ))

        # Vendor security patch (separate from Android patch)
        if info.vendor_security_patch and info.vendor_security_patch != info.security_patch:
            components.append(Component(
                name="Vendor Security Patch",
                vendor=info.manufacturer or "",
                component_type="operating-system",
                resolved_version=info.vendor_security_patch,
                versions=[VersionConfidence(
                    version=info.vendor_security_patch,
                    confidence=0.95,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"build.prop ro.vendor.build.security_patch={info.vendor_security_patch}",
                )],
            ))

        return components
