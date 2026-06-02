"""Linux/OpenWrt detection plugin."""

import re
from ...core.context import AnalysisContext
from ...extraction.models import Component, VersionConfidence, ExtractionMethod
from ..base import RTOSPlugin
from ..registry import RTOSRegistry


@RTOSRegistry.register
class LinuxPlugin(RTOSPlugin):
    @property
    def rtos_name(self) -> str:
        return "Linux"

    @property
    def vendor(self) -> str:
        return "Linux Foundation"

    def detect(self, context: AnalysisContext) -> float:
        score = 0.0
        data = context.raw_data[:16 * 1024 * 1024]

        if b"Linux version " in data:
            score += 0.5
        if b"OpenWrt" in data or b"LEDE" in data:
            score += 0.4
        elif b"DD-WRT" in data:
            score += 0.4
        if b"vmlinux" in data or b"vmlinuz" in data:
            score += 0.1
        if b"/proc/" in data and b"/sys/" in data:
            score += 0.1
        if b"ext4" in data or b"squashfs" in data or b"jffs2" in data:
            score += 0.05

        return min(score, 1.0)

    async def analyze(self, context: AnalysisContext) -> list[Component]:
        """Extract Linux kernel version and distribution info."""
        components: list[Component] = []
        data = context.raw_data[:16 * 1024 * 1024]
        text = data.decode("ascii", errors="ignore")

        # Extract kernel version
        m = re.search(r"Linux version (\d+\.\d+\.\d+[^\s]*)", text)
        if m:
            kernel_ver = m.group(1)
            components.append(Component(
                name="linux_kernel",
                vendor="linux",
                component_type="operating-system",
                resolved_version=kernel_ver,
                versions=[VersionConfidence(
                    version=kernel_ver,
                    confidence=0.95,
                    method=ExtractionMethod.STRING_PATTERN,
                    evidence=f"Linux version {kernel_ver}",
                )],
                purl=f"pkg:generic/linux/kernel@{kernel_ver}",
            ))

        # Detect distribution
        distro = ""
        if b"OpenWrt" in data:
            distro = "OpenWrt"
            dm = re.search(r'DISTRIB_RELEASE="([^"]+)"', text)
            if not dm:
                dm = re.search(r"OpenWrt[/ ]([\d][\w.\-]+)", text)
            if dm:
                distro_ver = dm.group(1)
                components.append(Component(
                    name="openwrt",
                    vendor="openwrt",
                    component_type="operating-system",
                    resolved_version=distro_ver,
                    versions=[VersionConfidence(
                        version=distro_ver,
                        confidence=0.90,
                        method=ExtractionMethod.STRING_PATTERN,
                        evidence=f"OpenWrt {distro_ver}",
                    )],
                    purl=f"pkg:generic/openwrt/openwrt@{distro_ver}",
                ))
        elif b"DD-WRT" in data:
            distro = "DD-WRT"

        return components

    def get_version_patterns(self) -> list[str]:
        return [
            r"Linux version (\d+\.\d+\.\d+)",
            r"OpenWrt[/ ](\S+)",
        ]

    def get_known_symbols(self) -> list[str]:
        return [
            "do_fork", "sys_open", "sys_read", "printk",
            "schedule", "kthread_create", "kmalloc",
        ]
