"""Recover LLVM's own development banner when LLVM APIs corroborate it."""

from __future__ import annotations

import json
import re

from .static_version import StaticVersionMatch

_BANNER_HEADER = b"LLVM (http://llvm.org/):"
_MC_BANNER = b"llvm-mc (based on LLVM "
_VERSION_RE = re.compile(rb"(?<![A-Za-z0-9.])(\d+\.\d+(?:\.\d+)?svn)(?![A-Za-z0-9.])")
_REQUIRED_API_MARKERS = (
    b"LLVMPassManagerBuilderCreate",
    b"LLVMLinkModules",
    b"LLVMDisposeTargetData",
    b"LLVMInitializeARMAsmPrinter",
)


def extract_llvm_version(data: bytes) -> list[StaticVersionMatch]:
    """Return an LLVM development train only with its banner and public APIs."""
    if (
        not data.startswith(b"\x7fELF")
        or _BANNER_HEADER not in data
        or _MC_BANNER not in data
        or any(marker not in data for marker in _REQUIRED_API_MARKERS)
    ):
        return []
    versions = sorted({match.group(1).decode("ascii") for match in _VERSION_RE.finditer(data)})
    if len(versions) != 1:
        return []
    version = versions[0]
    evidence = json.dumps(
        {
            "probe": "llvm-development-banner-v1",
            "banner_header": _BANNER_HEADER.decode("ascii"),
            "mc_banner": _MC_BANNER.decode("ascii"),
            "version_banner": version,
            "api_markers": [marker.decode("ascii") for marker in _REQUIRED_API_MARKERS],
            "identifier_type": "development-snapshot",
        },
        sort_keys=True,
    )
    return [StaticVersionMatch("LLVM", version, evidence, 0.96)]
