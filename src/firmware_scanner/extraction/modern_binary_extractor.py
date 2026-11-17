"""High-precision component extractors for Go, Rust, Linux Kernel modules, Python, and Node.js.

Extracts exact dependencies and versions from:
- Go binaries: runtime.modinfo and Go buildinfo (100% confidence)
- Rust binaries: Cargo registry crate paths in binary .rodata
- Linux Kernel modules (.ko): ELF .modinfo section (driver version, license, author)
- Python packages: .dist-info/METADATA and PKG-INFO
- Node.js packages: package.json in web roots
"""

import json
import re
import struct
from typing import Optional

from .models import Component, VersionConfidence, ExtractionMethod


# Go buildinfo magic sequence: \xff Go buildinf:
_GO_BUILDINF_MAGIC = b"\xff\x20\x47\x6f\x20\x62\x75\x69\x6c\x64\x69\x6e\x66\x3a"

# Rust crate pattern in .rodata
_RUST_CRATE_RE = re.compile(
    rb"/\.cargo/registry/src/[^/]+/([a-zA-Z0-9_\-]+)-(\d+\.\d+(?:\.\d+)?(?:[\.\-_][a-zA-Z0-9]+)?)/"
)


def extract_go_buildinfo(data: bytes, filename: str) -> list[Component]:
    """Extract exact Go module dependencies from Go compiled binaries."""
    components: list[Component] = []
    seen: set[str] = set()

    modinfo_text: Optional[str] = None

    # Method 1: Magic-based search
    pos = data.find(_GO_BUILDINF_MAGIC)
    if pos >= 0:
        window = data[pos : pos + 131072]
        path_pos = window.find(b"path\t")
        if path_pos >= 0:
            end_pos = window.find(b"\x00", path_pos)
            if end_pos < 0:
                end_pos = len(window)
            modinfo_text = window[path_pos:end_pos].decode("utf-8", errors="ignore")

    # Method 2: Raw table search fallback
    if not modinfo_text:
        raw_pos = data.find(b"\ndep\t")
        if raw_pos >= 0:
            start_pos = data.rfind(b"\npath\t", max(0, raw_pos - 4096), raw_pos)
            if start_pos < 0:
                start_pos = raw_pos
            end_pos = data.find(b"\x00", raw_pos)
            if end_pos < 0:
                end_pos = raw_pos + 32768
            modinfo_text = data[start_pos:end_pos].decode("utf-8", errors="ignore")

    if not modinfo_text:
        return components

    for line in modinfo_text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        p_type = parts[0]

        if p_type == "mod" and len(parts) >= 3:
            mod_path = parts[1].strip()
            mod_ver = parts[2].strip()
            if mod_path not in seen:
                seen.add(mod_path)
                components.append(Component(
                    name=mod_path,
                    component_type="application",
                    resolved_version=mod_ver.lstrip("v"),
                    purl=f"pkg:golang/{mod_path}@{mod_ver}",
                    description=f"Go main module in {filename}",
                    versions=[VersionConfidence(
                        version=mod_ver.lstrip("v"),
                        confidence=1.0,
                        method=ExtractionMethod.MANIFEST_BINARY,
                        evidence=f"runtime.modinfo in {filename}",
                    )],
                ))

        elif p_type == "dep" and len(parts) >= 3:
            dep_path = parts[1].strip()
            dep_ver = parts[2].strip()
            if dep_path not in seen:
                seen.add(dep_path)
                clean_ver = dep_ver.lstrip("v")
                components.append(Component(
                    name=dep_path,
                    component_type="library",
                    resolved_version=clean_ver,
                    purl=f"pkg:golang/{dep_path}@{dep_ver}",
                    description=f"Go dependency module in {filename}",
                    versions=[VersionConfidence(
                        version=clean_ver,
                        confidence=1.0,
                        method=ExtractionMethod.MANIFEST_BINARY,
                        evidence=f"Go buildinfo dependency in {filename}",
                    )],
                ))

    return components


def extract_rust_crates(data: bytes, filename: str) -> list[Component]:
    """Extract Rust crate names and versions from compiled binary strings."""
    components: list[Component] = []
    seen: set[str] = set()

    for match in _RUST_CRATE_RE.finditer(data):
        crate_name = match.group(1).decode("ascii", errors="ignore")
        crate_ver = match.group(2).decode("ascii", errors="ignore")
        if crate_name in seen:
            continue
        seen.add(crate_name)

        components.append(Component(
            name=crate_name,
            component_type="library",
            resolved_version=crate_ver,
            purl=f"pkg:cargo/{crate_name}@{crate_ver}",
            description=f"Rust crate dependency in {filename}",
            versions=[VersionConfidence(
                version=crate_ver,
                confidence=0.95,
                method=ExtractionMethod.STRING_PATTERN,
                evidence=f"Cargo registry path in {filename}",
            )],
        ))

    return components


def extract_kernel_module_info(data: bytes, filename: str) -> list[Component]:
    """Parse .modinfo section from Linux Kernel Module (.ko)."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return []

    modinfo_bytes: Optional[bytes] = None

    # Parse ELF section headers
    try:
        ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = data[5]   # 1 = LE, 2 = BE
        endian = "<" if ei_data == 1 else ">"

        if ei_class == 1:  # ELF32
            shoff = struct.unpack_from(f"{endian}I", data, 32)[0]
            shentsize = struct.unpack_from(f"{endian}H", data, 46)[0]
            shnum = struct.unpack_from(f"{endian}H", data, 48)[0]
            shstrndx = struct.unpack_from(f"{endian}H", data, 50)[0]
        else:  # ELF64
            shoff = struct.unpack_from(f"{endian}Q", data, 40)[0]
            shentsize = struct.unpack_from(f"{endian}H", data, 58)[0]
            shnum = struct.unpack_from(f"{endian}H", data, 60)[0]
            shstrndx = struct.unpack_from(f"{endian}H", data, 62)[0]

        # Get string table
        strtab_offset = 0
        if shstrndx < shnum:
            entry_offset = shoff + shstrndx * shentsize
            if ei_class == 1:
                strtab_offset = struct.unpack_from(f"{endian}I", data, entry_offset + 16)[0]
            else:
                strtab_offset = struct.unpack_from(f"{endian}Q", data, entry_offset + 24)[0]

        # Find .modinfo
        for i in range(shnum):
            entry_offset = shoff + i * shentsize
            if entry_offset + shentsize > len(data):
                break
            name_idx = struct.unpack_from(f"{endian}I", data, entry_offset)[0]
            if strtab_offset + name_idx < len(data):
                sec_name = data[strtab_offset + name_idx :].split(b"\x00")[0]
                if sec_name == b".modinfo":
                    if ei_class == 1:
                        sec_offset = struct.unpack_from(f"{endian}I", data, entry_offset + 16)[0]
                        sec_size = struct.unpack_from(f"{endian}I", data, entry_offset + 20)[0]
                    else:
                        sec_offset = struct.unpack_from(f"{endian}Q", data, entry_offset + 24)[0]
                        sec_size = struct.unpack_from(f"{endian}Q", data, entry_offset + 32)[0]

                    modinfo_bytes = data[sec_offset : sec_offset + sec_size]
                    break
    except Exception:
        pass

    # Fallback search for vermagic= / license=
    if not modinfo_bytes:
        pos = data.find(b"license=")
        if pos >= 0:
            start_pos = max(0, pos - 1024)
            end_pos = min(len(data), pos + 4096)
            modinfo_bytes = data[start_pos:end_pos]

    if not modinfo_bytes:
        return []

    props: dict[str, str] = {}
    for entry in modinfo_bytes.split(b"\x00"):
        if b"=" in entry:
            try:
                k, v = entry.decode("utf-8", errors="ignore").split("=", 1)
                props[k.strip()] = v.strip()
            except Exception:
                pass

    if not props:
        return []

    mod_name = filename.rsplit("/", 1)[-1].replace(".ko", "")
    version = props.get("version", "")
    if not version and "vermagic" in props:
        # e.g. "5.10.110-arm64 SMP mod_unload" -> "5.10.110"
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", props["vermagic"])
        if m:
            version = m.group(1)

    license_str = props.get("license", "")
    desc = props.get("description", f"Linux kernel driver module {mod_name}")
    author = props.get("author", "")

    return [
        Component(
            name=f"kernel-module/{mod_name}",
            vendor=author,
            component_type="device-driver",
            resolved_version=version,
            purl=f"pkg:generic/{mod_name}@{version}" if version else f"pkg:generic/{mod_name}",
            licenses=[license_str] if license_str else [],
            description=desc,
            versions=[VersionConfidence(
                version=version,
                confidence=0.95 if version else 0.70,
                method=ExtractionMethod.MANIFEST_BINARY,
                evidence=f".modinfo in {filename}",
            )],
        )
    ]


def extract_python_dist_info(text: str, filename: str) -> list[Component]:
    """Parse Python .dist-info/METADATA or PKG-INFO."""
    headers: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            break  # headers end at first empty line
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    name = headers.get("name")
    version = headers.get("version")
    if not name or not version:
        return []

    license_str = headers.get("license", "")
    desc = headers.get("summary", f"Python package {name}")
    author = headers.get("author", "")

    return [
        Component(
            name=name,
            vendor=author,
            component_type="library",
            resolved_version=version,
            purl=f"pkg:pypi/{name}@{version}",
            licenses=[license_str] if license_str else [],
            description=desc,
            versions=[VersionConfidence(
                version=version,
                confidence=1.0,
                method=ExtractionMethod.MANIFEST_BINARY,
                evidence=f"Python dist-info in {filename}",
            )],
        )
    ]


def extract_npm_package_json(text: str, filename: str) -> list[Component]:
    """Parse Node.js package.json file."""
    try:
        pkg = json.loads(text)
    except Exception:
        return []

    if not isinstance(pkg, dict):
        return []

    name = pkg.get("name")
    version = pkg.get("version")
    if not name or not version:
        return []

    license_str = pkg.get("license", "")
    desc = pkg.get("description", f"Node.js package {name}")

    return [
        Component(
            name=name,
            component_type="library",
            resolved_version=version,
            purl=f"pkg:npm/{name}@{version}",
            licenses=[license_str] if license_str else [],
            description=desc,
            versions=[VersionConfidence(
                version=version,
                confidence=1.0,
                method=ExtractionMethod.MANIFEST_BINARY,
                evidence=f"package.json in {filename}",
            )],
        )
    ]
