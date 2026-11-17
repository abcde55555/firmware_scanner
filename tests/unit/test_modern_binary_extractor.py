"""Unit tests for Go buildinfo, Rust crates, Kernel modules, Python, and Node.js extraction."""

import struct
from firmware_scanner.extraction.modern_binary_extractor import (
    extract_go_buildinfo,
    extract_rust_crates,
    extract_kernel_module_info,
    extract_python_dist_info,
    extract_npm_package_json,
)
from firmware_scanner.extraction.smart_analyzer import SmartSectionAnalyzer


def test_go_buildinfo_extraction():
    # Construct a mock Go binary snippet with buildinfo
    buf = bytearray(b"\x00" * 1024)
    magic = b"\xff\x20\x47\x6f\x20\x62\x75\x69\x6c\x64\x69\x6e\x66\x3a"
    buf[100 : 100 + len(magic)] = magic

    modinfo = (
        b"\npath\tgithub.com/example/gateway\n"
        b"mod\tgithub.com/example/gateway\tv1.2.0\th1:abc\n"
        b"dep\tgithub.com/gin-gonic/gin\tv1.9.1\th1:def\n"
        b"dep\tgolang.org/x/crypto\tv0.17.0\th1:ghi\n\x00"
    )
    buf[120 : 120 + len(modinfo)] = modinfo

    comps = extract_go_buildinfo(bytes(buf), "usr/bin/gateway")
    assert len(comps) == 3

    main_mod = next(c for c in comps if c.name == "github.com/example/gateway")
    assert main_mod.resolved_version == "1.2.0"
    assert main_mod.component_type == "application"

    gin_dep = next(c for c in comps if c.name == "github.com/gin-gonic/gin")
    assert gin_dep.resolved_version == "1.9.1"
    assert gin_dep.purl == "pkg:golang/github.com/gin-gonic/gin@v1.9.1"
    assert gin_dep.versions[0].confidence == 1.0


def test_rust_crates_extraction():
    # Construct mock Rust binary with cargo registry paths
    data = (
        b"Error in /.cargo/registry/src/index.crates.io-6f17d22bba15001f/tokio-1.35.0/src/runtime.rs\n"
        b"Panic at /.cargo/registry/src/index.crates.io-6f17d22bba15001f/serde-1.0.193/src/de.rs\n"
    )
    comps = extract_rust_crates(data, "usr/bin/sensor_agent")
    assert len(comps) == 2

    tokio_comp = next(c for c in comps if c.name == "tokio")
    assert tokio_comp.resolved_version == "1.35.0"
    assert tokio_comp.purl == "pkg:cargo/tokio@1.35.0"

    serde_comp = next(c for c in comps if c.name == "serde")
    assert serde_comp.resolved_version == "1.0.193"
    assert serde_comp.purl == "pkg:cargo/serde@1.0.193"


def test_kernel_module_modinfo_extraction():
    # Construct a minimal ELF with .modinfo section or fallback string
    buf = bytearray(b"\x7fELF" + b"\x01\x01\x01\x00" + b"\x00" * 56)
    modinfo_content = (
        b"version=3.2.1\x00"
        b"description=Realtek RTL8152 USB Ethernet Driver\x00"
        b"author=Realtek NIC Team\x00"
        b"license=GPL\x00"
        b"depends=usbcore,mii\x00"
    )
    buf.extend(modinfo_content)

    comps = extract_kernel_module_info(bytes(buf), "lib/modules/r8152.ko")
    assert len(comps) == 1
    c = comps[0]
    assert c.name == "kernel-module/r8152"
    assert c.resolved_version == "3.2.1"
    assert "Realtek" in c.description
    assert c.licenses == ["GPL"]
    assert c.component_type == "device-driver"


def test_python_dist_info_extraction():
    metadata_text = (
        "Metadata-Version: 2.1\n"
        "Name: requests\n"
        "Version: 2.31.0\n"
        "Summary: Python HTTP for Humans.\n"
        "Author: Kenneth Reitz\n"
        "License: Apache 2.0\n"
    )
    comps = extract_python_dist_info(metadata_text, "usr/lib/python3.10/site-packages/requests-2.31.0.dist-info/METADATA")
    assert len(comps) == 1
    c = comps[0]
    assert c.name == "requests"
    assert c.resolved_version == "2.31.0"
    assert c.purl == "pkg:pypi/requests@2.31.0"
    assert c.licenses == ["Apache 2.0"]


def test_npm_package_json_extraction():
    pkg_json = '{"name": "express", "version": "4.18.2", "description": "Fast, unopinionated, minimalist web framework", "license": "MIT"}'
    comps = extract_npm_package_json(pkg_json, "www/admin/package.json")
    assert len(comps) == 1
    c = comps[0]
    assert c.name == "express"
    assert c.resolved_version == "4.18.2"
    assert c.purl == "pkg:npm/express@4.18.2"
    assert c.licenses == ["MIT"]
