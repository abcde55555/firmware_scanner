"""LLVM development banners require corroborating tool and API markers."""

import pytest

from firmware_scanner.extraction.binary_inventory import BinaryInventory
from firmware_scanner.extraction.llvm_version import extract_llvm_version


def _fixture(version: bytes = b"3.1svn") -> bytes:
    return (
        b"\x7fELF"
        b"\0LLVM (http://llvm.org/):\0LLVM\0 version \0"
        + version
        + b"\0llvm-mc (based on LLVM \0"
        b"LLVMPassManagerBuilderCreate\0"
        b"LLVMLinkModules\0"
        b"LLVMDisposeTargetData\0"
        b"LLVMInitializeARMAsmPrinter\0"
    )


def test_llvm_banner_and_api_markers_recover_development_snapshot():
    hits = extract_llvm_version(_fixture())

    assert [(hit.name, hit.version, hit.confidence) for hit in hits] == [
        ("LLVM", "3.1svn", 0.96)
    ]


def test_llvm_android_numeric_build_version_is_supported():
    hits = extract_llvm_version(_fixture(b"3.8.275480"))

    assert [(hit.name, hit.version) for hit in hits] == [("LLVM", "3.8.275480")]


def test_llvm_detector_rejects_incomplete_or_conflicting_evidence():
    assert extract_llvm_version(b"\x7fELF\0LLVM (http://llvm.org/):\0") == []
    conflicting = _fixture() + b"\0llvm-mc (based on LLVM 3.2svn)\0"
    assert extract_llvm_version(conflicting) == []


@pytest.mark.parametrize(
    ("filename", "version"),
    [
        ("libLLVM.so", b"3.1svn"),
        ("libLLVM_android.so", b"3.8.275480"),
    ],
)
def test_llvm_host_receives_its_own_observed_build_version(filename, version):
    components = BinaryInventory().extract(
        _fixture(version),
        filename,
        f"/lib/{filename}",
    )

    assert components[0].name == filename
    assert components[0].resolved_version == version.decode("ascii")
    assert components[0].component_type == "library"
