"""LLVM development banners require corroborating tool and API markers."""

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


def test_llvm_detector_rejects_incomplete_or_conflicting_evidence():
    assert extract_llvm_version(b"\x7fELF\0LLVM (http://llvm.org/):\0") == []
    conflicting = _fixture() + b"\x003.2svn\x00"
    assert extract_llvm_version(conflicting) == []


def test_llvm_host_receives_its_own_observed_development_version():
    components = BinaryInventory().extract(
        _fixture(),
        "libLLVM.so",
        "/lib/libLLVM.so",
    )

    assert components[0].name == "libLLVM.so"
    assert components[0].resolved_version == "3.1svn"
    assert components[0].component_type == "library"
