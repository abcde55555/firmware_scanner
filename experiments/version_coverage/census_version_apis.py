#!/usr/bin/env python3
"""Bounded census of defined ELF version/release-named APIs in two ext4 images.

This is a candidate scout only. It reads direct ELF files named by the frozen
host observations, never opens nested archive paths, and never loads target code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

MAX_ELF = 64 * 1024 * 1024
SYMBOL_RE = re.compile(r"(?:version|release|revision|vernum|ver_str)", re.IGNORECASE)
INTERFACE_RE = re.compile(
    r"(?:aidl|hidl|hal|interface|protocol|wire|schema|api[_-]?level|"
    r"android[_-]?version|platform[_-]?version|sdk[_-]?version)", re.IGNORECASE
)
ROOT = Path(__file__).resolve().parents[2]
DEFAULTS = {
    "system": {
        "image": Path("/home/kali/Desktop/work/project/vulnscan/system.img"),
        "observations": ROOT / "reports/version-coverage-next-20261118/final-reviewed/system/file-observations.json",
    },
    "allwinner": {
        "image": ROOT / "reports/accuracy-20261118/evidence/allwinner-system.img",
        "observations": ROOT / "reports/version-coverage-next-20261118/final-reviewed/allwinner/file-observations.json",
    },
}


def sha256(data: bytes | mmap.mmap) -> str:
    h = hashlib.sha256()
    view = memoryview(data)
    for offset in range(0, len(view), 1024 * 1024):
        h.update(view[offset : offset + 1024 * 1024])
    return h.hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_defined_symbols(data: bytes):
    """Return only defined STT_FUNC/OBJECT symbols with version-like names."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    elf = ELFFile(__import__("io").BytesIO(data))
    found, seen = [], set()
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            name = symbol.name
            if not name or symbol["st_shndx"] == "SHN_UNDEF":
                continue
            kind = symbol["st_info"]["type"]
            if kind not in ("STT_FUNC", "STT_OBJECT") or not SYMBOL_RE.search(name):
                continue
            key = (name, kind, int(symbol["st_size"]), int(symbol["st_value"]))
            if key in seen:
                continue
            seen.add(key)
            found.append({"name": name, "type": kind.removeprefix("STT_"), "size": int(symbol["st_size"]),
                          "value": hex(int(symbol["st_value"])),
                          "interface_or_protocol_name": bool(INTERFACE_RE.search(name))})
    return elf, found


def _read_candidates(image_path: Path, observation_path: Path, label: str):
    from firmware_scanner.android.ext4_reader import Ext4Reader

    observations = json.loads(observation_path.read_text())
    selected = {}
    nested = 0
    for item in observations:
        path = item.get("location", "")
        if "!" in path:
            nested += 1
            continue
        claims = item.get("claims", [])
        if item.get("type") != "library" or not any(not c.get("version") for c in claims):
            continue
        selected.setdefault(path, item)

    errors = []
    scanned = []
    cache = {}
    with image_path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as image:
        reader = Ext4Reader(image)
        if not reader.is_valid():
            raise ValueError(f"{label}: input is not a valid ext4 image")
        for path, host in sorted(selected.items()):
            base = {"path": path, "host_sha256": host.get("sha256"), "host_size": host.get("size")}
            try:
                size = reader.file_size(path)
                if not size:
                    raise ValueError("missing or empty ext4 file")
                if size > MAX_ELF:
                    raise ValueError("file exceeds 64 MiB read bound")
                data = reader.read_file(path, max_size=MAX_ELF)
                if len(data) != size:
                    raise ValueError(f"short read: expected {size}, got {len(data)}")
                if not data.startswith(b"\x7fELF"):
                    raise ValueError("direct path is not ELF")
                digest = hashlib.sha256(data).hexdigest()
                if host.get("sha256") and digest != host["sha256"]:
                    raise ValueError("ELF SHA-256 differs from the frozen file observation")
                if digest not in cache:
                    try:
                        elf, symbols = parse_defined_symbols(data)
                        cache[digest] = {"status": "analyzed", "architecture": elf.get_machine_arch(),
                                         "elf_class": elf.elfclass, "byteorder": elf.little_endian,
                                         "matches": symbols, "analysis_error": None}
                    except Exception as exc:  # noqa: BLE001 - retain each parse failure
                        cache[digest] = {"status": "analysis-error", "matches": [],
                                         "analysis_error": f"{type(exc).__name__}: {exc}"}
                analysis = cache[digest]
                scanned.append({**base, "sha256": digest, "size": size,
                                "architecture": analysis.get("architecture"),
                                "elf_class": analysis.get("elf_class"),
                                "defined_version_symbols": analysis["matches"],
                                "analysis_status": analysis["status"],
                                "analysis_error": analysis.get("analysis_error"),
                                "sha_cache_reused": sum(x.get("sha256") == digest for x in scanned) > 0})
            except Exception as exc:  # noqa: BLE001 - every skipped read is counted and retained
                errors.append({**base, "stage": "read", "error": f"{type(exc).__name__}: {exc}"})
    unique = {}
    for row in scanned:
        unique.setdefault(row["sha256"], row)
    family_paths = defaultdict(set)
    family_symbols = defaultdict(set)
    for row in scanned:
        for match in row["defined_version_symbols"]:
            family = Path(row["path"]).name
            family = re.sub(r"\.so(?:\..*)?$", "", family)
            family_paths[family].add(row["path"])
            family_symbols[family].add(match["name"])
    return {
        "label": label, "image": str(image_path.resolve()), "image_size": image_path.stat().st_size,
        "image_sha256": file_sha256(image_path), "observation_source": str(observation_path.resolve()),
        "observation_source_sha256": hashlib.sha256(observation_path.read_bytes()).hexdigest(),
        "observations_total": len(observations), "nested_paths_excluded": nested,
        "eligible_unique_paths": len(selected), "read_ok_paths": len(scanned),
        "read_errors_or_bound_skips": len(errors), "unique_sha256_analyzed": len(cache),
        "duplicate_sha_paths": len(scanned) - len(unique),
        "analysis_errors": sum(x["status"] == "analysis-error" for x in cache.values()),
        "paths_with_version_like_defined_symbols": sum(bool(x["defined_version_symbols"]) for x in scanned),
        "read_errors": errors, "files": scanned,
        "symbol_families": [{"library_basename": name, "paths": sorted(paths),
                             "symbols": sorted(family_symbols[name]),
                             "interface_or_protocol_only_names": all(INTERFACE_RE.search(s) for s in family_symbols[name])}
                            for name, paths in sorted(family_paths.items())],
    }


def run(system_image: Path, allwinner_image: Path, output: Path):
    # Defer imports until the CLI configures the local source tree.
    data = {"method": "read-only mmap + Ext4Reader; direct host-claim libraries only; max 64 MiB per file; pyelftools defined STT_FUNC/STT_OBJECT; no target execution",
            "compiler_ids_soname_hal_or_api_version_used_as_release": False,
            "inputs": {}}
    for label, image in (("system", system_image), ("allwinner", allwinner_image)):
        data["inputs"][label] = _read_candidates(image, DEFAULTS[label]["observations"], label)
    candidate_specs = [
        ("libbpf", "system", "/system/lib64/libbpf.so", ("libbpf_version_string", "libbpf_major_version", "libbpf_minor_version"), "The named APIs/objects expose libbpf's own release; inspect returned values and ABI before any product rule."),
        ("libdrm", "system", "/system/lib64/libdrm.so", ("drmGetLibVersion", "drmGetVersion"), "Library version API is plausible; validate returned struct semantics and release mapping."),
        ("e2fsprogs libblkid", "system", "/system/lib64/libext2_blkid.so", ("blkid_get_library_version",), "Explicit library-version getter; confirm returned text is the library release."),
        ("e2fsprogs libblkid", "allwinner", "/lib/libext2_blkid.so", ("blkid_get_library_version",), "Same family on ARM; explicit library-version getter, still candidate evidence."),
        ("mDNSResponder libdnssd", "allwinner", "/lib/libmdnssd.so", ("VersionString_SCCS_libdnssd",), "Defined version-named object; inspect string contents and provenance before treating as a release."),
        ("WebRTC audio processing", "allwinner", "/lib/libwebrtc_audio_preprocessing.so", ("WebRtcAec_get_version", "WebRtcAecm_get_version", "WebRtcAgc_Version", "WebRtcNsx_get_version", "WebRtcVad_get_version"), "Several defined component-version APIs; validate whether outputs identify the bundled library release."),
        ("MEMSAlgLib sensor algorithms", "allwinner", "/lib/hw/sensors.exdroid.so", ("MEMSAlgLib_Fusion_Get_Version", "MEMSAlgLib_eCompass_Get_Version", "MEMSAlgLib_Fusion_Get_Version_String", "MEMSAlgLib_eCompass_Get_Version_String"), "Defined version APIs for bundled algorithm components; candidate, not a host-library release yet."),
        ("M4 VideoEditor modules", "allwinner", "/lib/libvideoeditor_core.so", ("M4PTO3GPP_GetVersion", "M4xVSS_GetVersion", "M4VSS3GPP_GetVersion", "M4PCMR_getVersion", "M4AMRR_getVersion", "M4MCS_getVersion", "M4MP4W_getVersion"), "Multiple module-version APIs; likely component/module releases rather than one shared-library version."),
    ]
    evidence = []
    for family, label, path, wanted, rationale in candidate_specs:
        for row in data["inputs"][label]["files"]:
            if row["path"] != path:
                continue
            matches = [s for s in row["defined_version_symbols"] if s["name"] in wanted]
            if matches:
                evidence.append({"family": family, "source": label, "path": path,
                                 "sha256": row["sha256"], "size": row["size"],
                                 "architecture": row["architecture"], "symbols": matches,
                                 "status": "candidate_only", "rationale": rationale})
    data["family_candidates"] = evidence[:10]
    family_counts = Counter(row["family"] for row in data["family_candidates"])
    data["family_candidate_summary"] = {
        "record_count": len(data["family_candidates"]),
        "unique_family_count": len(family_counts),
        "records_per_family": dict(sorted(family_counts.items())),
    }
    data["family_exclusions"] = [
        {"family": "AIDL/HIDL/HAL interface version symbols", "reason": "describe interface/API compatibility, not library release"},
        {"family": "protobuf VersionString/VerifyVersion symbols", "reason": "runtime compatibility guard; supported API family already exists"},
        {"family": "ICU getVersion/getUnicodeVersion/resource versions", "reason": "supported ICU getter/helper family; some values describe Unicode/CLDR/resource data"},
        {"family": "SQLite sqlite3_libversion", "reason": "supported function API in static_version and semantic_version at e872bd7; sqlite3_version OBJECT is not supported by object_version at that baseline; NOTICE evidence is known stale and is not a version source"},
        {"family": "libevent event_get_version", "reason": "existing static API family; pinned configure.ac says 2.1.12-stable while Bionic header and API return 2.1.8-stable; keep each source distinct and do not promote API output automatically"},
        {"family": "LZ4/Zstandard and FreeType symbols", "reason": "LZ4/Zstandard have supported static/semantic function APIs; FreeType has a previously reviewed experimental prototype, not production function API support at e872bd7"},
        {"family": "protocol, schema, codec-stream, PDF/document, device API versions", "reason": "describe interface or data-format versions rather than library releases"},
    ]
    data["source_script"] = str(Path(__file__).resolve())
    data["source_script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    data["api_support_comparison"] = {
        "baseline_commit": "e872bd73d3113f7b8c72da1623a3ef88320dc8ea",
        "baseline_source_sha256": {
            "src/firmware_scanner/extraction/static_version.py": "d19929a864278f3073501c0f1fefc4f37a74b3f05db5995ffd07f460613b2440",
            "src/firmware_scanner/extraction/semantic_version.py": "5857e8e92328a28523525a0d47f55190f78f09eb2084f88284cf5838f5316ff7",
            "src/firmware_scanner/extraction/object_version.py": "be722481f4ff0f4d22492adfb9a13113718b598b1c0efce5f6daa00410127b68",
        },
        "known_support_families": ["static_version getters (LZ4, zstd, HarfBuzz, SQLite, libpcap, cJSON, libuv, Opus, libvpx, libevent)",
                                    "semantic_version integer/string function getters and protobuf semantic probe",
                                    "ICU getter/helper function probe", "protobuf ELF32 runtime check", "TensorFlow Lite JNI runtime function probe",
                                    "object_version: CryptoAuthLib atca_version object only"],
        "sqlite_api_support": [
            {"symbol": "sqlite3_libversion", "symbol_type": "STT_FUNC", "supported": True,
             "modules": ["static_version.py", "semantic_version.py"]},
            {"symbol": "sqlite3_libversion_number", "symbol_type": "STT_FUNC", "supported": True,
             "modules": ["semantic_version.py"]},
            {"symbol": "sqlite3_version", "symbol_type": "STT_OBJECT", "supported": False,
             "module": "object_version.py", "reason": "Only CryptoAuthLib atca_version is supported at the pinned baseline."},
        ],
        "object_version_supported_objects": [
            {"family": "CryptoAuthLib", "symbol": "atca_version", "symbol_type": "STT_OBJECT",
             "required_defined_functions": ["atcab_init", "atcab_version"]},
        ],
        "support_meaning": "Registered APIs at the pinned baseline, subject to each extractor's proof and architecture limits; not evidence that every sample matches.",
        "candidate_results_are_unverified": True,
        "sqlite_notice_evidence_is_stale": True,
        "libevent_notice_field_is_not_a_single_version_oracle": True,
    }
    data["external_metadata_policy"] = "Manifests and NOTICE files are provenance leads only; neither assigns an exact library release without source/API reconciliation. No candidate in this census is a formal version claim."
    data["version_source_boundary_examples"] = [{
        "family": "libevent", "pinned_source_commit": "67b0e8c658b80d176b5b1a497cbc7e954f3d5266",
        "configure_ac": {"value": "2.1.12-stable", "sha256": "3521d78af82b23115139341eca948d91eb9d8a32731661189295844f91ec29ce"},
        "bionic_event_config_header": {"value": "2.1.8-stable", "sha256": "203d37391619e3b79eaba4755221c89fe0d68347a253f98aadde85158249c03f"},
        "event_get_version_implementation": {"returns": "EVENT__VERSION", "sha256": "0850c2927a1900ab017710733c0416efdb21af0436e98207f8669ec957af7bd4"},
        "interpretation": "Configure metadata, Bionic header, API return, and NOTICE fields have distinct provenance; API output remains a candidate and is not automatically upstream code release truth.",
        "evidence_manifest": "reports/version-corpus-20261118/upstream/manifest-second.json and manifest-third.json",
    }]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    summary = {label: {k: v for k, v in result.items() if k not in ("files", "read_errors", "symbol_families")}
               | {"symbol_families": result["symbol_families"]}
               for label, result in data["inputs"].items()}
    print(json.dumps({"output": str(output), "source_script_sha256": data["source_script_sha256"],
                      "family_candidate_summary": data["family_candidate_summary"],
                      "summary": summary}, indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system-image", type=Path, default=DEFAULTS["system"]["image"])
    parser.add_argument("--allwinner-image", type=Path, default=DEFAULTS["allwinner"]["image"])
    parser.add_argument("--output", type=Path, default=ROOT / "reports/version-corpus-20261118/census.json")
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / "src"))
    run(args.system_image, args.allwinner_image, args.output)


if __name__ == "__main__":
    main()
