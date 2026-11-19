"""Bounded ELF32 frame-removal experiment; never load or execute target bytes.

Only exact EBP setup/restore and optional AND ESP,-power_of_two (2..64)
are removed. Original instruction addresses survive for PIC arithmetic. Value
evaluation and version interpretation stay with the existing production helpers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import re
import zipfile
from pathlib import Path

from capstone.x86 import X86_OP_IMM

from firmware_scanner.extraction.semantic_version import (
    ELFView, INTEGER_GETTERS, STRING_GETTERS, X86_32_STRING_GETTERS,
    SemanticVersionExtractor, decode_integer,
)

ROOT = Path(__file__).resolve().parents[2]
MAX_ELF = 64 * 1024 * 1024
STACK_REGISTERS = {"ebp", "esp", "bp", "sp", "bpl", "spl"}


def x86_frame_return(image: ELFView, instructions) -> int | None:
    """Prove a balanced frame and evaluate its stack-independent canonical body.

    Unsupported framing (including LEAVE), partial decoding, stack operands,
    control flow, traps and unknown calls fail closed. Unframed straight-line
    bodies use the same guards and the original evaluator.
    """
    if image.machine != "EM_386" or image.elf.elfclass != 32 or not image.elf.little_endian:
        return None
    code = list(instructions)
    if not code or not 0 < sum(i.size for i in code) <= 128:
        return None
    if any(a.address + a.size != b.address for a, b in zip(code, code[1:])):
        return None
    if image.read(code[0].address, sum(i.size for i in code), executable=True) != b"".join(
        bytes(i.bytes) for i in code
    ):
        return None
    if bytes(code[-1].bytes) != b"\xc3":
        return None
    start = 0
    while start < len(code) - 1 and code[start].mnemonic in ("nop", "endbr32"):
        start += 1
    body = code[start:-1]
    if body and bytes(body[0].bytes) == b"\x55":
        if (len(body) < 5 or bytes(body[1].bytes) not in (b"\x89\xe5", b"\x8b\xec")
                or bytes(body[-2].bytes) not in (b"\x89\xec", b"\x8b\xe5")
                or bytes(body[-1].bytes) != b"\x5d"):
            return None
        body = body[2:-2]
        if body and body[0].mnemonic == "and":
            align = body[0]
            raw = bytes(align.bytes)
            if not (raw.startswith(b"\x83\xe4") and len(raw) == 3
                    or raw.startswith(b"\x81\xe4") and len(raw) == 6):
                return None
            mask = int(align.operands[1].imm) & 0xffffffff
            alignment = (-mask) & 0xffffffff
            if alignment not in (2, 4, 8, 16, 32, 64):
                return None
            body = body[1:]
    if not body:
        return None
    for instruction in body:
        if instruction.mnemonic == "call":
            ops = instruction.operands
            if (len(instruction.bytes) != 5 or instruction.bytes[0] != 0xe8
                    or len(ops) != 1 or ops[0].type != X86_OP_IMM):
                return None
            address = int(ops[0].imm)
            register = image.pc_thunk(address)
            if register not in ("eax", "ecx", "edx", "ebx", "esi", "edi"):
                return None
            index = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi").index(register)
            if image.read(address, 4, executable=True) != bytes((0x8b, 0x04 + 8 * index, 0x24, 0xc3)):
                return None
            continue
        if instruction.mnemonic not in ("mov", "add", "lea", "nop", "endbr32"):
            return None
        reads, writes = instruction.regs_access()
        if any(instruction.reg_name(reg) in STACK_REGISTERS for reg in (*reads, *writes)):
            return None
    return SemanticVersionExtractor._x86_32_return(image, [*body, code[-1]])


def compare_getters(data: bytes) -> list[dict]:
    """Compare only registered getters using their existing value semantics."""
    image = ELFView(data)
    if image.machine != "EM_386" or image.elf.elfclass != 32:
        return []
    strings = {**STRING_GETTERS, **X86_32_STRING_GETTERS}
    rows = []
    for name in sorted(INTEGER_GETTERS.keys() | strings.keys()):
        function = image.functions.get(name)
        if function is None or not 0 < function[1] <= 128:
            continue
        instructions = image.instructions(*function)
        old = SemanticVersionExtractor._x86_32_return(image, instructions)
        new = x86_frame_return(image, instructions)
        if name in INTEGER_GETTERS:
            component, encoding = INTEGER_GETTERS[name]
            convert = lambda value: decode_integer(value, encoding) if value is not None else None
            old_version, new_version = convert(old), convert(new)
            text = None
        else:
            component, prefix = strings[name]

            def convert(pointer):
                text = image.c_string(pointer, readonly=True) if pointer is not None else None
                if text is None or not text.startswith(prefix):
                    return None
                value = text[len(prefix):]
                return value if re.fullmatch(r"v?\d+\.\d+(?:\.\d+)*[A-Za-z0-9.+_-]*", value) else None

            old_version, new_version = convert(old), convert(new)
            encoding = "readonly-c-string"
            text = image.c_string(new, readonly=True) if new is not None else None
        rows.append({"function": name, "component": component, "vaddr": hex(function[0]),
                     "size": function[1], "encoding": encoding, "baseline_value": old,
                     "wrapper_value": new, "baseline_version": old_version,
                     "wrapper_version": new_version, "string": text,
                     "gain": old_version is None and new_version is not None,
                     "instructions": image.format_instructions(instructions)})
    return rows


def _annotate(rows: list[dict], observation: dict) -> list[dict]:
    """Separate evaluator gains from versions already present in frozen claims."""
    claims = observation.get("claims", [])
    for row in rows:
        row["existing_component_versions"] = sorted({c["version"] for c in claims
                                                    if c["name"] == row["component"] and c.get("version")})
        row["new_component_version"] = row["gain"] and not row["existing_component_versions"]
    return rows


def compare_apex_paths(reader, observations: list[dict]) -> dict:
    """Read only prelisted /lib/ paths through existing APEX filesystem readers."""
    from firmware_scanner.android.apex_payload import _BytesReader, MAX_PAYLOAD_BYTES
    from firmware_scanner.android.ext4_reader import Ext4Reader
    from firmware_scanner.android.erofs_reader import ErofsReader

    groups = {}
    for observation in observations:
        location = observation["location"]
        marker = "!/apex_payload.img/lib/"
        if (marker in location and observation.get("type") == "library"
                and any(not c.get("version") for c in observation.get("claims", []))):
            outer, inner = location.split("!/apex_payload.img", 1)
            if "!/" not in outer:
                groups.setdefault(outer, []).append((inner, observation))
    report = {"method": "prelisted unknown /lib/ observations only; no filesystem walk",
              "containers": [], "files": [], "gains": [], "errors": [], "paths_read": 0,
              "elf32_i386_files": 0}
    total = 0
    for outer, entries in sorted(groups.items()):
        try:
            data = reader.read_file(outer, max_size=MAX_PAYLOAD_BYTES)
            for _ in range(3):
                with zipfile.ZipFile(_BytesReader(data)) as archive:
                    name = "apex_payload.img" if "apex_payload.img" in archive.namelist() else "original_apex"
                    infos = [i for i in archive.infolist() if i.filename == name]
                    if len(infos) != 1 or infos[0].file_size > MAX_PAYLOAD_BYTES:
                        raise ValueError("missing, duplicate or oversized APEX member")
                    data = archive.read(infos[0])
                if name == "apex_payload.img":
                    break
            else:
                raise ValueError("APEX nesting exceeds experiment bound")
            payload = Ext4Reader(data)
            if not payload.is_valid():
                payload = ErofsReader(data)
            if not payload.is_valid():
                raise ValueError("unsupported APEX payload filesystem")
            report["containers"].append({"path": outer, "listed_paths": len(entries)})
            for inner, observation in entries:
                elf = payload.read_file(inner, max_size=MAX_ELF)
                if elf is None or len(elf) != observation["size"]:
                    raise ValueError(f"truncated prelisted APEX ELF: {inner}")
                total += len(elf)
                if total > MAX_PAYLOAD_BYTES:
                    raise ValueError("APEX cumulative ELF byte budget exceeded")
                report["paths_read"] += 1
                if not elf.startswith(b"\x7fELF\x01\x01"):
                    continue
                digest = hashlib.sha256(elf).hexdigest()
                if digest != observation["sha256"]:
                    raise ValueError(f"frozen APEX ELF SHA256 mismatch: {inner}")
                if elf[18:20] != b"\x03\x00":
                    continue
                report["elf32_i386_files"] += 1
                names = INTEGER_GETTERS.keys() | STRING_GETTERS.keys() | X86_32_STRING_GETTERS.keys()
                if not any(name.encode() + b"\0" in elf for name in names):
                    continue
                rows = _annotate(compare_getters(elf), observation)
                report["files"].append({"path": observation["location"], "sha256": digest, "getters": rows})
                report["gains"].extend({"path": observation["location"], "sha256": digest, **row}
                                       for row in rows if row["gain"])
        except Exception as exc:
            report["errors"].append({"path": outer, "error": str(exc)})
    return report


def run(census_path: Path, output: Path, *, apex: bool = False) -> dict:
    """Read the frozen system census's direct unknown i386 libraries, not a scan."""
    from firmware_scanner.android.ext4_reader import Ext4Reader

    census = json.loads(census_path.read_text())["inputs"]["system"]
    observations = json.loads(Path(census["observation_source"]).read_text())
    by_path = {o["location"]: o for o in observations}
    unknown = {o["location"] for o in observations if o.get("type") == "library"
               and any(not claim.get("version") for claim in o.get("claims", []))}
    registered = INTEGER_GETTERS.keys() | STRING_GETTERS.keys() | X86_32_STRING_GETTERS.keys()
    candidates = [f for f in census["files"] if f.get("elf_class") == 32
                  and f.get("architecture") == "x86" and f["path"] in unknown
                  and any(s["name"] in registered for s in f["defined_version_symbols"])]
    report = {"method": "read-only Ext4Reader; registered getters only; no target execution",
              "census": str(census_path), "image": census["image"],
              "census_sha256": hashlib.sha256(census_path.read_bytes()).hexdigest(),
              "observation_source": census["observation_source"],
              "observation_source_sha256": hashlib.sha256(Path(census["observation_source"]).read_bytes()).hexdigest(),
              "experiment_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "baseline_source_sha256": hashlib.sha256(
                  (ROOT / "src/firmware_scanner/extraction/semantic_version.py").read_bytes()).hexdigest(),
              "unknown_filter": "library observation with at least one unknown component claim",
              "candidate_files": len(candidates), "files": [], "gains": [], "errors": [],
              "apex": "not inspected by direct runner"}
    with Path(census["image"]).open("rb") as handle, mmap.mmap(
        handle.fileno(), 0, access=mmap.ACCESS_READ
    ) as backing:
        reader = Ext4Reader(backing)
        for candidate in candidates:
            path = candidate["path"]
            try:
                data = reader.read_file(path, max_size=MAX_ELF)
                digest = hashlib.sha256(data).hexdigest()
                if digest != candidate["sha256"]:
                    raise ValueError("census file SHA256 mismatch")
                rows = _annotate(compare_getters(data), by_path[path])
                report["files"].append({"path": path, "sha256": digest, "getters": rows})
                report["gains"].extend({"path": path, "sha256": digest, **row}
                                       for row in rows if row["gain"])
            except Exception as exc:
                report["errors"].append({"path": path, "error": str(exc)})
        if apex:
            report["apex"] = compare_apex_paths(reader, observations)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--census", type=Path, default=ROOT / "reports/version-corpus-20261118/census.json")
    parser.add_argument("--output", type=Path, default=ROOT / "reports/version-corpus-20261118/x86-frame/direct.json")
    parser.add_argument("--apex", action="store_true", help="also read prelisted APEX /lib/ observations")
    arguments = parser.parse_args()
    result = run(arguments.census, arguments.output, apex=arguments.apex)
    print(json.dumps({"candidate_files": result["candidate_files"],
                      "gains": len(result["gains"]), "errors": result["errors"],
                      "apex_gains": len(result["apex"]["gains"]) if arguments.apex else None}))
