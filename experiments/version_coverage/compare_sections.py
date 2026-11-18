"""Compare bounded ELF section profiles; report candidates, never exact releases.

This offline experiment validates cached public AARs and their indexed native
members before comparing them to read-only firmware files. Equal code sections
can occur in several published releases and do not identify a unique artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import zipfile
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit

from elftools.elf.elffile import ELFFile

from firmware_scanner.android.archive_reader import FilesystemFile
from firmware_scanner.android.ext4_reader import Ext4Reader

_SECTIONS = (".text", ".rodata", ".data.rel.ro", ".note.android.ident")
_MAX_MEMBER = 64 * 1024 * 1024


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def profile(data: bytes) -> dict | None:
    image = ELFFile(BytesIO(data))
    sections = {}
    for name in _SECTIONS:
        matches = [s for s in image.iter_sections() if s.name == name]
        if len(matches) != 1:
            return None
        section = matches[0]
        if section["sh_type"] == "SHT_NOBITS" or not int(section["sh_flags"]) & 2:
            return None
        start, size = int(section["sh_offset"]), int(section["sh_size"])
        if not 0 < size <= _MAX_MEMBER or start < 0 or start + size > len(data):
            return None
        sections[name] = {"vaddr": int(section["sh_addr"]), "size": size,
                          "flags": int(section["sh_flags"]),
                          "sha256": _sha(data[start:start + size])}
    if sections[".text"]["size"] < 128:
        return None
    return {"machine": image.header["e_machine"], "bits": image.elfclass,
            "little_endian": image.little_endian, "sections": sections}


def _bounded_member(archive: zipfile.ZipFile, name: str) -> bytes:
    entries = [i for i in archive.infolist() if i.filename == name]
    if len(entries) != 1 or not 0 < entries[0].file_size <= _MAX_MEMBER:
        raise ValueError("missing, duplicate or oversized ELF member: " + name)
    with archive.open(entries[0]) as member:
        data = member.read(_MAX_MEMBER + 1)
    if len(data) != entries[0].file_size:
        raise ValueError("ELF member size mismatch: " + name)
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("references", type=Path)
    parser.add_argument("targets", type=Path, help="JSON list of location/sha256 records")
    parser.add_argument("output", type=Path)
    parser.add_argument("--index", type=Path, default=(Path(__file__).resolve().parents[2]
                        / "src/firmware_scanner/data/binary_samples.json"))
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("use a new output path")
    manifest_path = args.references / "checksum-manifest.json"
    artifacts = {row["url"]: row for row in json.loads(manifest_path.read_text())["artifacts"]}
    cached_archives = {}
    references = []
    for record in json.loads(args.index.read_text())["samples"]:
        source = record["source"]
        if source not in cached_archives:
            archive = args.references / Path(urlsplit(source).path).name
            if archive.stat().st_size > 128 * 1024 * 1024:
                raise ValueError("reference archive exceeds 128 MiB")
            data = archive.read_bytes()
            if _sha(data) != artifacts[source]["sha256"]:
                raise ValueError("reference AAR checksum mismatch: " + source)
            cached_archives[source] = archive
        with zipfile.ZipFile(cached_archives[source]) as archive:
            data = _bounded_member(archive, record["artifact_path"])
        if _sha(data) != record["sha256"]:
            raise ValueError("reference member checksum mismatch: " + record["artifact_path"])
        references.append({**record, "profile": profile(data)})

    results = []
    with args.image.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        fs = Ext4Reader(mm)
        if not fs.is_valid():
            raise ValueError("not an ext4 image")
        for target in json.loads(args.targets.read_text()):
            location = target["location"]
            path, member = location.split("!/", 1)
            with FilesystemFile(fs, path) as stream, zipfile.ZipFile(stream) as archive:
                data = _bounded_member(archive, member)
            digest = _sha(data)
            if digest != target["sha256"]:
                raise ValueError("target changed: " + location)
            item = profile(data)
            candidates = [{k: v for k, v in record.items() if k != "profile"}
                          for record in references if item and record["profile"] == item]
            controls = {}
            if item:
                image = ELFFile(BytesIO(data))
                offset = int(image.get_section_by_name(".text")["sh_offset"])
                mutant = bytearray(data)
                mutant[offset] ^= 1
                controls = {"text_byte_change_rejected": profile(bytes(mutant)) != item,
                            "unreferenced_trailer_preserves_profile": profile(data + b"trailer") == item,
                            "trailer_changes_whole_file_hash": _sha(data + b"trailer") != digest}
                if not all(controls.values()):
                    raise ValueError("section-profile control failed")
            results.append({"location": location, "sha256": digest, "profile": item,
                            "candidates": candidates, "exact_version": None, "controls": controls})
    payload = {"method": "four-section-equality-candidates-only", "script_sha256": _sha(Path(__file__).read_bytes()),
               "image": str(args.image.resolve()), "image_sha256": _file_sha(args.image),
               "targets_sha256": _file_sha(args.targets),
               "index_sha256": _sha(args.index.read_bytes()), "manifest_sha256": _sha(manifest_path.read_bytes()),
               "reference_records": len(references), "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps({"references": len(references), "targets": len(results),
                      "targets_with_candidates": sum(bool(r["candidates"]) for r in results),
                      "exact_versions": 0, "output": str(args.output)}))


if __name__ == "__main__":
    main()
