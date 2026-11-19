#!/usr/bin/env python3
"""Reproduce a product-core scan with frozen source, file evidence and input hashes.

Accepts an ext4 partition. For an extracted partition, --origin records the original
container as well; this does not claim that other container partitions were scanned.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import mmap
import resource
import shutil
import subprocess
import sys
import time
from pathlib import Path


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--origin', type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    snapshot = output / 'source'
    if snapshot.exists():
        raise SystemExit('Use a new output directory; frozen source already exists')
    shutil.copytree(repo / 'src', snapshot, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    sys.path.insert(0, str(snapshot))
    manifest = {str(path.relative_to(snapshot)): sha256(path)
                for path in sorted(snapshot.rglob('*')) if path.is_file()}
    (output / 'source-sha256.json').write_text(json.dumps(manifest, indent=2) + '\n')

    from firmware_scanner.android.ext4_reader import Ext4Reader
    from firmware_scanner.android.provenance import apply_component_taxonomy
    from firmware_scanner.android.system_scanner import AndroidSystemScanner
    from firmware_scanner.cli.app import _deduplicate_components
    from firmware_scanner.extraction.binary_inventory import BinaryInventory
    from firmware_scanner.extraction.family_provenance import apply_family_version_provenance
    from firmware_scanner.sbom.cyclonedx import CycloneDXGenerator

    observations = []
    original_extract = BinaryInventory.extract
    def record_extract(self, data, filename, location, component_type='library'):
        components = original_extract(self, data, filename, location, component_type)
        observations.append({'location': location, 'filename': filename, 'size': len(data),
                             'sha256': hashlib.sha256(data).hexdigest(), 'type': component_type,
                             'claims': [{'name': c.name, 'version': c.resolved_version,
                                         'versions': [v.model_dump(mode='json') for v in c.versions]}
                                        for c in components]})
        if len(observations) % 100 == 0:
            print(json.dumps({'analysed_elf_files': len(observations), 'last_file': location}), flush=True)
        return components
    BinaryInventory.extract = record_extract

    started = time.monotonic()
    firmware = {'path': str(args.image.resolve()), 'size': args.image.stat().st_size,
                'sha256': sha256(args.image)}
    if args.origin:
        firmware['origin'] = {'path': str(args.origin.resolve()),
                              'size': args.origin.stat().st_size, 'sha256': sha256(args.origin)}
    (output / 'input.json').write_text(json.dumps(firmware, indent=2) + '\n')
    with args.image.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        reader = Ext4Reader(data)
        if not reader.is_valid():
            raise SystemExit('Not a valid ext4 partition')
        result = AndroidSystemScanner(
            reader,
            image_sha256=firmware['sha256'],
        ).scan()
        family_stats = apply_family_version_provenance(result.components)
        apply_component_taxonomy(result.components)
        components = _deduplicate_components(result.components)
    payload = {'firmware': firmware, 'components': [c.model_dump(mode='json') for c in components],
               'warnings': result.warnings, 'build_info': dataclasses.asdict(result.build_info),
               'provenance_stats': result.provenance_stats,
               'family_provenance_stats': family_stats,
               'method': 'Product AndroidSystemScanner and CLI dedup; frozen source; read-only ext4; no target execution'}
    (output / 'system_analysis.json').write_text(json.dumps(payload, indent=2, ensure_ascii=False) + '\n')
    (output / 'file-observations.json').write_text(json.dumps(observations, indent=2) + '\n')
    sbom = CycloneDXGenerator().generate(components, firmware_path=str(args.image),
                                        firmware_hash_sha256=firmware['sha256'])
    (output / 'system_sbom.json').write_text(json.dumps(sbom, indent=2, ensure_ascii=False) + '\n')
    metrics = {'seconds': round(time.monotonic() - started, 3), 'exit_code': 0,
               'peak_rss_kb': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
               'components': len(components), 'raw_components': len(result.components),
               'analysed_elf_files': len(observations), 'apex_modules': result.apex_count,
               'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()}
    (output / 'metrics.json').write_text(json.dumps(metrics, indent=2) + '\n')
    print(json.dumps(metrics), flush=True)


if __name__ == '__main__':
    main()
