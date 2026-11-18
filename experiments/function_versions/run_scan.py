"""Opt-in product-core scan with additional function-semantics evidence.

Usage (from repository root):
  PYTHONPATH=src python experiments/function_versions/run_scan.py IMAGE OUTPUT
The product source is untouched; only this process uses the experimental class.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import mmap
import resource
import sys
import time
from pathlib import Path
from urllib.parse import quote

from semantic_probe import SemanticVersionProbe
from firmware_scanner.extraction import binary_inventory
from firmware_scanner.extraction.models import ExtractionMethod, VersionConfidence

try:
    from icu_probe import extract_icu
except ImportError:
    def extract_icu(data):
        return []


OriginalInventory = binary_inventory.BinaryInventory
observations = []
cache = {}


class ExperimentalInventory(OriginalInventory):
    def extract(self, data, filename, location, component_type='library'):
        components = super().extract(data, filename, location, component_type)
        digest = hashlib.sha256(data).hexdigest()
        if digest not in cache:
            icu = extract_icu(data) if b'u_getVersion' in data and b'u_versionFromString' in data else []
            cache[digest] = SemanticVersionProbe().extract(data) + icu
        hits = cache[digest]
        if not hits:
            return components
        before = [(c.name, c.resolved_version) for c in components]
        for hit in hits:
            key = binary_inventory.identity_key(hit.name)
            target = next((c for c in components if binary_inventory.identity_key(c.name) == key
                           or any(p['name'] == 'firmware:identity'
                                  and binary_inventory.identity_key(p['value']) == key
                                  for p in c.properties)), None)
            if target is None:
                target = OriginalInventory._component(hit.name, 'library', location, [], [
                    {'name': 'firmware:evidence:location', 'value': location},
                    {'name': 'firmware:evidence:container', 'value': filename},
                    {'name': 'firmware:relationship', 'value': 'contains-evidence-for'},
                    {'name': 'firmware:identity', 'value': hit.name},
                ])
                components.append(target)
            target.properties.append({'name': 'firmware:experiment:function-evidence', 'value': hit.evidence})
            # Integer getters cannot establish a missing DEV/GIT suffix. Keep
            # an existing full string, with the numeric observation as a fact.
            if any(target.resolved_version.startswith(hit.version + separator) for separator in ('-', '+')):
                target.properties.append({'name': 'firmware:version:numeric-base', 'value': hit.version})
                continue
            claim = VersionConfidence(version=hit.version, confidence=hit.confidence,
                                      method=ExtractionMethod.DISASSEMBLY, evidence=hit.evidence)
            if claim not in target.versions:
                target.versions.append(claim)
            values = {v.version for v in target.versions if v.version}
            target.resolved_version = next(iter(values)) if len(values) == 1 else ''
            target.properties = [p for p in target.properties if p['name'] not in
                                 ('firmware:version:conflict', 'firmware:version:kind')]
            if len(values) > 1:
                target.properties.append({'name': 'firmware:version:conflict', 'value': ', '.join(sorted(values))})
            else:
                target.properties.append({'name': 'firmware:version:kind', 'value': 'observed-version-api'})
            target.purl = 'pkg:generic/' + quote(target.name, safe='._-')
            if target.resolved_version:
                target.purl += '@' + quote(target.resolved_version, safe='._-+')
        observations.append({'location': location, 'sha256': digest, 'size': len(data),
                             'before': before, 'after': [(c.name, c.resolved_version) for c in components],
                             'hits': [dataclasses.asdict(hit) for hit in hits]})
        return components


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    image, output = map(Path, sys.argv[1:])
    output.mkdir(parents=True, exist_ok=True)
    # Import consumers after patching the class, so Android and APK paths use it.
    binary_inventory.BinaryInventory = ExperimentalInventory
    from firmware_scanner.android.ext4_reader import Ext4Reader
    from firmware_scanner.android.system_scanner import AndroidSystemScanner
    from firmware_scanner.cli.app import _deduplicate_components
    from firmware_scanner.sbom.cyclonedx import CycloneDXGenerator

    started = time.monotonic()
    with image.open('rb') as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            reader = Ext4Reader(data)
            if not reader.is_valid():
                raise SystemExit('not a valid ext4 image')
            result = AndroidSystemScanner(reader).scan()
            components = _deduplicate_components(result.components)
    payload = {'firmware': {'path': str(image), 'size': image.stat().st_size},
               'components': [c.model_dump(mode='json') for c in components],
               'warnings': result.warnings, 'build_info': dataclasses.asdict(result.build_info),
               'method': 'Product core with opt-in function-semantics prototype; no target execution'}
    (output / 'system_analysis.json').write_text(json.dumps(payload, indent=2, ensure_ascii=False) + '\n')
    sbom = CycloneDXGenerator().generate(components, firmware_path=str(image), firmware_hash_sha256='')
    (output / 'system_sbom.json').write_text(json.dumps(sbom, indent=2, ensure_ascii=False) + '\n')
    (output / 'function-observations.json').write_text(json.dumps(observations, indent=2, ensure_ascii=False) + '\n')
    metrics = {'seconds': round(time.monotonic() - started, 3),
               'peak_rss_kb': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
               'components': len(components), 'raw_components': len(result.components),
               'function_evidence_files': len(observations), 'exit_code': 0}
    (output / 'metrics.json').write_text(json.dumps(metrics, indent=2) + '\n')
    print(json.dumps(metrics), flush=True)


if __name__ == '__main__':
    main()
