#!/usr/bin/env python3
"""Count exact BSim function vectors across known releases and a target file.

This is an identity/candidate experiment, not an exact-version classifier. It
uses equality of Ghidra's generated feature vectors, not the weighted BSim
similarity or significance score. Constants can be absent from these vectors.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def read_signatures(path):
    root = ET.parse(path).getroot()
    # Ghidra also serializes imported-function executables (often "unknown").
    # Their order is unspecified; only the basename's own MD5 may contribute.
    md5 = Path(path).name.removeprefix('sigs_')
    owners = [item for item in root.findall('./execlist')
              if item.findtext('./exe/md5') == md5]
    if len(owners) != 1:
        raise ValueError('Expected exactly one owning executable for signature file')
    owner = owners[0]
    executable = owner.find('./exe')
    vectors = []
    for function in owner.findall('./fdesc'):
        features = tuple(sorted((int(item.text, 0), int(item.get('tf', '1')))
                                for item in function.findall('./lshcosine/hash')))
        if len(features) >= 10:
            vectors.append({'name': function.get('name'), 'address': function.get('addr'),
                            'features': features})
    return {'name': executable.findtext('name'), 'md5': executable.findtext('md5'),
            'arch': executable.findtext('arch'), 'settings': root.get('settings'),
            'vectors': vectors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    base = args.directory
    records = [read_signatures(path) for path in sorted((base / 'signatures').glob('sigs_*'))]
    target_hash = hashlib.md5((base / 'inputs/query-graphics-path.so').read_bytes()).hexdigest()
    target = next(record for record in records if record['md5'] == target_hash)
    refs_by_md5 = {record['md5']: record for record in records}
    comparisons = []
    for reference in json.loads((base / 'references.json').read_text()):
        candidate = refs_by_md5.get(reference['md5_for_ghidra'])
        if candidate is None:
            comparisons.append({'version': reference['version'], 'status': 'NOT_ANALYSED'})
            continue
        if candidate['arch'] != target['arch'] or candidate['settings'] != target['settings']:
            raise ValueError('Incompatible BSim architecture/settings')
        signatures = collections.defaultdict(list)
        for vector in candidate['vectors']:
            signatures[vector['features']].append(vector['name'])
        matches = [{'target_function': vector['name'], 'target_vaddr': vector['address'],
                    'distinct_features': len(vector['features']),
                    'reference_functions': signatures[vector['features']]}
                   for vector in target['vectors'] if vector['features'] in signatures]
        comparisons.append({'version': reference['version'], 'status': 'ANALYSED',
                            'reference_functions': len(candidate['vectors']),
                            'target_functions': len(target['vectors']), 'exact_vectors': len(matches),
                            'fraction': len(matches) / len(target['vectors']) if target['vectors'] else 0,
                            'matches': matches, 'source': reference['source']})
    output = {'method': 'Equality of Ghidra BSim feature vectors with >=10 distinct features',
              'query_sha256': hashlib.sha256((base / 'inputs/query-graphics-path.so').read_bytes()).hexdigest(),
              'settings': target['settings'], 'architecture': target['arch'],
              'comparisons': comparisons,
              'exact_version_claim': None,
              'limitation': 'A matching function vector does not prove a release; no version is promoted from this experiment.'}
    (base / 'comparison.json').write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps([{k: v for k, v in row.items() if k not in ('matches', 'source')}
                      for row in comparisons], indent=2))


if __name__ == '__main__':
    main()
