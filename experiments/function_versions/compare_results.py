"""Compare the fixed baseline with opt-in scans; counts are not global accuracy."""
from __future__ import annotations

import json
from pathlib import Path

from firmware_scanner.extraction.binary_inventory import identity_key

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'reports/function-version-experiment-20261118'
BASELINE = ROOT / 'reports/accuracy-20261118'


def family(name):
    value = identity_key(name)
    return {'icuuc': 'icu', 'icui18n': 'icu'}.get(value, value)


def counts(payload):
    components = payload['components']
    native = [c for c in components if c.get('component_type') == 'library'
              and 'native library' in c.get('description', '').lower()]
    return {'components': len(components), 'native': len(native),
            'native_with_version_candidate': sum(bool(c['resolved_version']) for c in native),
            'all_nonempty_version_fields': sum(bool(c['resolved_version']) for c in components),
            'conflict_records': sum(any(p['name'] == 'firmware:version:conflict' for p in c.get('properties', [])) for c in components),
            'warnings': payload.get('warnings', [])}


def locate(components, case):
    for c in components:
        if family(c['name']) != family(case['name']):
            continue
        if any(p['name'] == 'firmware:evidence:location' and p['value'] == case['location']
               for p in c.get('properties', [])):
            return c
    return None


def main():
    results, findings, payloads = {}, [], {}
    for image in ('allwinner', 'system'):
        before = json.loads((BASELINE / 'after' / image / 'system_analysis.json').read_text())
        after = json.loads((DATA / 'after' / image / 'system_analysis.json').read_text())
        payloads[image] = {'baseline': before, 'experiment': after}
        sbom = json.loads((DATA / 'after' / image / 'system_sbom.json').read_text())
        refs = [c['bom-ref'] for c in sbom['components']]
        results[image] = {'baseline': counts(before), 'experiment': counts(after),
                          'metrics': json.loads((DATA / 'after' / image / 'metrics.json').read_text()),
                          'sbom_components': len(refs), 'unique_bom_refs': len(set(refs))}
        observations = json.loads((DATA / 'after' / image / 'function-observations.json').read_text())
        dedup = set()
        for observation in observations:
            for hit in observation['hits']:
                key = (image, observation['location'], family(hit['name']), hit['version'])
                if key in dedup:
                    continue
                dedup.add(key)
                previous = {version for name, version in observation['before']
                            if family(name) == family(hit['name']) and version}
                if hit['version'] in previous:
                    kind = 'confirms_existing_version'
                elif not previous:
                    kind = 'new_version_observation'
                elif any(v.startswith(hit['version'] + sep) for v in previous for sep in ('-', '+')):
                    kind = 'numeric_base_only_full_suffix_preserved'
                else:
                    kind = 'different_version_requires_review'
                findings.append({'image': image, 'location': observation['location'],
                                 'sha256': observation['sha256'], 'family': family(hit['name']),
                                 'version': hit['version'], 'previous': sorted(previous), 'kind': kind,
                                 'evidence': hit['evidence']})
    cases = json.loads((BASELINE / 'evidence-checkpoints.json').read_text())['cases']
    checkpoints = []
    for old in cases:
        case = {key: old[key] for key in ('image', 'name', 'expected', 'location', 'reason')}
        # New independent getter inspection refines two formerly unknown labels.
        # Apply the same revised oracle to both baseline and experiment.
        if case['image'] == 'allwinner' and case['name'] == 'libharfbuzz_ng.so':
            case['expected'] = '0.9.5'
            case['reason'] = 'new independent ARM getter/string evidence; former unknown was a policy label, not established ground truth'
        if case['image'] == 'allwinner' and case['name'] == 'libicuuc.so':
            case['expected'] = '51.1.0.1'
            case['reason'] = 'new independent u_getVersion string/dataflow evidence; inline parser remains unsupported by prototype'
        for phase in ('baseline', 'experiment'):
            c = locate(payloads[case['image']][phase]['components'], case)
            case[phase] = {'present': c is not None, 'version': c['resolved_version'] if c else None,
                           'pass': c is not None and c['resolved_version'] == case['expected']}
        checkpoints.append(case)
    result = {'scope': 'fixed two-image product-core comparison; candidate counts and deliberately selected checkpoints only',
              'native_count_definition': 'library records from native-library scan descriptions; never a .so substring in a package name',
              'images': results, 'findings_summary': {kind: sum(r['kind'] == kind for r in findings)
                                                     for kind in sorted({r['kind'] for r in findings})},
              'checkpoints': {'oracle_refinement': 'two old unknown-policy labels replaced by newly confirmed API versions for BOTH phases',
                              'total': len(checkpoints),
                              'passes': {phase: sum(c[phase]['pass'] for c in checkpoints) for phase in ('baseline', 'experiment')},
                              'cases': checkpoints}}
    (DATA / 'comparison.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    (DATA / 'file-version-observations.json').write_text(json.dumps(findings, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'checkpoints'}, ensure_ascii=False, indent=2))
    print('CHECKPOINTS', result['checkpoints']['passes'])
    for row in findings:
        if row['kind'] != 'confirms_existing_version':
            print(row['kind'], row['image'], row['location'], row['family'], row['version'])


if __name__ == '__main__':
    main()
