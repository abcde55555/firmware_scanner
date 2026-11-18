"""Real-file mutation controls and known-source compiler fixtures (never executed).

Run from repository root with PYTHONPATH=src. The compiler fixtures exercise
decoder shapes; they are not an upstream-library corpus or accuracy benchmark.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from semantic_probe import ELFView, SemanticVersionProbe, VERIFY, VERSION_STRING

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / 'reports/function-version-experiment-20261118/controls'
MOUNT = Path('/home/kali/Desktop/work/project/vulnscan/mnt_system')


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    probe = SemanticVersionProbe()
    controls = []
    def check(name, data, expected):
        actual = {(h.name, h.version) for h in probe.extract(data)}
        controls.append({'case': name, 'sha256': hashlib.sha256(data).hexdigest(),
                         'expected': sorted(expected), 'actual': sorted(actual),
                         'pass': actual == expected})
    original = (MOUNT / 'system/lib64/libprotobuf-cpp-full.so').read_bytes()
    image = ELFView(original)
    address, size = image.functions[VERIFY]
    start = next(int(s['p_offset']) + address - int(s['p_vaddr']) for s in image.loads
                 if s['p_vaddr'] <= address < s['p_vaddr'] + s['p_filesz'])
    check('real-protobuf', original, {('Protobuf', '3.21.12')})
    for name, old, new in [
        ('boundary-not-consistent-with-message', 3021013, 3021014),
        ('message-not-consistent-with-boundary', 3021012, 3021013),
    ]:
        body = original[start:start + size].replace(old.to_bytes(4, 'little'), new.to_bytes(4, 'little'))
        assert body != original[start:start + size]
        check(name, original[:start] + body + original[start + size:], set())
    for name, symbol in [('library-definition-not-present', VERIFY), ('formatter-not-present', VERSION_STRING)]:
        check(name, original.replace(symbol.encode(), symbol[:-1].encode() + b'X'), set())
    body = original[start:start + size]
    changed = body.replace(bytes.fromhex('0f8c'), bytes.fromhex('0f8d'), 1)
    assert changed != body
    check('failure-direction-reversed', original[:start] + changed + original[start + size:], set())
    for branch in ('jl', 'jge'):
        source, binary = OUTPUT / f'unrelated-{branch}.s', OUTPUT / f'unrelated-{branch}.so'
        source.write_text(f'''.text
.globl {VERIFY}
.type {VERIFY},@function
{VERIFY}:
 cmp $3021013, %esi
 {branch} .Lother
 mov $3021012, %esi
 call {VERSION_STRING}@PLT
 ret
.Lother:
 mov $3021012, %esi
 call {VERSION_STRING}@PLT
 ret
.size {VERIFY}, .-{VERIFY}
.globl {VERSION_STRING}
.type {VERSION_STRING},@function
{VERSION_STRING}:
 ret
.size {VERSION_STRING}, .-{VERSION_STRING}
.section .note.GNU-stack,"",@progbits
''')
        subprocess.run(['cc', '-shared', '-fPIC', '-nostdlib', str(source), '-o', str(binary)], check=True, capture_output=True)
        check('unrelated-exclusive-blocks-' + branch, binary.read_bytes(), set())
    check('truncated-elf', original[:60], set())
    arm = (ROOT / 'reports/function-version-experiment-20261118/scout/objects/allwinner_lib_libharfbuzz_ng.so').read_bytes()
    check('real-arm-harfbuzz', arm, {('HarfBuzz', '0.9.5')})
    image = ELFView(arm)
    address, size = image.functions['hb_version_string']
    start = next(int(s['p_offset']) + address - int(s['p_vaddr']) for s in image.loads
                 if s['p_vaddr'] <= address < s['p_vaddr'] + s['p_filesz'])
    body = arm[start:start + size]
    for name, replacement in [('conditional-return-rejected', bytes.fromhex('1eff2f11')),
                              ('loop-rejected', bytes.fromhex('feffffea'))]:
        changed = body.replace(bytes.fromhex('1eff2fe1'), replacement)
        assert body != changed
        check(name, arm[:start] + changed + arm[start + size:], set())

    builds = []
    for compiler_name in ('gcc', 'clang'):
        compiler = shutil.which(compiler_name)
        if not compiler:
            continue
        compiler_version = subprocess.check_output([compiler, '--version'], text=True).splitlines()[0]
        for numeric in (3044003, 3044005):
            expected = {('SQLite', f'3.44.{numeric % 1000}'), ('LZ4', '1.10.0'), ('Brotli', '1.0.9')}
            for optimization in ('-O0', '-O2', '-Os'):
                for stripped in (False, True):
                    stem = f'{compiler_name}-{numeric}-{optimization[1:]}-strip{int(stripped)}'
                    source, binary = OUTPUT / (stem + '.c'), OUTPUT / (stem + '.so')
                    source.write_text(
                        f'int sqlite3_libversion_number(void) {{ return {numeric}; }}\n'
                        'int LZ4_versionNumber(void) { return 11000; }\n'
                        'unsigned int BrotliDecoderVersion(void) { return 0x01000009; }\n')
                    command = [compiler, '-shared', '-fPIC', '-nostdlib', optimization,
                               '-Wl,--build-id=none', str(source), '-o', str(binary)]
                    subprocess.run(command, check=True, capture_output=True)
                    if stripped:
                        subprocess.run(['strip', '--strip-all', str(binary)], check=True, capture_output=True)
                    data = binary.read_bytes()
                    actual = {(hit.name, hit.version) for hit in probe.extract(data)}
                    builds.append({'case': stem, 'compiler': compiler_version,
                                   'command': command, 'strip_all': stripped,
                                   'dynamic_symbols_retained': True,
                                   'sha256': hashlib.sha256(data).hexdigest(),
                                   'expected': sorted(expected), 'actual': sorted(actual),
                                   'wrong': sorted(actual - expected), 'missed': sorted(expected - actual)})
        source, binary = OUTPUT / (compiler_name + '-runtime.c'), OUTPUT / (compiler_name + '-runtime.so')
        source.write_text('extern int runtime_value; int LZ4_versionNumber(void) { return runtime_value; }\n')
        subprocess.run([compiler, '-shared', '-fPIC', '-nostdlib', '-O2', str(source), '-o', str(binary)], check=True, capture_output=True)
        check(compiler_name + '-runtime-dependent-return', binary.read_bytes(), set())
        source, binary = OUTPUT / (compiler_name + '-caller.cpp'), OUTPUT / (compiler_name + '-caller.so')
        source.write_text('namespace google { namespace protobuf { namespace internal {\n'
                          'void VerifyVersion(int,int,const char*); } } }\n'
                          'extern "C" void use() { google::protobuf::internal::VerifyVersion(3021013,3021000,"caller"); }\n')
        subprocess.run([compiler, '-shared', '-fPIC', '-nostdlib', '-O2', str(source), '-o', str(binary)], check=True, capture_output=True)
        check(compiler_name + '-header-version-caller-only', binary.read_bytes(), set())
    result = {'scope': 'known-source API-shape fixtures and real-file mutation controls; not library accuracy benchmark',
              'controls': controls, 'builds': builds,
              'summary': {'controls_pass': sum(r['pass'] for r in controls), 'controls_total': len(controls),
                          'builds': len(builds), 'fixture_expected_version_observations': sum(len(r['expected']) for r in builds),
                          'fixture_correct_observations': sum(len(r['actual']) for r in builds if not r['wrong']),
                          'fixture_wrong_observations': sum(len(r['wrong']) for r in builds),
                          'fixture_missed_observations': sum(len(r['missed']) for r in builds)}}
    (OUTPUT / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['summary']), flush=True)
    assert all(r['pass'] for r in controls)
    assert builds and any(r['actual'] for r in builds) and not any(r['wrong'] for r in builds)


if __name__ == '__main__':
    main()
