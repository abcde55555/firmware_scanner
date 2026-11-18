"""Reproduce ICU's real-file and in-memory mutation controls, no ELF execution."""
import hashlib
import json
import struct
from pathlib import Path

from icu_probe import _Image, extract_icu

ROOT = Path(__file__).resolve().parents[2]
INPUT = Path('/home/kali/Desktop/work/project/vulnscan/mnt_system/system/lib64/arm64/libicuuc.so')


def main():
    data = INPUT.read_bytes()
    hits = extract_icu(data)
    assert len(hits) == 1 and hits[0].version == '76.1'
    evidence = json.loads(hits[0].evidence)
    image = _Image(data)
    def offset(address):
        return next(file_offset + address - vaddr for vaddr, file_offset, size, _ in image.loads
                    if vaddr <= address < vaddr + size)
    cases = []
    def check(name, mutated):
        actual = [(h.name, h.version) for h in extract_icu(mutated)]
        cases.append({'case': name, 'matches': actual, 'passed': not actual})
    check('unicode-getter-only', data.replace(b'u_getVersion_76\0', b'x_getVersion_76\0'))
    relocs = image.elf.get_section_by_name('.rela.plt')
    symbols = image.elf.get_section(relocs['sh_link'])
    other = next(index for index, symbol in enumerate(symbols.iter_symbols())
                 if symbol.name == 'u_getUnicodeVersion_76')
    index = next(index for index, relocation in enumerate(relocs.iter_relocations())
                 if symbols.get_symbol(relocation['r_info_sym']).name == evidence['defined_helper'])
    relocation = relocs.get_relocation(index)
    mutated = bytearray(data)
    struct.pack_into('<Q', mutated, int(relocs['sh_offset']) + index * int(relocs['sh_entsize']) + 8,
                     other << 32 | (relocation['r_info'] & 0xffffffff))
    check('wrong-relocation-callee', bytes(mutated))
    mutated = bytearray(data)
    at = offset(int(evidence['branch_target_va'], 16) + 4)
    word = struct.unpack_from('<I', mutated, at)[0]
    struct.pack_into('<I', mutated, at, word ^ (1 << 10))
    check('wrong-got-slot', bytes(mutated))
    mutated = bytearray(data)
    at = offset(int(evidence['getter_va'], 16) + 4)
    word = struct.unpack_from('<I', mutated, at)[0]
    struct.pack_into('<I', mutated, at, word | (1 << 22))
    check('shifted-getter-add', bytes(mutated))
    mutated = bytearray(data)
    at = offset(int(evidence['string_va'], 16))
    mutated[at:at + 6] = b'999.1\0'
    check('uint8-overflow', bytes(mutated))
    other = Path('/home/kali/Desktop/work/project/vulnscan/mnt_system/system/lib/arm/libicuuc.so')
    check('unsupported-arm32', other.read_bytes())
    other = ROOT / 'reports/function-version-experiment-20261118/scout/objects/allwinner_lib_libicuuc.so'
    check('unsupported-allwinner-inline-parser', other.read_bytes())
    result = {'input': str(INPUT), 'sha256': hashlib.sha256(data).hexdigest(),
              'positive': [{'name': h.name, 'version': h.version, 'evidence': json.loads(h.evidence)} for h in hits],
              'negative_and_unsupported_controls': cases,
              'summary': {'real_hits': len(hits), 'controls': len(cases), 'controls_passed': sum(c['passed'] for c in cases)}}
    out = ROOT / 'reports/function-version-experiment-20261118/controls/icu-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['summary']))
    assert all(c['passed'] for c in cases)


if __name__ == '__main__':
    main()
