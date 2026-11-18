"""A shared data section is not proof of a full binary's release version."""
import hashlib
import shutil
import subprocess

import pytest

from firmware_scanner.extraction.hash_matcher import BinaryHashMatcher


def test_same_rodata_different_code_is_not_an_exact_binary_match(tmp_path):
    cc = shutil.which('cc')
    if not cc:
        pytest.skip('C compiler required for independent real ELF fixtures')
    blobs = []
    for value in (1, 2):
        src = tmp_path / f'v{value}.c'
        src.write_text(f'const char *banner = "a shared constant"; int version(void) {{ return {value}; }}')
        target = tmp_path / f'v{value}.so'
        subprocess.run([cc, '-shared', '-fPIC', str(src), '-o', str(target)], check=True)
        blobs.append(target.read_bytes())
    first = BinaryHashMatcher()._extract_elf_section_hashes(blobs[0])
    second = BinaryHashMatcher()._extract_elf_section_hashes(blobs[1])
    assert first['.rodata'] == second['.rodata']
    assert first['.text'] != second['.text']
    matcher = BinaryHashMatcher({first['.rodata']: ('example', '1.0', '', 'library', '', '', [])})
    assert matcher.match_binary(blobs[1], 'v2.so') is None


def test_whole_file_digest_matches_only_identical_bytes():
    blob = b'known build fixture' * 20
    matcher = BinaryHashMatcher({hashlib.sha256(blob).hexdigest(): ('example', '1.0', '', 'library', '', '', [])})
    assert matcher.match_binary(blob, 'example').resolved_version == '1.0'
    assert matcher.match_binary(blob + b'changed', 'example') is None
