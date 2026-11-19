"""Keep imported dependency signatures outside the queried executable."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'experiments/version_coverage'))
from compare_bsim import read_signatures


def executable(md5, name, function):
    hashes = ''.join(f'<hash tf="1">{value}</hash>' for value in range(10))
    return (f'<execlist><exe><md5>{md5}</md5><name>{name}</name>'
            f'<arch>x86:LE:64:default</arch></exe>'
            f'<fdesc name="{function}" addr="0x100"><lshcosine>{hashes}'
            '</lshcosine></fdesc></execlist>')


@pytest.mark.parametrize('dependency_first', [True, False])
def test_reads_only_file_owning_executable(tmp_path, dependency_first):
    own = executable('a' * 32, 'actual.so', 'own_function')
    dependency = executable('b' * 32, 'unknown', 'dependency_function')
    path = tmp_path / ('sigs_' + 'a' * 32)
    body = dependency + own if dependency_first else own + dependency
    path.write_text(f'<description settings="0x4d">{body}</description>')
    result = read_signatures(path)
    assert result['md5'] == 'a' * 32
    assert result['name'] == 'actual.so'
    assert [item['name'] for item in result['vectors']] == ['own_function']


def test_rejects_mislabeled_or_missing_executable(tmp_path):
    path = tmp_path / ('sigs_' + 'a' * 32)
    path.write_text('<description>' + executable('b' * 32, 'unknown', 'wrong')
                    + '</description>')
    with pytest.raises(ValueError, match='owning executable'):
        read_signatures(path)


def test_rejects_duplicate_owning_executable(tmp_path):
    path = tmp_path / ('sigs_' + 'a' * 32)
    body = executable('a' * 32, 'actual.so', 'first')
    path.write_text('<description>' + body + body + '</description>')
    with pytest.raises(ValueError, match='owning executable'):
        read_signatures(path)
