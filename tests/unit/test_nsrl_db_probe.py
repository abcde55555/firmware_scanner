"""Hash membership must not turn distributor application versions into library releases."""
import sqlite3

import pytest

from experiments.version_coverage.nsrl_db_probe import probe

HASH = 'ab' * 32


def database(tmp_path, *, bad_schema=False):
    path = tmp_path / 'nsrl.db'
    with sqlite3.connect(path) as connection:
        connection.execute('CREATE TABLE FILE (sha256 TEXT, file_size INTEGER, file_name TEXT, package_id INTEGER)')
        if not bad_schema:
            connection.execute('CREATE TABLE PKG (package_id INTEGER, name TEXT, version TEXT)')
            connection.executemany('INSERT INTO PKG VALUES (?, ?, ?)', [(1, 'Video Player', '9.7'), (2, 'Video Player', '9.8')])
            connection.executemany('INSERT INTO FILE VALUES (?, ?, ?, ?)', [(HASH.upper(), 100, 'libcodec.so', 1), (HASH.upper(), 100, 'libcodec.so', 2)])
    return path


def observation(**overrides):
    row = {'sha256': HASH, 'size': 100, 'filename': 'libcodec.so', 'location': '/lib/libcodec.so', 'type': 'library',
           'claims': [{'name': 'libcodec.so', 'version': ''}]}
    return row | overrides


def test_exact_hash_preserves_multiple_distribution_versions_without_library_version(tmp_path):
    result = probe(database(tmp_path), [observation()])
    assert result['matched_unique_hashes'] == 1
    assert result['unknown_host_matched_paths'] == 1
    assert result['upstream_version_gains'] == 0
    assert {r['package_version'] for r in result['matches'][0]['distributions']} == {'9.7', '9.8'}
    assert result['matches'][0]['upstream_version'] is None


def test_no_hit_and_wrong_size_are_not_matched(tmp_path):
    result = probe(database(tmp_path), [observation(sha256='cd' * 32), observation(size=99)])
    assert result['matched_unique_hashes'] == 0
    assert result['size_mismatch_rows'] == 2


def test_duplicate_files_count_paths_and_unique_hashes_separately(tmp_path):
    result = probe(database(tmp_path), [observation(), observation(location='/lib64/libcodec.so')])
    assert result['unknown_host_paths'] == 2
    assert result['unique_target_hashes'] == 1
    assert result['matched_unique_hashes'] == 1
    assert result['unknown_host_matched_paths'] == 2


def test_dependency_version_does_not_make_the_host_known(tmp_path):
    row = observation(claims=[{'name': 'libcodec.so', 'version': ''}, {'name': 'zlib', 'version': '1.2.8'}])
    assert probe(database(tmp_path), [row])['unknown_host_paths'] == 1


def test_invalid_schema_and_invalid_digest_fail_explicitly(tmp_path):
    with pytest.raises(ValueError, match='schema'):
        probe(database(tmp_path, bad_schema=True), [observation()])
    with pytest.raises(ValueError, match='SHA-256'):
        probe(tmp_path / 'unused', [observation(sha256='bad')])


def delta_archive(tmp_path, sql):
    from zipfile import ZipFile
    path = tmp_path / 'delta.zip'
    with ZipFile(path, 'w') as archive:
        archive.writestr('rds/android_minimal_delta.sql', sql)
    return path


def file_insert(digest=HASH, filename='libcodec.so'):
    return ("INSERT INTO FILE(sha256,sha1,md5,crc32,file_name,file_size,package_id) VALUES("
            f"'{digest.upper()}','{'ef' * 20}','{'12' * 16}','12345678','{filename}',100,1);\n")


def test_delta_hash_membership_resolves_existing_base_package_without_inventing_library_release(tmp_path):
    from experiments.version_coverage.nsrl_db_probe import probe_delta
    result = probe_delta(database(tmp_path), delta_archive(tmp_path, file_insert()), [observation()])
    assert result['matched_unique_hashes'] == 1
    assert result['upstream_version_gains'] == 0
    assert result['file_insert_rows_scanned'] == 1
    # The delta inserts this file for package 1; package 2 is a base-only association.
    assert {d['package_version'] for d in result['matches'][0]['distributions']} == {'9.7'}


def test_delta_can_add_package_and_preserve_quoted_filename(tmp_path):
    from experiments.version_coverage.nsrl_db_probe import probe_delta
    sql = file_insert(filename="libO''Brien.so") + (
        "INSERT INTO PKG(package_id,name,version,operating_system_id,manufacturer_id,language,application_type) "
        "VALUES(1,'Another App','12.4',1,1,'en','Utility');\n")
    result = probe_delta(database(tmp_path), delta_archive(tmp_path, sql), [observation()])
    assert result['matches'][0]['distributions'][0]['file_name'] == "libO'Brien.so"
    assert result['matches'][0]['distributions'][0]['package_version'] == '12.4'


@pytest.mark.parametrize('sql', [
    "DELETE FROM FILE WHERE package_id=1;\n",
    "UPDATE FILE SET sha256='" + HASH.upper() + "';\n",
    file_insert('cd' * 32).rstrip() + file_insert(),
])
def test_delta_projection_rejects_unsupported_changes_and_multiple_statements(tmp_path, sql):
    from experiments.version_coverage.nsrl_db_probe import probe_delta
    with pytest.raises(ValueError, match='unsupported'):
        probe_delta(database(tmp_path), delta_archive(tmp_path, sql), [observation()])
