#!/usr/bin/env python3
"""Offline NSRL RDSv3 minimal hash probe; distribution releases stay separate.

The observation input is a frozen product scan's file-observations.json. Every
lookup uses SHA-256 and size. No network calls or upstream version assignment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import resource
import sqlite3
import tempfile
import time
import zipfile
from collections import Counter
from contextlib import closing
from pathlib import Path

MAX_DISTRIBUTIONS = 1024
_REQUIRED = {
    'FILE': {'sha256', 'file_size', 'file_name', 'package_id'},
    'PKG': {'package_id', 'name', 'version'},
}
_UNKNOWN = {'', 'unknown', 'detected', 'detected (version unknown)'}
_SQL_STRING = rb"'(?:[^']|'')*'"
_LITERAL = rb'(?:' + _SQL_STRING + rb'|[0-9]+)'
_INSERT = re.compile(
    rb'INSERT INTO (FILE|PKG|MFG|OS|VERSION)\(([a-z0-9_,]+)\) VALUES\('
    + _LITERAL + rb'(?:,' + _LITERAL + rb')*\);'
)
_FILE_INSERT = re.compile(
    rb"INSERT INTO FILE\(sha256,sha1,md5,crc32,file_name,file_size,package_id\) VALUES\('"
    rb"([a-fA-F0-9]{64})','[a-fA-F0-9]{40}','[a-fA-F0-9]{32}','[a-fA-F0-9]{8}',"
    + _SQL_STRING + rb',[0-9]+,[0-9]+\);'
)


def _connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA trusted_schema=OFF')
    connection.execute('PRAGMA query_only=ON')
    connection.execute('PRAGMA cache_size=-32768')
    connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 16 * 1024 * 1024)
    for table, required in _REQUIRED.items():
        columns = {row['name'] for row in connection.execute(f'PRAGMA table_info({table})')}
        if not required.issubset(columns):
            connection.close()
            raise ValueError(f'unsupported NSRL minimal schema: missing {table} columns')
    return connection


def probe(database: Path, observations: list[dict]) -> dict:
    """Report exact file membership, never treating a package release as a library release."""
    by_hash: dict[str, list[dict]] = {}
    for observation in observations:
        digest = observation.get('sha256', '')
        if not isinstance(digest, str) or not re.fullmatch(r'[a-fA-F0-9]{64}', digest):
            raise ValueError('invalid observation SHA-256')
        if not isinstance(observation.get('size'), int) or observation['size'] < 0:
            raise ValueError('invalid observation size')
        by_hash.setdefault(digest.lower(), []).append(observation)
    report = {
        'observation_paths': len(observations),
        'unique_target_hashes': len(by_hash),
        'unknown_host_paths': 0,
        'matched_unique_hashes': 0,
        'matched_paths': 0,
        'unknown_host_matched_paths': 0,
        'size_mismatch_rows': 0,
        'truncated_hashes': [],
        'upstream_version_gains': 0,
        'matches': [],
        'scope': 'SHA-256 and size membership in the supplied NSRL minimal database',
        'attribution': 'PKG.version is the distributing package version; no native upstream release inferred',
    }
    with closing(_connection(database)) as connection:
        for digest, files in sorted(by_hash.items()):
            rows = list(connection.execute(
                'SELECT f.file_size, f.file_name, f.package_id, '
                'p.name AS package_name, p.version AS package_version '
                'FROM FILE AS f LEFT JOIN PKG AS p ON f.package_id=p.package_id '
                'WHERE f.sha256 IN (?, ?) LIMIT ?',
                (digest, digest.upper(), MAX_DISTRIBUTIONS + 1),
            ))
            if len(rows) > MAX_DISTRIBUTIONS:
                report['truncated_hashes'].append(digest)
                rows = rows[:MAX_DISTRIBUTIONS]
            matched = False
            for file in files:
                claims = file.get('claims', [])
                # BinaryInventory always emits the containing ELF first. Versions
                # of later embedded dependencies do not identify the host release.
                host = claims[0] if claims else {}
                host_unknown = (file.get('type') == 'library'
                                and str(host.get('version') or '').strip().lower() in _UNKNOWN)
                report['unknown_host_paths'] += host_unknown
                distributions = [dict(row) for row in rows if row['file_size'] == file['size']]
                report['size_mismatch_rows'] += sum(row['file_size'] != file['size'] for row in rows)
                if not distributions:
                    continue
                matched = True
                report['matched_paths'] += 1
                report['unknown_host_matched_paths'] += host_unknown
                report['matches'].append({
                    'location': file.get('location'), 'filename': file.get('filename'),
                    'sha256': digest, 'size': file['size'], 'host_unknown': host_unknown,
                    'upstream_version': None, 'distributions': distributions,
                    'distributions_truncated': digest in report['truncated_hashes'],
                })
            report['matched_unique_hashes'] += matched
    return report


def probe_delta(database: Path, archive: Path, observations: list[dict]) -> dict:
    """Query literal, append-only RDS deltas through an exact target projection.

    Reject changes to FILE keys or nonliteral/multiple statements instead of
    silently claiming a zero hit. NSRL's June/September 2026 minimal Android
    deltas contain FILE/PKG/MFG inserts and VERSION bookkeeping only. Retaining
    matching FILE inserts and resolving their package IDs gives the same target
    memberships without inserting millions of unrelated files into the base DB.
    """
    targets = {row['sha256'].upper() for row in observations}
    if any(not re.fullmatch(r'[A-F0-9]{64}', value) for value in targets):
        raise ValueError('invalid observation SHA-256')
    counts: Counter[str] = Counter()
    sql_hash = hashlib.sha256()
    first_file: bytes | None = None
    with tempfile.TemporaryDirectory(prefix='nsrl-projection-') as temporary:
        path = Path(temporary) / 'projection.db'
        with closing(sqlite3.connect(path)) as connection:
            connection.execute('CREATE TABLE FILE (sha256 TEXT, sha1 TEXT, md5 TEXT, crc32 TEXT, '
                               'file_name TEXT, file_size INTEGER, package_id INTEGER)')
            connection.execute('CREATE TABLE PKG (package_id INTEGER, name TEXT, version TEXT, '
                               'operating_system_id INTEGER, manufacturer_id INTEGER, '
                               'language TEXT, application_type TEXT)')
            with zipfile.ZipFile(archive) as zipped:
                members = [info for info in zipped.infolist() if info.filename.endswith('_delta.sql')]
                if len(members) != 1 or members[0].file_size > 4 * 1024**3:
                    raise ValueError('unsupported NSRL delta member or byte budget')
                with zipped.open(members[0]) as source:
                    while raw := source.readline(2 * 1024 * 1024 + 1):
                        if len(raw) > 2 * 1024 * 1024:
                            raise ValueError('unsupported oversized NSRL SQL statement')
                        sql_hash.update(raw)
                        statement = raw.strip()
                        # Literal filenames may contain newlines; gather only
                        # such incomplete statements, under the same byte cap.
                        while not sqlite3.complete_statement(statement.decode('utf-8')):
                            continuation = source.readline(2 * 1024 * 1024 + 1)
                            if not continuation or len(raw) + len(continuation) > 2 * 1024 * 1024:
                                raise ValueError('unsupported incomplete NSRL SQL statement')
                            sql_hash.update(continuation)
                            raw += continuation
                            statement = raw.strip()
                        if statement in (b'BEGIN TRANSACTION;', b'COMMIT;'):
                            counts[statement.decode()] += 1
                            continue
                        if re.fullmatch(rb"DELETE FROM VERSION WHERE version='[0-9.]+';", statement):
                            counts['DELETE FROM VERSION'] += 1
                            continue
                        match = _INSERT.fullmatch(statement)
                        if match is None:
                            raise ValueError('unsupported NSRL delta statement; append-only proof failed')
                        table = match[1].decode()
                        counts[f'INSERT INTO {table}'] += 1
                        if table == 'FILE':
                            file_match = _FILE_INSERT.fullmatch(statement)
                            if file_match is None:
                                raise ValueError('unsupported NSRL FILE literal or column order')
                            if first_file is None:
                                first_file = statement
                            if file_match[1].decode().upper() in targets:
                                connection.execute(statement.decode())
                        elif table == 'PKG':
                            connection.execute(statement.decode())
            if first_file is None:
                raise ValueError('unsupported empty NSRL FILE delta')
            # Keep a known delta member as a query control. Its path is never
            # included in firmware totals unless the firmware actually has it.
            first_sha = _FILE_INSERT.fullmatch(first_file)[1].decode()
            if not connection.execute('SELECT 1 FROM FILE WHERE sha256=?', (first_sha,)).fetchone():
                connection.execute(first_file.decode())
            with closing(_connection(database)) as baseline:
                identifiers = list(connection.execute('SELECT DISTINCT package_id FROM FILE'))
                for (package_id,) in identifiers:
                    if connection.execute('SELECT 1 FROM PKG WHERE package_id=?', (package_id,)).fetchone():
                        continue
                    connection.executemany('INSERT INTO PKG(package_id,name,version) VALUES(?,?,?)',
                                           baseline.execute('SELECT package_id,name,version FROM PKG '
                                                            'WHERE package_id=?', (package_id,)))
            connection.commit()
            known = connection.execute('SELECT sha256,file_size,file_name FROM FILE LIMIT 1').fetchone()
        result = probe(path, observations)
        control = {'sha256': known[0], 'size': known[1], 'filename': known[2],
                   'location': 'delta-database-positive-control', 'type': 'control', 'claims': []}
        result.update({
            'archive': str(archive.resolve()), 'archive_sha256': _sha256(archive),
            'sql_sha256': sql_hash.hexdigest(), 'file_insert_rows_scanned': counts['INSERT INTO FILE'],
            'operations': dict(counts), 'append_only_membership_proven': True,
            'positive_control_hit': probe(path, [control])['matched_unique_hashes'] == 1,
        })
        return result


def _sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database', type=Path)
    parser.add_argument('--observations', action='append', required=True, metavar='NAME=PATH')
    parser.add_argument('--delta', action='append', type=Path, default=[],
                        help='NSRL minimal delta ZIP; accepts literal append-only membership changes')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic()
    result = {
        'schema': 'nsrl-offline-probe/v1',
        'database': {'path': str(args.database.resolve()), 'size': args.database.stat().st_size,
                     'sha256': _sha256(args.database)},
        'probe_sha256': _sha256(Path(__file__)),
        'inputs': {},
    }
    for argument in args.observations:
        name, separator, value = argument.partition('=')
        if not separator or name in result['inputs']:
            raise SystemExit('--observations requires unique NAME=PATH')
        path = Path(value)
        rows = json.loads(path.read_text())
        if not isinstance(rows, list):
            raise SystemExit('observations must be a JSON list')
        result['inputs'][name] = {
            'observations_path': str(path.resolve()), 'observations_sha256': _sha256(path),
            **probe(args.database, rows),
        }
        if args.delta:
            result['inputs'][name]['deltas'] = [probe_delta(args.database, path, rows)
                                               for path in args.delta]
    # Exercise the actual schema/index using a known database member. This is a
    # query control, not a claim that this member occurs in either firmware.
    with closing(_connection(args.database)) as connection:
        known = connection.execute('SELECT sha256, file_size, file_name FROM FILE LIMIT 1').fetchone()
    if known is None:
        raise SystemExit('NSRL database is empty')
    positive = {'sha256': known['sha256'], 'size': known['file_size'],
                'filename': known['file_name'], 'location': 'database-positive-control',
                'type': 'control', 'claims': []}
    negative = positive | {'sha256': hashlib.sha256(b'nsrl-db-probe-negative-control-v1').hexdigest()}
    controls = probe(args.database, [positive, negative])
    result['controls'] = {'positive_hit': any(m['location'] == positive['location']
                                            and m['sha256'] == positive['sha256'].lower()
                                            for m in controls['matches']),
                          'negative_absent': not any(m['sha256'] == negative['sha256']
                                                     for m in controls['matches'])}
    result['seconds'] = round(time.monotonic() - started, 3)
    result['peak_rss_kb'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    result['exit_code'] = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'output': str(args.output), 'controls': result['controls'],
                      'inputs': {name: {key: value for key, value in item.items()
                                        if key not in ('matches', 'truncated_hashes')}
                                 for name, item in result['inputs'].items()}}))


if __name__ == '__main__':
    main()
