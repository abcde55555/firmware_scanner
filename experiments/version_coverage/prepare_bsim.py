#!/usr/bin/env python3
"""Prepare read-only Graphics Path evidence for the bounded Ghidra experiment.

Reference bytes must match the bundled index and the downloaded AAR checksum
manifest. The query is read directly from a ZIP inside an ext4 firmware image.
No input binary is executed. Outputs belong in an ignored report directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from firmware_scanner.android.archive_reader import FilesystemFile
from firmware_scanner.android.ext4_reader import Ext4Reader


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('references', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--query', default=(
        '/product/priv-app/Tubesky/Tubesky.apk!/lib/x86_64/libandroidx.graphics.path.so'))
    parser.add_argument('--index', type=Path, default=(
        Path(__file__).resolve().parents[2] / 'src/firmware_scanner/data/binary_samples.json'))
    args = parser.parse_args()
    inputs = args.output / 'inputs'
    inputs.mkdir(parents=True, exist_ok=False)
    archive_path, member_path = args.query.split('!/', 1)
    with args.image.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        reader = Ext4Reader(data)
        if not reader.is_valid():
            raise ValueError('Not an ext4 image')
        with FilesystemFile(reader, archive_path) as stream, zipfile.ZipFile(stream) as archive:
            info = archive.getinfo(member_path)
            if info.file_size > 64 * 1024 * 1024:
                raise ValueError('Query member exceeds 64 MiB')
            query = archive.read(info)
    (inputs / 'query-graphics-path.so').write_bytes(query)
    (args.output / 'query.json').write_text(json.dumps({
        'image': str(args.image.resolve()), 'location': args.query, 'size': len(query),
        'sha256': hashlib.sha256(query).hexdigest(),
    }, indent=2) + '\n')

    manifest = json.loads((args.references / 'checksum-manifest.json').read_text())
    artifacts = {row['url']: row for row in manifest['artifacts']}
    records = []
    for sample in json.loads(args.index.read_text())['samples']:
        if sample['name'] != 'libandroidx.graphics.path.so' or sample['architecture'] != 'x86_64':
            continue
        archive_name = Path(urlsplit(sample['source']).path).name
        archive_data = (args.references / archive_name).read_bytes()
        if hashlib.sha256(archive_data).hexdigest() != artifacts[sample['source']]['sha256']:
            raise ValueError('Reference AAR checksum mismatch: ' + archive_name)
        with zipfile.ZipFile(args.references / archive_name) as archive:
            info = archive.getinfo(sample['artifact_path'])
            if info.file_size > 64 * 1024 * 1024:
                raise ValueError('Reference member exceeds 64 MiB')
            binary = archive.read(info)
        if hashlib.sha256(binary).hexdigest() != sample['sha256']:
            raise ValueError('Reference member checksum mismatch: ' + archive_name)
        path = inputs / ('ref-graphics-path-' + sample['version'] + '.so')
        path.write_bytes(binary)
        records.append({'version': sample['version'], 'file': str(path), 'sha256': sample['sha256'],
                        'md5_for_ghidra': hashlib.md5(binary).hexdigest(), 'source': sample['source']})
    (args.output / 'references.json').write_text(json.dumps(records, indent=2) + '\n')
    print(json.dumps({'references': len(records), 'query_sha256': hashlib.sha256(query).hexdigest()}))


if __name__ == '__main__':
    main()
