#!/usr/bin/env python3
"""Create a development candidate bundle; never publish or modify source files."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import subprocess
import tarfile
import time
import zipfile

ROOT = Path(__file__).resolve().parent.parent
WINDOWS_FEATURES = {'dav', 'https', 'rustls', 's3', 'smb'}
GNU_FEATURES = WINDOWS_FEATURES | {'default', 'hdfs', 'nfs', 'oci', 'remote', 'sftp', 'tar'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pe_imports(data, offset):
    optional = offset + 24
    sections = struct.unpack_from('<H', data, offset + 6)[0]
    size = struct.unpack_from('<H', data, offset + 20)[0]
    if size < 128 or optional + size + sections * 40 > len(data):
        raise ValueError('truncated PE headers')
    import_rva = struct.unpack_from('<I', data, optional + 120)[0]
    if not import_rva:
        return []

    def file_offset(rva):
        for number in range(sections):
            section = optional + size + number * 40
            virtual_size, address, raw_size, raw_offset = struct.unpack_from('<IIII', data, section + 8)
            if address <= rva < address + min(virtual_size, raw_size):
                result = raw_offset + rva - address
                if result < len(data):
                    return result
        raise ValueError('PE import RVA outside file-backed sections')

    cursor = file_offset(import_rva)
    names = set()
    for _ in range(512):
        descriptor = struct.unpack_from('<IIIII', data, cursor)
        if not any(descriptor):
            return sorted(names)
        name = file_offset(descriptor[3])
        end = data.find(b'\0', name, min(name + 261, len(data)))
        if end < 0:
            raise ValueError('unterminated PE import name')
        text = data[name:end].decode('ascii')
        if not re.fullmatch(r'[A-Za-z0-9_.-]+\.dll', text, re.IGNORECASE):
            raise ValueError('invalid PE import name')
        names.add(text.lower())
        cursor += 20
    raise ValueError('unterminated PE import table')


def identify(data, target):
    if target == 'x86_64-pc-windows-msvc':
        if len(data) < 64 or data[:2] != b'MZ':
            raise ValueError('expected Windows PE binary')
        offset = struct.unpack_from('<I', data, 60)[0]
        if (offset + 26 > len(data) or data[offset:offset+4] != b'PE\0\0'
                or struct.unpack_from('<H', data, offset + 4)[0] != 0x8664
                or struct.unpack_from('<H', data, offset + 24)[0] != 0x20B):
            raise ValueError('expected PE32+ AMD64 machine')
        return {'format': 'PE32+', 'machine': 'AMD64', 'imports': pe_imports(data, offset)}
    if (len(data) < 20 or data[:6] != b'\x7fELF\x02\x01'
            or struct.unpack_from('<H', data, 18)[0] != 62):
        raise ValueError('expected ELF64 little-endian x86-64 machine')
    return {'format': 'ELF64', 'machine': 'x86-64'}


def bundle(args):
    if not re.fullmatch(r'[0-9a-f]{40}', args.revision):
        raise ValueError('expected exact Git source revision')
    if not 315532800 <= args.epoch <= 4354819198:
        raise ValueError('source epoch outside ZIP timestamp range')
    metadata = json.loads(args.metadata.read_text(encoding='utf-8-sig'))
    root = metadata['resolve']['root']
    package = next(p for p in metadata['packages'] if p['id'] == root)
    features = set(next(n['features'] for n in metadata['resolve']['nodes'] if n['id'] == root))
    expected = WINDOWS_FEATURES if args.target == 'x86_64-pc-windows-msvc' else GNU_FEATURES
    # crates.io package is rust-cp; the installed command remains rcp.
    if package['name'] != 'rust-cp' or features != expected:
        raise ValueError('Cargo metadata does not match the qualified feature profile')
    data = args.binary.read_bytes()
    identity = identify(data, args.target)
    if any(name.startswith(('vcruntime', 'msvcp')) for name in identity.get('imports', [])):
        raise ValueError('Windows candidate requires static MSVC runtime linkage')
    executable = 'rcp.exe' if args.target == 'x86_64-pc-windows-msvc' else 'rcp'
    files = {executable: data, 'LICENSE': (ROOT / 'LICENSE').read_bytes(),
             'THIRD_PARTY_LICENSES.txt': args.notices.read_bytes(),
             'RUNTIME.txt': args.runtime.read_bytes(),
             'PORTABILITY.md': (ROOT / 'docs/src/portability.md').read_bytes()}
    if any(not contents.strip() for contents in files.values()):
        raise ValueError('candidate requires nonempty license/notices/runtime documentation')
    if args.target == 'x86_64-unknown-linux-gnu':
        if args.glibc is None:
            raise ValueError('GNU candidate requires ABI gate evidence')
        gate = args.glibc.read_bytes()
        match = re.search(rb'Maximum required: (\d+)\.(\d+); allowed: 2\.34\b', gate)
        if not match or tuple(map(int, match.groups())) > (2, 34):
            raise ValueError('candidate has no passing GLIBC <=2.34 gate evidence')
        files['glibc-requirements.txt'] = gate
    manifest = {'schemaVersion': 1, 'candidate': True, 'sourceRevision': args.revision,
                'sourceEpoch': args.epoch, 'target': args.target, 'version': package['version'],
                'features': sorted(features), 'binary': identity,
                'files': {name: sha(contents) for name, contents in sorted(files.items())}}
    files['MANIFEST.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    files['SHA256SUMS'] = ''.join(f'{sha(contents)}  {name}\n' for name, contents in sorted(files.items())).encode()
    args.output.mkdir(parents=True, exist_ok=True)
    suffix = 'zip' if executable.endswith('.exe') else 'tar.gz'
    path = args.output / f'rcp-{args.target}-candidate.{suffix}'
    if suffix == 'zip':
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, contents in sorted(files.items()):
                entry = zipfile.ZipInfo(name, time.gmtime(args.epoch)[:6])
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.create_system = 3
                entry.external_attr = (0o100755 if name == executable else 0o100644) << 16
                archive.writestr(entry, contents)
    else:
        with path.open('wb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.GNU_FORMAT) as archive:
                for name, contents in sorted(files.items()):
                    entry = tarfile.TarInfo(name)
                    entry.size, entry.mtime = len(contents), args.epoch
                    entry.mode = 0o755 if name == executable else 0o644
                    entry.uid = entry.gid = 0
                    archive.addfile(entry, io.BytesIO(contents))
    checksum = sha(path.read_bytes())
    path.with_name(path.name + '.sha256').write_text(f'{checksum}  {path.name}\n', encoding='ascii')
    return {'archive': str(path), 'archiveSha256': checksum, 'binarySha256': sha(data),
            'target': args.target, 'sourceRevision': args.revision, 'imports': identity.get('imports', [])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'notices', 'runtime', 'metadata', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--glibc', type=Path)
    parser.add_argument('--target', choices=['x86_64-pc-windows-msvc', 'x86_64-unknown-linux-gnu'], required=True)
    parser.add_argument('--revision', default=subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip())
    parser.add_argument('--epoch', type=int, default=int(subprocess.check_output(['git', '-C', str(ROOT), 'show', '-s', '--format=%ct', 'HEAD'], text=True)))
    print(json.dumps(bundle(parser.parse_args()), indent=2))


if __name__ == '__main__':
    main()
