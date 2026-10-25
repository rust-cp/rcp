"""Candidate completeness, identity, reproducibility and refusal controls."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('candidate', Path(__file__).with_name('package-candidate.py'))
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class CandidateBundle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = argparse.Namespace(binary=self.root/'binary', notices=self.root/'notices',
            runtime=self.root/'runtime', metadata=self.root/'metadata', glibc=self.root/'glibc',
            output=self.root/'out', target='x86_64-unknown-linux-gnu', revision='a'*40, epoch=1790870000)
        data = bytearray(64)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', data, 18, 62)
        self.args.binary.write_bytes(data)
        self.args.notices.write_text('synthetic fixture notices\n')
        self.args.runtime.write_text('synthetic fixture runtime\n')
        self.args.glibc.write_text('Maximum required: 2.29; allowed: 2.34\n')
        self.metadata(candidate.GNU_FEATURES)

    def metadata(self, features):
        self.args.metadata.write_text(json.dumps({'packages':[{'id':'root','name':'rust-cp','version':'0.1.0'}],
            'resolve':{'root':'root','nodes':[{'id':'root','features':sorted(features)}]}}))

    def windows(self):
        self.args.target = 'x86_64-pc-windows-msvc'
        data = bytearray(512)
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 60, 64)
        data[64:68] = b'PE\0\0'
        struct.pack_into('<H', data, 68, 0x8664)
        struct.pack_into('<H', data, 84, 240)
        struct.pack_into('<H', data, 88, 0x20B)
        self.args.binary.write_bytes(data)
        self.metadata(candidate.WINDOWS_FEATURES)

    def verify_files(self, files):
        for line in files['SHA256SUMS'].decode().splitlines():
            digest, name = line.split('  ', 1)
            self.assertEqual(hashlib.sha256(files[name]).hexdigest(), digest)
        manifest = json.loads(files['MANIFEST.json'])
        self.assertEqual(manifest['sourceRevision'], 'a'*40)
        self.assertTrue(manifest['candidate'])
        self.assertTrue(files['LICENSE'] and files['THIRD_PARTY_LICENSES.txt'] and files['RUNTIME.txt'])

    def imported_dll(self, name):
        self.windows()
        data = bytearray(1024)
        data[:512] = self.args.binary.read_bytes()
        struct.pack_into('<H', data, 70, 1)
        struct.pack_into('<I', data, 208, 0x1000)
        struct.pack_into('<IIII', data, 336, 512, 0x1000, 512, 512)
        struct.pack_into('<IIIII', data, 512, 0, 0, 0, 0x1040, 0)
        encoded = name.encode('ascii') + b'\0'
        data[576:576+len(encoded)] = encoded
        self.args.binary.write_bytes(data)

    def test_system_dll_import_is_recorded(self):
        self.imported_dll('KERNEL32.dll')
        self.assertEqual(candidate.bundle(self.args)['imports'], ['kernel32.dll'])

    def test_dynamic_msvc_runtime_is_refused(self):
        self.imported_dll('VCRUNTIME140.dll')
        with self.assertRaisesRegex(ValueError, 'static MSVC'):
            candidate.bundle(self.args)

    def test_gnu_archive_has_only_regular_licensed_identified_files(self):
        result = candidate.bundle(self.args)
        with tarfile.open(result['archive']) as archive:
            self.assertTrue(all(m.isfile() and m.uid == 0 and m.gid == 0 for m in archive.getmembers()))
            self.verify_files({m.name:archive.extractfile(m).read() for m in archive.getmembers()})

    def test_windows_zip_has_licenses_profile_and_identity(self):
        self.windows()
        result = candidate.bundle(self.args)
        with zipfile.ZipFile(result['archive']) as archive:
            files = {name:archive.read(name) for name in archive.namelist()}
            self.assertIn('rcp.exe', files)
            self.verify_files(files)
            self.assertEqual(json.loads(files['MANIFEST.json'])['features'], sorted(candidate.WINDOWS_FEATURES))

    def test_same_inputs_produce_identical_archives(self):
        for windows in (False, True):
            if windows:
                self.windows()
            first = candidate.bundle(self.args)
            second = candidate.bundle(self.args)
            self.assertEqual(first['archiveSha256'], second['archiveSha256'])

    def test_wrong_machine_cannot_be_packaged(self):
        data = bytearray(self.args.binary.read_bytes())
        struct.pack_into('<H', data, 18, 183)
        self.args.binary.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'x86-64'):
            candidate.bundle(self.args)

    def test_missing_license_notices_refused(self):
        self.args.notices.write_text('')
        with self.assertRaisesRegex(ValueError, 'nonempty'):
            candidate.bundle(self.args)

    def test_unqualified_feature_profile_refused(self):
        self.metadata(candidate.GNU_FEATURES | {'system-zstd'})
        with self.assertRaisesRegex(ValueError, 'feature profile'):
            candidate.bundle(self.args)

    def test_newer_glibc_gate_refused(self):
        self.args.glibc.write_text('Maximum required: 2.39; allowed: 2.34\n')
        with self.assertRaisesRegex(ValueError, 'passing GLIBC'):
            candidate.bundle(self.args)

    def test_exact_source_revision_required(self):
        self.args.revision = 'main'
        with self.assertRaisesRegex(ValueError, 'exact Git'):
            candidate.bundle(self.args)


if __name__ == '__main__':
    unittest.main()
