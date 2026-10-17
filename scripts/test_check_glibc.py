"""Negative controls for architecture and GNU libc ABI qualification."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.name == 'posix', 'ELF gate requires GNU/Linux shell tools')
class AbiGate(unittest.TestCase):
    def run_gate(self, target, machine, interpreter, version, private=False):
        with tempfile.TemporaryDirectory() as directory:
            tool = Path(directory) / 'readelf'
            tool.write_text('''#!/bin/sh
case "$1" in
--file-header) printf 'Class: ELF64\\nMachine: %s\\n' "$MOCK_MACHINE" ;;
--program-headers) printf '[Requesting program interpreter: /lib/%s]\\n' "$MOCK_INTERPRETER" ;;
--version-info) printf 'Name: GLIBC_%s\\n' "$MOCK_VERSION" ;;
*) exit 2 ;;
esac
''')
            tool.chmod(0o755)
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'],
                       MOCK_MACHINE=machine, MOCK_INTERPRETER=interpreter,
                       MOCK_VERSION='PRIVATE' if private else version)
            args = ['bash', str(Path(__file__).with_name('check-glibc.sh')), 'fixture', '2.34']
            if target:
                args.append(target)
            return subprocess.run(args, env=env, capture_output=True, text=True)

    def test_existing_x86_default_still_passes(self):
        self.assertEqual(self.run_gate(None, 'Advanced Micro Devices X86-64', 'ld-linux-x86-64.so.2', '2.34').returncode, 0)

    def test_arm64_older_abi_passes(self):
        self.assertEqual(self.run_gate('aarch64-unknown-linux-gnu', 'AArch64', 'ld-linux-aarch64.so.1', '2.31').returncode, 0)

    def test_arm64_newer_abi_is_refused(self):
        result = self.run_gate('aarch64-unknown-linux-gnu', 'AArch64', 'ld-linux-aarch64.so.1', '2.39')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('exceeding GLIBC_2.34', result.stderr)

    def test_arm64_cannot_pass_as_x86(self):
        self.assertNotEqual(self.run_gate(None, 'AArch64', 'ld-linux-aarch64.so.1', '2.31').returncode, 0)

    def test_arm64_wrong_interpreter_is_refused(self):
        self.assertNotEqual(self.run_gate('aarch64-unknown-linux-gnu', 'AArch64', 'ld-linux-x86-64.so.2', '2.31').returncode, 0)

    def test_private_abi_is_refused(self):
        self.assertNotEqual(self.run_gate('aarch64-unknown-linux-gnu', 'AArch64', 'ld-linux-aarch64.so.1', '2.31', True).returncode, 0)


if __name__ == '__main__':
    unittest.main()
