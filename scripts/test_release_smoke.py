"""Checksum files list every published release asset, one digest per line."""

import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("release_smoke", Path(__file__).with_name("release-smoke.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class ChecksumTests(unittest.TestCase):
    def test_each_asset_keeps_its_own_digest(self):
        rows = smoke.checksums(
            "abc  rcp-v0.1.1-x86_64-unknown-linux-gnu.tar.gz\n"
            "def  rcp-v0.1.1-x86_64-unknown-linux-gnu.tar.gz.spdx.json\n"
        )
        self.assertEqual(
            rows,
            [
                ("abc", "rcp-v0.1.1-x86_64-unknown-linux-gnu.tar.gz"),
                ("def", "rcp-v0.1.1-x86_64-unknown-linux-gnu.tar.gz.spdx.json"),
            ],
        )
