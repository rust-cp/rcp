#!/usr/bin/env python3
"""Regression checks for release dependency notice collection."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("third_party_licenses", Path(__file__).with_name("third-party-licenses.py"))
licenses = importlib.util.module_from_spec(spec)
spec.loader.exec_module(licenses)


class NoticeTests(unittest.TestCase):
    def metadata(self, directory):
        packages = []
        for name in ["root", "runtime", "nested", "build", "dev"]:
            path = directory / name
            path.mkdir()
            (path / "Cargo.toml").write_text("", encoding="utf-8")
            packages.append({"id": name, "name": name, "version": "1.0.0", "license": "MIT", "manifest_path": str(path / "Cargo.toml")})
        edge = lambda name, kind: {"pkg": name, "dep_kinds": [{"kind": kind}]}
        nodes = [{"id": "root", "deps": [edge("runtime", None), edge("build", "build"), edge("dev", "dev")]},
                 {"id": "runtime", "deps": [edge("nested", None)]}]
        nodes.extend({"id": name, "deps": []} for name in ["nested", "build", "dev"])
        return {"packages": packages, "resolve": {"root": "root", "nodes": nodes}}

    def test_runtime_graph_and_nested_notices_are_preserved(self):
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch)
            metadata = self.metadata(directory)
            (directory / "runtime" / "LICENSE").write_text("Root copyright notice\n", encoding="utf-8")
            nested = directory / "runtime" / "third_party"
            nested.mkdir()
            (nested / "LICENSE.txt").write_text("Nested copyright and conditions\n", encoding="utf-8")
            (directory / "nested" / "NOTICE").write_text("Transitive attribution\n", encoding="utf-8")
            output = licenses.render_notices(metadata)
            self.assertIn("Root copyright notice\n", output)
            self.assertIn("third_party/LICENSE.txt", output)
            self.assertIn("Nested copyright and conditions\n", output)
            self.assertIn("Transitive attribution\n", output)
            self.assertNotIn("build 1.0.0", output)
            self.assertNotIn("dev 1.0.0", output)
            self.assertEqual(output, licenses.render_notices(metadata))

    def test_missing_notices_fail_instead_of_publishing_incomplete_bundle(self):
        with tempfile.TemporaryDirectory() as scratch:
            with self.assertRaisesRegex(ValueError, "no license notices"):
                licenses.render_notices(self.metadata(Path(scratch)))

    def test_declared_custom_license_file_is_included(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch)
            notice = path / "custom.txt"
            notice.write_text("Custom license\n", encoding="utf-8")
            package = {"name": "custom", "version": "1", "manifest_path": str(path / "Cargo.toml"), "license_file": "custom.txt"}
            self.assertEqual(licenses.license_files(package)[1], [notice])


if __name__ == "__main__":
    unittest.main()
