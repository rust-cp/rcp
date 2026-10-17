"""The release SBOM follows the runtime Cargo graph and ignores build tools."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("spdx_sbom", Path(__file__).with_name("spdx-sbom.py"))
sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sbom)


def metadata():
    def package(name, version, checksum=None, license="Apache-2.0 OR MIT"):
        record = {
            "id": f"{name}-{version}",
            "name": name,
            "version": version,
            "license": license,
            "repository": f"https://example.test/{name}",
        }
        if checksum:
            record["source"] = "registry+https://github.com/rust-lang/crates.io-index"
            record["checksum"] = checksum
        return record

    edge = lambda name, kind: {"pkg": name, "dep_kinds": [{"kind": kind}]}
    return {
        "packages": [
            package("rcp", "0.1.1", license="Apache-2.0") | {"source": None},
            package("runtime", "1.2.3", "a" * 64),
            package("nested", "2.0.0", "b" * 64),
            package("build", "9.9.9", "c" * 64),
        ],
        "resolve": {
            "root": "rcp-0.1.1",
            "nodes": [
                {"id": "rcp-0.1.1", "deps": [edge("runtime-1.2.3", None), edge("build-9.9.9", "build")]},
                {"id": "runtime-1.2.3", "deps": [edge("nested-2.0.0", None)]},
                {"id": "nested-2.0.0", "deps": []},
                {"id": "build-9.9.9", "deps": []},
            ],
        },
    }


class SpdxTests(unittest.TestCase):
    def test_lockfile_checksum_fills_a_registry_package(self):
        with tempfile.TemporaryDirectory() as scratch:
            lock = Path(scratch) / "Cargo.lock"
            lock.write_text(
                'version = 4\n\n[[package]]\nname = "nested"\nversion = "2.0.0"\nchecksum = "' + ("d" * 64) + '"\n',
                encoding="utf-8",
            )
            body = json.loads(sbom.render(metadata(), None, sbom.lock_checksums(lock)))
            nested = next(package for package in body["packages"] if package["name"] == "nested")
            self.assertEqual(nested["checksums"][0]["checksumValue"], "d" * 64)
    def test_runtime_graph_omits_build_dependencies(self):
        body = json.loads(sbom.render(metadata(), None))
        names = [package["name"] for package in body["packages"]]
        self.assertEqual(names, ["rcp", "nested", "runtime"])
        self.assertEqual(body["spdxVersion"], "SPDX-2.3")
        self.assertEqual(body["packages"][0]["licenseDeclared"], "Apache-2.0")
        self.assertEqual(body["packages"][1]["licenseConcluded"], "NOASSERTION")
        self.assertEqual(body["packages"][1]["checksums"][0]["checksumValue"], "b" * 64)
        self.assertNotIn("build", names)
        relationships = {
            (item["spdxElementId"], item["relationshipType"], item["relatedSpdxElement"])
            for item in body["relationships"]
        }
        self.assertIn(("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-Package-0"), relationships)
        self.assertIn(("SPDXRef-Package-0", "DEPENDS_ON", "SPDXRef-Package-2"), relationships)
        self.assertIn(("SPDXRef-Package-2", "DEPENDS_ON", "SPDXRef-Package-1"), relationships)

    def test_check_accepts_the_rendered_document_and_rejects_a_stale_one(self):
        graph = metadata()
        fresh = sbom.comparable(sbom.document(graph, None))
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "rcp.spdx.json"
            path.write_text(sbom.render(graph, None), encoding="utf-8")
            self.assertEqual(sbom.comparable(json.loads(path.read_text(encoding="utf-8"))), fresh)
            stale = json.loads(path.read_text(encoding="utf-8"))
            stale["packages"][1]["versionInfo"] = "9.9.9"
            self.assertNotEqual(sbom.comparable(stale), fresh)
