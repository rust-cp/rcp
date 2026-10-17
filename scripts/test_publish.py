"""Publication regressions using an isolated repository and a local ORAS stub."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class Publication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rcp-publish-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copy(Path(__file__).with_name("publish.sh"), self.root / "scripts/publish.sh")
        (self.root / "Cargo.toml").write_text('version = "0.1.0"\n')
        self.bin = self.root / "bin"
        self.bin.mkdir()
        oras = self.bin / "oras"
        oras.write_text("#!/usr/bin/env python3\nimport json,os,sys\n"
                        "open(os.environ['CAPTURE'],'w').write(json.dumps(sys.argv[1:]))\n"
                        "print(json.dumps({'digest': os.environ['DIGEST']}))\n")
        oras.chmod(0o755)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "remote", "add", "origin",
                        "https://github.com/rust-cp/rcp.git"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Test",
                        "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"], check=True)
        self.capture = self.root / "capture.json"
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ["PATH"],
                        RCP_BIN="/usr/bin/true", CAPTURE=str(self.capture),
                        DIGEST="sha256:"+"a"*64, GITHUB_OUTPUT=str(self.root / "output"))
        for key in ("RCP_BUILD_TARGET", "RCP_BUILD_RUSTC", "RCP_BUILD_REVISION", "RCP_BUILD_SOURCE", "RCP_BUILD_VERSION"):
            self.env.pop(key, None)

    def run_publish(self):
        return subprocess.run(["bash", str(self.root / "scripts/publish.sh"),
                               "localhost/test", "test"], env=self.env, capture_output=True, text=True)

    def test_external_dynamic_binary_does_not_invent_build_provenance(self):
        result = self.run_publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        args = json.loads(self.capture.read_text())
        self.assertIn("io.github.rust-cp.rcp.build.target=unknown", args)
        self.assertIn("io.github.rust-cp.rcp.build.rustc=unknown", args)
        self.assertIn("io.github.rust-cp.rcp.binary.linkage=dynamic", args)
        self.assertIn("org.opencontainers.image.revision=unknown", args)
        self.assertIn("org.opencontainers.image.version=unknown", args)

    def test_missing_custom_binary_does_not_build_or_publish(self):
        self.env["RCP_BIN"] = str(self.root / "missing")
        result = self.run_publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not executable", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_local_build_uses_explicit_host_and_records_its_source(self):
        self.env.pop("RCP_BIN")
        self.env.pop("CARGO_TARGET_DIR", None)
        rustc = self.bin / "rustc"
        rustc.write_text('#!/bin/sh\nif [ "$1" = "-vV" ]; then echo "host: x86_64-unknown-linux-gnu"; else echo "rustc fixture"; fi\n')
        rustc.chmod(0o755)
        cargo = self.bin / "cargo"
        cargo.write_text('#!/usr/bin/env python3\nimport pathlib,shutil,sys\n'
                         'assert sys.argv[-2:] == ["--target", "x86_64-unknown-linux-gnu"]\n'
                         'p=pathlib.Path("target/x86_64-unknown-linux-gnu/release/rcp")\n'
                         'p.parent.mkdir(parents=True); shutil.copy("/usr/bin/true", p)\n')
        cargo.chmod(0o755)
        result = self.run_publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        args = json.loads(self.capture.read_text())
        self.assertIn("io.github.rust-cp.rcp.build.target=x86_64-unknown-linux-gnu", args)
        self.assertIn("io.github.rust-cp.rcp.build.rustc=rustc fixture", args)
        self.assertIn("org.opencontainers.image.version=0.1.0", args)
        self.assertIn("org.opencontainers.image.source=https://github.com/rust-cp/rcp", args)
        self.assertNotIn("org.opencontainers.image.revision=unknown", args)

    def test_malformed_digest_does_not_report_success(self):
        for digest in ("", "sha256:abc", "sha256:"+"a"*65):
            with self.subTest(digest=digest):
                self.env["DIGEST"] = digest
                result = self.run_publish()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("pushed localhost/test@", result.stdout)
                self.assertFalse((self.root / "output").exists())


if __name__ == "__main__":
    unittest.main()
