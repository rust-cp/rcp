"""Regression checks for individual, fail-closed SARIF dispositions."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class FindingsGate(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        for folder in ("scripts", ".github", "src", "reports"):
            (self.root / folder).mkdir()
        shutil.copyfile(Path(__file__).with_name("check-codeql-results.py"), self.root / "scripts/gate.py")
        (self.root / "src/fixture.rs").write_text("const FIXTURE: &str = \"synthetic\";\n")
        (self.root / "src/mod.rs").write_text("#[cfg(test)]\nmod fixture;\n")
        self.entry = {
            "ruleId": "fixture-rule",
            "path": "src/fixture.rs",
            "partialFingerprints": {"primaryLocationLineHash": "fixture:1"},
            "classification": "false_positive",
            "scope": "test_fixture",
            "flowDigest": hashlib.sha256(b"[]").hexdigest(),
            "owningFunction": "fixture",
            "reason": "Synthetic input in a test-only fixture.",
            "cfgTestEvidence": [{"path": "src/mod.rs"}],
            "sourceHashes": {
                path: hashlib.sha256((self.root / path).read_bytes()).hexdigest()
                for path in ("src/fixture.rs", "src/mod.rs")
            },
        }
        self.result = {
            "ruleId": "fixture-rule",
            "partialFingerprints": {"primaryLocationLineHash": "fixture:1"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/fixture.rs"}, "region": {"startLine": 1},
            }}],
            "message": {"text": "SENSITIVE-FINDING-TEXT"},
        }
        self.save_manifest([self.entry])
        self.save_report({"results": [self.result]})

    def save_manifest(self, entries):
        (self.root / ".github/codeql-dispositions.json").write_text(json.dumps({
            "schemaVersion": 2, "status": "individually_reviewed", "findings": entries,
        }))

    def save_report(self, run):
        (self.root / "reports/test.sarif").write_text(json.dumps({"version": "2.1.0", "runs": [run]}))

    def check_gate(self, passes):
        output = subprocess.run(
            [sys.executable, str(self.root / "scripts/gate.py"), str(self.root / "reports")],
            capture_output=True, text=True,
        )
        self.assertEqual(output.returncode == 0, passes, output.stdout + output.stderr)
        self.assertNotIn("SENSITIVE-FINDING-TEXT", output.stdout + output.stderr)

    def test_exact_reviewed_fixture_and_clean_report_pass(self):
        self.check_gate(True)
        self.save_report({"results": []})
        self.check_gate(True)

    def test_a_new_fingerprint_requires_review(self):
        self.result["partialFingerprints"]["primaryLocationLineHash"] = "new:1"
        self.save_report({"results": [self.result]})
        self.check_gate(False)

    def test_changed_flow_at_same_sink_requires_review(self):
        self.result["codeFlows"] = [{"threadFlows": [{"locations": [{"location": {
            "physicalLocation": {"artifactLocation": {"uri": "src/new-secret.rs"},
                                 "region": {"startLine": 7}},
        }}]}]}]
        self.save_report({"results": [self.result]})
        self.check_gate(False)

    def test_any_individually_reviewed_flow_passes_and_only_those(self):
        alternate = [{"threadFlows": [{"locations": [{"location": {
            "physicalLocation": {"artifactLocation": {"uri": "src/fixture.rs"},
                                 "region": {"startLine": 1}},
        }}]}]}]
        reviewed = json.dumps([alternate[0]["threadFlows"][0]["locations"][0]["location"]["physicalLocation"]],
                              sort_keys=True, separators=(",", ":")).encode()
        self.entry["flowDigests"] = [self.entry.pop("flowDigest"), hashlib.sha256(reviewed).hexdigest()]
        self.save_manifest([self.entry])
        self.check_gate(True)
        self.result["codeFlows"] = alternate
        self.save_report({"results": [self.result]})
        self.check_gate(True)
        self.entry["flowDigests"] = self.entry["flowDigests"][:1]
        self.save_manifest([self.entry])
        self.check_gate(False)

    def test_malformed_or_ambiguous_flow_lists_fail(self):
        digest = self.entry["flowDigest"]
        for flows in ([], [digest, "short"], digest):
            self.entry.pop("flowDigest", None)
            self.entry["flowDigests"] = flows
            self.save_manifest([self.entry])
            self.check_gate(False)
        self.entry["flowDigest"] = digest
        self.entry["flowDigests"] = [digest]
        self.save_manifest([self.entry])
        self.check_gate(False)

    def test_individual_non_secret_report_data_needs_evidence(self):
        self.entry["scope"] = "non_secret_report_data"
        self.entry["nonSecretEvidence"] = self.entry.pop("cfgTestEvidence")
        self.save_manifest([self.entry])
        self.check_gate(True)
        self.entry["nonSecretEvidence"] = []
        self.save_manifest([self.entry])
        self.check_gate(False)

    def test_changed_source_and_changed_test_gating_require_review(self):
        for path in ("src/fixture.rs", "src/mod.rs"):
            original = (self.root / path).read_bytes()
            (self.root / path).write_bytes(original + b"// changed\n")
            self.check_gate(False)
            (self.root / path).write_bytes(original)

    def test_failed_analysis_and_missing_report_fail(self):
        self.save_report({"invocations": [{"executionSuccessful": False}]})
        self.check_gate(False)
        (self.root / "reports/test.sarif").unlink()
        self.check_gate(False)

    def test_duplicate_dispositions_and_missing_scope_evidence_fail(self):
        self.save_manifest([self.entry, self.entry])
        self.check_gate(False)
        self.entry["sourceHashes"].pop("src/mod.rs")
        self.save_manifest([self.entry])
        self.check_gate(False)


if __name__ == "__main__":
    unittest.main()
