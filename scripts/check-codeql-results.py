#!/usr/bin/env python3
"""Make CodeQL findings reviewable from the SARIF the analysis writes, independent of upload."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parent.parent


def flow_digest(result):
    """Pin every reported source-to-sink location, without storing finding text."""
    locations = [
        location.get("location", {}).get("physicalLocation", {})
        for flow in result.get("codeFlows", [])
        for thread in flow.get("threadFlows", [])
        for location in thread.get("locations", [])
    ]
    encoded = json.dumps(locations, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def reviewed_flows(entry):
    """CodeQL reports one representative path per finding and may pick a different one on
    an unchanged tree, so an entry lists every path that was individually reviewed."""
    flows = entry.get("flowDigests", [entry["flowDigest"]] if entry.get("flowDigest") else [])
    if "flowDigest" in entry and "flowDigests" in entry:
        return set()
    if not isinstance(flows, list) or not all(isinstance(f, str) and len(f) == 64 for f in flows):
        return set()
    return set(flows)


dispositions = {}
manifest = root / ".github/codeql-dispositions.json"
if manifest.exists():
    reviewed = json.loads(manifest.read_text())
    if reviewed.get("schemaVersion") != 2 or reviewed.get("status") != "individually_reviewed":
        raise SystemExit("Invalid CodeQL disposition manifest")
    for entry in reviewed["findings"]:
        key = (entry["ruleId"], entry["path"], entry["partialFingerprints"]["primaryLocationLineHash"])
        if key in dispositions or entry.get("classification") != "false_positive":
            raise SystemExit("Duplicate or invalid CodeQL disposition")
        scope = entry.get("scope")
        evidence = entry.get("cfgTestEvidence" if scope == "test_fixture" else "nonSecretEvidence")
        if (
            scope not in {"test_fixture", "non_secret_report_data"}
            or not entry.get("reason")
            or not entry.get("owningFunction")
            or not evidence
            or not reviewed_flows(entry)
        ):
            raise SystemExit("CodeQL disposition needs an individual reason, flow and evidence")
        required_sources = {entry["path"], *(e["path"] for e in evidence)}
        if set(entry.get("sourceHashes", {})) != required_sources:
            raise SystemExit("CodeQL disposition must pin all source and test-gating evidence")
        dispositions[key] = entry

files = sorted(Path(sys.argv[1]).glob("*.sarif"))
if not files:
    raise SystemExit("CodeQL produced no SARIF report")
unreviewed = 0
accepted = 0
for path in files:
    report = json.loads(path.read_text())
    if report.get("version") != "2.1.0" or not report.get("runs"):
        raise SystemExit(f"Invalid or empty CodeQL SARIF report: {path.name}")
    for run in report.get("runs", []):
        for invocation in run.get("invocations", []):
            if invocation.get("executionSuccessful") is False:
                raise SystemExit(f"CodeQL analysis failed: {path.name}")
        results = run.get("results", [])
        print(f"{path.name}: {len(results)} findings")
        for result in results:
            # Print identifiers and locations, never source snippets or potential secrets.
            locations = result.get("locations", [])
            physical = locations[0].get("physicalLocation", {}) if locations else {}
            filename = physical.get("artifactLocation", {}).get("uri", "unknown")
            line = physical.get("region", {}).get("startLine", "?")
            rule = result.get("ruleId", "unknown")
            fingerprint = result.get("partialFingerprints", {}).get("primaryLocationLineHash")
            entry = dispositions.get((rule, filename, fingerprint))
            if entry:
                if flow_digest(result) not in reviewed_flows(entry):
                    raise SystemExit(f"CodeQL disposition needs renewed data-flow review: {filename}:{line}")
                for source, digest in entry["sourceHashes"].items():
                    location = (root / source).resolve()
                    if not location.is_relative_to(root) or not location.is_file():
                        raise SystemExit("CodeQL disposition names an invalid source")
                    if hashlib.sha256(location.read_bytes()).hexdigest() != digest:
                        raise SystemExit(f"CodeQL disposition needs renewed source review: {source}")
                accepted += 1
                print(f"  individually reviewed {entry['scope']}: {rule} at {filename}:{line} ({entry['owningFunction']})")
            else:
                unreviewed += 1
                print(f"  unreviewed: {rule} at {filename}:{line}")
print(f"{accepted} individually reviewed findings; {unreviewed} unresolved findings")
if unreviewed:
    raise SystemExit("CodeQL findings require individual disposition before release")
