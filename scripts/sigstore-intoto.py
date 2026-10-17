#!/usr/bin/env python3
"""Copy the in-toto statement out of a Sigstore bundle as one JSON line.

`actions/attest-build-provenance` writes a Sigstore bundle. Scorecard and SLSA
consumers look for an `*.intoto.jsonl` asset next to the archive. This keeps the
signed DSSE envelope, so the statement and its signature stay together. It does
not invent a statement when the bundle has none.
"""

import base64
import json
from pathlib import Path
import sys


def envelope_line(bundle):
    envelope = bundle.get("dsseEnvelope")
    if not isinstance(envelope, dict) or "payload" not in envelope:
        raise ValueError("sigstore bundle has no DSSE envelope")
    payload = base64.b64decode(envelope["payload"])
    statement = json.loads(payload)
    if not isinstance(statement, dict):
        raise ValueError("DSSE payload is not a JSON object")
    if statement.get("_type") not in {None, "https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"}:
        raise ValueError("DSSE payload is not an in-toto statement")
    if "predicateType" not in statement and statement.get("_type") is None:
        raise ValueError("DSSE payload has no in-toto predicate")
    return json.dumps(envelope, separators=(",", ":"), sort_keys=True)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: sigstore-intoto.py BUNDLE OUTPUT.jsonl")
    bundle = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    Path(sys.argv[2]).write_text(envelope_line(bundle) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
