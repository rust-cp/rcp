"""Provenance export keeps the signed envelope and rejects anything else."""

import base64
import importlib.util
import json
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("sigstore_intoto", Path(__file__).with_name("sigstore-intoto.py"))
intoto = importlib.util.module_from_spec(spec)
spec.loader.exec_module(intoto)


def bundle_for(statement):
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "dsseEnvelope": {
            "payload": payload,
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": "c2ln", "keyid": ""}],
        },
    }


class IntotoTests(unittest.TestCase):
    def test_signed_statement_is_one_json_line(self):
        statement = {"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1", "subject": []}
        line = intoto.envelope_line(bundle_for(statement))
        self.assertNotIn("\n", line)
        envelope = json.loads(line)
        self.assertEqual(json.loads(base64.b64decode(envelope["payload"])), statement)
        self.assertEqual(envelope["signatures"][0]["sig"], "c2ln")

    def test_a_bundle_without_a_statement_is_refused(self):
        with self.assertRaises(ValueError):
            intoto.envelope_line({"dsseEnvelope": {"payload": base64.b64encode(b"[]").decode()}})
        with self.assertRaises(ValueError):
            intoto.envelope_line({})
