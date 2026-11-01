import hashlib
import hmac
import json
import unittest
from odas.gateway import canonical, verify_gateway_envelope

KEY = b"synthetic-testing-key-at-least-32-bytes-long"


def envelope(message, results=None, gateway_id="local-test"):
    payload = {"gateway_id": gateway_id,
               "message_sha256": hashlib.sha256(message).hexdigest(),
               "results": results if results is not None else {"dmarc": "fail"}}
    payload["mac"] = hmac.new(KEY, canonical(payload), hashlib.sha256).hexdigest()
    return canonical(payload)


class GatewayTests(unittest.TestCase):
    def test_valid_evidence_review_only(self):
        r = verify_gateway_envelope(b"From: a@example.org\n\n", envelope(b"From: a@example.org\n\n"),
                                    {"local-test": KEY})
        self.assertTrue(r["trusted"])
        self.assertTrue(r["message_bound"])
        self.assertEqual(r["decision"], "no-blocking-decision")

    def test_wrong_message_rejected(self):
        with self.assertRaises(ValueError):
            verify_gateway_envelope(b"another", envelope(b"original"), {"local-test": KEY})

    def test_tampering_rejected(self):
        e = json.loads(envelope(b"original"))
        e["results"]["dmarc"] = "pass"
        with self.assertRaises(ValueError):
            verify_gateway_envelope(b"original", canonical(e), {"local-test": KEY})

    def test_unknown_gateway_rejected(self):
        with self.assertRaises(ValueError):
            verify_gateway_envelope(b"x", envelope(b"x"), {})

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            verify_gateway_envelope(b"x", envelope(b"x"), {"local-test": b"x" * 32})

    def test_duplicate_json_field_rejected(self):
        with self.assertRaises(ValueError):
            verify_gateway_envelope(b"x", b'{"gateway_id":"a","gateway_id":"b"}', {"a": KEY})

    def test_oversized_envelope_rejected(self):
        with self.assertRaises(ValueError):
            verify_gateway_envelope(b"x", b"x" * 8193, {"local-test": KEY})

    def test_invalid_authentication_result_rejected(self):
        with self.assertRaises(ValueError):
            verify_gateway_envelope(b"x", envelope(b"x", {"spf": "impossible"}), {"local-test": KEY})

    def test_missing_sender_does_not_block(self):
        r = verify_gateway_envelope(b"To: b@example.org\n\n",
                                    envelope(b"To: b@example.org\n\n", {"spf": "fail"}),
                                    {"local-test": KEY})
        self.assertEqual(r["decision"], "no-blocking-decision")


if __name__ == "__main__":
    unittest.main()
