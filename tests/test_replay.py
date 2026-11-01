import hashlib
import hmac
import json
import os
import tempfile
import unittest

from odas.gateway import canonical
from odas.replay import verify_fresh_evidence

KEY = b"test-only-key-32-bytes-minimum-not-production"
NOW = 1800000000


def signed(message=b"hello", nonce="a" * 32, issued_at=NOW, key_id="k1",
           results=None):
    payload = {"gateway_id": "gw1", "key_id": key_id, "nonce": nonce,
               "issued_at": issued_at,
               "message_sha256": hashlib.sha256(message).hexdigest(),
               "results": {"dmarc": "fail"} if results is None else results}
    payload["mac"] = hmac.new(KEY, canonical(payload), hashlib.sha256).hexdigest()
    return canonical(payload)


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "replay.sqlite")
        self.keys = {("gw1", "k1"): KEY, ("gw1", "k2"): KEY}

    def tearDown(self):
        self.tmp.cleanup()

    def verify(self, env, message=b"hello", **kw):
        return verify_fresh_evidence(message, env, self.keys, self.db, now=NOW, **kw)

    def test_first_valid_message_observation_only(self):
        r = self.verify(signed())
        self.assertTrue(r["replay_protected"])
        self.assertEqual(r["decision"], "no-blocking-decision")

    def test_replay_rejected(self):
        self.verify(signed())
        with self.assertRaisesRegex(ValueError, "Replay"):
            self.verify(signed())

    def test_nonce_stays_consumed_across_connections(self):
        self.verify(signed())
        with self.assertRaises(ValueError):
            verify_fresh_evidence(b"hello", signed(), self.keys, self.db, now=NOW)

    def test_expired_rejected(self):
        with self.assertRaises(ValueError):
            self.verify(signed(issued_at=NOW - 301))

    def test_future_rejected(self):
        with self.assertRaises(ValueError):
            self.verify(signed(issued_at=NOW + 31))

    def test_message_tamper_rejected(self):
        with self.assertRaises(ValueError):
            self.verify(signed(), message=b"other")

    def test_mac_tamper_rejected(self):
        obj = json.loads(signed())
        obj["results"]["dmarc"] = "pass"
        with self.assertRaises(ValueError):
            self.verify(canonical(obj))

    def test_unknown_key_rejected(self):
        with self.assertRaises(ValueError):
            self.verify(signed(key_id="unknown"))

    def test_key_rotation_accepts_new_id(self):
        self.verify(signed(nonce="a" * 32))
        r = self.verify(signed(nonce="b" * 32, key_id="k2"))
        self.assertTrue(r["replay_protected"])

    def test_nonce_cannot_reuse_after_rotation(self):
        self.verify(signed())
        with self.assertRaisesRegex(ValueError, "Replay"):
            self.verify(signed(key_id="k2"))

    def test_invalid_result_does_not_consume_nonce(self):
        with self.assertRaises(ValueError):
            self.verify(signed(results={"dmarc": "bogus"}))
        self.assertTrue(self.verify(signed())["replay_protected"])

    def test_duplicate_json_rejected(self):
        with self.assertRaises(ValueError):
            self.verify(b'{"nonce":"a","nonce":"b"}')

    def test_in_memory_db_not_allowed(self):
        with self.assertRaises(ValueError):
            verify_fresh_evidence(b"hello", signed(), self.keys, ":memory:", now=NOW)


if __name__ == "__main__":
    unittest.main()
