import sys
import types
import unittest
from unittest.mock import patch

from odas.dkim_verify import verify_dkim


class DKIMAdapterTests(unittest.TestCase):
    def test_invalid_input_rejected(self):
        with self.assertRaises(ValueError):
            verify_dkim("not bytes", lambda _: None)

    def test_missing_dns_callback_rejected(self):
        with self.assertRaises(ValueError):
            verify_dkim(b"test", None)

    def test_oversize_message_rejected(self):
        with self.assertRaises(ValueError):
            verify_dkim(b"x" * 256001, lambda _: None)

    def test_pass_observation_only(self):
        fake = types.SimpleNamespace(verify=lambda message, **kwargs: True)
        with patch.dict(sys.modules, {"dkim": fake}):
            r = verify_dkim(b"From: x@example.org\r\n\r\n", lambda _: None)
        self.assertEqual(r["status"], "pass")
        self.assertEqual(r["decision"], "no-blocking-decision")

    def test_fail_observation_only(self):
        fake = types.SimpleNamespace(verify=lambda message, **kwargs: False)
        with patch.dict(sys.modules, {"dkim": fake}):
            r = verify_dkim(b"From: x@example.org\r\n\r\n", lambda _: None)
        self.assertEqual(r["status"], "fail")
        self.assertEqual(r["decision"], "no-blocking-decision")

    def test_dns_exception_is_indeterminate(self):
        def failing(*args, **kwargs):
            raise TimeoutError("test DNS timeout")
        fake = types.SimpleNamespace(verify=failing)
        with patch.dict(sys.modules, {"dkim": fake}):
            r = verify_dkim(b"test", lambda _: None)
        self.assertEqual(r["status"], "indeterminate")
        self.assertEqual(r["decision"], "no-blocking-decision")

    def test_invalid_dns_response_indeterminate(self):
        def fake_verify(message, dnsfunc, **kwargs):
            dnsfunc(b"selector._domainkey.example.org")
            return True
        fake = types.SimpleNamespace(verify=fake_verify)
        with patch.dict(sys.modules, {"dkim": fake}):
            r = verify_dkim(b"test", lambda _: "not bytes")
        self.assertEqual(r["status"], "indeterminate")


if __name__ == "__main__":
    unittest.main()
