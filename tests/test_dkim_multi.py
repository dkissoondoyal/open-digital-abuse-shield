import unittest
from unittest.mock import patch
import sys
import types
from odas.dkim_multi import verify_dkim_signatures


class MultipleSignatureTests(unittest.TestCase):
    def test_no_signatures_is_indeterminate(self):
        r = verify_dkim_signatures(b"From: a@example.org\r\n\r\nHello", lambda _: None)
        self.assertEqual(r["status"], "indeterminate")
        self.assertEqual(r["decision"], "no-blocking-decision")

    def test_signature_limit(self):
        headers = b"DKIM-Signature: v=1; d=example.org; s=test; b=x\r\n" * 3
        r = verify_dkim_signatures(headers + b"\r\nBody", lambda _: None, max_signatures=2)
        self.assertEqual(r["status"], "indeterminate")

    def test_validated_signing_domain_only(self):
        message = (b"DKIM-Signature: v=1; d=example.org; s=test; b=x\r\n"
                   b"DKIM-Signature: v=1; d=evil.test; s=test; b=y\r\n\r\nBody")
        class FakeDKIM:
            count = 0
            def __init__(self, _message):
                pass
            def verify(self, *, idx, dnsfunc):
                return idx == 0
        with patch.dict(sys.modules, {"dkim": types.SimpleNamespace(DKIM=FakeDKIM)}):
            r = verify_dkim_signatures(message, lambda _: None)
        self.assertEqual(r["status"], "pass")
        self.assertEqual(r["signatures"][0]["signing_domain"], "example.org")
        self.assertNotIn("signing_domain", r["signatures"][1])

    def test_dns_error_indeterminate(self):
        message = b"DKIM-Signature: v=1; d=example.org; s=test; b=x\r\n\r\nBody"
        class FakeDKIM:
            def __init__(self, _message):
                pass
            def verify(self, *, idx, dnsfunc):
                try:
                    dnsfunc(b"test._domainkey.example.org")
                except TimeoutError:
                    return False
        with patch("dkim.DKIM", FakeDKIM):
            r = verify_dkim_signatures(message, lambda _: (_ for _ in ()).throw(TimeoutError()))
        self.assertEqual(r["signatures"][0]["status"], "indeterminate")


if __name__ == "__main__":
    unittest.main()
