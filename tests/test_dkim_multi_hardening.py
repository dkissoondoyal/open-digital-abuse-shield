"""Conservative DKIM boundary regression tests (no live DNS)."""
import unittest
from unittest.mock import patch
import types
import sys

from odas.dkim_multi import verify_dkim_signatures

MESSAGE = (b"From: a@example.org\r\n"
           b"DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=test; b=abc; bh=abc\r\n"
           b"\r\nbody\r\n")


class DKIMBoundaryTests(unittest.TestCase):
    def test_missing_separator_indeterminate(self):
        result = verify_dkim_signatures(b"From: a@example.org\r\n", lambda _: b"key")
        self.assertEqual(result["status"], "indeterminate")
        self.assertEqual(result["decision"], "no-blocking-decision")

    def test_invalid_dns_name_is_indeterminate(self):
        class FakeDKIM:
            def __init__(self, message):
                pass
            def verify(self, *, idx, dnsfunc):
                dnsfunc(b"x" * 256)
                return True
        with patch.dict(sys.modules, {"dkim": types.SimpleNamespace(DKIM=FakeDKIM)}):
            result = verify_dkim_signatures(MESSAGE, lambda _: b"key")
        self.assertEqual(result["signatures"][0]["status"], "indeterminate")
        self.assertEqual(result["decision"], "no-blocking-decision")

    def test_invalid_dns_txt_is_indeterminate(self):
        class FakeDKIM:
            def __init__(self, message):
                pass
            def verify(self, *, idx, dnsfunc):
                dnsfunc(b"test._domainkey.example.org")
                return True
        with patch.dict(sys.modules, {"dkim": types.SimpleNamespace(DKIM=FakeDKIM)}):
            result = verify_dkim_signatures(MESSAGE, lambda _: b"x" * 65536)
        self.assertEqual(result["signatures"][0]["status"], "indeterminate")
        self.assertEqual(result["decision"], "no-blocking-decision")


if __name__ == "__main__":
    unittest.main()
