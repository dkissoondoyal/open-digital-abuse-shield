"""Adversarial DKIM signing-domain disclosure tests (no live DNS).

A mocked crypto verifier tests the reporting boundary only; it is not proof
that dkimpy would accept a malformed signature.
"""
import sys
import types
import unittest
from unittest.mock import patch

from odas.dkim_multi import verify_dkim_signatures


class SigningDomainDisclosureTests(unittest.TestCase):
    def observe(self, signature):
        message = b"From: a@example.org\r\nDKIM-Signature: " + signature + b"\r\n\r\nbody"
        class FakeDKIM:
            def __init__(self, message):
                pass
            def verify(self, *, idx, dnsfunc):
                return True
        with patch.dict(sys.modules, {"dkim": types.SimpleNamespace(DKIM=FakeDKIM)}):
            return verify_dkim_signatures(message, lambda _: b"key")

    def test_duplicate_signing_domains_are_not_reported(self):
        result = self.observe(b"v=1; d=good.example; s=x; d=evil.example; b=x")
        self.assertEqual(result["decision"], "no-blocking-decision")
        self.assertNotIn("signing_domain", result["signatures"][0])

    def test_folded_single_signing_domain_is_reported(self):
        result = self.observe(b"v=1;\r\n d=EXAMPLE.org; s=x; b=x")
        self.assertEqual(result["signatures"][0].get("signing_domain"), "example.org")
        self.assertEqual(result["decision"], "no-blocking-decision")

    def test_malformed_signing_domain_not_reported(self):
        result = self.observe(b"v=1; d=example.org evil.test; s=x; b=x")
        self.assertNotIn("signing_domain", result["signatures"][0])


if __name__ == "__main__":
    unittest.main()
