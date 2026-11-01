"""Integration regression tests for shared DNS lookup budgets (offline only)."""
import sys
import types
import unittest
from unittest.mock import patch

from odas.dkim_verify import verify_dkim
from odas.dkim_multi import verify_dkim_signatures


MESSAGE = (
    b"From: a@example.org\r\n"
    b"DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=test; b=abc; bh=abc\r\n"
    b"DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=other; b=def; bh=def\r\n"
    b"\r\nbody\r\n"
)


class DNSBudgetIntegrationTests(unittest.TestCase):
    def test_single_verifier_budget_exhaustion_is_indeterminate(self):
        class Fake:
            @staticmethod
            def verify(message, dnsfunc, **kwargs):
                for _ in range(11):
                    try:
                        dnsfunc(b"test._domainkey.example.org")
                    except Exception:
                        pass
                return True

        with patch.dict(sys.modules, {"dkim": types.SimpleNamespace(verify=Fake.verify)}):
            result = verify_dkim(MESSAGE, lambda _: b"key")
        self.assertEqual(result["status"], "indeterminate")
        self.assertEqual(result["decision"], "no-blocking-decision")

    def test_multi_verifier_shares_budget_across_signatures(self):
        class FakeDKIM:
            def __init__(self, message):
                pass

            def verify(self, *, idx, dnsfunc):
                for _ in range(6):
                    try:
                        dnsfunc(b"test._domainkey.example.org")
                    except Exception:
                        pass
                return True

        with patch.dict(sys.modules, {"dkim": types.SimpleNamespace(DKIM=FakeDKIM)}):
            result = verify_dkim_signatures(MESSAGE, lambda _: b"key")
        self.assertEqual(result["signatures"][0]["status"], "pass")
        self.assertEqual(result["signatures"][1]["status"], "indeterminate")
        self.assertEqual(result["decision"], "no-blocking-decision")

    def test_single_verifier_oversized_dns_result_is_indeterminate(self):
        def fake_verify(message, dnsfunc, **kwargs):
            dnsfunc(b"test._domainkey.example.org")
            return True

        with patch.dict(sys.modules, {"dkim": types.SimpleNamespace(verify=fake_verify)}):
            result = verify_dkim(MESSAGE, lambda _: b"x" * 8193)
        self.assertEqual(result["status"], "indeterminate")


if __name__ == "__main__":
    unittest.main()
