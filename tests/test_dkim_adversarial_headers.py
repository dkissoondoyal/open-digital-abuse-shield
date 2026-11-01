"""Offline adversarial header regressions for experimental DKIM observations."""
import unittest

from odas.dkim_multi import verify_dkim_signatures


SIGNATURE = b"DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=test; b=x; bh=y\r\n"


class AdversarialHeaderTests(unittest.TestCase):
    def assert_uncertain(self, message, reason):
        result = verify_dkim_signatures(message, lambda _: b"key")
        self.assertEqual(result["status"], "indeterminate")
        self.assertEqual(result["reason"], reason)
        self.assertEqual(result["decision"], "no-blocking-decision")

    def test_duplicate_from_is_not_treated_as_authenticated_identity(self):
        self.assert_uncertain(
            b"From: a@example.org\r\nFrom: b@evil.test\r\n" + SIGNATURE + b"\r\nbody",
            "duplicate-from-header",
        )

    def test_oversized_header_is_indeterminate(self):
        self.assert_uncertain(
            b"X-Padding: " + b"a" * 65536 + b"\r\n" + SIGNATURE + b"\r\nbody",
            "header-size-limit-exceeded",
        )

    def test_bare_carriage_return_is_indeterminate(self):
        self.assert_uncertain(
            b"From: a@example.org\rX-Test: unexpected\r\n" + SIGNATURE + b"\r\nbody",
            "malformed-headers",
        )


if __name__ == "__main__":
    unittest.main()
