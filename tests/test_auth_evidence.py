import unittest
from odas.auth_evidence import evaluate_gateway_evidence


class GatewayEvidenceTests(unittest.TestCase):
    def test_untrusted_forged_pass_ignored(self):
        r = evaluate_gateway_evidence({"dmarc": "pass"})
        self.assertFalse(r["trusted"])
        self.assertEqual(r["findings"], [])

    def test_fail_never_blocks(self):
        r = evaluate_gateway_evidence({"dmarc": "fail"}, trusted_gateway=True)
        self.assertEqual(r["decision"], "no-blocking-decision")
        self.assertEqual(r["findings"][0]["severity"], "review")

    def test_pass_not_proof_of_safety(self):
        r = evaluate_gateway_evidence({"spf": "pass"}, trusted_gateway=True)
        self.assertIn("not proof of safety", r["findings"][0]["detail"])

    def test_forwarding_failure_review_only(self):
        r = evaluate_gateway_evidence({"spf": "fail", "dkim": "pass", "dmarc": "pass"},
                                      trusted_gateway=True)
        self.assertEqual(r["decision"], "no-blocking-decision")

    def test_malformed_results_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_gateway_evidence({"dmarc": "definitely-pass"}, trusted_gateway=True)

    def test_unknown_methods_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_gateway_evidence({"fake": "pass"}, trusted_gateway=True)

    def test_untrusted_input_not_parsed(self):
        r = evaluate_gateway_evidence("forged evidence", trusted_gateway=False)
        self.assertFalse(r["trusted"])


if __name__ == "__main__":
    unittest.main()
