import unittest
from odas.analyzer import analyze


class AnalyzerTests(unittest.TestCase):
    def test_normal_message_not_blocked(self):
        result = analyze(b'From: Alice <alice@example.org>\nTo: Bob <bob@example.net>\nSubject: Hi\n\n')
        self.assertEqual(result['decision'], 'no-blocking-decision')
        self.assertEqual(result['findings'], [])

    def test_missing_from_is_review_only(self):
        result = analyze(b'To: Bob <bob@example.net>\n\n')
        self.assertEqual(result['findings'][0]['code'], 'FROM_COUNT')
        self.assertEqual(result['decision'], 'no-blocking-decision')

    def test_untrusted_authentication_results(self):
        result = analyze(b'From: a@example.org\nAuthentication-Results: attacker.invalid; dkim=pass\n\n')
        self.assertFalse(result['authentication_results_trusted'])

    def test_different_reply_to_is_informational(self):
        result = analyze(b'From: a@example.org\nReply-To: help@example.net\n\n')
        self.assertEqual(result['findings'][0]['severity'], 'info')

    def test_input_limit(self):
        with self.assertRaises(ValueError):
            analyze(b'x' * 256001)


if __name__ == '__main__':
    unittest.main()
