"""Real cryptographic DKIM integration tests, not mocks.

The test generates an ephemeral RSA key and a signed message at runtime,
then checks valid, tampered, and wrong-public-key verification.
Requires optional test dependencies: dkimpy and cryptography.
"""
import base64
import unittest

from odas.dkim_verify import verify_dkim

try:
    import dkim
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
except ImportError:
    dkim = None


@unittest.skipIf(dkim is None, "Install dkimpy and cryptography for crypto integration tests")
class RealDKIMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.private_pem = cls.private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption())
        public_der = cls.private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.dns_record = b"v=DKIM1; k=rsa; p=" + base64.b64encode(public_der)
        cls.message = (b"From: Test <sender@example.org>\r\n"
                       b"To: recipient@example.net\r\n"
                       b"Subject: ODAS integration test\r\n"
                       b"Date: Sun, 01 Nov 2026 08:00:00 +0000\r\n"
                       b"\r\n"
                       b"Original body for signature verification.\r\n")
        signature = dkim.sign(cls.message, b"test", b"example.org",
                              cls.private_pem, include_headers=[b"from", b"to", b"subject", b"date"])
        cls.signed = signature + cls.message

    def test_real_valid_signature(self):
        result = verify_dkim(self.signed, lambda _: self.dns_record)
        self.assertEqual(result["status"], "pass", result)
        self.assertEqual(result["decision"], "no-blocking-decision")

    def test_modified_body_fails(self):
        altered = self.signed.replace(b"Original body", b"Tampered body")
        result = verify_dkim(altered, lambda _: self.dns_record)
        self.assertEqual(result["status"], "fail", result)
        self.assertEqual(result["decision"], "no-blocking-decision")

    def test_wrong_public_key_fails(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_der = other.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        wrong_record = b"v=DKIM1; k=rsa; p=" + base64.b64encode(wrong_der)
        result = verify_dkim(self.signed, lambda _: wrong_record)
        self.assertEqual(result["status"], "fail", result)

    def test_dns_callback_error_is_indeterminate_even_if_library_returns_false(self):
        # Some verifier libraries may catch a DNS callback error and return False.
        # Our adapter must still report uncertainty, not a definitive fail.
        from unittest.mock import patch
        def swallowed_error(message, dnsfunc, **kwargs):
            try:
                dnsfunc(b"test._domainkey.example.org")
            except TimeoutError:
                return False
            return True
        with patch.object(dkim, "verify", swallowed_error):
            result = verify_dkim(self.signed, lambda _: (_ for _ in ()).throw(TimeoutError()))
        self.assertEqual(result["status"], "indeterminate", result)

    def test_dns_error_is_indeterminate(self):
        def timeout(_):
            raise TimeoutError("simulated DNS outage")
        result = verify_dkim(self.signed, timeout)
        self.assertEqual(result["status"], "indeterminate", result)


if __name__ == "__main__":
    unittest.main()
