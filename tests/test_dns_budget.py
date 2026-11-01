"""Offline regression tests for bounded DKIM DNS lookups."""
import unittest

from odas.dns_budget import DNSBudgetExceeded, bounded_dns_txt_lookup


class DNSBudgetTests(unittest.TestCase):
    def test_two_calls_then_exhausted(self):
        seen = []
        lookup = bounded_dns_txt_lookup(lambda name: seen.append(name) or b"key", max_lookups=2)
        self.assertEqual(lookup(b"a.example.org"), b"key")
        self.assertEqual(lookup(b"b.example.org"), b"key")
        with self.assertRaises(DNSBudgetExceeded):
            lookup(b"c.example.org")
        self.assertEqual(len(seen), 2)

    def test_oversized_response(self):
        lookup = bounded_dns_txt_lookup(lambda _: b"x" * 9, max_response_bytes=8)
        with self.assertRaises(DNSBudgetExceeded):
            lookup(b"a.example.org")

    def test_invalid_name_never_calls_resolver(self):
        seen = []
        lookup = bounded_dns_txt_lookup(lambda name: seen.append(name))
        for name in (b"", b"bad\x00name", b"bad\nname", b"x" * 256):
            with self.assertRaises(ValueError):
                lookup(name)
        self.assertEqual(seen, [])

    def test_invalid_configuration(self):
        for value in (0, -1, True, 101):
            with self.assertRaises(ValueError):
                bounded_dns_txt_lookup(lambda _: None, max_lookups=value)

    def test_none_is_allowed(self):
        self.assertIsNone(bounded_dns_txt_lookup(lambda _: None)(b"a.example.org"))


if __name__ == "__main__":
    unittest.main()
