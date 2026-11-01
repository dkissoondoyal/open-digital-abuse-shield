"""Bounded DNS TXT callback for experimental DKIM observations.

This wrapper limits calls and response sizes, but does NOT enforce wall-clock
timeouts or establish DNS transport authenticity. The caller remains responsible
for resolver deadlines, DNSSEC policy, caching and network access.
"""
from collections.abc import Callable


class DNSBudgetExceeded(RuntimeError):
    """A lookup exceeded the configured resource budget."""


def bounded_dns_txt_lookup(callback: Callable, *, max_lookups: int = 10,
                           max_response_bytes: int = 8192):
    """Return a callback enforcing a cumulative lookup and response budget.

    The returned callback is intended to be created once per message and shared
    by all signature verifications. Never reuse it across unrelated messages.
    """
    if not callable(callback):
        raise ValueError("DNS callback required")
    if type(max_lookups) is not int or not 1 <= max_lookups <= 100:
        raise ValueError("Invalid lookup budget")
    if type(max_response_bytes) is not int or not 1 <= max_response_bytes <= 65535:
        raise ValueError("Invalid response budget")
    calls = 0

    def lookup(name: bytes, **_kwargs):
        nonlocal calls
        if not isinstance(name, bytes) or not 0 < len(name) <= 255:
            raise ValueError("Invalid DNS lookup name")
        if b"\x00" in name or any(c < 33 or c > 126 for c in name):
            raise ValueError("Invalid DNS lookup name")
        if calls >= max_lookups:
            raise DNSBudgetExceeded("DNS lookup budget exhausted")
        calls += 1
        result = callback(name)
        if result is not None and (
            not isinstance(result, bytes) or len(result) > max_response_bytes
        ):
            raise DNSBudgetExceeded("DNS response budget exceeded")
        return result

    return lookup
