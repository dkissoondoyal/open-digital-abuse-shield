"""Experimental offline DKIM verification using an explicit trusted DNS-key provider.

Install optional dependency: pip install 'dkimpy>=1.1,<2'
No network access is performed by this module: the caller supplies a DNS
resolver callback, which must enforce its own DNSSEC/transport/cache policy.
DKIM pass is NOT proof that a message is safe, and fail is NOT proof of abuse.
"""
from collections.abc import Callable
from odas.dns_budget import bounded_dns_txt_lookup

MAX_MESSAGE_BYTES = 256000


def verify_dkim(message: bytes, dns_txt_lookup: Callable, *, timeout_seconds=5):
    """Verify one DKIM signature cryptographically; never block email.

    dns_txt_lookup(name: bytes) -> bytes | None supplies DNS TXT bytes.
    This function delegates signature parsing and crypto to dkimpy.
    A production adapter must handle DNS resolution limits, multiple
    signatures, timeouts and trust boundaries explicitly.
    """
    if not isinstance(message, bytes) or len(message) > MAX_MESSAGE_BYTES:
        raise ValueError("Invalid message or message too large")
    if not callable(dns_txt_lookup):
        raise ValueError("DNS lookup callback required")
    if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) or not 0 < timeout_seconds <= 30:
        raise ValueError("Invalid timeout")
    try:
        import dkim
    except ImportError as exc:
        raise RuntimeError("Optional dkimpy dependency is not installed") from exc

    def lookup(name, **_kwargs):
        if not isinstance(name, bytes) or len(name) > 255:
            raise ValueError("Invalid DNS lookup name")
        value = bounded_lookup(name)
        if value is not None and (not isinstance(value, bytes) or len(value) > 65535):
            raise ValueError("Invalid DNS TXT result")
        return value

    bounded_lookup = bounded_dns_txt_lookup(dns_txt_lookup)
    dns_uncertain = False

    def tracked_lookup(name, **kwargs):
        nonlocal dns_uncertain
        try:
            return lookup(name, **kwargs)
        except Exception:
            dns_uncertain = True
            raise

    try:
        verified = bool(dkim.verify(message, dnsfunc=tracked_lookup, timeout=timeout_seconds))
    except Exception as exc:
        # Preserve uncertainty; do not convert DNS errors to definitive failures.
        return {"status": "indeterminate", "method": "dkim",
                "reason": type(exc).__name__, "decision": "no-blocking-decision"}
    if dns_uncertain:
        return {"status": "indeterminate", "method": "dkim",
                "reason": "dns-lookup-error", "decision": "no-blocking-decision"}
    return {"status": "pass" if verified else "fail", "method": "dkim",
            "decision": "no-blocking-decision",
            "caution": "DKIM outcome alone is neither proof of safety nor proof of abuse"}
