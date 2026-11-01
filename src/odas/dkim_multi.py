"""Experimental multi-signature DKIM observations, never an enforcement decision.

Each signature is verified independently using dkimpy's indexed verifier.
Identity is reported only for successfully verified signatures. Domain
alignment with RFC5322.From is deliberately NOT asserted here.
"""
from email.parser import BytesHeaderParser
from email.policy import default
import re

from odas.dkim_verify import verify_dkim, MAX_MESSAGE_BYTES


def verify_dkim_signatures(message: bytes, dns_txt_lookup, *, max_signatures=10):
    if not isinstance(message, bytes) or len(message) > MAX_MESSAGE_BYTES:
        raise ValueError("Invalid message")
    if not callable(dns_txt_lookup):
        raise ValueError("DNS callback required")
    if type(max_signatures) is not int or not 1 <= max_signatures <= 20:
        raise ValueError("Invalid signature limit")
    if b"\r
\r
" not in message:
        return {"method": "dkim", "status": "indeterminate",
                "reason": "missing-header-body-separator", "decision": "no-blocking-decision"}
    header = message.split(b"\r
\r
", 1)[0]
    if b"
" in header.replace(b"\r
", b""):
        raise ValueError("Non-CRLF header format")
    # Only header section is parsed; no message body is logged or returned.
    parsed = BytesHeaderParser(policy=default).parsebytes(header + b"\r
\r
")
    if parsed.defects or any(getattr(v, "defects", ()) for v in parsed.values()):
        return {"method": "dkim", "status": "indeterminate",
                "reason": "malformed-headers", "decision": "no-blocking-decision"}
    values = parsed.get_all("DKIM-Signature", [])
    if len(values) > max_signatures:
        return {"method": "dkim", "status": "indeterminate",
                "reason": "signature-limit-exceeded", "decision": "no-blocking-decision"}
    if not values:
        return {"method": "dkim", "signatures": [], "status": "indeterminate",
                "decision": "no-blocking-decision", "warning": "No DKIM signatures"}
    try:
        import dkim
    except ImportError as exc:
        raise RuntimeError("Optional dkimpy dependency is not installed") from exc
    observations = []
    for index, value in enumerate(values):
        dns_error = False
        def lookup(name, **kwargs):
            nonlocal dns_error
            try:
                if not isinstance(name, bytes) or not 0 < len(name) <= 255:
                    dns_error = True
                    raise ValueError("Invalid DNS lookup name")
                value = dns_txt_lookup(name)
                if value is not None and (not isinstance(value, bytes) or len(value) > 65535):
                    dns_error = True
                    raise ValueError("Invalid DNS TXT result")
                return value
            except Exception:
                dns_error = True
                raise
        try:
            verified = bool(dkim.DKIM(message).verify(idx=index, dnsfunc=lookup))
            status = "indeterminate" if dns_error else ("pass" if verified else "fail")
        except Exception:
            status = "indeterminate"
        item = {"index": index, "status": status}
        if status == "pass":
            match = re.search(r"(?:^|;)\s*d\s*=\s*([A-Za-z0-9_.-]+)\s*(?:;|$)", str(value), re.I)
            if match:
                item["signing_domain"] = match.group(1).lower()
        observations.append(item)
    return {"method": "dkim", "signatures": observations,
            "status": ("pass" if any(x["status"] == "pass" for x in observations)
                       else "indeterminate" if not observations or any(x["status"] == "indeterminate" for x in observations)
                       else "fail"),
            "decision": "no-blocking-decision",
            "warning": "Signing domain is not From-domain alignment or sender identity"}
