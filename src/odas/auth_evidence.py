"""Observation-only handling of independently supplied gateway authentication evidence.

IMPORTANT: Never derive trusted evidence from a message's Authentication-Results header.
Only an authenticated, configured gateway integration may supply this object.
This module does NOT independently verify SPF/DKIM/DMARC/ARC.
"""
from collections.abc import Mapping

RESULTS = frozenset({"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"})
METHODS = ("spf", "dkim", "dmarc", "arc")


def evaluate_gateway_evidence(evidence, *, trusted_gateway=False):
    """Return explainable observations; never an enforcement decision.

    trusted_gateway is an integration trust boundary, NOT a claim from email headers.
    Production integrations must authenticate gateway identity and bind evidence to
    the message being analysed before setting trusted_gateway=True.
    """
    if not trusted_gateway:
        return {"trusted": False, "decision": "no-blocking-decision",
                "findings": [], "status": "evidence-not-trusted"}
    if not isinstance(evidence, Mapping):
        raise ValueError("Trusted evidence must be a mapping")
    if set(evidence) - set(METHODS):
        raise ValueError("Unexpected authentication method")
    findings = []
    for method in METHODS:
        if method not in evidence:
            continue
        result = evidence[method]
        if not isinstance(result, str) or result not in RESULTS:
            raise ValueError("Invalid authentication result")
        if result in ("fail", "softfail", "permerror", "temperror"):
            findings.append({"code": method.upper() + "_RESULT",
                             "severity": "review",
                             "detail": method.upper() + " reported " + result +
                                       " by trusted gateway; not proof of abuse"})
        elif result == "pass":
            findings.append({"code": method.upper() + "_RESULT",
                             "severity": "info",
                             "detail": method.upper() + " reported pass by trusted gateway; not proof of safety"})
    return {"trusted": True, "decision": "no-blocking-decision",
            "status": "gateway-results-reported-not-independently-verified",
            "findings": findings}
