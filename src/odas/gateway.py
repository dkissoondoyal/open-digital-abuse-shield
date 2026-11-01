"""Experimental authenticated, message-bound gateway evidence.

This is a local verification primitive, NOT a deployed gateway integration.
The caller supplies trusted gateway keys through private configuration, never
through email headers or the submitted evidence envelope.
"""
import hashlib
import hmac
import json
from collections.abc import Mapping

from odas.auth_evidence import evaluate_gateway_evidence

MAX_ENVELOPE_BYTES = 8192
MAX_MESSAGE_BYTES = 256000


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def verify_gateway_envelope(message: bytes, envelope: bytes, trusted_keys: Mapping):
    """Validate authenticated evidence bound to the exact message bytes.

    Envelope JSON fields: gateway_id, message_sha256, results, mac.
    mac = hex(HMAC-SHA256(key, canonical JSON of all fields except mac)).
    Returns observation-only results. No replay prevention is provided.
    """
    if not isinstance(message, bytes) or len(message) > MAX_MESSAGE_BYTES:
        raise ValueError("Invalid message bytes or size")
    if not isinstance(envelope, bytes) or len(envelope) > MAX_ENVELOPE_BYTES:
        raise ValueError("Invalid envelope bytes or size")
    def unique_pairs(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError("Duplicate JSON field")
            result[k] = v
        return result
    try:
        obj = json.loads(envelope.decode("utf-8"), object_pairs_hook=unique_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite number")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Malformed evidence envelope") from exc
    if not isinstance(obj, dict) or set(obj) != {"gateway_id", "message_sha256", "results", "mac"}:
        raise ValueError("Invalid envelope schema")
    gateway_id, digest, mac = obj["gateway_id"], obj["message_sha256"], obj["mac"]
    if not isinstance(gateway_id, str) or not gateway_id or len(gateway_id) > 128:
        raise ValueError("Invalid gateway ID")
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("Invalid message digest")
    if not isinstance(mac, str) or len(mac) != 64 or any(c not in "0123456789abcdef" for c in mac):
        raise ValueError("Invalid MAC")
    key = trusted_keys.get(gateway_id)
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("Unknown gateway or invalid configured key")
    payload = {k: v for k, v in obj.items() if k != "mac"}
    expected = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("Invalid gateway signature")
    if not hmac.compare_digest(digest, hashlib.sha256(message).hexdigest()):
        raise ValueError("Evidence does not match message")
    observation = evaluate_gateway_evidence(obj["results"], trusted_gateway=True)
    observation["gateway_id"] = gateway_id
    observation["message_bound"] = True
    observation["authentication_method"] = "hmac-sha256"
    observation["replay_protected"] = False
    return observation
