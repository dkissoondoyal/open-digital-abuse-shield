"""Experimental replay-resistant, observation-only gateway evidence.

A signed outer envelope binds gateway ID, key ID, nonce, timestamp, exact
message digest and authentication results. SQLite atomically records consumed
nonces. This is NOT a live SMTP integration or an SPF/DKIM/DMARC verifier.
"""
import hashlib
import hmac
import json
import sqlite3
import time
from collections.abc import Mapping

from odas.auth_evidence import evaluate_gateway_evidence
from odas.gateway import canonical

MAX_ENVELOPE_BYTES = 8192
MAX_MESSAGE_BYTES = 256000
MAX_AGE_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 30


def _unique_pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("Duplicate JSON key")
        d[k] = v
    return d


def verify_fresh_evidence(message: bytes, envelope: bytes, trusted_keys: Mapping,
                          replay_db: str, *, now=None):
    """Verify authenticated evidence and atomically consume a gateway nonce.

    trusted_keys maps (gateway_id, key_id) to 32+-byte random secret keys.
    replay_db must be a protected persistent local SQLite database path.
    now is injectable for deterministic testing, not from untrusted input.
    """
    if not isinstance(message, bytes) or len(message) > MAX_MESSAGE_BYTES:
        raise ValueError("Invalid message")
    if not isinstance(envelope, bytes) or len(envelope) > MAX_ENVELOPE_BYTES:
        raise ValueError("Invalid envelope")
    if not isinstance(replay_db, str) or not replay_db or replay_db == ":memory:":
        raise ValueError("Persistent replay database required")
    try:
        obj = json.loads(envelope.decode("utf-8"), object_pairs_hook=_unique_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid number")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Malformed envelope") from exc
    if not isinstance(obj, dict) or set(obj) != {
            "gateway_id", "key_id", "nonce", "issued_at", "message_sha256", "results", "mac"}:
        raise ValueError("Invalid envelope fields")
    gateway_id, key_id, nonce = obj["gateway_id"], obj["key_id"], obj["nonce"]
    if any(not isinstance(v, str) or not 1 <= len(v) <= 128 or
           not all(c.isascii() and (c.isalnum() or c in "-_") for c in v)
           for v in (gateway_id, key_id)):
        raise ValueError("Invalid gateway or key ID")
    if not isinstance(nonce, str) or len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
        raise ValueError("Invalid nonce; require 128-bit random hex")
    issued_at = obj["issued_at"]
    if type(issued_at) is not int or issued_at < 0:
        raise ValueError("Invalid timestamp")
    current = int(time.time()) if now is None else now
    if type(current) is not int or current < 0:
        raise ValueError("Invalid verifier clock")
    if issued_at < current - MAX_AGE_SECONDS or issued_at > current + MAX_FUTURE_SKEW_SECONDS:
        raise ValueError("Expired or future evidence")
    digest, mac = obj["message_sha256"], obj["mac"]
    if any(not isinstance(v, str) or len(v) != 64 or
           any(c not in "0123456789abcdef" for c in v) for v in (digest, mac)):
        raise ValueError("Invalid digest or MAC")
    key = trusted_keys.get((gateway_id, key_id))
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("Unknown key")
    expected = hmac.new(key, canonical({k: v for k, v in obj.items() if k != "mac"}),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("Authentication failed")
    if not hmac.compare_digest(digest, hashlib.sha256(message).hexdigest()):
        raise ValueError("Message mismatch")
    # Validate results BEFORE consuming nonce.
    observation = evaluate_gateway_evidence(obj["results"], trusted_gateway=True)
    # BEGIN IMMEDIATE serialises concurrent writers; uniqueness prevents reuse.
    # No pruning: replay protection must not silently expire while old signed
    # envelopes might be accepted due to clock changes. Plan retention separately.
    with sqlite3.connect(replay_db, timeout=5) as db:
        db.execute("CREATE TABLE IF NOT EXISTS seen (gateway TEXT NOT NULL, nonce TEXT NOT NULL, "
                   "PRIMARY KEY (gateway, nonce))")
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("INSERT INTO seen (gateway, nonce) VALUES (?, ?)", (gateway_id, nonce))
            db.commit()
        except sqlite3.IntegrityError as exc:
            db.rollback()
            raise ValueError("Replay detected") from exc
    observation.update({"gateway_id": gateway_id, "key_id": key_id,
                        "message_bound": True, "replay_protected": True,
                        "decision": "no-blocking-decision"})
    return observation
