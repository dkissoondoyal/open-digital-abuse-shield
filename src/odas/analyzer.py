"""Conservative offline analysis of untrusted RFC 5322 email headers.

This module does not verify SPF, DKIM, DMARC or ARC. Authentication-Results
headers are merely reported as untrusted claims unless supplied by a trusted
mail gateway in a future integration.
"""
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import json
import sys

MAX_BYTES = 256_000


def analyze(data: bytes) -> dict:
    if len(data) > MAX_BYTES:
        raise ValueError('Input exceeds 256 KB limit')
    msg = BytesParser(policy=policy.default).parsebytes(data, headersonly=True)
    from_headers = msg.get_all('From', [])
    reply_headers = msg.get_all('Reply-To', [])
    findings = []
    if len(from_headers) != 1:
        findings.append({'code': 'FROM_COUNT', 'severity': 'review',
                         'detail': 'Expected exactly one From header'})
    if len(reply_headers) > 1:
        findings.append({'code': 'REPLY_TO_COUNT', 'severity': 'review',
                         'detail': 'Multiple Reply-To headers require review'})
    if from_headers and reply_headers:
        sender = parseaddr(str(from_headers[0]))[1]
        reply = parseaddr(str(reply_headers[0]))[1]
        if sender and reply and sender.lower() != reply.lower():
            findings.append({'code': 'REPLY_TO_DIFFERS', 'severity': 'info',
                             'detail': 'Reply-To differs from From; often legitimate'})
    if msg.defects:
        findings.append({'code': 'PARSER_DEFECT', 'severity': 'review',
                         'detail': 'Malformed header syntax detected'})
    auth_headers = msg.get_all('Authentication-Results', [])
    return {
        'version': '0.1.0', 'mode': 'offline-observation-only',
        'decision': 'no-blocking-decision',
        'authentication_results_claims_present': bool(auth_headers),
        'authentication_results_trusted': False,
        'findings': findings,
        'limitations': [
            'No DNS lookups or cryptographic authentication performed',
            'Authentication-Results may be forged in submitted input',
            'No finding establishes malicious intent',
            'No automatic delivery or rejection decisions',
        ],
    }


def main():
    if len(sys.argv) != 2:
        print('Usage: python -m odas.analyzer path/to/headers.txt', file=sys.stderr)
        return 2
    try:
        with open(sys.argv[1], 'rb') as handle:
            data = handle.read(MAX_BYTES + 1)
        print(json.dumps(analyze(data), indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
