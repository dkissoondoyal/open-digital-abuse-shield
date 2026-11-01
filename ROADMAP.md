# ODAS Roadmap

## Design constraints
- Never trust an externally supplied Authentication-Results header.
- Do not equate SPF, DKIM or DMARC failure with malicious intent.
- Protect forwarding, mailing lists and other legitimate workflows.
- Avoid central collection of message bodies or personal information.
- Make all security actions reversible and auditable where possible.
- Measure false-positive rates before enforcing any automated block.

## Phase 1 (v0.1)
Local, dependency-free observation-only prototype, tests and documentation.

## Phase 2
Trusted gateway ingestion, independently verified authentication outcomes, synthetic fixtures and evaluation dataset.

## Phase 3
Cryptographically signed indicator feeds, source provenance, expiry, validation, rollback and abuse reporting governance.

## Phase 4
Opt-in pilot in shadow mode, documented accuracy metrics, user notice and appeal processes.

## Phase 5
Optional quarantine, manual release, operator controls and narrowly scoped enforcement after review.
