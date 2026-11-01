# Open Digital Abuse Shield (ODAS)

Open-source, privacy-preserving email and DNS abuse detection with proactive protection and minimal false positives.

## Mission

Protect users against email and domain-related abuse while preserving legitimate communication. ODAS is an independent community project and is not affiliated with ICANN.

## Initial scope

Version 0.1 focuses on offline email-header analysis and explainable findings. It does **not** intercept live mail or automatically reject messages. SPF, DKIM, DMARC and ARC verification require trustworthy authentication results and/or appropriate DNS and cryptographic checks; suspicious-looking headers alone are not proof of abuse.

## Principles

- Privacy by design and data minimisation
- No automatic blocking based solely on a risk score
- Explainable, reviewable decisions and false-positive correction
- Signed and validated threat intelligence updates in future phases
- Independent testing before deployment

## Status

Early prototype / initial repository setup. Code, tests, security policy and roadmap will be added as part of the first development milestone.

## Licence

Apache-2.0 planned for the project source code.
