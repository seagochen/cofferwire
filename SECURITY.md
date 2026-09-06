# Security Policy

## Current status

Cofferwire is pre-1.0 and has not received an external security review (that review, and resolving its findings, is a version 1.0 release gate -- see `TESTING.md` section 12 and issue #27). Do not use it to protect sensitive or irreplaceable data.

## Supported versions

There is no released version yet. Only the current `develop` branch HEAD receives fixes; there is no compatibility or backport commitment to any older commit or tag. This will be revisited once a 1.0 release exists.

## Reporting a vulnerability

Email **xiantong.chen.2023@gmail.com** with the affected specification or implementation version (a commit hash is sufficient before a tagged release), impact, reproduction steps and any suggested mitigation. GitHub private vulnerability reporting for this repository is also accepted for reporters who prefer it; both reach the same maintainer. Do not open a public issue for an unpatched vulnerability, and do not include real user data, production credentials or private keys in a report.

## Response targets

These are targets for a pre-1.0, single-maintainer project, not contractual guarantees:

- **Acknowledgment:** within 5 business days of the report.
- **Initial severity assessment:** within 14 days of acknowledgment.
- **Fix or mitigation:** critical/high-severity findings are targeted within 30 days of confirmed severity; medium/low findings are handled best-effort and tracked once a fix is available.
- Coordinated disclosure: the reporter and maintainer agree on a disclosure date once a fix or mitigation exists; absent agreement, the default is disclosure once the fix ships.

## Security claims

Security claims must cite the applicable threat-model section and protocol version. End-to-end encryption does not automatically hide IP addresses, timing, message sizes, queue access patterns or blob access correlation. `spec/02-threat-model.md` states the general assumptions and limits; `spec/11-security-considerations.md` states the concrete bounded-work-before-authentication, rate-limiting and secret-redaction contract; `spec/12-privacy-considerations.md` states the concrete per-profile relay-observable metadata catalog.

