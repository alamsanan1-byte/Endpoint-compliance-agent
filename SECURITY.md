# Security Policy

## Project Scope

This repository is a portfolio and lab project for endpoint compliance monitoring. It is not intended for direct production deployment without additional hardening.

## Data Handling

Only synthetic or lab-generated data should be committed.

Do not commit:

- employer or client endpoint data
- real employee usernames or identities
- production hostnames
- API keys
- passwords
- certificates or private keys
- access tokens
- internal IP addressing from real organisations
- proprietary policy files

## Secrets

Secrets should be provided through environment variables or an appropriate secret-management system. A `.env` file must never be committed.

Use `.env.example` to document required variables without supplying secret values.

## Threats Considered

A production version of this architecture would need to address threats including:

- forged endpoint reports
- replayed reports
- unauthorised report submission
- compromised endpoint agents
- policy tampering
- collector compromise
- credential leakage
- denial of service
- insecure transport
- excessive dashboard privileges

## Production Hardening Ideas

Potential controls include:

- mutual TLS between agents and the collector
- unique device identities
- report signing
- timestamp and nonce validation
- rate limiting
- central secrets management
- role-based access control
- audit logging for policy changes
- database encryption and backup controls
- centrally managed agent deployment and updates

## Reporting Security Issues

This is a personal portfolio repository. If a security issue is found in the project, open a GitHub issue with enough detail to reproduce it, but do not include real credentials, secrets or sensitive third-party information.

## Implemented lab safeguards (v1.0)

- Required Bearer authentication on ingestion and every data endpoint; a short/absent key prevents startup.
- Strict typed report and policy validation, bounded report bodies and timestamp freshness checks.
- SHA-256 report deduplication and chronological latest-state selection.
- Parameterized SQLite queries, per-transaction connections and persistent alert debounce.
- HTTPS for remote agent submissions and webhooks, verified certificates and disabled redirects.
- Dashboard data inserted with `textContent`, a restrictive Content Security Policy and no key persistence in browser storage.
- Non-root Docker process, loopback-only published port, dropped capabilities and a read-only root filesystem.
- No automated endpoint remediation, secret collection or network scanning.

A shared lab API key grants both read and submit access and can impersonate any device. Machine-ID hashing is pseudonymisation, not authentication. Report deduplication prevents accidental duplicates, not malicious signed-payload replay. Do not treat endpoint-supplied facts or operator-asserted exceptions as trusted attestation. There is no rate limiter or automatic database retention; put a hardened gateway in front of any remote lab deployment. Production use requires independent security review and the additional controls listed above.
