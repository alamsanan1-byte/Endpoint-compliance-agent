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
