# Security Policy

Delegent Core is pre-alpha and not yet approved for public release.

## Scope

This repository covers the open-core proof vocabulary and dependency-free local
reference validation for delegated AI-agent authority.

In scope:

- proof and validation contract defects;
- validation behavior that allows the wrong audience, project, session, action,
  delegation, sender constraint, freshness window, revocation state, or replay
  state;
- audit event fields that hide or misrepresent validation outcomes;
- examples or docs that encourage raw sensitive payloads inside proofs or logs;
- public-boundary failures, such as private strategy or downstream product
  coupling entering this repository.

Out of scope:

- production key management;
- hosted policy services;
- persistent replay or revocation infrastructure;
- enterprise admin UI, governance workflows, integrations, and evidence export;
- claims that the local HMAC test implementation is production cryptography.

## Reporting

Please report security vulnerabilities using GitHub's private vulnerability
reporting flow for this repository. Do not open public issues for suspected
vulnerabilities, and do not include secrets, raw customer data, private
payloads, or live credentials in reports.

Before the first public release, this repository remains private. Security
issues are handled through the private project-management repository or private
repository issue process configured for the project.

## Current Guarantees

The current implementation is a reference implementation for contracts, demos,
and conformance tests. It is not a production authorization service.

The validator is expected to fail closed when required dependency state is
unavailable. If validation cannot prove a grant is current, audience-bound,
session-bound, sender-constrained, allowed for the requested action, and not
replayed, the safe result is deny or error-fail-closed.
