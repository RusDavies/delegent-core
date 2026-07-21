# Security Policy

Delegent Core is public pre-alpha open-core work.

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

This repository is public, but it has not had a package-publication or
supported-version release. Security issues may also be coordinated through the
private project-management repository when they involve non-public planning,
commercial implementation, or sensitive operational context.

## Supported Versions

Delegent Core has no supported public package versions before its first package
publication release.

The current `0.1.0` package metadata is pre-alpha and exists for contract
development, local examples, and verification work. A public supported-version
policy must be reviewed and updated before package publication.

## Current Guarantees

The current implementation is a reference implementation for contracts, demos,
and conformance tests. It is not a production authorization service.

The validator is expected to fail closed when required dependency state is
unavailable. If validation cannot prove a grant is current, audience-bound,
session-bound, sender-constrained, allowed for the requested action, and not
replayed, the safe result is deny or error-fail-closed.
