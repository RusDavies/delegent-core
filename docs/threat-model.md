# Delegent Core Threat Model

## Purpose

Delegent Core defines and verifies portable delegated-authority proofs for AI
agents. Its job is to let a relying product answer one narrow question:

> Does this specific agent action present valid scoped proof right now?

Delegent Core is not a general identity provider, secrets manager, production
policy service, admin console, or enterprise evidence platform.

## Protected Assets

- authority grants and their claims;
- sender-constrained proof material;
- replay handles and replay state;
- revocation status references and outcomes;
- policy and attestation references;
- validation decisions, reason codes, and audit event records;
- relying-product trust in the validator result.

## Trust Boundaries

- Issuer to presenter: a grant may be copied, replayed, expired, revoked, or
  altered after issue.
- Presenter to relying product: the relying product must treat presented proofs
  as untrusted until validation succeeds.
- Validator to dependency state: revocation, replay, policy, and attestation
  dependencies may be stale or unavailable.
- Audit output to operators: logs must explain decisions without embedding raw
  sensitive payloads.

## Core Threats

### Forged Or Altered Grants

Attackers may alter grant claims, forge signatures, change audiences, widen
actions, or change session/project binding.

Required behavior: reject malformed grants, wrong grant profiles, bad
signatures, wrong audiences, wrong projects, wrong sessions, and actions outside
the grant.

### Replay

Attackers may reuse a valid proof after it has already authorized an action.

Required behavior: bind replay handles to grants and reject repeated use when
the replay store reports prior use.

### Sender Constraint Bypass

Attackers may present a stolen grant without proving possession of the expected
sender constraint.

Required behavior: require the sender proof to match the grant's
`sender_constraint_id`, request method, URL, grant hash, replay handle, and
timestamp.

### Expiry And Freshness Failure

Attackers may present expired grants or grants before their validity window.

Required behavior: reject expired grants and grants that are not yet valid.

### Revocation Or Dependency Failure

Attackers may rely on stale revocation state, unavailable stores, or ambiguous
dependency responses.

Required behavior: deny revoked, denied, or expired grants; fail closed when
required dependency state is unknown or unavailable.

### Confused Deputy

A valid grant for one relying product, project, session, or action may be sent
to another relying product or endpoint.

Required behavior: validate audience, project, session, action, purpose, and
sender proof against the current request, not only against the grant.

### Sensitive Payload Leakage

Callers may include raw private content inside proof objects or audit records.

Required behavior: reject raw payloads in validation requests and prefer opaque
payload references, hashes, policy references, and audit metadata.

## Non-Goals

- production cryptographic key storage;
- hosted multi-tenant policy operations;
- enterprise workflow approval;
- organization-wide evidence dashboards;
- product-specific access control decisions beyond validating the presented
  proof contract.

## Public-Core Boundary

Delegent Core may define proof semantics, validator behavior, fixtures, tests,
schemas, and public-safe docs. It must not depend on private management notes,
paid-product implementation, customer strategy, workspace-local paths, channel
metadata, pricing, or downstream product assumptions.
