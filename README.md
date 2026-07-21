# Delegent Core

Public-intended open core for Delegent.

Delegent Core defines and verifies portable delegated-authority proof semantics
for AI agents. It should have standalone value: protocol shapes, validator
behavior, conformance fixtures, reason codes, audit schemas, and examples that
an unrelated relying product can use without the commercial control plane.

This repository is public pre-alpha open-core work. Package publication,
supported-version commitments, and production-use claims require a separate
release decision.

## Package Surface

- `delegent.contracts` defines the portable proof vocabulary:
  `AuthorityGrantClaims`, `SignedAuthorityGrant`, `SenderProof`,
  `DelegentRequest`, `ValidationResult`, decisions, reason codes, audit event
  names, and deterministic JSON serialization.
- `delegent.local` provides a dependency-free reference issuer and validator
  for demos, conformance tests, and relying-product adapter development:
  `AuthorityGrantIssuer`, `AuthorityProofValidator`,
  `CapabilityActionProfile`, `InMemoryReplayCache`,
  `StaticRevocationStatusProvider`, `StaticConformanceEvidenceProvider`,
  `StaticCredentialEvidenceProvider`, and `make_sender_proof`.
- `schemas/` contains JSON Schema fragments for grants, sender proofs,
  validation requests/results, reason codes, and audit events.
- `openapi/` contains a small OpenAPI 3.1 validation endpoint fragment for
  relying products that want an HTTP contract around local validation.
- `examples/` contains standalone relying-product examples that validate
  Delegent grants locally without any commercial service.

## Cryptography Warning

The local HMAC issuer, sender-proof helper, in-memory replay cache, and static
revocation provider are for tests, examples, conformance fixtures, and relying
product adapter development only. They are not production cryptography, key
management, replay infrastructure, revocation infrastructure, or authorization
operations.

## Conformance Evidence

Grants and validation requests may carry `conformance_evidence_ref`, a generic
reference to runtime or workflow conformance evidence. The local validator can
be configured to require evidence for selected actions, accept known-good
evidence, deny failed evidence, or fail closed when the evidence source is
unavailable.

## Credential Evidence

Grants and validation requests may carry `credential_evidence_ref`, a generic
reference to workload, sender-constraint, or managed-node credential evidence.
The local validator can require credential evidence for selected actions,
accept active evidence, deny revoked or expired evidence, and fail closed when
the credential evidence source is unavailable. Delegent Core keeps this generic:
SSH key and certificate lifecycle belongs to downstream integrations, not the
portable proof contract.

## Local Verification

```bash
python scripts/check.py
```

The gate currently runs:

```bash
python -m unittest discover -s tests
python scripts/check_public_boundary.py
```

## Local Release Candidate

Build and verify a locally installable release candidate with:

```bash
python scripts/check_release_candidate.py
```

The release-candidate gate builds the package, installs the wheel into a fresh
virtual environment, runs the conformance tests, and executes the standalone
examples without `PYTHONPATH` or commercial services.

## Minimal Example

```python
from datetime import UTC, datetime

from delegent import (
    AuthorityGrantIssuer,
    AuthorityProofValidator,
    CapabilityActionProfile,
    DelegentRequest,
    InMemoryAuditLog,
    InMemoryReplayCache,
    StaticRevocationStatusProvider,
    make_sender_proof,
)

now = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
audit = InMemoryAuditLog()
profile = CapabilityActionProfile({"create_record": 300})

issuer = AuthorityGrantIssuer(
    issuer="local-demo-issuer",
    signing_secret="grant-secret",
    action_profile=profile,
    audit_log=audit,
)
grant = issuer.issue(
    grant_id="grant-demo",
    now=now,
    audience="example-product",
    workload_id="agent-runtime:demo",
    workload_issuer="local-demo",
    delegation_id="delegation-demo",
    delegation_source_type="workflow",
    delegation_purpose="create controlled record",
    project_id="project-demo",
    session_id="session-demo",
    allowed_actions=("create_record",),
    sender_constraint_id="sender-key-demo",
    replay_handle="replay-demo",
    revocation_status_ref="grant-status-demo",
)
sender_proof = make_sender_proof(
    sender_constraint_id="sender-key-demo",
    method="POST",
    url="https://example-product.invalid/records",
    grant=grant,
    replay_handle="replay-demo",
    timestamp=now,
    sender_secret="sender-secret",
)
request = DelegentRequest(
    method="POST",
    url="https://example-product.invalid/records",
    audience="example-product",
    project_id="project-demo",
    session_id="session-demo",
    requested_action="create_record",
    purpose="create controlled record",
    grant=grant,
    sender_proof=sender_proof,
    payload_ref="private://session-demo/manifest.json",
)
validator = AuthorityProofValidator(
    audience="example-product",
    grant_signing_secret="grant-secret",
    sender_secrets={"sender-key-demo": "sender-secret"},
    revocation_status=StaticRevocationStatusProvider(),
    replay_cache=InMemoryReplayCache(),
    audit_log=audit,
)

assert validator.validate(request, now=now).allowed
```

More complete examples live under `examples/`:

```bash
PYTHONPATH=src python examples/document_review_gate.py
PYTHONPATH=src python examples/maintenance_window_gate.py
```

## Boundary

Delegent Core owns safe bus/proof semantics and local validation. It must not
contain private management strategy, customer-specific plans, downstream product
coupling, pricing, hosted control-plane implementation, or enterprise-only
governance workflows.

See `SECURITY.md` and `docs/threat-model.md` for the current public-safe
security posture and threat model.

## License

Delegent Core is licensed under the Apache License 2.0.
