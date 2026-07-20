# Delegent Core

Public-intended open core for Delegent.

Delegent Core defines and verifies portable delegated-authority proof semantics
for AI agents. It should have standalone value: protocol shapes, validator
behavior, conformance fixtures, reason codes, audit schemas, and examples that
an unrelated relying product can use without the commercial control plane.

This repository starts private until explicit public-release approval.

## Package Surface

- `delegent.contracts` defines the portable proof vocabulary:
  `AuthorityGrantClaims`, `SignedAuthorityGrant`, `SenderProof`,
  `DelegentRequest`, `ValidationResult`, decisions, reason codes, audit event
  names, and deterministic JSON serialization.
- `delegent.local` provides a dependency-free reference issuer and validator
  for demos, conformance tests, and relying-product adapter development:
  `AuthorityGrantIssuer`, `AuthorityProofValidator`,
  `CapabilityActionProfile`, `InMemoryReplayCache`,
  `StaticRevocationStatusProvider`, and `make_sender_proof`.

## Local Verification

```bash
python -m unittest discover -s tests
python scripts/check_public_boundary.py
```

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

## Boundary

Delegent Core owns safe bus/proof semantics and local validation. It must not
contain private management strategy, customer-specific plans, downstream product
coupling, pricing, hosted control-plane implementation, or enterprise-only
governance workflows.

See `SECURITY.md` and `docs/threat-model.md` for the current public-safe
security posture and threat model.
