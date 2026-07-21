from __future__ import annotations

import json
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

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
GRANT_SECRET = "example-grant-secret"
SENDER_SECRET = "example-sender-secret"
SENDER_ID = "sender-key-document-reviewer"


def run_example() -> dict[str, str]:
    audit = InMemoryAuditLog()
    action_profile = CapabilityActionProfile(
        action_ttl_seconds={
            "summarize_document": 15 * 60,
            "approve_document_summary": 5 * 60,
        }
    )
    issuer = AuthorityGrantIssuer(
        issuer="local-example-issuer",
        signing_secret=GRANT_SECRET,
        action_profile=action_profile,
        audit_log=audit,
    )
    grant = issuer.issue(
        grant_id="grant-document-review-demo",
        now=NOW,
        audience="document-review-service",
        workload_id="agent-runtime:document-reviewer",
        workload_issuer="local-example",
        delegation_id="delegation-document-review-demo",
        delegation_source_type="workflow",
        delegation_purpose="approve document summary",
        project_id="knowledge-base-demo",
        session_id="document-session-demo",
        allowed_actions=("approve_document_summary",),
        sender_constraint_id=SENDER_ID,
        replay_handle="replay-document-review-demo",
        revocation_status_ref="grant-status-document-review-demo",
    )
    url = "https://document-review.example/summary/approve"
    sender_proof = make_sender_proof(
        sender_constraint_id=SENDER_ID,
        method="POST",
        url=url,
        grant=grant,
        replay_handle="replay-document-review-demo",
        timestamp=NOW,
        sender_secret=SENDER_SECRET,
    )
    request = DelegentRequest(
        method="POST",
        url=url,
        audience="document-review-service",
        project_id="knowledge-base-demo",
        session_id="document-session-demo",
        requested_action="approve_document_summary",
        purpose="approve document summary",
        grant=grant,
        sender_proof=sender_proof,
        payload_ref="private://document-session-demo/summary.json",
    )
    validator = AuthorityProofValidator(
        audience="document-review-service",
        grant_signing_secret=GRANT_SECRET,
        sender_secrets={SENDER_ID: SENDER_SECRET},
        revocation_status=StaticRevocationStatusProvider(),
        replay_cache=InMemoryReplayCache(),
        audit_log=audit,
    )
    result = validator.validate(request, now=NOW)
    return {
        "example": "document_review_gate",
        "decision": result.decision,
        "reason_code": result.reason_code,
        "audit_event_type": result.audit_event["event_type"],
    }


if __name__ == "__main__":
    print(json.dumps(run_example(), sort_keys=True))
