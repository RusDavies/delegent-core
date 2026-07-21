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
SENDER_ID = "sender-key-maintenance-agent"


def run_example() -> dict[str, str]:
    audit = InMemoryAuditLog()
    action_profile = CapabilityActionProfile(
        action_ttl_seconds={
            "read_maintenance_window": 15 * 60,
            "reserve_maintenance_window": 5 * 60,
        }
    )
    issuer = AuthorityGrantIssuer(
        issuer="local-example-issuer",
        signing_secret=GRANT_SECRET,
        action_profile=action_profile,
        audit_log=audit,
    )
    grant = issuer.issue(
        grant_id="grant-maintenance-window-demo",
        now=NOW,
        audience="maintenance-planner",
        workload_id="agent-runtime:maintenance-planner",
        workload_issuer="local-example",
        delegation_id="delegation-maintenance-window-demo",
        delegation_source_type="workflow",
        delegation_purpose="reserve maintenance window",
        project_id="service-ops-demo",
        session_id="maintenance-session-demo",
        allowed_actions=("reserve_maintenance_window",),
        sender_constraint_id=SENDER_ID,
        replay_handle="replay-maintenance-window-demo",
        revocation_status_ref="grant-status-maintenance-window-demo",
    )
    url = "https://maintenance-planner.example/windows/reserve"
    sender_proof = make_sender_proof(
        sender_constraint_id=SENDER_ID,
        method="POST",
        url=url,
        grant=grant,
        replay_handle="replay-maintenance-window-demo",
        timestamp=NOW,
        sender_secret=SENDER_SECRET,
    )
    request = DelegentRequest(
        method="POST",
        url=url,
        audience="maintenance-planner",
        project_id="service-ops-demo",
        session_id="maintenance-session-demo",
        requested_action="reserve_maintenance_window",
        purpose="reserve maintenance window",
        grant=grant,
        sender_proof=sender_proof,
        payload_ref="private://maintenance-session-demo/window.json",
    )
    validator = AuthorityProofValidator(
        audience="maintenance-planner",
        grant_signing_secret=GRANT_SECRET,
        sender_secrets={SENDER_ID: SENDER_SECRET},
        revocation_status=StaticRevocationStatusProvider(),
        replay_cache=InMemoryReplayCache(),
        audit_log=audit,
    )
    result = validator.validate(request, now=NOW)
    return {
        "example": "maintenance_window_gate",
        "decision": result.decision,
        "reason_code": result.reason_code,
        "audit_event_type": result.audit_event["event_type"],
    }


if __name__ == "__main__":
    print(json.dumps(run_example(), sort_keys=True))
