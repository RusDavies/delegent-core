from __future__ import annotations

import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from delegent import (  # noqa: E402
    GRANT_PROFILE,
    SIGNATURE_ALG_TEST,
    AuditEventType,
    AuthorityGrantClaims,
    CapabilityActionProfile,
    ReasonCode,
    SignedAuthorityGrant,
    ValidationDecision,
    ValidationResult,
    canonical_json,
)

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)


class ContractTests(unittest.TestCase):
    def test_action_profile_uses_lowest_action_ttl(self) -> None:
        profile = CapabilityActionProfile(
            action_ttl_seconds={
                "read_context": 15 * 60,
                "create_record": 5 * 60,
                "change_sensitivity": 2 * 60,
            },
            review_required_actions=frozenset({"change_sensitivity"}),
        )

        self.assertEqual(profile.ttl_for(("read_context", "create_record")), 5 * 60)
        self.assertEqual(profile.ttl_for(("change_sensitivity",)), 2 * 60)

    def test_capability_grant_claims_are_deterministic(self) -> None:
        claims = AuthorityGrantClaims(
            grant_id="grant-demo",
            grant_profile=GRANT_PROFILE,
            issuer="local-prototype-issuer",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            audience="example-relying-product",
            workload_id="agent-runtime:demo",
            workload_issuer="local-demo",
            delegation_id="delegation-demo",
            delegation_source_type="workflow",
            delegation_purpose="create controlled record",
            project_id="project-demo",
            session_id="session-demo",
            allowed_actions=("create_record",),
            sender_constraint_id="sender-key-agent-runtime-1",
            replay_handle="replay-demo",
            revocation_status_ref="grant-status-demo",
            policy_decision_id="policy-decision-demo",
        ).as_dict()

        self.assertEqual(claims["grant_profile"], GRANT_PROFILE)
        self.assertEqual(claims["allowed_actions"], ["create_record"])
        self.assertIn('"allowed_actions":["create_record"]', canonical_json(claims))

    def test_signed_grant_contract_shape(self) -> None:
        grant = SignedAuthorityGrant(
            claims={"grant_id": "grant-demo"},
            signature="abc123",
            signature_alg=SIGNATURE_ALG_TEST,
        ).as_dict()

        self.assertEqual(
            grant,
            {
                "claims": {"grant_id": "grant-demo"},
                "signature": "abc123",
                "signature_alg": "hmac-sha256-test",
            },
        )

    def test_validation_result_allowed_uses_contract_decision(self) -> None:
        allowed = ValidationResult(
            decision=ValidationDecision.ALLOW,
            reason_code=ReasonCode.ALLOWED,
            audit_event={},
        )
        denied = ValidationResult(
            decision=ValidationDecision.DENY,
            reason_code=ReasonCode.WRONG_PROJECT,
            audit_event={},
        )

        self.assertTrue(allowed.allowed)
        self.assertFalse(denied.allowed)

    def test_audit_event_type_names_are_public_contracts(self) -> None:
        self.assertEqual(
            AuditEventType.AUTHORITY_GRANT_ISSUED,
            "authority_grant_issued",
        )
        self.assertEqual(
            AuditEventType.AUTHORITY_GRANT_VALIDATED,
            "authority_grant_validated",
        )


if __name__ == "__main__":
    unittest.main()
