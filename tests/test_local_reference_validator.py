from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from delegent import (  # noqa: E402
    AuthorityGrantIssuer,
    AuthorityProofValidator,
    CapabilityActionProfile,
    DelegentRequest,
    InMemoryAuditLog,
    InMemoryReplayCache,
    ReasonCode,
    StaticConformanceEvidenceProvider,
    StaticRevocationStatusProvider,
    ValidationDecision,
    make_sender_proof,
)

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
GRANT_SECRET = "synthetic-grant-secret"
SENDER_SECRET = "synthetic-sender-secret"
SENDER_ID = "sender-key-agent-runtime-1"


class LocalReferenceValidatorTests(unittest.TestCase):
    def test_allows_valid_action(self) -> None:
        flow = Flow()

        result = flow.validator.validate(flow.request(), now=NOW)

        self.assertTrue(result.allowed)
        self.assertEqual(result.reason_code, ReasonCode.ALLOWED)
        self.assertEqual(
            [event["event_type"] for event in flow.audit.events],
            ["authority_grant_issued", "authority_grant_validated"],
        )

    def test_rejects_wrong_audience(self) -> None:
        flow = Flow(audience="other-product")

        result = flow.validator.validate(flow.request(), now=NOW)

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason_code, ReasonCode.WRONG_AUDIENCE)

    def test_rejects_wrong_project(self) -> None:
        flow = Flow()

        result = flow.validator.validate(flow.request(project_id="other-project"), now=NOW)

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason_code, ReasonCode.WRONG_PROJECT)

    def test_rejects_wrong_session(self) -> None:
        flow = Flow()

        result = flow.validator.validate(flow.request(session_id="other-session"), now=NOW)

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason_code, ReasonCode.WRONG_SESSION)

    def test_rejects_action_outside_grant(self) -> None:
        flow = Flow()
        request = flow.request(requested_action="update_record")

        result = flow.validator.validate(request, now=NOW)

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason_code, ReasonCode.ACTION_NOT_ALLOWED)

    def test_rejects_expired_grant(self) -> None:
        flow = Flow()

        result = flow.validator.validate(flow.request(), now=NOW + timedelta(minutes=6))

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason_code, ReasonCode.GRANT_EXPIRED)

    def test_rejects_revoked_grant(self) -> None:
        flow = Flow(revocation_status={"grant-status-demo": "revoked"})

        result = flow.validator.validate(flow.request(), now=NOW)

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason_code, ReasonCode.GRANT_REVOKED_OR_DENIED)

    def test_fails_closed_when_revocation_status_unavailable(self) -> None:
        flow = Flow(revocation_status={"grant-status-demo": "unavailable"})

        result = flow.validator.validate(flow.request(), now=NOW)

        self.assertFalse(result.allowed)
        self.assertEqual(result.decision, ValidationDecision.ERROR_FAIL_CLOSED)
        self.assertEqual(result.reason_code, ReasonCode.DEPENDENCY_UNAVAILABLE)

    def test_rejects_failed_sender_constraint(self) -> None:
        flow = Flow(sender_secret="wrong-secret")

        result = flow.validator.validate(flow.request(), now=NOW)

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason_code, ReasonCode.SENDER_CONSTRAINT_FAILED)

    def test_rejects_sender_proof_not_bound_to_grant(self) -> None:
        flow = Flow()
        flow.validator.sender_secrets["sender-key-other-runtime"] = "other-sender-secret"
        request = flow.request()
        other_sender_proof = make_sender_proof(
            sender_constraint_id="sender-key-other-runtime",
            method=request.method,
            url=request.url,
            grant=flow.grant,
            replay_handle="replay-demo",
            timestamp=NOW,
            sender_secret="other-sender-secret",
        )
        request = replace(request, sender_proof=other_sender_proof)

        result = flow.validator.validate(request, now=NOW)

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason_code, ReasonCode.SENDER_CONSTRAINT_FAILED)

    def test_rejects_replay(self) -> None:
        flow = Flow()
        request = flow.request()

        first = flow.validator.validate(request, now=NOW)
        second = flow.validator.validate(request, now=NOW)

        self.assertTrue(first.allowed)
        self.assertFalse(second.allowed)
        self.assertEqual(second.reason_code, ReasonCode.REPLAY_DETECTED)

    def test_rejects_raw_payload_in_proof_request(self) -> None:
        flow = Flow()
        request = flow.request(raw_payload="private source document text")

        result = flow.validator.validate(request, now=NOW)

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason_code, ReasonCode.RAW_PAYLOAD_NOT_ALLOWED)

    def test_review_required_action_requires_policy_decision_at_issuance(self) -> None:
        with self.assertRaisesRegex(ValueError, "policy_decision_id"):
            Flow(allowed_actions=("change_sensitivity",), policy_decision_id=None)

    def test_accepts_required_conformance_evidence(self) -> None:
        flow = Flow(
            conformance_evidence_ref="conformance://runs/run-001/conformance/pass",
            conformance_required_actions=frozenset({"create_record"}),
            conformance_status={
                "conformance://runs/run-001/conformance/pass": "accepted"
            },
        )

        result = flow.validator.validate(
            flow.request(
                conformance_evidence_ref="conformance://runs/run-001/conformance/pass"
            ),
            now=NOW,
        )

        self.assertTrue(result.allowed)
        self.assertEqual(
            result.audit_event["conformance_evidence_ref"],
            "conformance://runs/run-001/conformance/pass",
        )

    def test_requires_conformance_evidence_for_configured_actions(self) -> None:
        flow = Flow(conformance_required_actions=frozenset({"create_record"}))

        result = flow.validator.validate(flow.request(), now=NOW)

        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason_code,
            ReasonCode.CONFORMANCE_EVIDENCE_REQUIRED,
        )

    def test_rejects_failed_conformance_evidence(self) -> None:
        flow = Flow(
            conformance_evidence_ref="conformance://runs/run-001/conformance/fail",
            conformance_required_actions=frozenset({"create_record"}),
            conformance_status={"conformance://runs/run-001/conformance/fail": "denied"},
        )

        result = flow.validator.validate(
            flow.request(
                conformance_evidence_ref="conformance://runs/run-001/conformance/fail"
            ),
            now=NOW,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason_code, ReasonCode.CONFORMANCE_EVIDENCE_FAILED)

    def test_fails_closed_when_conformance_evidence_unavailable(self) -> None:
        flow = Flow(
            conformance_evidence_ref="conformance://runs/run-001/conformance/pending",
            conformance_required_actions=frozenset({"create_record"}),
            conformance_status={
                "conformance://runs/run-001/conformance/pending": "unavailable"
            },
        )

        result = flow.validator.validate(
            flow.request(
                conformance_evidence_ref="conformance://runs/run-001/conformance/pending"
            ),
            now=NOW,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.decision, ValidationDecision.ERROR_FAIL_CLOSED)
        self.assertEqual(result.reason_code, ReasonCode.DEPENDENCY_UNAVAILABLE)

    def test_rejects_mismatched_conformance_evidence_reference(self) -> None:
        flow = Flow(
            conformance_evidence_ref="conformance://runs/run-001/conformance/pass",
            conformance_required_actions=frozenset({"create_record"}),
        )

        result = flow.validator.validate(
            flow.request(
                conformance_evidence_ref="conformance://runs/run-002/conformance/pass"
            ),
            now=NOW,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason_code, ReasonCode.CONFORMANCE_EVIDENCE_FAILED)


class Flow:
    def __init__(
        self,
        *,
        audience: str = "example-relying-product",
        allowed_actions: tuple[str, ...] = ("create_record",),
        policy_decision_id: str | None = "policy-decision-demo",
        conformance_evidence_ref: str | None = None,
        conformance_required_actions: frozenset[str] = frozenset(),
        conformance_status: dict[str, str] | None = None,
        revocation_status: dict[str, str] | None = None,
        sender_secret: str = SENDER_SECRET,
    ) -> None:
        self.audit = InMemoryAuditLog()
        self.action_profile = CapabilityActionProfile(
            action_ttl_seconds={
                "read_context": 15 * 60,
                "create_record": 5 * 60,
                "update_record": 5 * 60,
                "change_sensitivity": 2 * 60,
            },
            review_required_actions=frozenset({"change_sensitivity"}),
            unsupported_actions=frozenset({"email", "pay", "publish"}),
        )
        self.issuer = AuthorityGrantIssuer(
            issuer="local-prototype-issuer",
            signing_secret=GRANT_SECRET,
            action_profile=self.action_profile,
            audit_log=self.audit,
        )
        self.grant = self.issuer.issue(
            grant_id="grant-demo",
            now=NOW,
            audience=audience,
            workload_id="agent-runtime:demo",
            workload_issuer="local-demo",
            delegation_id="delegation-demo",
            delegation_source_type="workflow",
            delegation_purpose="create controlled record",
            project_id="project-demo",
            session_id="session-demo",
            allowed_actions=allowed_actions,
            sender_constraint_id=SENDER_ID,
            replay_handle="replay-demo",
            revocation_status_ref="grant-status-demo",
            policy_decision_id=policy_decision_id,
            conformance_evidence_ref=conformance_evidence_ref,
            sensitivity="restricted",
        )
        self.validator = AuthorityProofValidator(
            audience="example-relying-product",
            grant_signing_secret=GRANT_SECRET,
            sender_secrets={SENDER_ID: sender_secret},
            revocation_status=StaticRevocationStatusProvider(revocation_status),
            replay_cache=InMemoryReplayCache(),
            audit_log=self.audit,
            conformance_evidence=StaticConformanceEvidenceProvider(
                conformance_status
            ),
            conformance_required_actions=conformance_required_actions,
        )

    def request(
        self,
        *,
        project_id: str = "project-demo",
        session_id: str = "session-demo",
        requested_action: str = "create_record",
        conformance_evidence_ref: str | None = None,
        raw_payload: str | None = None,
    ) -> DelegentRequest:
        method = "POST"
        url = "https://relying-product.example/api/controlled-record"
        sender_proof = make_sender_proof(
            sender_constraint_id=SENDER_ID,
            method=method,
            url=url,
            grant=self.grant,
            replay_handle="replay-demo",
            timestamp=NOW,
            sender_secret=SENDER_SECRET,
        )
        return DelegentRequest(
            method=method,
            url=url,
            audience="example-relying-product",
            project_id=project_id,
            session_id=session_id,
            requested_action=requested_action,
            purpose="create controlled record",
            grant=self.grant,
            sender_proof=sender_proof,
            payload_ref="private://session-demo/manifest.json",
            conformance_evidence_ref=conformance_evidence_ref,
            raw_payload=raw_payload,
        )


if __name__ == "__main__":
    unittest.main()
