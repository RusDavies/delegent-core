"""Public Delegent proof and validation contracts.

These contracts define the portable vocabulary between an authority issuer, an
agent/runtime presenter, and a relying product. The open core intentionally
keeps production signing, policy storage, identity-provider integration, and
enterprise governance workflows outside this module.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

GRANT_PROFILE = "delegent-authority-grant.v0"
SIGNATURE_ALG_TEST = "hmac-sha256-test"
SENDER_CONSTRAINT_METHOD_TEST = "hmac-sha256-test"


class ValidationDecision:
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_REVIEW = "require_review"
    ERROR_FAIL_CLOSED = "error_fail_closed"


class ReasonCode:
    MISSING_FIELD = "missing_field"
    MALFORMED_PROOF = "malformed_proof"
    UNTRUSTED_ISSUER = "untrusted_issuer"
    WRONG_AUDIENCE = "wrong_audience"
    WRONG_PROJECT = "wrong_project"
    WRONG_SESSION = "wrong_session"
    ACTION_NOT_ALLOWED = "action_not_allowed"
    DELEGATION_MISSING = "delegation_missing"
    DELEGATION_EXPIRED = "delegation_expired"
    DELEGATION_REVOKED_OR_DENIED = "delegation_revoked_or_denied"
    GRANT_NOT_YET_VALID = "grant_not_yet_valid"
    GRANT_EXPIRED = "grant_expired"
    GRANT_REVOKED_OR_DENIED = "grant_revoked_or_denied"
    SENDER_CONSTRAINT_FAILED = "sender_constraint_failed"
    REPLAY_DETECTED = "replay_detected"
    POLICY_DENIED = "policy_denied"
    POLICY_REVIEW_REQUIRED = "policy_review_required"
    CONFORMANCE_EVIDENCE_REQUIRED = "conformance_evidence_required"
    CONFORMANCE_EVIDENCE_FAILED = "conformance_evidence_failed"
    ATTESTATION_REQUIRED = "attestation_required"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    RAW_PAYLOAD_NOT_ALLOWED = "raw_payload_not_allowed"
    INTERNAL_ERROR_FAIL_CLOSED = "internal_error_fail_closed"
    ALLOWED = "allowed"


class AuditEventType:
    AUTHORITY_GRANT_ISSUED = "authority_grant_issued"
    AUTHORITY_GRANT_VALIDATED = "authority_grant_validated"


def canonical_json(value: Any) -> str:
    """Serialize contract values deterministically for signing and fixtures."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True)
class CapabilityActionProfile:
    """Local policy for actions a reference issuer is willing to grant."""

    action_ttl_seconds: dict[str, int]
    review_required_actions: frozenset[str] = frozenset()
    unsupported_actions: frozenset[str] = frozenset()

    def ttl_for(self, allowed_actions: tuple[str, ...]) -> int:
        if not allowed_actions:
            raise ValueError("allowed_actions required")
        unknown = sorted(set(allowed_actions) - set(self.action_ttl_seconds))
        if unknown:
            raise ValueError(f"unknown actions: {', '.join(unknown)}")
        unsupported = sorted(set(allowed_actions).intersection(self.unsupported_actions))
        if unsupported:
            raise ValueError(f"unsupported actions: {', '.join(unsupported)}")
        return min(self.action_ttl_seconds[action] for action in allowed_actions)


@dataclass(frozen=True)
class AuthorityGrantClaims:
    grant_id: str
    grant_profile: str
    issuer: str
    issued_at: datetime
    expires_at: datetime
    audience: str
    workload_id: str
    workload_issuer: str
    delegation_id: str
    delegation_source_type: str
    delegation_purpose: str
    project_id: str
    session_id: str
    allowed_actions: tuple[str, ...]
    sender_constraint_id: str
    replay_handle: str
    revocation_status_ref: str
    not_before: datetime | None = None
    policy_decision_id: str | None = None
    conformance_evidence_ref: str | None = None
    attestation_result_id: str | None = None
    sensitivity: str | None = None
    request_context_hash: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "grant_profile": self.grant_profile,
            "issuer": self.issuer,
            "issued_at": self.issued_at.isoformat(),
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "expires_at": self.expires_at.isoformat(),
            "audience": self.audience,
            "workload_id": self.workload_id,
            "workload_issuer": self.workload_issuer,
            "delegation_id": self.delegation_id,
            "delegation_source_type": self.delegation_source_type,
            "delegation_purpose": self.delegation_purpose,
            "project_id": self.project_id,
            "session_id": self.session_id,
            "allowed_actions": list(self.allowed_actions),
            "sender_constraint_id": self.sender_constraint_id,
            "replay_handle": self.replay_handle,
            "revocation_status_ref": self.revocation_status_ref,
            "policy_decision_id": self.policy_decision_id,
            "conformance_evidence_ref": self.conformance_evidence_ref,
            "attestation_result_id": self.attestation_result_id,
            "sensitivity": self.sensitivity,
            "request_context_hash": self.request_context_hash,
        }


@dataclass(frozen=True)
class SignedAuthorityGrant:
    claims: dict[str, Any]
    signature: str
    signature_alg: str = SIGNATURE_ALG_TEST

    def as_dict(self) -> dict[str, Any]:
        return {
            "claims": self.claims,
            "signature": self.signature,
            "signature_alg": self.signature_alg,
        }


@dataclass(frozen=True)
class SenderProof:
    sender_constraint_id: str
    method: str
    url: str
    replay_handle: str
    timestamp: datetime
    signature: str

    def claims(self) -> dict[str, Any]:
        return {
            "sender_constraint_id": self.sender_constraint_id,
            "method": self.method.upper(),
            "url": self.url,
            "replay_handle": self.replay_handle,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(frozen=True)
class DelegentRequest:
    method: str
    url: str
    audience: str
    project_id: str
    session_id: str
    requested_action: str
    purpose: str
    grant: dict[str, Any]
    sender_proof: SenderProof
    payload_ref: str | None = None
    conformance_evidence_ref: str | None = None
    raw_payload: str | None = None


@dataclass(frozen=True)
class ValidationResult:
    decision: str
    reason_code: str
    audit_event: dict[str, Any]

    @property
    def allowed(self) -> bool:
        return self.decision == ValidationDecision.ALLOW


@dataclass(frozen=True)
class AuthorityGrantIssuedAuditEvent:
    grant_id: str
    issuer: str
    issued_at: datetime
    expires_at: datetime
    workload_id: str
    delegation_id: str
    project_id: str
    session_id: str
    allowed_actions: tuple[str, ...]
    sender_constraint_id: str
    policy_decision_id: str | None
    conformance_evidence_ref: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_type": AuditEventType.AUTHORITY_GRANT_ISSUED,
            "grant_id": self.grant_id,
            "issuer": self.issuer,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "workload_id": self.workload_id,
            "delegation_id": self.delegation_id,
            "project_id": self.project_id,
            "session_id": self.session_id,
            "allowed_actions": list(self.allowed_actions),
            "sender_constraint_id": self.sender_constraint_id,
            "policy_decision_id": self.policy_decision_id,
            "conformance_evidence_ref": self.conformance_evidence_ref,
            "result": "issued",
            "reason_code": ReasonCode.ALLOWED,
        }


@dataclass(frozen=True)
class AuthorityGrantValidatedAuditEvent:
    validated_at: datetime
    relying_product: str
    endpoint: str
    project_id: str
    session_id: str
    requested_action: str
    validation_result: str
    reason_code: str
    grant_id: str | None = None
    proof_id: str | None = None
    workload_id: str | None = None
    workload_issuer: str | None = None
    delegation_id: str | None = None
    capability_issuer: str | None = None
    sender_constraint_method: str = SENDER_CONSTRAINT_METHOD_TEST
    revocation_check_result: str | None = None
    policy_decision_id: str | None = None
    conformance_evidence_ref: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_type": AuditEventType.AUTHORITY_GRANT_VALIDATED,
            "grant_id": self.grant_id,
            "proof_id": self.proof_id,
            "validated_at": self.validated_at.isoformat(),
            "relying_product": self.relying_product,
            "endpoint": self.endpoint,
            "workload_id": self.workload_id,
            "workload_issuer": self.workload_issuer,
            "delegation_id": self.delegation_id,
            "capability_issuer": self.capability_issuer,
            "project_id": self.project_id,
            "session_id": self.session_id,
            "requested_action": self.requested_action,
            "sender_constraint_method": self.sender_constraint_method,
            "revocation_check_result": self.revocation_check_result,
            "policy_decision_id": self.policy_decision_id,
            "conformance_evidence_ref": self.conformance_evidence_ref,
            "validation_result": self.validation_result,
            "reason_code": self.reason_code,
        }
