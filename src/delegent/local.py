"""Dependency-free local issuer and reference validator for Delegent.

The local implementation is for conformance tests, demos, and relying-product
adapter development. It is intentionally not production cryptography, key
management, policy storage, replay infrastructure, or hosted governance.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .contracts import (
    GRANT_PROFILE,
    SIGNATURE_ALG_TEST,
    AuthorityGrantClaims,
    AuthorityGrantIssuedAuditEvent,
    AuthorityGrantValidatedAuditEvent,
    CapabilityActionProfile,
    DelegentRequest,
    ReasonCode,
    SenderProof,
    SignedAuthorityGrant,
    ValidationDecision,
    ValidationResult,
    canonical_json,
)


def _sign(value: Any, secret: str) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        canonical_json(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class InMemoryAuditLog:
    events: list[dict[str, Any]] = field(default_factory=list)

    def append(self, event: dict[str, Any]) -> None:
        self.events.append(event)


class InMemoryReplayCache:
    def __init__(self) -> None:
        self._used: set[tuple[str, str]] = set()

    def mark_used(self, grant_id: str, replay_handle: str) -> bool:
        key = (grant_id, replay_handle)
        if key in self._used:
            return False
        self._used.add(key)
        return True


class StaticRevocationStatusProvider:
    def __init__(self, statuses: dict[str, str] | None = None) -> None:
        self._statuses = statuses or {}

    def status(self, status_ref: str) -> str:
        return self._statuses.get(status_ref, "active")


class StaticConformanceEvidenceProvider:
    def __init__(self, statuses: dict[str, str] | None = None) -> None:
        self._statuses = statuses or {}

    def status(self, evidence_ref: str) -> str:
        return self._statuses.get(evidence_ref, "accepted")


class AuthorityGrantIssuer:
    def __init__(
        self,
        *,
        issuer: str,
        signing_secret: str,
        action_profile: CapabilityActionProfile,
        audit_log: InMemoryAuditLog,
        grant_profile: str = GRANT_PROFILE,
    ) -> None:
        self.issuer = issuer
        self.signing_secret = signing_secret
        self.action_profile = action_profile
        self.audit_log = audit_log
        self.grant_profile = grant_profile

    def issue(
        self,
        *,
        grant_id: str,
        now: datetime,
        audience: str,
        workload_id: str,
        workload_issuer: str,
        delegation_id: str,
        delegation_source_type: str,
        delegation_purpose: str,
        project_id: str,
        session_id: str,
        allowed_actions: tuple[str, ...],
        sender_constraint_id: str,
        replay_handle: str,
        revocation_status_ref: str,
        policy_decision_id: str | None = None,
        conformance_evidence_ref: str | None = None,
        attestation_result_id: str | None = None,
        sensitivity: str | None = None,
        request_context_hash: str | None = None,
    ) -> dict[str, Any]:
        self._validate_issue_request(allowed_actions, policy_decision_id)
        ttl = self.action_profile.ttl_for(allowed_actions)
        grant = AuthorityGrantClaims(
            grant_id=grant_id,
            grant_profile=self.grant_profile,
            issuer=self.issuer,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl),
            audience=audience,
            workload_id=workload_id,
            workload_issuer=workload_issuer,
            delegation_id=delegation_id,
            delegation_source_type=delegation_source_type,
            delegation_purpose=delegation_purpose,
            project_id=project_id,
            session_id=session_id,
            allowed_actions=allowed_actions,
            sender_constraint_id=sender_constraint_id,
            replay_handle=replay_handle,
            revocation_status_ref=revocation_status_ref,
            policy_decision_id=policy_decision_id,
            conformance_evidence_ref=conformance_evidence_ref,
            attestation_result_id=attestation_result_id,
            sensitivity=sensitivity,
            request_context_hash=request_context_hash,
        )
        self.audit_log.append(
            AuthorityGrantIssuedAuditEvent(
                grant_id=grant.grant_id,
                issuer=grant.issuer,
                issued_at=grant.issued_at,
                expires_at=grant.expires_at,
                workload_id=grant.workload_id,
                delegation_id=grant.delegation_id,
                project_id=grant.project_id,
                session_id=grant.session_id,
                allowed_actions=grant.allowed_actions,
                sender_constraint_id=grant.sender_constraint_id,
                policy_decision_id=grant.policy_decision_id,
                conformance_evidence_ref=grant.conformance_evidence_ref,
            ).as_dict()
        )
        claims = grant.as_dict()
        return SignedAuthorityGrant(
            claims=claims,
            signature=_sign(claims, self.signing_secret),
            signature_alg=SIGNATURE_ALG_TEST,
        ).as_dict()

    def _validate_issue_request(
        self,
        allowed_actions: tuple[str, ...],
        policy_decision_id: str | None,
    ) -> None:
        self.action_profile.ttl_for(allowed_actions)
        review_actions = set(allowed_actions).intersection(
            self.action_profile.review_required_actions
        )
        if review_actions and not policy_decision_id:
            raise ValueError("review-required actions require policy_decision_id")


def make_sender_proof(
    *,
    sender_constraint_id: str,
    method: str,
    url: str,
    grant: dict[str, Any],
    replay_handle: str,
    timestamp: datetime,
    sender_secret: str,
) -> SenderProof:
    claims = {
        "sender_constraint_id": sender_constraint_id,
        "method": method.upper(),
        "url": url,
        "grant_hash": grant_hash(grant),
        "replay_handle": replay_handle,
        "timestamp": timestamp.isoformat(),
    }
    return SenderProof(
        sender_constraint_id=sender_constraint_id,
        method=method,
        url=url,
        replay_handle=replay_handle,
        timestamp=timestamp,
        signature=_sign(claims, sender_secret),
    )


class AuthorityProofValidator:
    def __init__(
        self,
        *,
        audience: str,
        grant_signing_secret: str,
        sender_secrets: dict[str, str],
        revocation_status: StaticRevocationStatusProvider,
        replay_cache: InMemoryReplayCache,
        audit_log: InMemoryAuditLog,
        conformance_evidence: StaticConformanceEvidenceProvider | None = None,
        conformance_required_actions: frozenset[str] = frozenset(),
    ) -> None:
        self.audience = audience
        self.grant_signing_secret = grant_signing_secret
        self.sender_secrets = sender_secrets
        self.revocation_status = revocation_status
        self.replay_cache = replay_cache
        self.audit_log = audit_log
        self.conformance_evidence = conformance_evidence
        self.conformance_required_actions = conformance_required_actions

    def validate(
        self, request: DelegentRequest, *, now: datetime | None = None
    ) -> ValidationResult:
        checked_at = now or _utc_now()
        claims, reason = self._verified_claims(request)
        if reason:
            return self._result(ValidationDecision.DENY, reason, request, {}, checked_at)

        checks = [
            (claims.get("audience") == self.audience, ReasonCode.WRONG_AUDIENCE),
            (request.audience == self.audience, ReasonCode.WRONG_AUDIENCE),
            (claims.get("project_id") == request.project_id, ReasonCode.WRONG_PROJECT),
            (claims.get("session_id") == request.session_id, ReasonCode.WRONG_SESSION),
            (
                request.requested_action in set(claims.get("allowed_actions", [])),
                ReasonCode.ACTION_NOT_ALLOWED,
            ),
            (claims.get("delegation_id"), ReasonCode.DELEGATION_MISSING),
            (
                claims.get("delegation_purpose") == request.purpose,
                ReasonCode.DELEGATION_MISSING,
            ),
            (claims.get("workload_id"), ReasonCode.MISSING_FIELD),
            (claims.get("sender_constraint_id"), ReasonCode.MISSING_FIELD),
            (
                claims.get("sender_constraint_id")
                == request.sender_proof.sender_constraint_id,
                ReasonCode.SENDER_CONSTRAINT_FAILED,
            ),
        ]
        for ok, reason_code in checks:
            if not ok:
                return self._result(
                    ValidationDecision.DENY, reason_code, request, claims, checked_at
                )

        if request.raw_payload is not None:
            return self._result(
                ValidationDecision.DENY,
                ReasonCode.RAW_PAYLOAD_NOT_ALLOWED,
                request,
                claims,
                checked_at,
            )

        not_before = _parse_time(claims.get("not_before"))
        expires_at = _parse_time(claims.get("expires_at"))
        if not_before and checked_at < not_before:
            return self._result(
                ValidationDecision.DENY,
                ReasonCode.GRANT_NOT_YET_VALID,
                request,
                claims,
                checked_at,
            )
        if not expires_at or checked_at >= expires_at:
            return self._result(
                ValidationDecision.DENY,
                ReasonCode.GRANT_EXPIRED,
                request,
                claims,
                checked_at,
            )

        status = self.revocation_status.status(str(claims.get("revocation_status_ref")))
        if status in {"revoked", "denied", "expired"}:
            return self._result(
                ValidationDecision.DENY,
                ReasonCode.GRANT_REVOKED_OR_DENIED,
                request,
                claims,
                checked_at,
            )
        if status in {"unknown", "unavailable"}:
            return self._result(
                ValidationDecision.ERROR_FAIL_CLOSED,
                ReasonCode.DEPENDENCY_UNAVAILABLE,
                request,
                claims,
                checked_at,
            )

        conformance_result = self._conformance_result(request, claims)
        if conformance_result:
            decision, reason_code = conformance_result
            return self._result(decision, reason_code, request, claims, checked_at)

        if not self._sender_proof_valid(request):
            return self._result(
                ValidationDecision.DENY,
                ReasonCode.SENDER_CONSTRAINT_FAILED,
                request,
                claims,
                checked_at,
            )

        grant_id = str(claims.get("grant_id"))
        replay_handle = str(claims.get("replay_handle"))
        if request.sender_proof.replay_handle != replay_handle:
            return self._result(
                ValidationDecision.DENY,
                ReasonCode.REPLAY_DETECTED,
                request,
                claims,
                checked_at,
            )
        if not self.replay_cache.mark_used(grant_id, replay_handle):
            return self._result(
                ValidationDecision.DENY,
                ReasonCode.REPLAY_DETECTED,
                request,
                claims,
                checked_at,
            )

        return self._result(
            ValidationDecision.ALLOW, ReasonCode.ALLOWED, request, claims, checked_at
        )

    def _verified_claims(
        self, request: DelegentRequest
    ) -> tuple[dict[str, Any], str]:
        claims = request.grant.get("claims")
        signature = request.grant.get("signature")
        if not isinstance(claims, dict) or not isinstance(signature, str):
            return {}, ReasonCode.MALFORMED_PROOF
        if _sign(claims, self.grant_signing_secret) != signature:
            return {}, ReasonCode.UNTRUSTED_ISSUER
        if claims.get("grant_profile") != GRANT_PROFILE:
            return {}, ReasonCode.MALFORMED_PROOF
        return claims, ""

    def _sender_proof_valid(self, request: DelegentRequest) -> bool:
        sender_id = request.sender_proof.sender_constraint_id
        sender_secret = self.sender_secrets.get(sender_id)
        if not sender_secret:
            return False
        claims = {
            "sender_constraint_id": sender_id,
            "method": request.method.upper(),
            "url": request.url,
            "grant_hash": grant_hash(request.grant),
            "replay_handle": request.sender_proof.replay_handle,
            "timestamp": request.sender_proof.timestamp.isoformat(),
        }
        return hmac.compare_digest(
            _sign(claims, sender_secret), request.sender_proof.signature
        )

    def _conformance_result(
        self, request: DelegentRequest, claims: dict[str, Any]
    ) -> tuple[str, str] | None:
        grant_ref = claims.get("conformance_evidence_ref")
        request_ref = request.conformance_evidence_ref
        required = request.requested_action in self.conformance_required_actions

        if required and (not grant_ref or not request_ref):
            return (
                ValidationDecision.DENY,
                ReasonCode.CONFORMANCE_EVIDENCE_REQUIRED,
            )
        if request_ref and grant_ref and request_ref != grant_ref:
            return (
                ValidationDecision.DENY,
                ReasonCode.CONFORMANCE_EVIDENCE_FAILED,
            )
        if request_ref and not grant_ref:
            return (
                ValidationDecision.DENY,
                ReasonCode.CONFORMANCE_EVIDENCE_FAILED,
            )
        if not grant_ref:
            return None
        if request_ref is None:
            request_ref = str(grant_ref)
        if request_ref != grant_ref:
            return (
                ValidationDecision.DENY,
                ReasonCode.CONFORMANCE_EVIDENCE_FAILED,
            )
        if self.conformance_evidence is None:
            if required:
                return (
                    ValidationDecision.ERROR_FAIL_CLOSED,
                    ReasonCode.DEPENDENCY_UNAVAILABLE,
                )
            return None

        status = self.conformance_evidence.status(str(grant_ref))
        if status in {"accepted", "active", "passed"}:
            return None
        if status in {"denied", "failed", "rejected"}:
            return (
                ValidationDecision.DENY,
                ReasonCode.CONFORMANCE_EVIDENCE_FAILED,
            )
        if status in {"unknown", "unavailable"}:
            return (
                ValidationDecision.ERROR_FAIL_CLOSED,
                ReasonCode.DEPENDENCY_UNAVAILABLE,
            )
        return (
            ValidationDecision.ERROR_FAIL_CLOSED,
            ReasonCode.DEPENDENCY_UNAVAILABLE,
        )

    def _result(
        self,
        decision: str,
        reason_code: str,
        request: DelegentRequest,
        claims: dict[str, Any],
        now: datetime,
    ) -> ValidationResult:
        audit_event = AuthorityGrantValidatedAuditEvent(
            grant_id=claims.get("grant_id"),
            proof_id=claims.get("replay_handle"),
            validated_at=now,
            relying_product=self.audience,
            endpoint=request.url,
            workload_id=claims.get("workload_id"),
            workload_issuer=claims.get("workload_issuer"),
            delegation_id=claims.get("delegation_id"),
            capability_issuer=claims.get("issuer"),
            project_id=request.project_id,
            session_id=request.session_id,
            requested_action=request.requested_action,
            revocation_check_result=claims.get("revocation_status_ref"),
            policy_decision_id=claims.get("policy_decision_id"),
            conformance_evidence_ref=claims.get("conformance_evidence_ref"),
            validation_result=decision,
            reason_code=reason_code,
        ).as_dict()
        self.audit_log.append(audit_event)
        return ValidationResult(decision, reason_code, audit_event)


def grant_hash(grant: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(grant).encode("utf-8")).hexdigest()


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value)
    return None
