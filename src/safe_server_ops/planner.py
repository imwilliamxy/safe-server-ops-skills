"""Two-phase approval state machine (PENDING_APPROVAL -> APPROVED -> CONSUMED)."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any


class PlanError(ValueError):
    """Raised when a plan token is missing, expired, unapproved, or mismatched."""


@dataclass
class Plan:
    token: str
    kind: str  # "docker_restart" | "rsync_sync" | "config_apply" | "config_rollback"
    server: str
    target: str
    reason: str
    summary: str
    diff: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    status: str = "PENDING_APPROVAL"
    approved_by: str | None = None
    approved_at: float | None = None

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at

    def to_public_dict(self, include_diff: bool = False) -> dict[str, Any]:
        now = time.time()
        effective_status = "EXPIRED" if (self.status in {"PENDING_APPROVAL", "APPROVED"} and self.is_expired(now)) else self.status
        data: dict[str, Any] = {
            "plan_token": self.token,
            "kind": self.kind,
            "server": self.server,
            "target": self.target,
            "reason": self.reason,
            "summary": self.summary,
            "status": effective_status,
            "expires_in_seconds": max(0, int(self.expires_at - now)),
        }
        if self.approved_by:
            data["approved_by"] = self.approved_by
        if include_diff and self.diff:
            data["diff"] = self.diff
        return data


class PlanStore:
    """In-memory thread-safe store for short-lived approval plans."""

    def __init__(self, ttl_seconds: int = 180) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._plans: dict[str, Plan] = {}

    def _prune_locked(self) -> None:
        now = time.time()
        stale = [
            tok
            for tok, plan in self._plans.items()
            if (plan.status in {"CONSUMED", "REJECTED"} and now - plan.created_at > 3600)
            or (now > plan.expires_at + 600)
        ]
        for tok in stale:
            del self._plans[tok]

    def create(
        self,
        *,
        kind: str,
        server: str,
        target: str,
        reason: str,
        summary: str,
        payload: dict[str, Any],
        diff: str = "",
    ) -> Plan:
        now = time.time()
        token = f"pln_{secrets.token_hex(12)}"
        plan = Plan(
            token=token,
            kind=kind,
            server=server,
            target=target,
            reason=reason,
            summary=summary,
            diff=diff,
            payload=payload,
            created_at=now,
            expires_at=now + self._ttl,
        )
        with self._lock:
            self._prune_locked()
            self._plans[token] = plan
        return plan

    def list_pending(self) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            self._prune_locked()
            return [
                p.to_public_dict(include_diff=False)
                for p in self._plans.values()
                if p.status == "PENDING_APPROVAL" and not p.is_expired(now)
            ]

    def get_public(self, token: str, include_diff: bool = True) -> dict[str, Any]:
        with self._lock:
            plan = self._plans.get(token)
            if plan is None:
                raise PlanError(f"Unknown plan token: {token}")
            return plan.to_public_dict(include_diff=include_diff)

    def approve(self, token: str, approved_by: str) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            plan = self._plans.get(token)
            if plan is None:
                raise PlanError(f"Unknown plan token: {token}")
            if plan.is_expired(now):
                plan.status = "EXPIRED"
                raise PlanError("Plan token has expired. Please re-run plan/preview.")
            if plan.status != "PENDING_APPROVAL":
                raise PlanError(f"Plan token cannot be approved from status '{plan.status}'.")
            plan.status = "APPROVED"
            plan.approved_by = approved_by
            plan.approved_at = now
            return plan.to_public_dict(include_diff=False)

    def reject(self, token: str, rejected_by: str) -> dict[str, Any]:
        with self._lock:
            plan = self._plans.get(token)
            if plan is None:
                raise PlanError(f"Unknown plan token: {token}")
            if plan.status not in {"PENDING_APPROVAL", "APPROVED"}:
                raise PlanError(f"Plan token cannot be rejected from status '{plan.status}'.")
            plan.status = "REJECTED"
            plan.approved_by = f"rejected:{rejected_by}"
            return plan.to_public_dict(include_diff=False)

    def consume_approved(self, token: str, expected_kind: str) -> Plan:
        """Atomically verify a plan is APPROVED, unexpired, and matches expected_kind, then consume it."""
        now = time.time()
        with self._lock:
            plan = self._plans.get(token)
            if plan is None:
                raise PlanError(f"Unknown plan token: {token}")
            if plan.kind != expected_kind:
                raise PlanError(
                    f"Plan token kind mismatch: expected '{expected_kind}', got '{plan.kind}'."
                )
            if plan.is_expired(now):
                plan.status = "EXPIRED"
                raise PlanError("Plan token has expired. Please re-run plan/preview.")
            if plan.status == "PENDING_APPROVAL":
                raise PlanError(
                    "Plan token has NOT been approved yet. A human must approve it via ops-approve."
                )
            if plan.status != "APPROVED":
                raise PlanError(f"Plan token cannot be applied (status: '{plan.status}').")
            plan.status = "CONSUMED"
            return plan
