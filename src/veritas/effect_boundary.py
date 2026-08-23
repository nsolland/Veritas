"""Verification contract for REHT EffectBoundary execution receipts.

Veritas admits only intact, non-authoritative execution evidence. It never turns
an execution receipt into authority and it rejects any receipt whose content no
longer matches its REHT-produced receipt digest.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

_SCHEMA = "valo.reht.effect-boundary-observation.v1"
_ALLOWED_STATUS = {
    "BLOCKED",
    "NOT_COMMITTED",
    "FAILED",
    "COMMITTED",
    "COMMITTED_UNVERIFIED",
    "COMMITTED_WITH_DEVIATION",
}
_ALLOWED_REHT = {None, "ALLOW", "STEP_UP", "DENY"}
_FIELDS = frozenset(
    {
        "schema",
        "receipt_id",
        "status",
        "action_digest",
        "execution_context_hash",
        "reht_decision",
        "clearance_ref",
        "permit_ref",
        "effect_name",
        "effect_result_digest",
        "reason",
        "created_at",
        "postconditions_verified",
        "authority_granted",
    }
)
_HEX = set("0123456789abcdef")


class EffectBoundaryObservationError(ValueError):
    pass


def _digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_digest(name: str, value: Any, *, prefixed: bool = False) -> str:
    if not isinstance(value, str) or not value:
        raise EffectBoundaryObservationError(f"{name} is required")
    raw = value[7:] if value.startswith("sha256:") else value
    if prefixed and not value.startswith("sha256:"):
        raise EffectBoundaryObservationError(f"{name} must use sha256: prefix")
    if len(raw) != 64 or any(ch not in _HEX for ch in raw):
        raise EffectBoundaryObservationError(f"{name} must be a sha256 digest")
    return value


def _require_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise EffectBoundaryObservationError("created_at is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EffectBoundaryObservationError("created_at must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise EffectBoundaryObservationError("created_at must be timezone-aware")
    return value


@dataclass(frozen=True)
class EffectBoundaryExecutionObservationV1:
    payload: Mapping[str, Any]

    @classmethod
    def verify(
        cls,
        payload: Mapping[str, Any],
    ) -> "EffectBoundaryExecutionObservationV1":
        data = dict(payload)
        if data.get("schema") != _SCHEMA:
            raise EffectBoundaryObservationError("unsupported EffectBoundary observation schema")
        missing = _FIELDS.difference(data)
        extra = set(data).difference(_FIELDS)
        if missing or extra:
            details: list[str] = []
            if missing:
                details.append("missing: " + ", ".join(sorted(missing)))
            if extra:
                details.append("unexpected: " + ", ".join(sorted(extra)))
            raise EffectBoundaryObservationError("invalid receipt fields (" + "; ".join(details) + ")")
        if data.get("authority_granted") is not False:
            raise EffectBoundaryObservationError("execution observation cannot grant authority")
        if data.get("status") not in _ALLOWED_STATUS:
            raise EffectBoundaryObservationError("invalid execution receipt status")
        if data.get("reht_decision") not in _ALLOWED_REHT:
            raise EffectBoundaryObservationError("invalid REHT decision")

        _require_digest("receipt_id", data.get("receipt_id"), prefixed=True)
        _require_digest("action_digest", data.get("action_digest"))
        if data.get("execution_context_hash") is not None:
            _require_digest("execution_context_hash", data.get("execution_context_hash"))
        if data.get("effect_result_digest") is not None:
            _require_digest("effect_result_digest", data.get("effect_result_digest"))
        _require_timestamp(data.get("created_at"))
        if data.get("postconditions_verified") not in {None, True, False}:
            raise EffectBoundaryObservationError("postconditions_verified must be boolean or null")

        decision = data.get("reht_decision")
        status = data.get("status")
        if decision == "ALLOW":
            if not data.get("clearance_ref") or not data.get("permit_ref"):
                raise EffectBoundaryObservationError("REHT ALLOW evidence requires clearance and permit")
        if status == "NOT_COMMITTED" and decision not in {"STEP_UP", "DENY"}:
            raise EffectBoundaryObservationError("NOT_COMMITTED requires restrictive REHT decision")
        if status in {"COMMITTED", "COMMITTED_UNVERIFIED", "COMMITTED_WITH_DEVIATION", "FAILED"}:
            if decision != "ALLOW":
                raise EffectBoundaryObservationError("effect-attempt status requires REHT ALLOW")

        core = {key: value for key, value in data.items() if key not in {"schema", "receipt_id"}}
        expected = "sha256:" + _digest(core)
        if data["receipt_id"] != expected:
            raise EffectBoundaryObservationError("execution receipt digest mismatch")

        return cls(payload=dict(payload))

    @property
    def receipt_id(self) -> str:
        return str(self.payload["receipt_id"])

    def to_worm_payload(self) -> dict[str, Any]:
        """Return the verified evidence payload exactly as admitted."""
        return dict(self.payload)


__all__ = [
    "EffectBoundaryExecutionObservationV1",
    "EffectBoundaryObservationError",
]
