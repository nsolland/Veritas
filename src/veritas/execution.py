from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from veritas.contracts import ObservedEventV1

_SCHEMA = "valo.gateway.execution-observation.v1"
_ALLOWED_STATUS = {"succeeded", "failed", "partial", "blocked"}
_HEX = set("0123456789abcdef")


class GatewayExecutionObservationError(ValueError):
    pass


def _gateway_digest(value: Mapping[str, Any]) -> str:
    raw = json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _require_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise GatewayExecutionObservationError(f"{name} is required")
    return value


def _require_hex_digest(name: str, value: Any, *, prefixed: bool = False) -> str:
    text = _require_text(name, value)
    raw = text[7:] if prefixed and text.startswith("sha256:") else text
    if len(raw) != 64 or any(ch not in _HEX for ch in raw):
        raise GatewayExecutionObservationError(f"{name} must be a sha256 digest")
    if prefixed and not text.startswith("sha256:"):
        raise GatewayExecutionObservationError(f"{name} must use sha256: prefix")
    return text


def _require_timestamp(name: str, value: Any) -> str:
    text = _require_text(name, value)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise GatewayExecutionObservationError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise GatewayExecutionObservationError(f"{name} must be timezone-aware")
    return text


@dataclass(frozen=True)
class GatewayExecutionObservationV1:
    payload: Mapping[str, Any]

    @classmethod
    def verify(cls, payload: Mapping[str, Any]) -> GatewayExecutionObservationV1:
        data = dict(payload)
        if data.get("schema") != _SCHEMA:
            raise GatewayExecutionObservationError("unsupported Gateway observation schema")
        if data.get("authority_granted") is not False:
            raise GatewayExecutionObservationError("Veritas handoff must never grant authority")

        for name in (
            "execution_id",
            "permit_id",
            "execution_nonce",
            "clearance_id",
            "authority_envelope_id",
            "executor_id",
        ):
            _require_text(name, data.get(name))
        for name in ("permit_consumed_at", "started_at", "completed_at"):
            _require_timestamp(name, data.get(name))
        for name in (
            "clearance_digest",
            "authority_digest",
            "action_digest",
            "receipt_hash",
        ):
            _require_hex_digest(name, data.get(name))
        _require_hex_digest("observation_digest", data.get("observation_digest"), prefixed=True)

        status = data.get("status")
        if status not in _ALLOWED_STATUS:
            raise GatewayExecutionObservationError("invalid execution status")
        if data.get("response_digest") is not None:
            _require_hex_digest("response_digest", data.get("response_digest"))
        for name in ("previous_receipt_hash", "skill_binding_digest"):
            if data.get(name) is not None:
                value = data.get(name)
                if isinstance(value, str) and value.startswith("sha256:"):
                    _require_hex_digest(name, value, prefixed=True)
                else:
                    _require_hex_digest(name, value)

        claimed = data.pop("observation_digest")
        expected = _gateway_digest(data)
        if claimed != expected:
            raise GatewayExecutionObservationError("Gateway observation digest mismatch")

        started = datetime.fromisoformat(data["started_at"])
        completed = datetime.fromisoformat(data["completed_at"])
        consumed = datetime.fromisoformat(data["permit_consumed_at"])
        if completed < started:
            raise GatewayExecutionObservationError("completed_at precedes started_at")
        if consumed > completed:
            raise GatewayExecutionObservationError("permit consumed after execution completed")

        return cls(payload=dict(payload))

    def to_observed_event(self, *, source_id: str = "valo-gateway") -> ObservedEventV1:
        data = dict(self.payload)
        return ObservedEventV1(
            event_id=f"execution:{data['execution_id']}",
            source_id=source_id,
            event_type="execution_result_observed",
            observed_at=datetime.fromisoformat(data["completed_at"]),
            payload_digest=data["observation_digest"],
            provenance={
                "permit_id": data["permit_id"],
                "clearance_id": data["clearance_id"],
                "authority_envelope_id": data["authority_envelope_id"],
                "action_digest": data["action_digest"],
                "receipt_hash": data["receipt_hash"],
                "execution_status": data["status"],
                "authority_granted": False,
            },
        )
