from __future__ import annotations

import hashlib
import json

import pytest

from veritas.execution import (
    GatewayExecutionObservationError,
    GatewayExecutionObservationV1,
)


def _digest(value):
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _payload():
    data = {
        "schema": "valo.gateway.execution-observation.v1",
        "execution_id": "exec-1",
        "permit_id": "permit-1",
        "execution_nonce": "nonce-1",
        "permit_consumed_at": "2026-08-10T09:00:00+00:00",
        "clearance_id": "clearance-1",
        "clearance_digest": "a" * 64,
        "authority_envelope_id": "authority-1",
        "authority_digest": "b" * 64,
        "action_digest": "c" * 64,
        "executor_id": "tool:test",
        "started_at": "2026-08-10T09:00:00+00:00",
        "completed_at": "2026-08-10T09:00:01+00:00",
        "status": "succeeded",
        "response_digest": "d" * 64,
        "receipt_hash": "e" * 64,
        "previous_receipt_hash": None,
        "skill_binding_digest": None,
        "authority_granted": False,
    }
    data["observation_digest"] = _digest(data)
    return data


def test_verified_gateway_observation_becomes_non_authoritative_event():
    observation = GatewayExecutionObservationV1.verify(_payload())
    event = observation.to_observed_event()

    assert event.event_id == "execution:exec-1"
    assert event.event_type == "execution_result_observed"
    assert event.payload_digest.startswith("sha256:")
    assert event.provenance["permit_id"] == "permit-1"
    assert event.provenance["execution_status"] == "succeeded"
    assert event.provenance["authority_granted"] is False


def test_tampered_execution_status_breaks_observation_digest():
    payload = _payload()
    payload["status"] = "failed"

    with pytest.raises(GatewayExecutionObservationError, match="digest mismatch"):
        GatewayExecutionObservationV1.verify(payload)


def test_authority_smuggling_is_rejected_even_with_valid_digest():
    payload = _payload()
    payload["authority_granted"] = True
    payload.pop("observation_digest")
    payload["observation_digest"] = _digest(payload)

    with pytest.raises(GatewayExecutionObservationError, match="never grant authority"):
        GatewayExecutionObservationV1.verify(payload)


def test_missing_consumed_permit_time_fails_closed():
    payload = _payload()
    payload["permit_consumed_at"] = ""
    payload.pop("observation_digest")
    payload["observation_digest"] = _digest(payload)

    with pytest.raises(GatewayExecutionObservationError, match="permit_consumed_at is required"):
        GatewayExecutionObservationV1.verify(payload)


def test_execution_timeline_cannot_complete_before_start():
    payload = _payload()
    payload["completed_at"] = "2026-08-10T08:59:59+00:00"
    payload.pop("observation_digest")
    payload["observation_digest"] = _digest(payload)

    with pytest.raises(GatewayExecutionObservationError, match="precedes"):
        GatewayExecutionObservationV1.verify(payload)
