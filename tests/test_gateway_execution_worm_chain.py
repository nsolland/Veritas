from __future__ import annotations

import hashlib
import json

import pytest

from veritas.execution import GatewayExecutionObservationError, GatewayExecutionObservationV1
from veritas.service import VeritasChainService
from veritas.worm import WORMLog


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
        "execution_id": "exec-worm-1",
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


def test_gateway_execution_observation_builds_authorization_bound_package():
    package = GatewayExecutionObservationV1.verify(_payload()).to_observation_package(
        tenant_id="tenant-1"
    )
    payload = package.to_payload()

    assert payload["package_id"] == "gateway-execution:exec-worm-1"
    assert payload["execution_id"] == "exec-worm-1"
    assert payload["authorization_ref"] == "clearance:clearance-1"
    assert payload["authorization_digest"] == "sha256:" + "a" * 64
    assert payload["handoff_ref"] == "gateway-observation:exec-worm-1"
    assert payload["handoff_digest"] == _payload()["observation_digest"]
    assert payload["observed_events"][0]["event_id"] == "execution:exec-worm-1"
    assert payload["observed_events"][0]["provenance"]["authority_granted"] is False


def test_verified_gateway_execution_is_appended_to_worm_and_chain_verifies():
    worm = WORMLog()
    service = VeritasChainService(worm)

    entry_hash = service.store_gateway_execution_observation(
        _payload(), tenant_id="tenant-1"
    )

    assert isinstance(entry_hash, str)
    assert service.verify_chain() is True
    entry = service.find_entry("gateway-execution:exec-worm-1")
    assert entry is not None
    assert entry["authorization_ref"] == "clearance:clearance-1"
    assert entry["handoff_ref"] == "gateway-observation:exec-worm-1"
    assert entry["sequence"] == 1


def test_tampered_gateway_execution_never_reaches_worm():
    worm = WORMLog()
    service = VeritasChainService(worm)
    payload = _payload()
    payload["status"] = "failed"

    with pytest.raises(GatewayExecutionObservationError, match="digest mismatch"):
        service.store_gateway_execution_observation(payload, tenant_id="tenant-1")

    assert worm.read_all() == []
    assert service.verify_chain() is True


def test_gateway_execution_worm_entry_remains_non_authoritative():
    worm = WORMLog()
    service = VeritasChainService(worm)
    service.store_gateway_execution_observation(_payload(), tenant_id="tenant-1")

    entry = service.find_entry("gateway-execution:exec-worm-1")
    assert entry is not None
    event = entry["observed_events"][0]
    assert event["provenance"]["authority_granted"] is False
    assert "decision" not in event["provenance"]
