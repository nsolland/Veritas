from __future__ import annotations

import hashlib
import json

import pytest

from veritas.contracts import VeritasContractError
from veritas.execution import (
    GatewayExecutionObservationError,
    GatewayExecutionObservationV1,
)
from veritas.service import VeritasChainService
from veritas.worm import WORMLog

DIGEST = "sha256:" + "a" * 64
WORKSPACE_BINDING_DIGEST = "sha256:" + "b" * 64
KERNEL_CONTEXT_DIGEST = "sha256:" + "c" * 64


def _digest(value):
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _workspace_binding():
    return {
        "tenant_id": "tenant-1",
        "work_unit_id": "work-1",
        "workspace_id": "workspace-1",
        "workspace_digest": DIGEST,
        "workspace_expires_at": "2026-08-12T09:30:00+00:00",
        "program_ref": "program://workspace-1/function-1",
        "program_digest": DIGEST,
        "invocation_id": "invocation-1",
        "candidate_id": "candidate-1",
        "candidate_digest": DIGEST,
        "proposed_action_digest": DIGEST,
        "conformance_report_id": "conformance-1",
        "conformance_digest": DIGEST,
        "source_state_digest": DIGEST,
        "conformed_state_digest": DIGEST,
        "source_event_position": 42,
        "conformed_at": "2026-08-12T09:00:00+00:00",
        "dependency_digest": DIGEST,
        "workspace_binding_digest": WORKSPACE_BINDING_DIGEST,
        "kernel_context_digest": KERNEL_CONTEXT_DIGEST,
    }


def _payload(*, governed: bool = True):
    data = {
        "schema": "valo.gateway.execution-observation.v1",
        "execution_id": "exec-workspace-1",
        "permit_id": "permit-1",
        "execution_nonce": "nonce-1",
        "permit_consumed_at": "2026-08-12T09:00:00+00:00",
        "clearance_id": "clearance-1",
        "clearance_digest": "d" * 64,
        "authority_envelope_id": "authority-1",
        "authority_digest": "e" * 64,
        "action_digest": "f" * 64,
        "executor_id": "tool:test",
        "started_at": "2026-08-12T09:00:00+00:00",
        "completed_at": "2026-08-12T09:00:01+00:00",
        "status": "succeeded",
        "response_digest": "1" * 64,
        "receipt_hash": "2" * 64,
        "previous_receipt_hash": None,
        "skill_binding_digest": None,
        "authority_granted": False,
    }
    if governed:
        data.update(
            {
                "workspace_binding": _workspace_binding(),
                "workspace_binding_digest": WORKSPACE_BINDING_DIGEST,
                "kernel_context_digest": KERNEL_CONTEXT_DIGEST,
            }
        )
    data["observation_digest"] = _digest(data)
    return data


def _resign(payload):
    payload.pop("observation_digest", None)
    payload["observation_digest"] = _digest(payload)


def test_workspace_lineage_is_preserved_as_non_authoritative_worm_evidence():
    payload = _payload()
    observation = GatewayExecutionObservationV1.verify(payload)
    event = observation.to_observed_event()
    package = observation.to_observation_package(tenant_id="tenant-1")
    package_payload = package.to_payload()

    assert event.provenance["workspace_binding"] == _workspace_binding()
    assert event.provenance["workspace_binding_digest"] == WORKSPACE_BINDING_DIGEST
    assert event.provenance["kernel_context_digest"] == KERNEL_CONTEXT_DIGEST
    assert event.provenance["authority_granted"] is False
    assert package_payload["workspace_binding"] == _workspace_binding()
    assert package_payload["workspace_binding_digest"] == WORKSPACE_BINDING_DIGEST
    assert package_payload["kernel_context_digest"] == KERNEL_CONTEXT_DIGEST

    worm = WORMLog()
    service = VeritasChainService(worm)
    service.store_gateway_execution_observation(payload, tenant_id="tenant-1")
    entry = service.find_entry("gateway-execution:exec-workspace-1")

    assert entry is not None
    assert entry["workspace_binding"]["source_event_position"] == 42
    assert entry["workspace_binding"]["candidate_id"] == "candidate-1"
    assert service.verify_chain() is True


def test_legacy_observation_payload_remains_workspace_field_free():
    package = GatewayExecutionObservationV1.verify(
        _payload(governed=False)
    ).to_observation_package(tenant_id="tenant-1")
    package_payload = package.to_payload()

    assert "workspace_binding" not in package_payload
    assert "workspace_binding_digest" not in package_payload
    assert "kernel_context_digest" not in package_payload


@pytest.mark.parametrize(
    "missing",
    ["workspace_binding", "workspace_binding_digest", "kernel_context_digest"],
)
def test_partial_workspace_binding_fails_closed(missing):
    payload = _payload()
    payload.pop(missing)
    _resign(payload)

    with pytest.raises(GatewayExecutionObservationError, match="must be bound together"):
        GatewayExecutionObservationV1.verify(payload)


def test_malformed_lineage_digest_fails_closed():
    payload = _payload()
    payload["workspace_binding"]["workspace_digest"] = "not-a-digest"
    _resign(payload)

    with pytest.raises(GatewayExecutionObservationError, match="must be a sha256 digest"):
        GatewayExecutionObservationV1.verify(payload)


def test_nested_and_top_level_binding_drift_fails_closed():
    payload = _payload()
    payload["workspace_binding"]["kernel_context_digest"] = "sha256:" + "0" * 64
    _resign(payload)

    with pytest.raises(GatewayExecutionObservationError, match="binding digest mismatch"):
        GatewayExecutionObservationV1.verify(payload)


def test_lineage_drift_breaks_gateway_observation_digest():
    payload = _payload()
    payload["workspace_binding"]["candidate_id"] = "candidate-tampered"

    with pytest.raises(GatewayExecutionObservationError, match="digest mismatch"):
        GatewayExecutionObservationV1.verify(payload)


def test_lineage_cannot_smuggle_authority_semantics():
    payload = _payload()
    payload["workspace_binding"]["decision"] = "ALLOW"
    _resign(payload)

    with pytest.raises(GatewayExecutionObservationError, match="unexpected: decision"):
        GatewayExecutionObservationV1.verify(payload)


def test_workspace_tenant_mismatch_never_reaches_worm():
    worm = WORMLog()
    service = VeritasChainService(worm)

    with pytest.raises(VeritasContractError, match="tenant mismatch"):
        service.store_gateway_execution_observation(
            _payload(), tenant_id="tenant-other"
        )

    assert worm.read_all() == []


def test_post_write_workspace_mutation_breaks_worm_chain():
    worm = WORMLog()
    service = VeritasChainService(worm)
    service.store_gateway_execution_observation(_payload(), tenant_id="tenant-1")

    worm._entries[0]["workspace_binding"]["candidate_id"] = "candidate-tampered"

    assert service.verify_chain() is False
