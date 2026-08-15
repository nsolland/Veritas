from __future__ import annotations

import hashlib
import json

import pytest

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
        "tenant_id": "tenant-tee",
        "work_unit_id": "work-tee",
        "workspace_id": "workspace-tee",
        "workspace_digest": DIGEST,
        "workspace_expires_at": "2026-08-15T13:30:00+00:00",
        "program_ref": "program://confidential/run",
        "program_digest": DIGEST,
        "invocation_id": "invocation-tee",
        "candidate_id": "candidate-tee",
        "candidate_digest": DIGEST,
        "proposed_action_digest": DIGEST,
        "conformance_report_id": "conformance-tee",
        "conformance_digest": DIGEST,
        "source_state_digest": DIGEST,
        "conformed_state_digest": DIGEST,
        "source_event_position": 7,
        "conformed_at": "2026-08-15T13:00:00+00:00",
        "dependency_digest": DIGEST,
        "workspace_binding_digest": WORKSPACE_BINDING_DIGEST,
        "kernel_context_digest": KERNEL_CONTEXT_DIGEST,
    }


def _substrate_binding():
    return {
        "schema_version": "confidential_execution_binding.v1",
        "substrate_kind": "TEE",
        "attested_workspace_digest": DIGEST,
        "substrate_attestation_digest": "sha256:" + "d" * 64,
        "attestation_evidence_digest": "sha256:" + "e" * 64,
        "substrate_id": "gpu-node-1",
        "tee_type": "NVIDIA_CC",
        "gpu_identity": "gpu:0000:01:00.0",
        "cc_mode": "CONFIDENTIAL_COMPUTE",
        "measurement": "sha384:trusted-measurement",
        "attestation_verifier": "verifier:enterprise-tee",
        "attested_at": "2026-08-15T12:59:59Z",
        "valid_until": "2026-08-15T13:10:00Z",
        "max_attestation_age_seconds": 300,
        "model_digest": "sha256:" + "f" * 64,
        "workload_digest": "sha256:" + "1" * 64,
        "verification_status": "VERIFIED",
        "confidentiality_protected": True,
        "integrity_protected": True,
        "isolation_enforced": True,
        "authority_effect": "NO_AUTHORITY_CREATION",
        "can_issue_clearance": False,
    }


def _payload():
    substrate = _substrate_binding()
    data = {
        "schema": "valo.gateway.execution-observation.v1",
        "execution_id": "exec-tee-1",
        "permit_id": "permit-tee-1",
        "execution_nonce": "nonce-tee-1",
        "permit_consumed_at": "2026-08-15T13:00:01+00:00",
        "clearance_id": "clearance-tee-1",
        "clearance_digest": "2" * 64,
        "authority_envelope_id": "authority-tee-1",
        "authority_digest": "3" * 64,
        "action_digest": "4" * 64,
        "executor_id": "tool:confidential-compute",
        "started_at": "2026-08-15T13:00:01+00:00",
        "completed_at": "2026-08-15T13:00:02+00:00",
        "status": "succeeded",
        "response_digest": "5" * 64,
        "receipt_hash": "6" * 64,
        "previous_receipt_hash": None,
        "skill_binding_digest": None,
        "authority_granted": False,
        "workspace_binding": _workspace_binding(),
        "workspace_binding_digest": WORKSPACE_BINDING_DIGEST,
        "kernel_context_digest": KERNEL_CONTEXT_DIGEST,
        "execution_substrate_binding": substrate,
        "execution_substrate_digest": _digest(substrate),
    }
    data["observation_digest"] = _digest(data)
    return data


def _resign(payload):
    payload.pop("observation_digest", None)
    payload["observation_digest"] = _digest(payload)


def test_tee_evidence_is_preserved_as_provenance_without_authority_creation():
    payload = _payload()
    observation = GatewayExecutionObservationV1.verify(payload)
    event = observation.to_observed_event()
    package = observation.to_observation_package(tenant_id="tenant-tee")

    assert event.provenance["execution_substrate_binding"] == _substrate_binding()
    assert event.provenance["execution_substrate_digest"] == payload[
        "execution_substrate_digest"
    ]
    assert event.provenance["execution_substrate_evidence_only"] is True
    assert event.provenance["authority_granted"] is False
    assert package.observed_events[0].provenance[
        "execution_substrate_binding"
    ]["verification_status"] == "VERIFIED"

    worm = WORMLog()
    service = VeritasChainService(worm)
    service.store_gateway_execution_observation(payload, tenant_id="tenant-tee")
    entry = service.find_entry("gateway-execution:exec-tee-1")
    assert entry is not None
    provenance = entry["observed_events"][0]["provenance"]
    assert provenance["execution_substrate_binding"]["tee_type"] == "NVIDIA_CC"
    assert provenance["execution_substrate_evidence_only"] is True
    assert service.verify_chain() is True


def test_tampered_substrate_digest_fails_before_worm():
    payload = _payload()
    payload["execution_substrate_digest"] = "sha256:" + "0" * 64
    _resign(payload)
    worm = WORMLog()
    service = VeritasChainService(worm)

    with pytest.raises(
        GatewayExecutionObservationError,
        match="confidential execution substrate digest mismatch",
    ):
        service.store_gateway_execution_observation(payload, tenant_id="tenant-tee")
    assert worm.read_all() == []


@pytest.mark.parametrize(
    "missing", ["execution_substrate_binding", "execution_substrate_digest"]
)
def test_partial_substrate_binding_fails_closed(missing):
    payload = _payload()
    payload.pop(missing)
    _resign(payload)

    with pytest.raises(GatewayExecutionObservationError, match="must be bound together"):
        GatewayExecutionObservationV1.verify(payload)


def test_substrate_evidence_cannot_smuggle_clearance_authority():
    payload = _payload()
    payload["execution_substrate_binding"]["can_issue_clearance"] = True
    payload["execution_substrate_digest"] = _digest(
        payload["execution_substrate_binding"]
    )
    _resign(payload)

    with pytest.raises(
        GatewayExecutionObservationError, match="must not issue clearance"
    ):
        GatewayExecutionObservationV1.verify(payload)


def test_substrate_claim_change_without_resigning_breaks_observation_digest():
    payload = _payload()
    payload["execution_substrate_binding"]["gpu_identity"] = "gpu:tampered"
    payload["execution_substrate_digest"] = _digest(
        payload["execution_substrate_binding"]
    )

    with pytest.raises(GatewayExecutionObservationError, match="digest mismatch"):
        GatewayExecutionObservationV1.verify(payload)
