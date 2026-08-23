from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest

from veritas import (
    EffectBoundaryExecutionObservationV1,
    EffectBoundaryObservationError,
    VeritasChainService,
    WORMLog,
)


def _digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _receipt(*, status: str = "COMMITTED", decision: str | None = "ALLOW") -> dict:
    core = {
        "status": status,
        "action_digest": _digest({"action_id": "a1"}),
        "execution_context_hash": _digest({"state": "ready"}),
        "reht_decision": decision,
        "clearance_ref": "clearance:1" if decision == "ALLOW" else None,
        "permit_ref": "permit:1" if decision == "ALLOW" else None,
        "effect_name": "payment-adapter",
        "effect_result_digest": _digest({"ok": True}) if status.startswith("COMMITTED") else None,
        "reason": None,
        "created_at": "2026-08-23T20:00:00Z",
        "postconditions_verified": True if status == "COMMITTED" else None,
        "authority_granted": False,
    }
    return {
        "schema": "valo.reht.effect-boundary-observation.v1",
        "receipt_id": "sha256:" + _digest(core),
        **core,
    }


def test_valid_effect_boundary_receipt_verifies() -> None:
    receipt = _receipt()
    observation = EffectBoundaryExecutionObservationV1.verify(receipt)
    assert observation.receipt_id == receipt["receipt_id"]
    assert observation.to_worm_payload() == receipt


def test_tampered_receipt_is_rejected_before_storage() -> None:
    receipt = _receipt()
    receipt["effect_name"] = "other-adapter"
    with pytest.raises(EffectBoundaryObservationError, match="digest mismatch"):
        EffectBoundaryExecutionObservationV1.verify(receipt)


def test_receipt_cannot_claim_authority() -> None:
    receipt = _receipt()
    receipt["authority_granted"] = True
    with pytest.raises(EffectBoundaryObservationError, match="cannot grant authority"):
        EffectBoundaryExecutionObservationV1.verify(receipt)


def test_allow_effect_attempt_requires_clearance_and_permit() -> None:
    receipt = _receipt(status="FAILED")
    receipt["clearance_ref"] = None
    core = {k: v for k, v in receipt.items() if k not in {"schema", "receipt_id"}}
    receipt["receipt_id"] = "sha256:" + _digest(core)
    with pytest.raises(EffectBoundaryObservationError, match="requires clearance and permit"):
        EffectBoundaryExecutionObservationV1.verify(receipt)


def test_not_committed_requires_restrictive_reht_decision() -> None:
    receipt = _receipt(status="NOT_COMMITTED", decision="ALLOW")
    with pytest.raises(EffectBoundaryObservationError, match="restrictive REHT decision"):
        EffectBoundaryExecutionObservationV1.verify(receipt)


def test_pre_reht_mechanical_block_is_valid_non_authoritative_evidence() -> None:
    receipt = _receipt(status="BLOCKED", decision=None)
    receipt["clearance_ref"] = None
    receipt["permit_ref"] = None
    core = {k: v for k, v in receipt.items() if k not in {"schema", "receipt_id"}}
    receipt["receipt_id"] = "sha256:" + _digest(core)
    observation = EffectBoundaryExecutionObservationV1.verify(receipt)
    assert observation.payload["authority_granted"] is False


def test_service_verifies_then_appends_to_existing_worm_chain() -> None:
    worm = WORMLog()
    service = VeritasChainService(worm)
    receipt = _receipt()

    chain_hash = service.store_effect_boundary_execution_observation(receipt)

    assert isinstance(chain_hash, str)
    assert service.verify_chain() is True
    assert len(worm.read_all()) == 1
    stored = service.find_entry(receipt["receipt_id"])
    assert stored is not None
    assert stored["receipt_id"] == receipt["receipt_id"]
    assert stored["authority_granted"] is False


def test_tampered_receipt_never_reaches_worm() -> None:
    worm = WORMLog()
    service = VeritasChainService(worm)
    receipt = _receipt()
    tampered = deepcopy(receipt)
    tampered["action_digest"] = _digest({"action_id": "evil"})

    with pytest.raises(EffectBoundaryObservationError):
        service.store_effect_boundary_execution_observation(tampered)

    assert worm.read_all() == []
    assert service.verify_chain() is True
