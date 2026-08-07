"""Tests for Veritas contracts, WORM chain and chain service."""

from datetime import UTC, datetime

import pytest

from veritas.contracts import (
    BoundaryNegativeEvidenceV1,
    CompletedEvidencePackageV1,
    ObservationPackageV1,
    ObservedEventV1,
    StoredEvidenceReportV1,
)
from veritas.digest import canonical_digest
from veritas.service import VeritasChainService
from veritas.worm import WORMLog


def _digest() -> str:
    return canonical_digest("x")


def _event(event_id: str = "ev-1") -> ObservedEventV1:
    return ObservedEventV1(
        event_id=event_id,
        source_id="source-1",
        event_type="observation",
        observed_at=datetime(2026, 8, 5, tzinfo=UTC),
        payload_digest=_digest(),
        provenance={"source_url": "https://example.invalid/x"},
    )


def _package(skill_binding_digest: str | None = None) -> ObservationPackageV1:
    return ObservationPackageV1(
        package_id="pkg-1",
        tenant_id="tenant-1",
        execution_id="exec-1",
        authorization_ref="auth-ref-1",
        authorization_digest=_digest(),
        handoff_ref="handoff-ref-1",
        handoff_digest=_digest(),
        observed_events=[_event()],
        skill_binding_digest=skill_binding_digest,
    )


def _negative_evidence(
    *,
    enforcement_ref: str = "racs-enforcement-1",
    boundary_digest: str | None = None,
) -> BoundaryNegativeEvidenceV1:
    return BoundaryNegativeEvidenceV1(
        evidence_id="neg-1",
        tenant_id="tenant-1",
        execution_id="exec-1",
        authorization_ref="reht-clearance-1",
        authorization_digest=_digest(),
        boundary_ref="execution-boundary-1",
        boundary_digest=boundary_digest or _digest(),
        enforcement_ref=enforcement_ref,
        enforcement_digest=_digest(),
        coverage_ref="coverage-attestation-1",
        coverage_digest=_digest(),
        excluded_action={"action_class": "patient_record.read", "target": "patient-7"},
        window_start=datetime(2026, 8, 5, 10, 0, tzinfo=UTC),
        window_end=datetime(2026, 8, 5, 10, 5, tzinfo=UTC),
        recorded_at=datetime(2026, 8, 5, 10, 6, tzinfo=UTC),
    )


def test_observation_package_round_trip():
    payload = _package().to_payload()
    assert payload["package_id"] == "pkg-1"
    assert payload["observed_events"][0]["event_id"] == "ev-1"
    assert len(payload["observed_events"]) == 1
    assert "skill_binding_digest" not in payload


def test_observation_package_attests_agent_skill_binding():
    skill_binding = "sha256:" + "a" * 64
    payload = _package(skill_binding).to_payload()
    assert payload["skill_binding_digest"] == skill_binding


def test_observation_package_rejects_invalid_agent_skill_binding():
    with pytest.raises(ValueError, match="skill_binding_digest"):
        _package("sha256:" + "a" * 63).to_payload()


def test_agent_skill_binding_changes_canonical_receipt_digest():
    legacy = canonical_digest(_package().to_payload())
    bound = canonical_digest(_package("sha256:" + "b" * 64).to_payload())
    assert legacy != bound


def test_negative_evidence_is_explicitly_boundary_derived():
    payload = _negative_evidence().to_payload()
    assert payload["negative_evidence_basis"] == "enforced_boundary"
    assert payload["authorization_ref"] == "reht-clearance-1"
    assert payload["boundary_ref"] == "execution-boundary-1"
    assert payload["enforcement_ref"] == "racs-enforcement-1"
    assert payload["coverage_ref"] == "coverage-attestation-1"
    assert payload["excluded_action"]["action_class"] == "patient_record.read"


def test_negative_evidence_rejects_missing_enforcement_binding():
    with pytest.raises(ValueError, match="enforcement_ref"):
        _negative_evidence(enforcement_ref="").to_payload()


def test_negative_evidence_rejects_invalid_window():
    evidence = _negative_evidence()
    invalid = BoundaryNegativeEvidenceV1(
        evidence_id=evidence.evidence_id,
        tenant_id=evidence.tenant_id,
        execution_id=evidence.execution_id,
        authorization_ref=evidence.authorization_ref,
        authorization_digest=evidence.authorization_digest,
        boundary_ref=evidence.boundary_ref,
        boundary_digest=evidence.boundary_digest,
        enforcement_ref=evidence.enforcement_ref,
        enforcement_digest=evidence.enforcement_digest,
        coverage_ref=evidence.coverage_ref,
        coverage_digest=evidence.coverage_digest,
        excluded_action=evidence.excluded_action,
        window_start=evidence.window_end,
        window_end=evidence.window_start,
        recorded_at=evidence.recorded_at,
    )
    with pytest.raises(ValueError, match="window_end"):
        invalid.to_payload()


def test_negative_evidence_digest_changes_with_boundary():
    first = canonical_digest(_negative_evidence().to_payload())
    second = canonical_digest(
        _negative_evidence(boundary_digest="sha256:" + "b" * 64).to_payload()
    )
    assert first != second


def test_completed_evidence_rejects_analysis_fields():
    completion = {
        "completion_id": "c-1",
        "execution_id": "exec-1",
        "observation_package_ref": "pkg-1",
        "observations": ["o"],
        "classification": "secret",
    }
    with pytest.raises(ValueError, match="analysis fields"):
        CompletedEvidencePackageV1(
            record_id="rec-1",
            tenant_id="t",
            execution_id="exec-1",
            observation_package_ref="pkg-1",
            completion=completion,
            iteration=1,
            recorded_at=datetime(2026, 8, 5, tzinfo=UTC),
        ).to_payload()


def test_worm_read_snapshot_cannot_tamper_with_chain():
    worm = WORMLog()
    worm.append("e1", {"package_id": "pkg-1"})
    worm.append("e2", {"package_id": "pkg-2"})
    snapshot = worm.read_all()
    snapshot[0]["package_id"] = "tampered"
    assert worm.verify() is True
    assert worm.read_all()[0]["package_id"] == "pkg-1"


def test_worm_persist_and_load(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    worm = WORMLog()
    worm.append("e1", {"package_id": "pkg-1"})
    worm.persist(ledger)
    loaded = WORMLog.load(ledger)
    assert loaded.verify() is True
    assert len(loaded.read_all()) == 1


def test_chain_service_records_and_verifies():
    worm = WORMLog()
    service = VeritasChainService(worm)
    service.store_observation_package(_package())
    service.store_boundary_negative_evidence(_negative_evidence())
    report = StoredEvidenceReportV1(
        report_id="rep-1",
        tenant_id="t",
        execution_id="exec-1",
        authorization_ref="auth-ref-1",
        authorization_digest=_digest(),
        observation_package_ref="pkg-1",
        observation_package_digest=_digest(),
        report={"report_id": "rep-1", "execution_id": "exec-1", "observations": []},
        evidence_chain=[
            {"artifact_ref": "pkg-1", "artifact_digest": _digest()},
        ],
        stored_at=datetime(2026, 8, 5, tzinfo=UTC),
    )
    service.store_evidence_report(report)
    assert service.verify_chain() is True
    assert service.find_entry("pkg-1") is not None
    assert service.find_entry("neg-1") is not None
    assert service.find_entry("rep-1") is not None
