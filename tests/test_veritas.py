"""Tests for Veritas contracts, WORM chain and chain service."""

from datetime import datetime, timezone

import pytest

from veritas.contracts import (
    CompletedEvidencePackageV1,
    ObservedEventV1,
    ObservationPackageV1,
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
        observed_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
        payload_digest=_digest(),
        provenance={"source_url": "https://example.invalid/x"},
    )


def _package() -> ObservationPackageV1:
    return ObservationPackageV1(
        package_id="pkg-1",
        tenant_id="tenant-1",
        execution_id="exec-1",
        authorization_ref="auth-ref-1",
        authorization_digest=_digest(),
        handoff_ref="handoff-ref-1",
        handoff_digest=_digest(),
        observed_events=[_event()],
    )


def test_observation_package_round_trip():
    payload = _package().to_payload()
    assert payload["package_id"] == "pkg-1"
    assert payload["observed_events"][0]["event_id"] == "ev-1"
    assert len(payload["observed_events"]) == 1


def test_completed_evidence_rejects_analysis_fields():
    completion = {
        "completion_id": "c-1",
        "execution_id": "exec-1",
        "observation_package_ref": "pkg-1",
        "observations": ["o"],
        "classification": "secret",  # forbidden
    }
    with pytest.raises(ValueError, match="analysis fields"):
        CompletedEvidencePackageV1(
            record_id="rec-1",
            tenant_id="t",
            execution_id="exec-1",
            observation_package_ref="pkg-1",
            completion=completion,
            iteration=1,
            recorded_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
        ).to_payload()


def test_worm_chain_verifies_and_detects_tamper():
    worm = WORMLog()
    worm.append("e1", {"package_id": "pkg-1"})
    worm.append("e2", {"package_id": "pkg-2"})
    assert worm.verify() is True
    entries = worm.read_all()
    entries[0]["package_id"] = "tampered"
    assert worm.verify() is False


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
        stored_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
    )
    service.store_evidence_report(report)
    assert service.verify_chain() is True
    assert service.find_entry("pkg-1") is not None
    assert service.find_entry("rep-1") is not None
