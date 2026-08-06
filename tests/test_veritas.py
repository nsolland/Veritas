"""Tests for Veritas contracts, WORM integrity and chain service."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from veritas.contracts import (
    CompletedEvidencePackageV1,
    ObservationPackageV1,
    ObservedEventV1,
    StoredEvidenceReportV1,
)
from veritas.digest import CanonicalizationError, canonical_digest
from veritas.service import VeritasChainError, VeritasChainService
from veritas.worm import WORMIntegrityError, WORMLog


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


def _package(package_id: str = "pkg-1") -> ObservationPackageV1:
    return ObservationPackageV1(
        package_id=package_id,
        tenant_id="tenant-1",
        execution_id="exec-1",
        authorization_ref="auth-ref-1",
        authorization_digest=_digest(),
        handoff_ref="handoff-ref-1",
        handoff_digest=_digest(),
        observed_events=[_event()],
    )


def _report(report_id: str = "rep-1") -> StoredEvidenceReportV1:
    return StoredEvidenceReportV1(
        report_id=report_id,
        tenant_id="tenant-1",
        execution_id="exec-1",
        authorization_ref="auth-ref-1",
        authorization_digest=_digest(),
        observation_package_ref="pkg-1",
        observation_package_digest=_digest(),
        report={
            "report_id": report_id,
            "execution_id": "exec-1",
            "observations": [],
        },
        evidence_chain=[
            {"artifact_ref": "pkg-1", "artifact_digest": _digest()},
        ],
        stored_at=datetime(2026, 8, 5, tzinfo=UTC),
    )


def test_observation_package_round_trip() -> None:
    payload = _package().to_payload()
    assert payload["package_id"] == "pkg-1"
    assert payload["observed_events"][0]["event_id"] == "ev-1"
    assert len(payload["observed_events"]) == 1


def test_observation_package_rejects_duplicate_event_ids() -> None:
    package = ObservationPackageV1(
        package_id="pkg-1",
        tenant_id="tenant-1",
        execution_id="exec-1",
        authorization_ref="auth-ref-1",
        authorization_digest=_digest(),
        handoff_ref="handoff-ref-1",
        handoff_digest=_digest(),
        observed_events=[_event(), _event()],
    )
    with pytest.raises(ValueError, match="event ids must be unique"):
        package.to_payload()


def test_completed_evidence_rejects_analysis_fields() -> None:
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
            tenant_id="tenant-1",
            execution_id="exec-1",
            observation_package_ref="pkg-1",
            completion=completion,
            iteration=1,
            recorded_at=datetime(2026, 8, 5, tzinfo=UTC),
        ).to_payload()


@pytest.mark.parametrize("value", [{"unsupported": {"set"}}, {"number": float("nan")}])
def test_canonical_digest_rejects_non_canonical_json(value: object) -> None:
    with pytest.raises(CanonicalizationError, match="strict canonical JSON"):
        canonical_digest(value)


def test_worm_defensively_copies_payload_and_read_views() -> None:
    nested = {"observations": [{"value": 1}]}
    worm = WORMLog()
    worm.append("e1", nested)

    nested["observations"][0]["value"] = 2
    snapshot = worm.read_all()
    snapshot[0]["observations"][0]["value"] = 3

    assert worm.read_all()[0]["observations"][0]["value"] == 1
    assert worm.verify() is True


@pytest.mark.parametrize("reserved", ["id", "prev", "hash"])
def test_worm_rejects_reserved_payload_fields(reserved: str) -> None:
    worm = WORMLog()
    with pytest.raises(WORMIntegrityError, match="reserved fields"):
        worm.append("e1", {reserved: "override"})


def test_worm_rejects_duplicate_entry_ids() -> None:
    worm = WORMLog()
    worm.append("e1", {"package_id": "pkg-1"})
    with pytest.raises(WORMIntegrityError, match="duplicate entry id"):
        worm.append("e1", {"package_id": "pkg-2"})
    assert worm.verify() is True


def test_worm_tail_zero_is_empty_and_negative_is_rejected() -> None:
    worm = WORMLog()
    worm.append("e1", {"package_id": "pkg-1"})
    assert worm.tail(0) == []
    with pytest.raises(ValueError, match="non-negative"):
        worm.tail(-1)


def test_worm_persist_is_append_only_and_idempotent(tmp_path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    worm = WORMLog(ledger)
    worm.append("e1", {"package_id": "pkg-1"})
    worm.persist()
    first_bytes = ledger.read_bytes()

    worm.append("e2", {"package_id": "pkg-2"})
    worm.persist()
    second_bytes = ledger.read_bytes()
    worm.persist()

    assert second_bytes.startswith(first_bytes)
    assert ledger.read_bytes() == second_bytes
    assert len(ledger.read_text(encoding="utf-8").splitlines()) == 2
    assert WORMLog.load(ledger).verify() is True


def test_worm_load_rejects_tampered_chain(tmp_path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    worm = WORMLog(ledger)
    worm.append("e1", {"package_id": "pkg-1"})
    worm.persist()

    entry = json.loads(ledger.read_text(encoding="utf-8"))
    entry["package_id"] = "tampered"
    ledger.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    with pytest.raises(WORMIntegrityError, match="verification failed"):
        WORMLog.load(ledger)


def test_worm_load_rejects_invalid_json(tmp_path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(WORMIntegrityError, match="invalid ledger JSON at line 1"):
        WORMLog.load(ledger)


def test_worm_persist_rejects_divergent_existing_prefix(tmp_path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    worm = WORMLog(ledger)
    worm.append("e1", {"package_id": "pkg-1"})
    worm.persist()

    entry = json.loads(ledger.read_text(encoding="utf-8"))
    entry["package_id"] = "different"
    ledger.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    with pytest.raises(WORMIntegrityError, match="diverges"):
        worm.persist()


def test_chain_service_records_and_verifies() -> None:
    worm = WORMLog()
    service = VeritasChainService(worm)
    service.store_observation_package(_package())
    service.store_evidence_report(_report())

    assert service.verify_chain() is True
    assert service.find_entry("pkg-1") is not None
    assert service.find_entry("rep-1") is not None
    assert [entry["sequence"] for entry in worm.read_all()] == [1, 2]


def test_chain_service_resumes_sequence_after_reload(tmp_path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    worm = WORMLog(ledger)
    VeritasChainService(worm).store_observation_package(_package())
    worm.persist()

    loaded = WORMLog.load(ledger)
    VeritasChainService(loaded).store_evidence_report(_report())

    assert [entry["sequence"] for entry in loaded.read_all()] == [1, 2]
    assert loaded.verify() is True


def test_chain_service_duplicate_record_fails_without_sequence_gap() -> None:
    worm = WORMLog()
    service = VeritasChainService(worm)
    service.store_observation_package(_package())

    with pytest.raises(VeritasChainError, match="duplicate entry id"):
        service.store_observation_package(_package())

    service.store_evidence_report(_report())
    assert [entry["sequence"] for entry in worm.read_all()] == [1, 2]


def test_find_entry_returns_defensive_snapshot() -> None:
    worm = WORMLog()
    service = VeritasChainService(worm)
    service.store_observation_package(_package())

    found = service.find_entry("pkg-1")
    assert found is not None
    found["package_id"] = "tampered"

    assert service.find_entry("pkg-1") is not None
    assert worm.verify() is True
