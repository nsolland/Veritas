"""Veritas hardening tests: fail-closed digests, determinism, lifecycle, CLI."""

from datetime import datetime, timezone
import json

import pytest

from veritas.cli import main as cli_main
from veritas.contracts import (
    CompletedEvidencePackageV1,
    FinalEvidenceBindingV1,
    ObservedEventV1,
    ObservationPackageV1,
    StoredEvidenceReportV1,
    VeritasContractError,
)
from veritas.digest import canonical_digest, stable_json
from veritas.service import VeritasChainService
from veritas.worm import WORMLog


def _digest(seed: str = "x") -> str:
    return canonical_digest(seed)


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


def _completed() -> CompletedEvidencePackageV1:
    return CompletedEvidencePackageV1(
        record_id="rec-1",
        tenant_id="tenant-1",
        execution_id="exec-1",
        observation_package_ref="pkg-1",
        completion={
            "completion_id": "c-1",
            "execution_id": "exec-1",
            "observation_package_ref": "pkg-1",
            "observations": ["ok"],
        },
        iteration=1,
        recorded_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
    )


def _report() -> StoredEvidenceReportV1:
    return StoredEvidenceReportV1(
        report_id="rep-1",
        tenant_id="tenant-1",
        execution_id="exec-1",
        authorization_ref="auth-ref-1",
        authorization_digest=_digest(),
        observation_package_ref="pkg-1",
        observation_package_digest=_digest(),
        report={
            "report_id": "rep-1",
            "execution_id": "exec-1",
            "observations": [],
        },
        evidence_chain=[{"artifact_ref": "pkg-1", "artifact_digest": _digest()}],
        stored_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
    )


def _binding() -> FinalEvidenceBindingV1:
    return FinalEvidenceBindingV1(
        follow_on_id="fo-1",
        tenant_id="tenant-1",
        execution_id="exec-1",
        authorization_ref="auth-ref-1",
        authorization_digest=_digest(),
        observation_package_ref="pkg-1",
        observation_package_digest=_digest(),
        evidence_report_ref="rep-1",
        evidence_report_digest=_digest(),
        evidence_chain_head_ref="chain-head-1",
        evidence_chain_head_digest=_digest(),
        bound_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
    )


# ---- Fail-closed canonicalization ----


def test_stable_json_fails_closed_on_non_canonical_content():
    with pytest.raises(TypeError):
        stable_json({"at": datetime(2026, 8, 5, tzinfo=timezone.utc)})
    with pytest.raises(TypeError):
        canonical_digest({"obj": object()})


def test_stable_json_rejects_unordered_sets():
    with pytest.raises(TypeError):
        stable_json({"items": {"a", "b"}})


def test_digest_deterministic_across_key_order():
    assert canonical_digest({"b": 1, "a": 2}) == canonical_digest({"a": 2, "b": 1})


def test_digest_stable_across_unicode_and_whitespace():
    assert canonical_digest({"s": "v"}) == canonical_digest({"s": "v"})
    assert canonical_digest("å") == canonical_digest("å")


def test_negative_zero_canonicalized_like_jcs():
    assert stable_json(-0.0) == stable_json(0.0)


# ---- Contracts ----


def test_final_evidence_binding_round_trip():
    payload = _binding().to_payload()
    assert payload["follow_on_id"] == "fo-1"
    assert payload["evidence_report_digest"].startswith("sha256:")


def test_observation_package_rejects_duplicate_event_ids():
    dup = ObservationPackageV1(
        package_id="pkg-1",
        tenant_id="tenant-1",
        execution_id="exec-1",
        authorization_ref="auth-ref-1",
        authorization_digest=_digest(),
        handoff_ref="handoff-ref-1",
        handoff_digest=_digest(),
        observed_events=[_event("ev-1"), _event("ev-1")],
    )
    with pytest.raises(VeritasContractError, match="unique"):
        dup.to_payload()


def test_completed_evidence_iteration_must_be_positive():
    from dataclasses import replace

    bad = replace(_completed(), iteration=0)
    with pytest.raises(VeritasContractError, match="positive"):
        bad.to_payload()


def test_evidence_chain_must_start_with_observation_package():
    from dataclasses import replace

    bad = replace(
        _report(),
        evidence_chain=[{"artifact_ref": "other", "artifact_digest": _digest()}],
    )
    with pytest.raises(VeritasContractError, match="start with"):
        bad.to_payload()


# ---- Full lifecycle ----


def test_full_lifecycle_chain_verifies(tmp_path):
    worm = WORMLog()
    service = VeritasChainService(worm)
    service.store_observation_package(_package())
    service.store_completed_evidence(_completed())
    service.store_evidence_report(_report())
    service.store_final_evidence_binding(_binding())
    assert service.verify_chain() is True
    assert service.find_entry("fo-1") is not None

    ledger = tmp_path / "ledger.jsonl"
    worm.persist(ledger)
    loaded = WORMLog.load(ledger)
    assert loaded.verify() is True
    assert len(loaded.read_all()) == 4


def test_worm_append_after_load_keeps_chain_valid(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    worm = WORMLog()
    worm.append("e1", {"package_id": "pkg-1"})
    worm.persist(ledger)

    loaded = WORMLog.load(ledger)
    loaded.append("e2", {"package_id": "pkg-2"})
    assert loaded.verify() is True
    assert len(loaded.read_all()) == 2


def test_service_sequence_continues_after_reload(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    worm = WORMLog()
    service = VeritasChainService(worm)
    service.store_observation_package(_package())
    worm.persist(ledger)

    reloaded = VeritasChainService(WORMLog.load(ledger))
    reloaded.store_completed_evidence(_completed())
    payloads = [entry for entry in reloaded.worm.read_all()]
    assert [entry["sequence"] for entry in payloads] == [1, 2]


# ---- CLI ----


def test_cli_verifies_valid_ledger(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    worm = WORMLog()
    worm.append("e1", {"package_id": "pkg-1"})
    worm.persist(ledger)
    assert cli_main([str(ledger)]) == 0


def test_cli_detects_tampered_ledger(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    worm = WORMLog()
    worm.append("e1", {"package_id": "pkg-1"})
    worm.persist(ledger)

    entries = [
        json.loads(line) for line in ledger.read_text().strip().splitlines()
    ]
    entries[0]["package_id"] = "tampered"
    with open(ledger, "w") as fh:
        for entry in entries:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
    assert cli_main([str(ledger)]) == 1


def test_cli_missing_ledger_returns_2(tmp_path):
    assert cli_main([str(tmp_path / "missing.jsonl")]) == 2
