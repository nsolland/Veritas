"""Tests for CSRD/ESRS Veritas sustainability bindings (#1492, Slice 9)."""

from __future__ import annotations

import pytest

from veritas.sustainability import (
    AssuranceEvidencePackBindingV1,
    SustainabilityArtifactV1,
    SustainabilityVeritasService,
)
from veritas.worm import WORMLog


def _artifact(artifact_id="a-1", artifact_type="datapoint", prior_ref=None, **overrides):
    kwargs = {
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "tenant_id": "t1",
        "entity_id": "e1",
        "period_id": "p-2026",
        "payload_digest": "digest-1",
    }
    if prior_ref is not None:
        kwargs["prior_ref"] = prior_ref
    kwargs.update(overrides)
    return SustainabilityArtifactV1(**kwargs)


def test_artifacts_are_append_only():
    worm = WORMLog()
    svc = SustainabilityVeritasService(worm)
    svc.record_artifact(_artifact("a-1", "source_evidence"))
    svc.record_artifact(_artifact("a-2", "calculation_run"))
    assert len(worm.read_all()) == 2
    # integrity verifies
    assert svc.verify_integrity("a-1") is True
    assert svc.verify_integrity("missing") is False


def test_duplicate_artifact_rejected():
    worm = WORMLog()
    svc = SustainabilityVeritasService(worm)
    svc.record_artifact(_artifact("a-1"))
    from veritas.worm import WORMIntegrityError

    with pytest.raises(WORMIntegrityError, match="duplicate"):
        svc.record_artifact(_artifact("a-1"))


def test_restatement_preserves_history():
    worm = WORMLog()
    svc = SustainabilityVeritasService(worm)
    svc.record_artifact(_artifact("report-2025", "report_freeze"))
    svc.record_artifact(_artifact("report-2026", "restatement", prior_ref="report-2025"))
    # both remain; 2026 points to 2025; history unchanged
    assert svc.verify_integrity("report-2025") is True
    assert svc.verify_integrity("report-2026") is True
    assert svc.restatement_preserves_history("report-2025", "report-2026") is True


def test_assurance_opinion_hash_bound():
    worm = WORMLog()
    svc = SustainabilityVeritasService(worm)
    binding = AssuranceEvidencePackBindingV1(
        pack_binding_id="pb-1",
        report_freeze_ref="report-2025",
        report_freeze_digest="d-report-2025",
        opinion_ref="opinion-1",
        opinion_digest="d-opinion-1",
    )
    svc.bind_assurance_opinion(binding)
    assert svc.verify_integrity("pb-1") is True
    entry = next(e for e in worm.read_all() if e["id"] == "pb-1")
    assert entry["report_freeze_digest"] == "d-report-2025"
    assert entry["opinion_digest"] == "d-opinion-1"


def test_all_artifact_types_recordable():
    worm = WORMLog()
    svc = SustainabilityVeritasService(worm)
    types = [
        "source_evidence", "calculation_run", "datapoint", "control_execution",
        "materiality_decision", "reht_clearance", "report_freeze",
        "publish_receipt", "restatement", "assurance_opinion",
    ]
    for i, t in enumerate(types):
        svc.record_artifact(_artifact(f"a-{i}", t))
    assert len(worm.read_all()) == len(types)


def test_veritas_verifies_integrity_not_correctness():
    """Veritas proves integrity; it never attests professional correctness."""
    worm = WORMLog()
    svc = SustainabilityVeritasService(worm)
    svc.record_artifact(_artifact("a-1"))
    assert svc.verify_integrity("a-1") is True
    # There is no correctness/compliance field anywhere in the contract.
    artifact = _artifact()
    assert not hasattr(artifact, "compliant")
    assert not hasattr(artifact, "correct")
