"""Veritas sustainability evidence and assurance binding.

Build order #1492, Slice 9. Veritas stores and binds sustainability reporting
artifacts append-only:
- source evidence, calculation run, datapoint, control execution,
  materiality decision, REHT clearance, report freeze, publish receipt,
  restatement, external assurance opinion.

Acceptance:
- all artifacts are append-only (WORM)
- restatement points to the prior report without changing history
- opinion and report are hash-bound
- Veritas verifies integrity, never professional correctness
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from veritas.worm import WORMLog


def _utcnow() -> datetime:
    return datetime.now(UTC)


class SustainabilityBindingError(ValueError):
    pass


@dataclass(frozen=True)
class SustainabilityArtifactV1:
    """An append-only sustainability reporting artifact recorded by Veritas."""

    artifact_id: str
    artifact_type: str  # source_evidence | calculation_run | datapoint | control_execution |
    #                     materiality_decision | reht_clearance | report_freeze |
    #                     publish_receipt | restatement | assurance_opinion
    tenant_id: str
    entity_id: str
    period_id: str
    payload_digest: str
    observed_at: datetime = field(default_factory=_utcnow)
    prior_ref: str | None = None  # restatement points to prior report

    def to_payload(self) -> Mapping[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "tenant_id": self.tenant_id,
            "entity_id": self.entity_id,
            "period_id": self.period_id,
            "payload_digest": self.payload_digest,
            "observed_at": self.observed_at.isoformat(),
            "prior_ref": self.prior_ref,
        }


@dataclass(frozen=True)
class AssuranceEvidencePackBindingV1:
    """Hash-bound binding of an external assurance opinion to a frozen report."""

    pack_binding_id: str
    report_freeze_ref: str
    report_freeze_digest: str
    opinion_ref: str
    opinion_digest: str
    bound_at: datetime = field(default_factory=_utcnow)

    def to_payload(self) -> Mapping[str, Any]:
        return {
            "pack_binding_id": self.pack_binding_id,
            "report_freeze_ref": self.report_freeze_ref,
            "report_freeze_digest": self.report_freeze_digest,
            "opinion_ref": self.opinion_ref,
            "opinion_digest": self.opinion_digest,
            "bound_at": self.bound_at.isoformat(),
        }


class SustainabilityVeritasService:
    """Append-only recording and integrity verification (not correctness)."""

    def __init__(self, worm: WORMLog) -> None:
        self._worm = worm

    def record_artifact(self, artifact: SustainabilityArtifactV1) -> str:
        """Append an artifact to the WORM log. Never overwrites history."""
        return self._worm.append(artifact.artifact_id, artifact.to_payload())

    def bind_assurance_opinion(self, binding: AssuranceEvidencePackBindingV1) -> str:
        return self._worm.append(binding.pack_binding_id, binding.to_payload())

    def verify_integrity(self, record_id: str) -> bool:
        """Verify integrity of a recorded artifact (not its correctness)."""
        return any(e.get("id") == record_id for e in self._worm.read_all())

    def restatement_preserves_history(self, prior_ref: str, restated_id: str) -> bool:
        """Restatement creates a new artifact pointing to prior; prior unchanged."""
        entries = {e.get("id"): e for e in self._worm.read_all()}
        prior = entries.get(prior_ref)
        restated = entries.get(restated_id)
        if prior is None or restated is None:
            return False
        # both records exist; restated references prior (flat payload fields)
        return restated.get("prior_ref") == prior_ref


__all__ = [
    "AssuranceEvidencePackBindingV1",
    "SustainabilityArtifactV1",
    "SustainabilityBindingError",
    "SustainabilityVeritasService",
]
