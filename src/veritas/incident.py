"""Non-interpretive evidence binding for governed incident response."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from veritas.contracts import VeritasContractError


_FORBIDDEN_ANALYSIS_FIELDS = frozenset(
    {"classification", "conclusion", "severity", "root_cause", "evidence_sufficient"}
)


@dataclass(frozen=True)
class IncidentArtifactRefV1:
    artifact_ref: str
    artifact_digest: str
    artifact_type: str

    def to_dict(self) -> dict[str, str]:
        _require_text("artifact_ref", self.artifact_ref)
        _require_digest("artifact_digest", self.artifact_digest)
        _require_text("artifact_type", self.artifact_type)
        return {
            "artifact_ref": self.artifact_ref,
            "artifact_digest": self.artifact_digest,
            "artifact_type": self.artifact_type,
        }


@dataclass(frozen=True)
class IncidentEvidenceChainV1:
    chain_id: str
    tenant_id: str
    incident_id: str
    subject_ref: str
    pre_state: IncidentArtifactRefV1
    diagnostic_evidence: Sequence[IncidentArtifactRefV1]
    authorization: IncidentArtifactRefV1
    execution: IncidentArtifactRefV1
    post_state: IncidentArtifactRefV1
    metadata: Mapping[str, Any] = field(default_factory=dict)
    recorded_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_payload(self) -> dict[str, Any]:
        for name, value in {
            "chain_id": self.chain_id,
            "tenant_id": self.tenant_id,
            "incident_id": self.incident_id,
            "subject_ref": self.subject_ref,
        }.items():
            _require_text(name, value)
        diagnostics = [item.to_dict() for item in self.diagnostic_evidence]
        if not diagnostics:
            raise VeritasContractError("diagnostic_evidence must not be empty")
        metadata = dict(self.metadata)
        forbidden = _FORBIDDEN_ANALYSIS_FIELDS.intersection(metadata)
        if forbidden:
            raise VeritasContractError(
                "incident evidence metadata contains analysis fields: "
                + ", ".join(sorted(forbidden))
            )
        return {
            "chain_id": self.chain_id,
            "tenant_id": self.tenant_id,
            "incident_id": self.incident_id,
            "subject_ref": self.subject_ref,
            "pre_state": self.pre_state.to_dict(),
            "diagnostic_evidence": diagnostics,
            "authorization": self.authorization.to_dict(),
            "execution": self.execution.to_dict(),
            "post_state": self.post_state.to_dict(),
            "metadata": metadata,
            "recorded_at": _timestamp(self.recorded_at),
        }


def _require_text(name: str, value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        raise VeritasContractError(f"{name} is required")


def _require_digest(name: str, value: Any) -> None:
    _require_text(name, value)
    if len(value) != 64:
        raise VeritasContractError(f"{name} must be a 64-character digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise VeritasContractError(f"{name} must be hexadecimal") from exc


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise VeritasContractError("recorded_at must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
