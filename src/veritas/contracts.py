"""Wire contracts for Veritas observation and follow-on receipts.

Veritas records and attests observations. It does not analyse, classify, or
conclude what the observations mean.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


class VeritasContractError(ValueError):
    pass


@dataclass(frozen=True)
class ObservedEventV1:
    event_id: str
    source_id: str
    event_type: str
    observed_at: datetime
    payload_digest: str
    provenance: Mapping[str, Any]
    payload_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        _require_text("event_id", self.event_id)
        _require_text("source_id", self.source_id)
        _require_text("event_type", self.event_type)
        _require_digest("payload_digest", self.payload_digest)
        return {
            "event_id": self.event_id,
            "source_id": self.source_id,
            "event_type": self.event_type,
            "observed_at": _timestamp(self.observed_at),
            "payload_digest": self.payload_digest,
            "payload_ref": self.payload_ref,
            "provenance": dict(self.provenance),
        }


@dataclass(frozen=True)
class ObservationPackageV1:
    package_id: str
    tenant_id: str
    execution_id: str
    authorization_ref: str
    authorization_digest: str
    handoff_ref: str
    handoff_digest: str
    observed_events: Sequence[ObservedEventV1]
    skill_binding_digest: str | None = None
    unavailable_sources: Sequence[str] = field(default_factory=tuple)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_payload(self) -> dict[str, Any]:
        for name, value in {
            "package_id": self.package_id,
            "tenant_id": self.tenant_id,
            "execution_id": self.execution_id,
            "authorization_ref": self.authorization_ref,
            "handoff_ref": self.handoff_ref,
        }.items():
            _require_text(name, value)
        _require_digest("authorization_digest", self.authorization_digest)
        _require_digest("handoff_digest", self.handoff_digest)
        if self.skill_binding_digest is not None:
            _require_digest("skill_binding_digest", self.skill_binding_digest)
        events = [event.to_dict() for event in self.observed_events]
        if len({event["event_id"] for event in events}) != len(events):
            raise VeritasContractError("observed event ids must be unique")
        payload = {
            "package_id": self.package_id,
            "tenant_id": self.tenant_id,
            "execution_id": self.execution_id,
            "authorization_ref": self.authorization_ref,
            "authorization_digest": self.authorization_digest,
            "handoff_ref": self.handoff_ref,
            "handoff_digest": self.handoff_digest,
            "observed_events": events,
            "unavailable_sources": sorted(set(self.unavailable_sources)),
            "created_at": _timestamp(self.created_at),
        }
        if self.skill_binding_digest is not None:
            payload["skill_binding_digest"] = self.skill_binding_digest
        return payload


@dataclass(frozen=True)
class CompletedEvidencePackageV1:
    record_id: str
    tenant_id: str
    execution_id: str
    observation_package_ref: str
    completion: Mapping[str, Any]
    iteration: int
    recorded_at: datetime

    def to_payload(self) -> dict[str, Any]:
        for name, value in {
            "record_id": self.record_id,
            "tenant_id": self.tenant_id,
            "execution_id": self.execution_id,
            "observation_package_ref": self.observation_package_ref,
        }.items():
            _require_text(name, value)
        if self.iteration < 1:
            raise VeritasContractError("iteration must be positive")
        completion = dict(self.completion)
        _require_text("completion.completion_id", completion.get("completion_id"))
        if completion.get("execution_id") != self.execution_id:
            raise VeritasContractError("completed evidence execution_id mismatch")
        if completion.get("observation_package_ref") != self.observation_package_ref:
            raise VeritasContractError(
                "completed evidence observation_package_ref mismatch"
            )
        observations = completion.get("observations")
        if not isinstance(observations, list):
            raise VeritasContractError("completed evidence observations must be a list")
        forbidden = {"classification", "conclusion", "evidence_sufficient"}
        if forbidden.intersection(completion):
            raise VeritasContractError("completed evidence contains analysis fields")
        return {
            "record_id": self.record_id,
            "tenant_id": self.tenant_id,
            "execution_id": self.execution_id,
            "observation_package_ref": self.observation_package_ref,
            "completion": completion,
            "iteration": self.iteration,
            "recorded_at": _timestamp(self.recorded_at),
        }


@dataclass(frozen=True)
class StoredEvidenceReportV1:
    report_id: str
    tenant_id: str
    execution_id: str
    authorization_ref: str
    authorization_digest: str
    observation_package_ref: str
    observation_package_digest: str
    report: Mapping[str, Any]
    evidence_chain: Sequence[Mapping[str, str]] = field(default_factory=tuple)
    stored_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_payload(self) -> dict[str, Any]:
        for name, value in {
            "report_id": self.report_id,
            "tenant_id": self.tenant_id,
            "execution_id": self.execution_id,
            "authorization_ref": self.authorization_ref,
            "observation_package_ref": self.observation_package_ref,
        }.items():
            _require_text(name, value)
        _require_digest("authorization_digest", self.authorization_digest)
        _require_digest("observation_package_digest", self.observation_package_digest)
        report = dict(self.report)
        if report.get("report_id") != self.report_id:
            raise VeritasContractError("stored report_id must match BARO report")
        if report.get("execution_id") != self.execution_id:
            raise VeritasContractError("stored execution_id must match BARO report")
        if not self.evidence_chain:
            raise VeritasContractError("evidence_chain must contain observation package")
        chain = []
        for item in self.evidence_chain:
            ref = item.get("artifact_ref")
            digest = item.get("artifact_digest")
            _require_text("evidence_chain.artifact_ref", ref)
            _require_digest("evidence_chain.artifact_digest", digest)
            chain.append({"artifact_ref": ref, "artifact_digest": digest})
        if chain[0] != {
            "artifact_ref": self.observation_package_ref,
            "artifact_digest": self.observation_package_digest,
        }:
            raise VeritasContractError(
                "evidence_chain must start with the observation package"
            )
        return {
            "report_id": self.report_id,
            "tenant_id": self.tenant_id,
            "execution_id": self.execution_id,
            "authorization_ref": self.authorization_ref,
            "authorization_digest": self.authorization_digest,
            "observation_package_ref": self.observation_package_ref,
            "observation_package_digest": self.observation_package_digest,
            "report": report,
            "evidence_chain": chain,
            "stored_at": _timestamp(self.stored_at),
        }


@dataclass(frozen=True)
class FinalEvidenceBindingV1:
    follow_on_id: str
    tenant_id: str
    execution_id: str
    authorization_ref: str
    authorization_digest: str
    observation_package_ref: str
    observation_package_digest: str
    evidence_report_ref: str
    evidence_report_digest: str
    evidence_chain_head_ref: str
    evidence_chain_head_digest: str
    bound_at: datetime

    def to_payload(self) -> dict[str, Any]:
        for name, value in {
            "follow_on_id": self.follow_on_id,
            "tenant_id": self.tenant_id,
            "execution_id": self.execution_id,
            "authorization_ref": self.authorization_ref,
            "observation_package_ref": self.observation_package_ref,
            "evidence_report_ref": self.evidence_report_ref,
            "evidence_chain_head_ref": self.evidence_chain_head_ref,
        }.items():
            _require_text(name, value)
        for name, value in {
            "authorization_digest": self.authorization_digest,
            "observation_package_digest": self.observation_package_digest,
            "evidence_report_digest": self.evidence_report_digest,
            "evidence_chain_head_digest": self.evidence_chain_head_digest,
        }.items():
            _require_digest(name, value)
        return {
            "follow_on_id": self.follow_on_id,
            "tenant_id": self.tenant_id,
            "execution_id": self.execution_id,
            "authorization_ref": self.authorization_ref,
            "authorization_digest": self.authorization_digest,
            "observation_package_ref": self.observation_package_ref,
            "observation_package_digest": self.observation_package_digest,
            "evidence_report_ref": self.evidence_report_ref,
            "evidence_report_digest": self.evidence_report_digest,
            "evidence_chain_head_ref": self.evidence_chain_head_ref,
            "evidence_chain_head_digest": self.evidence_chain_head_digest,
            "bound_at": _timestamp(self.bound_at),
        }


def _require_text(name: str, value: object) -> None:
    if not isinstance(value, str) or not value:
        raise VeritasContractError(f"{name} is required")


def _require_digest(name: str, value: object) -> None:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise VeritasContractError(f"{name} must be a sha256 digest")
    suffix = value[7:]
    if len(suffix) != 64 or any(char not in "0123456789abcdef" for char in suffix):
        raise VeritasContractError(f"{name} must be a sha256 digest")


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise VeritasContractError("timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
