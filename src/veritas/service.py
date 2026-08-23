"""Veritas chain service — record and verify observation/follow-on receipts.

Veritas attests observations and persists them without interpreting their
meaning. It does not analyse, classify, conclude or authorize.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from veritas.contracts import (
    BoundaryNegativeEvidenceV1,
    CompletedEvidencePackageV1,
    FinalEvidenceBindingV1,
    ObservationPackageV1,
    StoredEvidenceReportV1,
)
from veritas.effect_boundary import EffectBoundaryExecutionObservationV1
from veritas.execution import GatewayExecutionObservationV1
from veritas.incident import IncidentEvidenceChainV1
from veritas.worm import WORMLog


class VeritasChainError(ValueError):
    pass


class VeritasChainService:
    """Attests observation packages and follow-on receipts to a WORM ledger."""

    def __init__(self, worm: WORMLog) -> None:
        self.worm = worm
        self._sequence = len(worm.read_all())

    @staticmethod
    def _next_entry_id(prefix: str, record_id: str) -> str:
        return f"{prefix}-{record_id}"

    def store_observation_package(self, package: ObservationPackageV1) -> str:
        payload = package.to_payload()
        self._sequence += 1
        payload["sequence"] = self._sequence
        return self.worm.append(
            self._next_entry_id("obs-pkg", package.package_id), payload
        )

    def store_gateway_execution_observation(
        self, payload: Mapping[str, Any], *, tenant_id: str
    ) -> str:
        """Verify Gateway execution evidence, package it, and append it to WORM."""
        observation = GatewayExecutionObservationV1.verify(payload)
        package = observation.to_observation_package(tenant_id=tenant_id)
        return self.store_observation_package(package)

    def store_effect_boundary_execution_observation(
        self,
        payload: Mapping[str, Any],
    ) -> str:
        """Verify a two-core REHT EffectBoundary receipt and append it to WORM.

        Invalid/tampered receipts never reach storage. The stored artifact is
        execution evidence only and must have ``authority_granted=false``.
        """
        observation = EffectBoundaryExecutionObservationV1.verify(payload)
        worm_payload = observation.to_worm_payload()
        self._sequence += 1
        worm_payload["sequence"] = self._sequence
        return self.worm.append(
            self._next_entry_id("effect-boundary", observation.receipt_id),
            worm_payload,
        )

    def store_boundary_negative_evidence(
        self, evidence: BoundaryNegativeEvidenceV1
    ) -> str:
        payload = evidence.to_payload()
        self._sequence += 1
        payload["sequence"] = self._sequence
        return self.worm.append(
            self._next_entry_id("negative-evidence", evidence.evidence_id), payload
        )

    def store_completed_evidence(self, package: CompletedEvidencePackageV1) -> str:
        payload = package.to_payload()
        self._sequence += 1
        payload["sequence"] = self._sequence
        return self.worm.append(
            self._next_entry_id("completed", package.record_id), payload
        )

    def store_evidence_report(self, report: StoredEvidenceReportV1) -> str:
        payload = report.to_payload()
        self._sequence += 1
        payload["sequence"] = self._sequence
        return self.worm.append(
            self._next_entry_id("evidence-report", report.report_id), payload
        )

    def store_final_evidence_binding(self, binding: FinalEvidenceBindingV1) -> str:
        payload = binding.to_payload()
        self._sequence += 1
        payload["sequence"] = self._sequence
        return self.worm.append(
            self._next_entry_id("final-binding", binding.follow_on_id), payload
        )

    def store_incident_evidence_chain(self, chain: IncidentEvidenceChainV1) -> str:
        """Append one non-interpretive binding across an incident evidence chain."""
        payload = chain.to_payload()
        self._sequence += 1
        payload["sequence"] = self._sequence
        return self.worm.append(
            self._next_entry_id("incident-chain", chain.chain_id), payload
        )

    def verify_chain(self) -> bool:
        """Verify the full WORM chain is intact."""
        return self.worm.verify()

    def find_entry(self, record_id: str) -> Mapping[str, Any] | None:
        """Return the entry whose stable record identifier matches ``record_id``."""
        for entry in self.worm.read_all():
            if record_id in (
                entry.get("package_id"),
                entry.get("evidence_id"),
                entry.get("record_id"),
                entry.get("report_id"),
                entry.get("follow_on_id"),
                entry.get("chain_id"),
                entry.get("incident_id"),
                entry.get("receipt_id"),
            ):
                return entry
        return None
