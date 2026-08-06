"""Veritas chain service — record and verify observation/follow-on receipts.

Veritas attests observations and persists them without interpreting their
meaning. It does not analyse, classify, conclude or authorize.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from veritas.contracts import (
    CompletedEvidencePackageV1,
    FinalEvidenceBindingV1,
    ObservationPackageV1,
    StoredEvidenceReportV1,
)
from veritas.worm import WORMIntegrityError, WORMLog


class VeritasChainError(ValueError):
    pass


class VeritasChainService:
    """Attests observation packages and follow-on receipts to a WORM ledger."""

    def __init__(self, worm: WORMLog) -> None:
        if not worm.verify():
            raise VeritasChainError("cannot attach service to an invalid WORM chain")
        self.worm = worm
        self._sequence = self._resume_sequence()

    @staticmethod
    def _next_entry_id(prefix: str, record_id: str) -> str:
        return f"{prefix}-{record_id}"

    def _resume_sequence(self) -> int:
        sequence = 0
        for entry in self.worm.read_all():
            if "sequence" not in entry:
                continue
            value = entry["sequence"]
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise VeritasChainError("stored sequence must be a positive integer")
            if value <= sequence:
                raise VeritasChainError("stored sequences must be strictly increasing")
            sequence = value
        return sequence

    def _store(self, prefix: str, record_id: str, payload: dict[str, Any]) -> str:
        next_sequence = self._sequence + 1
        payload["sequence"] = next_sequence
        try:
            digest = self.worm.append(
                self._next_entry_id(prefix, record_id),
                payload,
            )
        except WORMIntegrityError as exc:
            raise VeritasChainError(str(exc)) from exc
        self._sequence = next_sequence
        return digest

    def store_observation_package(self, package: ObservationPackageV1) -> str:
        return self._store("obs-pkg", package.package_id, package.to_payload())

    def store_completed_evidence(self, package: CompletedEvidencePackageV1) -> str:
        return self._store("completed", package.record_id, package.to_payload())

    def store_evidence_report(self, report: StoredEvidenceReportV1) -> str:
        return self._store("evidence-report", report.report_id, report.to_payload())

    def store_final_evidence_binding(self, binding: FinalEvidenceBindingV1) -> str:
        return self._store("final-binding", binding.follow_on_id, binding.to_payload())

    def verify_chain(self) -> bool:
        """Verify the full WORM chain is intact."""
        return self.worm.verify()

    def find_entry(self, record_id: str) -> Mapping[str, Any] | None:
        """Return a defensive snapshot of the matching stored receipt."""
        for entry in self.worm.read_all():
            if record_id in (
                entry.get("package_id"),
                entry.get("record_id"),
                entry.get("report_id"),
                entry.get("follow_on_id"),
            ):
                return entry
        return None
