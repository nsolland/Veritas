"""Veritas — VALO receipt layer (LA6)."""

from veritas.contracts import (
    CompletedEvidencePackageV1,
    FinalEvidenceBindingV1,
    ObservedEventV1,
    ObservationPackageV1,
    StoredEvidenceReportV1,
)
from veritas.digest import CANONICALIZATION_ALGORITHM, canonical_digest, stable_json
from veritas.service import VeritasChainError, VeritasChainService
from veritas.worm import WORMLog

__version__ = "0.1.0"

__all__ = [
    "CANONICALIZATION_ALGORITHM",
    "CompletedEvidencePackageV1",
    "FinalEvidenceBindingV1",
    "ObservedEventV1",
    "ObservationPackageV1",
    "StoredEvidenceReportV1",
    "VeritasChainError",
    "VeritasChainService",
    "WORMLog",
    "canonical_digest",
    "stable_json",
]
