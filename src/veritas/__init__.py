"""Veritas — VALO receipt layer (LA6)."""

from veritas.contracts import (
    CompletedEvidencePackageV1,
    FinalEvidenceBindingV1,
    ObservationPackageV1,
    ObservedEventV1,
    StoredEvidenceReportV1,
)
from veritas.digest import (
    CANONICALIZATION_ALGORITHM,
    CanonicalizationError,
    canonical_digest,
    stable_json,
)
from veritas.service import VeritasChainError, VeritasChainService
from veritas.worm import WORMIntegrityError, WORMLog

__version__ = "0.1.0"

__all__ = [
    "CANONICALIZATION_ALGORITHM",
    "CanonicalizationError",
    "CompletedEvidencePackageV1",
    "FinalEvidenceBindingV1",
    "ObservationPackageV1",
    "ObservedEventV1",
    "StoredEvidenceReportV1",
    "VeritasChainError",
    "VeritasChainService",
    "WORMIntegrityError",
    "WORMLog",
    "canonical_digest",
    "stable_json",
]
