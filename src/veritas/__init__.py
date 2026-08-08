"""Veritas — VALO receipt layer (LA6)."""

from veritas.contracts import (
    BoundaryNegativeEvidenceV1,
    CompletedEvidencePackageV1,
    FinalEvidenceBindingV1,
    ObservationPackageV1,
    ObservedEventV1,
    StoredEvidenceReportV1,
)
from veritas.digest import CANONICALIZATION_ALGORITHM, canonical_digest, stable_json
from veritas.receipt_archive import (
    LocalReceiptArchive,
    ReceiptArchiveBindingV1,
    ReceiptArchiveDeletionV1,
    ReceiptArchiveRecordV1,
    ReceiptArchiveService,
)
from veritas.service import VeritasChainError, VeritasChainService
from veritas.worm import WORMIntegrityError, WORMLog

__version__ = "0.1.0"

__all__ = [
    "CANONICALIZATION_ALGORITHM",
    "BoundaryNegativeEvidenceV1",
    "CompletedEvidencePackageV1",
    "FinalEvidenceBindingV1",
    "LocalReceiptArchive",
    "ObservationPackageV1",
    "ObservedEventV1",
    "ReceiptArchiveBindingV1",
    "ReceiptArchiveDeletionV1",
    "ReceiptArchiveRecordV1",
    "ReceiptArchiveService",
    "StoredEvidenceReportV1",
    "VeritasChainError",
    "VeritasChainService",
    "WORMIntegrityError",
    "WORMLog",
    "canonical_digest",
    "stable_json",
]
