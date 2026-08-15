"""Veritas — VALO receipt layer (LA6)."""

from veritas.contracts import (
    BoundaryNegativeEvidenceV1,
    CompletedEvidencePackageV1,
    FinalEvidenceBindingV1,
    GovernedWorkspaceLineageEvidenceV1,
    ObservationPackageV1,
    ObservedEventV1,
    StoredEvidenceReportV1,
)
from veritas.digest import CANONICALIZATION_ALGORITHM, canonical_digest, stable_json
from veritas.execution import (
    GatewayExecutionObservationError,
    GatewayExecutionObservationV1,
)
from veritas.execution_substrate import ConfidentialExecutionEvidenceV1
from veritas.receipts import (
    AccessibleReceiptArchiver,
    ReceiptArchiveError,
    ReceiptArchiveRecordV1,
    add_warranty_end,
    extract_receipt_fields,
)
from veritas.service import VeritasChainError, VeritasChainService
from veritas.worm import WORMIntegrityError, WORMLog

__version__ = "0.1.0"

__all__ = [
    "CANONICALIZATION_ALGORITHM",
    "AccessibleReceiptArchiver",
    "BoundaryNegativeEvidenceV1",
    "CompletedEvidencePackageV1",
    "ConfidentialExecutionEvidenceV1",
    "FinalEvidenceBindingV1",
    "GatewayExecutionObservationError",
    "GatewayExecutionObservationV1",
    "GovernedWorkspaceLineageEvidenceV1",
    "ObservationPackageV1",
    "ObservedEventV1",
    "ReceiptArchiveError",
    "ReceiptArchiveRecordV1",
    "StoredEvidenceReportV1",
    "VeritasChainError",
    "VeritasChainService",
    "WORMIntegrityError",
    "WORMLog",
    "add_warranty_end",
    "canonical_digest",
    "extract_receipt_fields",
    "stable_json",
]
