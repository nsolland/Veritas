"""Accessible receipt archiver — local-first receipt and warranty archive.

Build order #70 (``accessible-receipt-archiver``, founder ADOPTED). A
privacy-first archive where the user owns every receipt. Registration, field
extraction, search and delete-everything all run locally; nothing is uploaded
by default.

Each immutable archive record can produce an ``ObservedEventV1`` /
``ObservationPackageV1`` that is fed into the durable, tamper-evident Veritas
receipt chain.

Veritas boundary: archiving a receipt NEVER grants clearance or execution
authority. The ``authority_granted`` provenance flag is always ``False`` and
the binding carries no permit/clearance fields.
"""

from __future__ import annotations

import calendar
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any, Final

from veritas.contracts import ObservationPackageV1, ObservedEventV1
from veritas.digest import canonical_digest
from veritas.service import VeritasChainService
from veritas.worm import WORMLog

_ARCHIVE_SOURCE_ID: Final = "accessible-receipt-archiver"
_EXTRACTED_FIELDS: Final = frozenset({"shop", "date", "amount", "warranty_end"})
_DIGEST_PREFIX: Final = "sha256:"

_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_DMY_DATE = re.compile(r"\b(\d{1,2})[./](\d{1,2})[./](\d{2,4})\b")
_DATE_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}|\b\d{1,2}[./]\d{1,2}[./]\d{2,4}\b"
)
_AMOUNT_PATTERN = re.compile(
    r"(?:kr\.?\s*)?(\d{1,3}(?:[ .]\d{3})*(?:[.,]\d{2})|\d+[.,]\d{2})",
    re.IGNORECASE,
)
_TRAILING_DECIMAL = re.compile(r"[.,](\d{2})$")


class ReceiptArchiveError(ValueError):
    """Raised when a receipt archive operation is invalid."""


def _utcnow() -> datetime:
    return datetime.now(UTC)


def add_warranty_end(iso_date: str, months: int) -> str:
    """Return the warranty end date ``months`` after ``iso_date``.

    Calendar-safe: the resulting day is clamped to the target month's length
    and no timezone arithmetic is involved (date-only, drift-free).
    """
    if months < 1:
        raise ReceiptArchiveError("warranty months must be positive")
    parsed = date.fromisoformat(iso_date)
    month_index = parsed.year * 12 + (parsed.month - 1) + months
    year, month0 = divmod(month_index, 12)
    month = month0 + 1
    day = min(parsed.day, calendar.monthrange(year, month)[1])
    return date(year, month, day).isoformat()


def _normalize_date(raw: str) -> str:
    if _ISO_DATE.fullmatch(raw):
        return raw
    match = _DMY_DATE.search(raw)
    if not match:
        return ""
    day_s, month_s, year_s = match.groups()
    if day_s is None or month_s is None or year_s is None:
        return ""
    if len(year_s) == 2:
        year_s = ("19" if int(year_s) > 50 else "20") + year_s
    return f"{year_s}-{int(month_s):02d}-{int(day_s):02d}"


def _money_to_number(raw: str) -> float | None:
    text = raw.strip()
    match = _TRAILING_DECIMAL.search(text)
    if match:
        int_part = re.sub(r"[ .,]", "", text[: match.start()])
        decimal = match.group(1)
        if decimal is None:
            return None
        return float((int_part if int_part else "0") + "." + decimal)
    digits = re.sub(r"[ .,]", "", text)
    if not digits:
        return None
    return float(digits)


def extract_receipt_fields(
    text: str, *, warranty_months: int | None = None
) -> dict[str, str]:
    """Heuristic field extraction from pasted/photographed receipt text.

    Amount: the largest money-formatted number is the total. Date: the first
    recognizable date is the purchase date. Shop: the first non-empty line that
    is neither date- nor digit-dominated. Extraction is a convenience, never an
    authority: every field stays user-correctable.
    """
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    fields: dict[str, str] = {
        "shop": "",
        "date": "",
        "amount": "",
        "warranty_end": "",
    }

    for line in lines:
        match = _DATE_PATTERN.search(line)
        if match:
            fields["date"] = _normalize_date(match.group(0))
            break

    best: float | None = None
    for line in lines:
        for match in _AMOUNT_PATTERN.finditer(line):
            value = _money_to_number(match.group(1))
            if value is not None and (best is None or value > best):
                best = value
    if best is not None:
        fields["amount"] = f"{best:.2f}"

    for line in lines:
        digits = sum(1 for char in line if char.isdigit())
        if digits < len(line) / 2 and not _DATE_PATTERN.search(line):
            fields["shop"] = line
            break

    if warranty_months is not None and fields["date"] and not fields["warranty_end"]:
        fields["warranty_end"] = add_warranty_end(fields["date"], warranty_months)
    return fields


@dataclass(frozen=True)
class ReceiptArchiveRecordV1:
    """An immutable archival record for a receipt or warranty document.

    The record is immutable and append-only: revisions create superseding
    records and never rewrite history. ``deleted`` is the user-owned delete
    flag (local tombstones never alter the immutable record content).
    """

    archive_id: str
    tenant_id: str
    source_payload_digest: str
    source_text: str
    extracted: Mapping[str, str]
    recorded_at: datetime = field(default_factory=_utcnow)
    supersedes: str | None = None
    deleted: bool = False

    def to_payload(self) -> dict[str, Any]:
        for name, value in {
            "archive_id": self.archive_id,
            "tenant_id": self.tenant_id,
            "source_text": self.source_text,
        }.items():
            _require_text(name, value)
        _require_digest("source_payload_digest", self.source_payload_digest)
        _require_timestamp("recorded_at", self.recorded_at)
        if not isinstance(self.deleted, bool):
            raise ReceiptArchiveError("deleted must be a boolean")
        if not isinstance(self.extracted, Mapping):
            raise ReceiptArchiveError("extracted must be a mapping")
        unknown = set(self.extracted) - _EXTRACTED_FIELDS
        if unknown:
            extra = ", ".join(sorted(unknown))
            raise ReceiptArchiveError(f"unexpected extracted fields: {extra}")
        for name, raw_value in {
            "extracted.shop": self.extracted.get("shop"),
            "extracted.date": self.extracted.get("date"),
        }.items():
            _require_text(name, raw_value)
        for key, value in self.extracted.items():
            if not isinstance(value, str):
                raise ReceiptArchiveError(f"extracted.{key} must be a string")
        return {
            "archive_id": self.archive_id,
            "tenant_id": self.tenant_id,
            "source_payload_digest": self.source_payload_digest,
            "source_text": self.source_text,
            "extracted": dict(self.extracted),
            "recorded_at": _timestamp(self.recorded_at),
            "supersedes": self.supersedes,
            "deleted": self.deleted,
        }

    def to_observed_event(
        self, *, source_id: str = _ARCHIVE_SOURCE_ID
    ) -> ObservedEventV1:
        """Produce a Veritas ``ObservedEventV1`` binding for this record.

        The event attests that a receipt was registered and archived. It
        carries no authority semantics: ``authority_granted`` is always
        ``False``.
        """
        return ObservedEventV1(
            event_id=f"receipt:{self.archive_id}",
            source_id=source_id,
            event_type="receipt_registered",
            observed_at=self.recorded_at,
            payload_digest=canonical_digest(self.to_payload()),
            provenance={
                "archive_id": self.archive_id,
                "tenant_id": self.tenant_id,
                "authority_granted": False,
                "authority_note": (
                    "archiving a receipt never grants clearance or "
                    "execution authority"
                ),
            },
        )


class AccessibleReceiptArchiver:
    """Append-only, local-first receipt archive with Veritas binding.

    Every record is immutable and append-only. Deletion is user-owned:
    ``delete`` and ``delete_everything`` tombstone records locally and never
    call out to a network or cloud service. A durable Veritas chain binding is
    produced only when the archive is explicitly configured with a WORM log.
    """

    def __init__(
        self, tenant_id: str = "local-user", worm: WORMLog | None = None
    ) -> None:
        if not isinstance(tenant_id, str) or not tenant_id:
            raise ReceiptArchiveError("tenant_id is required")
        self._tenant_id = tenant_id
        self._worm = worm
        self._entries: list[ReceiptArchiveRecordV1] = []
        self._deleted: set[str] = set()

    # ---- registration ----

    def register(
        self,
        source_text: str,
        *,
        extracted: Mapping[str, str] | None = None,
        warranty_months: int | None = None,
    ) -> str:
        """Register a receipt and return its immutable ``archive_id``."""
        if not isinstance(source_text, str) or not source_text.strip():
            raise ReceiptArchiveError("source_text is required")
        if extracted is None:
            fields = extract_receipt_fields(
                source_text, warranty_months=warranty_months
            )
        else:
            if not isinstance(extracted, Mapping):
                raise ReceiptArchiveError("extracted must be a mapping")
            unknown = set(extracted) - _EXTRACTED_FIELDS
            if unknown:
                extra = ", ".join(sorted(unknown))
                raise ReceiptArchiveError(f"unexpected extracted fields: {extra}")
            fields = dict(extracted)
            if (
                warranty_months is not None
                and fields.get("warranty_end") == ""
                and fields.get("date")
            ):
                fields["warranty_end"] = add_warranty_end(
                    fields["date"], warranty_months
                )
        record = self._build_record(source_text, fields)
        return record.archive_id

    def _build_record(
        self, source_text: str, fields: dict[str, str]
    ) -> ReceiptArchiveRecordV1:
        digest = canonical_digest({"source_text": source_text, "extracted": fields})
        record = ReceiptArchiveRecordV1(
            archive_id=f"rcpt-{len(self._entries) + 1}",
            tenant_id=self._tenant_id,
            source_payload_digest=digest,
            source_text=source_text,
            extracted=fields,
        )
        record.to_payload()  # eager validation
        self._entries.append(record)
        return record

    def revise(
        self,
        archive_id: str,
        *,
        source_text: str | None = None,
        extracted: Mapping[str, str] | None = None,
    ) -> str:
        """Append a superseding revision. History is never rewritten."""
        prior = self._latest(archive_id)
        if prior is None:
            raise ReceiptArchiveError(f"unknown archive_id: {archive_id}")
        fields = dict(extracted) if extracted is not None else dict(prior.extracted)
        unknown = set(fields) - _EXTRACTED_FIELDS
        if unknown:
            extra = ", ".join(sorted(unknown))
            raise ReceiptArchiveError(f"unexpected extracted fields: {extra}")
        next_text = source_text if source_text is not None else prior.source_text
        record = ReceiptArchiveRecordV1(
            archive_id=f"rcpt-{len(self._entries) + 1}",
            tenant_id=self._tenant_id,
            source_payload_digest=canonical_digest(
                {"source_text": next_text, "extracted": fields}
            ),
            source_text=next_text,
            extracted=fields,
            supersedes=prior.archive_id,
        )
        record.to_payload()  # eager validation
        self._entries.append(record)
        return record.archive_id

    # ---- user-owned deletion ----

    def delete(self, archive_id: str) -> bool:
        """Tombstone a receipt locally.

        Returns False if the archive_id is unknown or already deleted.
        """
        if archive_id in self._deleted:
            return False
        if self._latest(archive_id) is None:
            return False
        self._deleted.add(archive_id)
        return True

    def delete_everything(self) -> int:
        """Delete all receipts the user owns. Returns the number removed."""
        active = [record["archive_id"] for record in self.list_records()]
        self._deleted.update(active)
        return len(active)

    # ---- reading ----

    def get(self, archive_id: str) -> ReceiptArchiveRecordV1 | None:
        for entry in self._entries:
            if entry.archive_id == archive_id:
                return entry
        return None

    def record_count(self) -> int:
        """Number of records in the append-only history."""
        return len(self._entries)

    def list_records(self, include_deleted: bool = False) -> list[dict[str, Any]]:
        """Return the current archive state (chain heads) as JSON-safe dicts."""
        records: list[dict[str, Any]] = []
        seen_roots: set[str] = set()
        for entry in reversed(self._entries):
            root = self._root(entry.archive_id)
            if root in seen_roots:
                continue
            seen_roots.add(root)
            if not include_deleted and entry.archive_id in self._deleted:
                continue
            records.append(self._export(entry))
        return records

    def search(self, query: str) -> list[dict[str, Any]]:
        """Search receipts by shop name (case-insensitive substring)."""
        needle = query.strip().lower()
        if not needle:
            return self.list_records()
        return [
            record
            for record in self.list_records()
            if needle in str(record["extracted"].get("shop", "")).lower()
        ]

    def export_all(self) -> list[dict[str, Any]]:
        """Export the user-owned archive as JSON-serializable dicts."""
        return self.list_records()

    # ---- Veritas chain binding ----

    def veritas_binding(self, archive_id: str) -> ObservedEventV1:
        """Produce the ``ObservedEventV1`` for the latest revision of a receipt."""
        record = self._latest(archive_id)
        if record is None:
            raise ReceiptArchiveError(f"unknown archive_id: {archive_id}")
        return record.to_observed_event()

    def publish_to_chain(
        self,
        archive_id: str,
        *,
        service: VeritasChainService | None = None,
    ) -> str:
        """Bind a receipt into the durable Veritas chain (returns entry digest).

        Requires a WORM log (configured at construction or via ``service``).
        The binding self-references the user's local archive as its source and
        never grants clearance or execution authority.
        """
        record = self._latest(archive_id)
        if record is None:
            raise ReceiptArchiveError(f"unknown archive_id: {archive_id}")
        package = ObservationPackageV1(
            package_id=f"rcpt-pkg-{record.archive_id}",
            tenant_id=self._tenant_id,
            execution_id=f"archive:{record.archive_id}",
            authorization_ref=f"archive:{self._tenant_id}",
            authorization_digest=canonical_digest(
                {"tenant_id": self._tenant_id, "authority_granted": False}
            ),
            handoff_ref=f"archive:{record.archive_id}",
            handoff_digest=canonical_digest(record.to_payload()),
            observed_events=[record.to_observed_event()],
        )
        if service is not None:
            chain_service = service
        elif self._worm is not None:
            chain_service = VeritasChainService(self._worm)
        else:
            raise ReceiptArchiveError("no WORM chain configured for binding")
        return chain_service.store_observation_package(package)

    # ---- internal ----

    def _root(self, archive_id: str) -> str:
        current = archive_id
        seen: set[str] = set()
        while current not in seen:
            seen.add(current)
            entry = self.get(current)
            if entry is None or entry.supersedes is None:
                return current
            current = entry.supersedes
        return archive_id

    def _latest(self, archive_id: str) -> ReceiptArchiveRecordV1 | None:
        root = self._root(archive_id)
        latest: ReceiptArchiveRecordV1 | None = None
        for entry in self._entries:
            if self._root(entry.archive_id) == root:
                latest = entry
        return latest

    def _export(self, entry: ReceiptArchiveRecordV1) -> dict[str, Any]:
        payload = entry.to_payload()
        payload["deleted"] = entry.archive_id in self._deleted
        return payload


def _require_text(name: str, value: object) -> None:
    if not isinstance(value, str) or not value:
        raise ReceiptArchiveError(f"{name} is required")


def _require_digest(name: str, value: object) -> None:
    if not isinstance(value, str) or not value.startswith(_DIGEST_PREFIX):
        raise ReceiptArchiveError(f"{name} must be a sha256 digest")
    suffix = value[len(_DIGEST_PREFIX) :]
    if len(suffix) != 64 or any(
        char not in "0123456789abcdef" for char in suffix
    ):
        raise ReceiptArchiveError(f"{name} must be a sha256 digest")


def _require_timestamp(name: str, value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReceiptArchiveError(f"{name} must be timezone-aware")


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


__all__ = [
    "AccessibleReceiptArchiver",
    "ReceiptArchiveError",
    "ReceiptArchiveRecordV1",
    "add_warranty_end",
    "extract_receipt_fields",
]
