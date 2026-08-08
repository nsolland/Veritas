"""Privacy-first local receipt archive with Veritas chain bindings.

The user-owned archive is mutable and deletable local state. Veritas stores only
opaque identifiers and canonical digests in its append-only WORM chain; raw
receipt text and extracted fields never enter the chain.

Field extraction is deliberately upstream. Veritas attests what it is given and
does not parse, classify, conclude, or authorize.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from os import PathLike
from pathlib import Path
from typing import Any, cast

from veritas.contracts import VeritasContractError
from veritas.digest import canonical_digest
from veritas.worm import WORMLog

Pathish = str | PathLike[str]
_ALLOWED_SOURCE_KINDS = frozenset({"paste", "photo", "import", "manual"})


@dataclass(frozen=True)
class ReceiptArchiveRecordV1:
    """User-owned local receipt/warranty record.

    This payload may contain personal or commercial data and MUST remain in the
    local archive. Only its canonical digest is projected into Veritas.
    """

    record_id: str
    shop: str | None = None
    purchase_date: date | None = None
    amount_minor: int | None = None
    currency: str = "NOK"
    warranty_end: date | None = None
    source_kind: str = "paste"
    source_text: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_payload(self) -> dict[str, Any]:
        _require_text("record_id", self.record_id)
        if self.shop is not None:
            _require_text("shop", self.shop)
        if self.amount_minor is not None and self.amount_minor < 0:
            raise VeritasContractError("amount_minor must be non-negative")
        if (
            not isinstance(self.currency, str)
            or len(self.currency) != 3
            or not self.currency.isalpha()
            or self.currency != self.currency.upper()
        ):
            raise VeritasContractError("currency must be a 3-letter uppercase code")
        if self.source_kind not in _ALLOWED_SOURCE_KINDS:
            raise VeritasContractError("source_kind is not supported")
        if self.source_text is not None and not isinstance(self.source_text, str):
            raise VeritasContractError("source_text must be text")
        if (
            self.purchase_date is not None
            and self.warranty_end is not None
            and self.warranty_end < self.purchase_date
        ):
            raise VeritasContractError("warranty_end cannot precede purchase_date")
        return {
            "record_id": self.record_id,
            "shop": self.shop,
            "purchase_date": _optional_date(self.purchase_date),
            "amount_minor": self.amount_minor,
            "currency": self.currency,
            "warranty_end": _optional_date(self.warranty_end),
            "source_kind": self.source_kind,
            "source_text": self.source_text,
            "created_at": _timestamp(self.created_at),
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> ReceiptArchiveRecordV1:
        record_id = payload.get("record_id")
        currency = payload.get("currency")
        source_kind = payload.get("source_kind")
        created_at = payload.get("created_at")
        _require_text("record_id", record_id)
        _require_text("currency", currency)
        _require_text("source_kind", source_kind)
        _require_text("created_at", created_at)
        assert isinstance(record_id, str)
        assert isinstance(currency, str)
        assert isinstance(source_kind, str)
        assert isinstance(created_at, str)

        shop = payload.get("shop")
        source_text = payload.get("source_text")
        amount_minor = payload.get("amount_minor")
        if shop is not None and not isinstance(shop, str):
            raise VeritasContractError("shop must be text")
        if source_text is not None and not isinstance(source_text, str):
            raise VeritasContractError("source_text must be text")
        if amount_minor is not None and not isinstance(amount_minor, int):
            raise VeritasContractError("amount_minor must be an integer")

        parsed_created_at = _parse_timestamp(created_at)
        record = cls(
            record_id=record_id,
            shop=shop,
            purchase_date=_parse_optional_date(payload.get("purchase_date")),
            amount_minor=amount_minor,
            currency=currency,
            warranty_end=_parse_optional_date(payload.get("warranty_end")),
            source_kind=source_kind,
            source_text=source_text,
            created_at=parsed_created_at,
        )
        record.to_payload()
        return record


@dataclass(frozen=True)
class ReceiptArchiveBindingV1:
    """Privacy-preserving WORM binding for one local archive record."""

    binding_id: str
    tenant_id: str
    archive_record_id: str
    record_digest: str
    local_record_ref: str
    source_kind: str
    bound_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    parser_ref: str | None = None

    def to_payload(self) -> dict[str, Any]:
        for name, value in {
            "binding_id": self.binding_id,
            "tenant_id": self.tenant_id,
            "archive_record_id": self.archive_record_id,
            "local_record_ref": self.local_record_ref,
            "source_kind": self.source_kind,
        }.items():
            _require_text(name, value)
        _require_digest("record_digest", self.record_digest)
        if self.source_kind not in _ALLOWED_SOURCE_KINDS:
            raise VeritasContractError("source_kind is not supported")
        if self.parser_ref is not None:
            _require_text("parser_ref", self.parser_ref)
        return {
            "receipt_archive_event": "bound",
            "binding_id": self.binding_id,
            "tenant_id": self.tenant_id,
            "archive_record_id": self.archive_record_id,
            "record_digest": self.record_digest,
            "local_record_ref": self.local_record_ref,
            "source_kind": self.source_kind,
            "parser_ref": self.parser_ref,
            "contains_user_content": False,
            "bound_at": _timestamp(self.bound_at),
        }


@dataclass(frozen=True)
class ReceiptArchiveDeletionV1:
    """Append-only attestation that the user deleted a local archive record."""

    deletion_id: str
    tenant_id: str
    archive_record_id: str
    binding_ref: str
    binding_digest: str
    deleted_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_payload(self) -> dict[str, Any]:
        for name, value in {
            "deletion_id": self.deletion_id,
            "tenant_id": self.tenant_id,
            "archive_record_id": self.archive_record_id,
            "binding_ref": self.binding_ref,
        }.items():
            _require_text(name, value)
        _require_digest("binding_digest", self.binding_digest)
        return {
            "receipt_archive_event": "deleted_local_record",
            "deletion_id": self.deletion_id,
            "tenant_id": self.tenant_id,
            "archive_record_id": self.archive_record_id,
            "binding_ref": self.binding_ref,
            "binding_digest": self.binding_digest,
            "contains_user_content": False,
            "deleted_at": _timestamp(self.deleted_at),
        }


class LocalReceiptArchive:
    """User-controlled local JSON archive. No network operations are performed."""

    def __init__(self, path: Pathish | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._records: dict[str, ReceiptArchiveRecordV1] = {}
        if self.path is not None and self.path.exists():
            self._load()

    def add(self, record: ReceiptArchiveRecordV1) -> None:
        record.to_payload()
        if record.record_id in self._records:
            raise VeritasContractError(f"duplicate archive record: {record.record_id}")
        self._records[record.record_id] = record
        self._persist_if_configured()

    def get(self, record_id: str) -> ReceiptArchiveRecordV1 | None:
        return self._records.get(record_id)

    def records(self) -> tuple[ReceiptArchiveRecordV1, ...]:
        return tuple(self._records[key] for key in sorted(self._records))

    def search(self, query: str) -> tuple[ReceiptArchiveRecordV1, ...]:
        needle = query.strip().casefold()
        if not needle:
            return self.records()
        matches: list[ReceiptArchiveRecordV1] = []
        for record in self.records():
            payload = record.to_payload()
            searchable = " ".join(
                str(payload[key])
                for key in (
                    "shop",
                    "purchase_date",
                    "amount_minor",
                    "currency",
                    "warranty_end",
                    "source_kind",
                    "source_text",
                )
                if payload[key] is not None
            ).casefold()
            if needle in searchable:
                matches.append(record)
        return tuple(matches)

    def export_json(self) -> str:
        payload = [record.to_payload() for record in self.records()]
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    def delete(self, record_id: str) -> ReceiptArchiveRecordV1 | None:
        record = self._records.pop(record_id, None)
        if record is not None:
            self._persist_if_configured()
        return record

    def delete_all(self) -> int:
        count = len(self._records)
        self._records.clear()
        self._persist_if_configured()
        return count

    def _persist_if_configured(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(f"{self.path}.tmp")
        data = self.export_json().encode("utf-8")
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)

    def _load(self) -> None:
        assert self.path is not None
        try:
            raw: object = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise VeritasContractError("invalid local receipt archive") from exc
        if not isinstance(raw, list):
            raise VeritasContractError("local receipt archive must contain a list")
        records: dict[str, ReceiptArchiveRecordV1] = {}
        for item in raw:
            if not isinstance(item, dict):
                raise VeritasContractError("local receipt archive item must be an object")
            record = ReceiptArchiveRecordV1.from_payload(
                cast(Mapping[str, Any], item)
            )
            if record.record_id in records:
                raise VeritasContractError(
                    f"duplicate archive record: {record.record_id}"
                )
            records[record.record_id] = record
        self._records = records


class ReceiptArchiveService:
    """Bind local receipt lifecycle events into the Veritas WORM chain."""

    def __init__(self, archive: LocalReceiptArchive, worm: WORMLog, tenant_id: str) -> None:
        _require_text("tenant_id", tenant_id)
        self.archive = archive
        self.worm = worm
        self.tenant_id = tenant_id

    def archive_record(
        self,
        record: ReceiptArchiveRecordV1,
        *,
        parser_ref: str | None = None,
    ) -> str:
        record_payload = record.to_payload()
        record_digest = canonical_digest(record_payload)
        binding = ReceiptArchiveBindingV1(
            binding_id=f"receipt-binding-{record.record_id}",
            tenant_id=self.tenant_id,
            archive_record_id=record.record_id,
            record_digest=record_digest,
            local_record_ref=f"local://receipt/{record.record_id}",
            source_kind=record.source_kind,
            parser_ref=parser_ref,
        )
        binding_payload = binding.to_payload()
        self.archive.add(record)
        try:
            return self.worm.append(binding.binding_id, binding_payload)
        except Exception:
            self.archive.delete(record.record_id)
            raise

    def delete_record(self, record_id: str) -> str:
        record = self.archive.get(record_id)
        if record is None:
            raise VeritasContractError(f"archive record not found: {record_id}")
        binding_id = f"receipt-binding-{record_id}"
        binding_digest = self._binding_digest(binding_id)
        deletion = ReceiptArchiveDeletionV1(
            deletion_id=f"receipt-deletion-{record_id}",
            tenant_id=self.tenant_id,
            archive_record_id=record_id,
            binding_ref=binding_id,
            binding_digest=binding_digest,
        )
        deletion_payload = deletion.to_payload()
        removed = self.archive.delete(record_id)
        assert removed is not None
        try:
            return self.worm.append(deletion.deletion_id, deletion_payload)
        except Exception:
            self.archive.add(removed)
            raise

    def delete_all(self) -> tuple[str, ...]:
        return tuple(self.delete_record(record.record_id) for record in self.archive.records())

    def verify_chain(self) -> bool:
        return self.worm.verify()

    def _binding_digest(self, binding_id: str) -> str:
        for entry in self.worm.read_all():
            if entry.get("id") == binding_id:
                digest = entry.get("hash")
                _require_digest("binding_digest", digest)
                assert isinstance(digest, str)
                return digest
        raise VeritasContractError(f"receipt binding not found: {binding_id}")


def _require_text(name: str, value: object) -> None:
    if not isinstance(value, str) or not value.strip():
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


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise VeritasContractError("created_at must be an ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise VeritasContractError("created_at must be timezone-aware")
    return parsed.astimezone(UTC)


def _optional_date(value: date | None) -> str | None:
    return value.isoformat() if value is not None else None


def _parse_optional_date(value: object) -> date | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise VeritasContractError("date fields must be ISO strings")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise VeritasContractError("date fields must be ISO dates") from exc


__all__ = [
    "LocalReceiptArchive",
    "ReceiptArchiveBindingV1",
    "ReceiptArchiveDeletionV1",
    "ReceiptArchiveRecordV1",
    "ReceiptArchiveService",
]
