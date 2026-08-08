"""Accessible Receipt Archiver v1 — local ownership and Veritas bindings."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime

import pytest

from veritas.receipt_archive import (
    LocalReceiptArchive,
    ReceiptArchiveRecordV1,
    ReceiptArchiveService,
)
from veritas.worm import WORMLog


def _record(record_id: str = "r-1") -> ReceiptArchiveRecordV1:
    return ReceiptArchiveRecordV1(
        record_id=record_id,
        shop="Stavanger Elektro",
        purchase_date=date(2026, 8, 8),
        amount_minor=129900,
        currency="NOK",
        warranty_end=date(2028, 8, 8),
        source_kind="paste",
        source_text="Stavanger Elektro\n08.08.2026\nTOTAL 1 299,00",
        created_at=datetime(2026, 8, 8, 12, 0, tzinfo=UTC),
    )


def test_local_archive_persists_searches_and_exports(tmp_path):
    path = tmp_path / "receipts.json"
    archive = LocalReceiptArchive(path)
    archive.add(_record())

    assert archive.get("r-1") is not None
    assert archive.search("elektro")[0].record_id == "r-1"
    assert archive.search("129900")[0].record_id == "r-1"

    exported = json.loads(archive.export_json())
    assert exported[0]["shop"] == "Stavanger Elektro"
    assert exported[0]["amount_minor"] == 129900
    assert exported[0]["source_text"].startswith("Stavanger Elektro")

    reloaded = LocalReceiptArchive(path)
    assert reloaded.get("r-1") == _record()


def test_local_archive_supports_per_item_and_delete_all():
    archive = LocalReceiptArchive()
    archive.add(_record("r-1"))
    archive.add(_record("r-2"))

    removed = archive.delete("r-1")
    assert removed is not None
    assert archive.get("r-1") is None
    assert archive.delete_all() == 1
    assert archive.records() == ()


def test_veritas_binding_never_contains_raw_receipt_fields():
    archive = LocalReceiptArchive()
    worm = WORMLog()
    service = ReceiptArchiveService(archive, worm, "tenant-1")

    service.archive_record(_record(), parser_ref="research-prototype/parser.js")
    entry = worm.read_all()[0]

    assert entry["receipt_archive_event"] == "bound"
    assert entry["contains_user_content"] is False
    assert entry["archive_record_id"] == "r-1"
    assert entry["record_digest"].startswith("sha256:")
    assert entry["local_record_ref"] == "local://receipt/r-1"
    for forbidden in (
        "shop",
        "purchase_date",
        "amount_minor",
        "currency",
        "warranty_end",
        "source_text",
    ):
        assert forbidden not in entry
    assert service.verify_chain() is True


def test_local_deletion_appends_tombstone_without_user_content():
    archive = LocalReceiptArchive()
    worm = WORMLog()
    service = ReceiptArchiveService(archive, worm, "tenant-1")
    binding_digest = service.archive_record(_record())

    deletion_digest = service.delete_record("r-1")

    assert deletion_digest.startswith("sha256:")
    assert archive.get("r-1") is None
    assert service.verify_chain() is True
    entries = worm.read_all()
    assert len(entries) == 2
    deletion = entries[1]
    assert deletion["receipt_archive_event"] == "deleted_local_record"
    assert deletion["binding_ref"] == "receipt-binding-r-1"
    assert deletion["binding_digest"] == binding_digest
    assert deletion["contains_user_content"] is False
    assert "shop" not in deletion
    assert "source_text" not in deletion


def test_service_delete_all_attests_each_local_deletion():
    archive = LocalReceiptArchive()
    worm = WORMLog()
    service = ReceiptArchiveService(archive, worm, "tenant-1")
    service.archive_record(_record("r-1"))
    service.archive_record(_record("r-2"))

    digests = service.delete_all()

    assert len(digests) == 2
    assert archive.records() == ()
    assert len(worm.read_all()) == 4
    assert service.verify_chain() is True


def test_record_digest_changes_when_local_user_data_changes():
    first_archive = LocalReceiptArchive()
    first_worm = WORMLog()
    ReceiptArchiveService(first_archive, first_worm, "tenant-1").archive_record(
        _record()
    )

    changed = ReceiptArchiveRecordV1(
        record_id="r-1",
        shop="Stavanger Elektro",
        purchase_date=date(2026, 8, 8),
        amount_minor=139900,
        currency="NOK",
        warranty_end=date(2028, 8, 8),
        source_kind="paste",
        created_at=datetime(2026, 8, 8, 12, 0, tzinfo=UTC),
    )
    second_archive = LocalReceiptArchive()
    second_worm = WORMLog()
    ReceiptArchiveService(second_archive, second_worm, "tenant-1").archive_record(
        changed
    )

    assert (
        first_worm.read_all()[0]["record_digest"]
        != second_worm.read_all()[0]["record_digest"]
    )


def test_archive_rejects_invalid_warranty_order():
    invalid = ReceiptArchiveRecordV1(
        record_id="r-1",
        purchase_date=date(2026, 8, 8),
        warranty_end=date(2025, 8, 8),
    )
    with pytest.raises(ValueError, match="warranty_end"):
        invalid.to_payload()


def test_archive_rejects_non_uppercase_currency():
    invalid = ReceiptArchiveRecordV1(record_id="r-1", currency="nok")
    with pytest.raises(ValueError, match="currency"):
        invalid.to_payload()


def test_veritas_receipt_archive_has_no_authority_surface():
    service = ReceiptArchiveService(LocalReceiptArchive(), WORMLog(), "tenant-1")
    for name in ("authorize", "permit", "clearance", "grant", "execute"):
        assert not hasattr(service, name)


def test_duplicate_binding_rolls_back_local_record():
    archive = LocalReceiptArchive()
    worm = WORMLog()
    service = ReceiptArchiveService(archive, worm, "tenant-1")
    service.archive_record(_record())
    archive.delete("r-1")

    with pytest.raises(ValueError, match="duplicate entry id"):
        service.archive_record(_record())

    assert archive.get("r-1") is None
    assert service.verify_chain() is True
