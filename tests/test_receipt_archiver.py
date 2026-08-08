"""Tests for the accessible receipt archiver (#70, P0 slice).

Coverage: deterministic digests, local-first privacy, user-owned
delete-everything, field extraction, Veritas chain binding, absence of
authority semantics, append-only revisions, cross-instance determinism,
invalid-payload rejection and empty-archive behaviour.
"""

from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime

import pytest

from veritas import receipts as receipts_module
from veritas.contracts import ObservedEventV1
from veritas.digest import canonical_digest
from veritas.receipts import (
    AccessibleReceiptArchiver,
    ReceiptArchiveError,
    ReceiptArchiveRecordV1,
    add_warranty_end,
    extract_receipt_fields,
)
from veritas.service import VeritasChainService
from veritas.worm import WORMLog

PROTOTYPE_TEXT = (
    "ELKJØP OSLO\nKvittering\n12.03.2026\n"
    "TV Samsung  kr 4 999,00\nTotalt kr 4999,00"
)


def _archiver(worm: WORMLog | None = None) -> AccessibleReceiptArchiver:
    return AccessibleReceiptArchiver(worm=worm)


def test_register_produces_deterministic_digest():
    archiver = _archiver()
    archive_id = archiver.register(PROTOTYPE_TEXT)
    record = archiver.get(archive_id)
    assert record is not None
    assert record.source_payload_digest.startswith("sha256:")
    expected = canonical_digest(
        {"source_text": PROTOTYPE_TEXT, "extracted": dict(record.extracted)}
    )
    assert record.source_payload_digest == expected


def test_local_first_no_network_no_cloud_upload(tmp_path):
    source = inspect.getsource(receipts_module)
    for token in (
        "import socket",
        "import urllib",
        "import requests",
        "http.client",
        "aiohttp",
        "httpx",
    ):
        assert token not in source, f"network import present: {token}"
    archiver = _archiver()
    archiver.register(PROTOTYPE_TEXT)
    assert archiver.record_count() == 1
    assert list(tmp_path.iterdir()) == []
    assert not hasattr(archiver, "upload")


def test_delete_everything_removes_all_records():
    archiver = _archiver()
    archiver.register(PROTOTYPE_TEXT)
    archiver.register("IKEA\n2025-11-02\nTotal 129.99")
    archiver.register("POWER\n2026-01-15\nkr 12 500,00")
    assert len(archiver.list_records()) == 3
    removed = archiver.delete_everything()
    assert removed == 3
    assert archiver.list_records() == []
    assert archiver.export_all() == []


def test_field_extraction_from_prototype_format():
    fields = extract_receipt_fields(PROTOTYPE_TEXT, warranty_months=24)
    assert fields["shop"] == "ELKJØP OSLO"
    assert fields["date"] == "2026-03-12"
    assert fields["amount"] == "4999.00"
    assert fields["warranty_end"] == "2028-03-12"
    assert add_warranty_end("2026-03-12", 24) == "2028-03-12"
    iso = extract_receipt_fields("IKEA\n2025-11-02\nTotal 129.99")
    assert iso["date"] == "2025-11-02"
    assert iso["amount"] == "129.99"


def test_veritas_binding_produces_observed_event():
    archiver = _archiver()
    archive_id = archiver.register(PROTOTYPE_TEXT)
    event = archiver.veritas_binding(archive_id)
    assert isinstance(event, ObservedEventV1)
    assert event.event_type == "receipt_registered"
    assert event.payload_digest.startswith("sha256:")
    assert event.event_id == f"receipt:{archive_id}"
    payload = event.to_dict()
    assert payload["provenance"]["authority_granted"] is False


def test_archiving_never_grants_authority():
    archiver = _archiver()
    archive_id = archiver.register(PROTOTYPE_TEXT)
    event = archiver.veritas_binding(archive_id).to_dict()
    provenance = event["provenance"]
    assert provenance["authority_granted"] is False
    for forbidden in ("clearance", "permit", "execution_authority"):
        assert forbidden not in provenance
        assert forbidden not in event
    record = archiver.get(archive_id)
    assert record is not None
    assert not hasattr(record, "clearance")
    assert not hasattr(record, "permit")


def test_revision_is_superseding_append_only():
    archiver = _archiver()
    first = archiver.register(PROTOTYPE_TEXT)
    revised = archiver.revise(
        first,
        extracted={
            "shop": "ELKJØP OSLO",
            "date": "2026-03-12",
            "amount": "4999.00",
            "warranty_end": "2028-03-12",
        },
    )
    assert archiver.record_count() == 2
    assert archiver.get(first) is not None
    assert archiver.get(revised) is not None
    assert archiver.get(revised).supersedes == first
    heads = archiver.list_records()
    assert len(heads) == 1
    assert heads[0]["archive_id"] == revised


def test_digest_deterministic_across_instances():
    left = _archiver()
    right = _archiver()
    left.register(PROTOTYPE_TEXT)
    right.register(PROTOTYPE_TEXT)
    left_record = left.list_records()[0]
    right_record = right.list_records()[0]
    assert left_record["source_payload_digest"] == right_record[
        "source_payload_digest"
    ]


def test_invalid_payload_extra_fields_rejected():
    archiver = _archiver()
    with pytest.raises(ReceiptArchiveError, match="unexpected extracted fields"):
        archiver.register(
            PROTOTYPE_TEXT,
            extracted={
                "shop": "ELKJØP OSLO",
                "date": "2026-03-12",
                "amount": "4999.00",
                "warranty_end": "",
                "customer_id": "42",
            },
        )
    with pytest.raises(ReceiptArchiveError, match="extracted.shop"):
        archiver.register(
            PROTOTYPE_TEXT,
            extracted={"date": "2026-03-12", "amount": "4999.00"},
        )


def test_empty_archive_has_no_records():
    archiver = _archiver()
    assert archiver.list_records() == []
    assert archiver.export_all() == []
    assert archiver.search("anything") == []
    assert archiver.record_count() == 0


def test_register_requires_non_empty_source():
    archiver = _archiver()
    with pytest.raises(ReceiptArchiveError, match="source_text is required"):
        archiver.register("")
    with pytest.raises(ReceiptArchiveError, match="source_text is required"):
        archiver.register("   \n  ")


def test_delete_single_record_is_user_owned():
    archiver = _archiver()
    first = archiver.register(PROTOTYPE_TEXT)
    second = archiver.register("IKEA\n2025-11-02\nTotal 129.99")
    assert archiver.delete(first) is True
    assert archiver.delete(first) is False
    assert [record["archive_id"] for record in archiver.list_records()] == [second]
    assert archiver.get(first) is not None  # immutable history retained


def test_search_filters_by_shop():
    archiver = _archiver()
    archiver.register(PROTOTYPE_TEXT)
    archiver.register("IKEA OSLO\n2025-11-02\nTotal 129.99")
    assert len(archiver.search("elk")) == 1
    assert archiver.search("elk")[0]["extracted"]["shop"] == "ELKJØP OSLO"
    assert len(archiver.search("oslo")) == 2
    assert len(archiver.search("")) == 2


def test_export_all_is_json_serializable():
    archiver = _archiver()
    archiver.register(PROTOTYPE_TEXT)
    archiver.register("IKEA\n2025-11-02\nTotal 129.99")
    payload = json.dumps(archiver.export_all(), ensure_ascii=False)
    assert "ELKJØP OSLO" in payload


def test_publish_to_chain_persists_and_verifies():
    worm = WORMLog()
    archiver = _archiver(worm)
    archive_id = archiver.register(PROTOTYPE_TEXT)
    digest = archiver.publish_to_chain(archive_id)
    assert digest.startswith("sha256:")
    chain = VeritasChainService(worm)
    assert chain.verify_chain() is True
    assert chain.find_entry(f"rcpt-pkg-{archive_id}") is not None


def test_publish_requires_configured_chain():
    archiver = _archiver()
    archive_id = archiver.register(PROTOTYPE_TEXT)
    with pytest.raises(ReceiptArchiveError, match="no WORM chain configured"):
        archiver.publish_to_chain(archive_id)


def test_observed_event_digest_is_tamper_evident():
    record = ReceiptArchiveRecordV1(
        archive_id="rcpt-1",
        tenant_id="local-user",
        source_payload_digest=canonical_digest({"source_text": PROTOTYPE_TEXT}),
        source_text=PROTOTYPE_TEXT,
        extracted={
            "shop": "ELKJØP OSLO",
            "date": "2026-03-12",
            "amount": "4999.00",
            "warranty_end": "2028-03-12",
        },
        recorded_at=datetime(2026, 8, 8, tzinfo=UTC),
    )
    event = record.to_observed_event()
    assert event.payload_digest == canonical_digest(record.to_payload())
