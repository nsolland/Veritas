"""Regression tests for Veritas WORM integrity boundaries."""

import json

import pytest

from veritas.worm import WORMIntegrityError, WORMLog


@pytest.mark.parametrize("field", ["id", "prev", "hash"])
def test_append_rejects_reserved_chain_fields(field):
    with pytest.raises(WORMIntegrityError, match="reserved fields"):
        WORMLog().append("e1", {field: "forged"})


def test_append_rejects_duplicate_entry_ids():
    worm = WORMLog()
    worm.append("e1", {"value": 1})
    with pytest.raises(WORMIntegrityError, match="duplicate entry id"):
        worm.append("e1", {"value": 2})


def test_tail_returns_defensive_snapshot():
    worm = WORMLog()
    worm.append("e1", {"nested": {"value": 1}})
    snapshot = worm.tail(1)
    snapshot[0]["nested"]["value"] = 9
    assert worm.tail(1)[0]["nested"]["value"] == 1


def test_load_rejects_tampered_chain(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    worm = WORMLog()
    worm.append("e1", {"value": 1})
    worm.persist(ledger)

    entry = json.loads(ledger.read_text())
    entry["value"] = 2
    ledger.write_text(json.dumps(entry) + "\n")

    with pytest.raises(WORMIntegrityError, match="verification failed"):
        WORMLog.load(ledger)


def test_load_rejects_malformed_json(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("{not-json}\n")
    with pytest.raises(WORMIntegrityError, match="invalid ledger JSON"):
        WORMLog.load(ledger)


def test_persist_appends_without_rewriting_prefix(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    worm = WORMLog()
    worm.append("e1", {"value": 1})
    worm.persist(ledger)
    prefix = ledger.read_bytes()

    worm.append("e2", {"value": 2})
    worm.persist(ledger)
    complete = ledger.read_bytes()
    assert complete.startswith(prefix)
    assert len(complete.splitlines()) == 2

    worm.persist(ledger)
    assert ledger.read_bytes() == complete


def test_persist_rejects_longer_existing_ledger(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    longer = WORMLog()
    longer.append("e1", {"value": 1})
    longer.append("e2", {"value": 2})
    longer.persist(ledger)

    shorter = WORMLog()
    shorter.append("e1", {"value": 1})
    with pytest.raises(WORMIntegrityError, match="longer"):
        shorter.persist(ledger)
