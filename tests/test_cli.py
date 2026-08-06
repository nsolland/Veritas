"""CLI regression tests for Veritas ledger verification."""

from __future__ import annotations

import json

from veritas.cli import main
from veritas.worm import WORMLog


def test_cli_reports_missing_ledger(capsys, tmp_path) -> None:
    status = main([str(tmp_path / "missing.jsonl")])

    captured = capsys.readouterr()
    assert status == 2
    assert "ledger not found" in captured.err


def test_cli_rejects_tampered_ledger(capsys, tmp_path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    worm = WORMLog(ledger)
    worm.append("entry-1", {"record_id": "record-1"})
    worm.persist()

    entry = json.loads(ledger.read_text(encoding="utf-8"))
    entry["record_id"] = "tampered"
    ledger.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    status = main([str(ledger)])

    captured = capsys.readouterr()
    assert status == 1
    assert "VERITAS FAILED" in captured.err


def test_cli_accepts_intact_ledger(capsys, tmp_path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    worm = WORMLog(ledger)
    worm.append("entry-1", {"record_id": "record-1"})
    worm.persist()

    status = main([str(ledger)])

    captured = capsys.readouterr()
    assert status == 0
    assert "VERITAS OK: 1 entries" in captured.out
