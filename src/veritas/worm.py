"""Veritas WORM audit log — SHA-256 hash-chained, append-only.

Every entry links to the previous via a canonical digest. Any modification
breaks the chain and fails ``verify()``.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from copy import deepcopy
from os import PathLike
from pathlib import Path
from typing import Any, Final, cast

from veritas.digest import canonical_digest, stable_json

_ZERO_HASH: Final = "0" * 64
_RESERVED_FIELDS: Final = frozenset({"id", "prev", "hash"})
Pathish = str | PathLike[str]


class WORMIntegrityError(ValueError):
    """Raised when a ledger operation would violate append-only integrity."""


class WORMLog:
    """Append-only, tamper-evident receipt ledger."""

    def __init__(self, path: Pathish | None = None) -> None:
        self.path = os.fspath(path) if path is not None else None
        self._entries: list[dict[str, Any]] = []
        self._entry_ids: set[str] = set()
        self._tail_hash = _ZERO_HASH

    def append(self, entry_id: str, payload: Mapping[str, Any]) -> str:
        """Append an immutable entry and return its canonical digest."""
        if not isinstance(entry_id, str) or not entry_id.strip():
            raise WORMIntegrityError("entry_id is required")
        if entry_id in self._entry_ids:
            raise WORMIntegrityError(f"duplicate entry id: {entry_id}")

        reserved = _RESERVED_FIELDS.intersection(payload)
        if reserved:
            names = ", ".join(sorted(reserved))
            raise WORMIntegrityError(f"payload contains reserved fields: {names}")

        entry = {
            "id": entry_id,
            "prev": self._tail_hash,
            **deepcopy(dict(payload)),
        }
        digest = canonical_digest(entry)
        entry["hash"] = digest

        self._entries.append(entry)
        self._entry_ids.add(entry_id)
        self._tail_hash = digest
        return digest

    def read_all(self) -> list[dict[str, Any]]:
        """Return a defensive snapshot; callers cannot mutate the ledger."""
        return deepcopy(self._entries)

    def tail(self, n: int = 10) -> list[dict[str, Any]]:
        if n < 0:
            raise ValueError("tail size must be non-negative")
        if n == 0:
            return []
        return deepcopy(self._entries[-n:])

    def verify(self) -> bool:
        prev = _ZERO_HASH
        seen_ids: set[str] = set()

        for entry in self._entries:
            entry_id = entry.get("id")
            if not isinstance(entry_id, str) or not entry_id or entry_id in seen_ids:
                return False
            if entry.get("prev") != prev:
                return False

            body = {key: value for key, value in entry.items() if key != "hash"}
            try:
                expected = canonical_digest(body)
            except (TypeError, ValueError):
                return False

            digest = entry.get("hash")
            if not isinstance(digest, str) or digest != expected:
                return False

            seen_ids.add(entry_id)
            prev = digest

        return self._tail_hash == prev and self._entry_ids == seen_ids

    def persist(self, path: Pathish | None = None) -> None:
        """Append new entries without rewriting an existing ledger prefix."""
        destination_value = path if path is not None else self.path
        if destination_value is None:
            raise ValueError("no ledger path configured")
        if not self.verify():
            raise WORMIntegrityError("refusing to persist an invalid in-memory chain")

        destination = Path(destination_value)
        existing_entries: list[dict[str, Any]] = []
        if destination.exists():
            existing_entries = self._read_entries(destination)
            if len(existing_entries) > len(self._entries):
                raise WORMIntegrityError("persisted ledger is longer than in-memory ledger")
            if existing_entries != self._entries[: len(existing_entries)]:
                raise WORMIntegrityError("persisted ledger diverges from in-memory chain")

        pending = self._entries[len(existing_entries) :]
        if pending:
            with destination.open("a", encoding="utf-8") as handle:
                for entry in pending:
                    handle.write(stable_json(entry) + "\n")
                handle.flush()
                os.fsync(handle.fileno())

        self.path = os.fspath(destination)

    @classmethod
    def load(cls, path: Pathish) -> WORMLog:
        source = Path(path)
        entries = cls._read_entries(source)

        log = cls(path=source)
        log._entries = entries
        log._entry_ids = {
            entry_id
            for entry in entries
            if isinstance((entry_id := entry.get("id")), str)
        }
        tail_hash = entries[-1].get("hash", _ZERO_HASH) if entries else _ZERO_HASH
        log._tail_hash = tail_hash if isinstance(tail_hash, str) else _ZERO_HASH
        if not log.verify():
            raise WORMIntegrityError("ledger hash chain verification failed")
        return log

    @staticmethod
    def _read_entries(path: Path) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        try:
            with path.open(encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        decoded = json.loads(stripped)
                    except json.JSONDecodeError as exc:
                        raise WORMIntegrityError(
                            f"invalid ledger JSON at line {line_number}"
                        ) from exc
                    if not isinstance(decoded, dict):
                        raise WORMIntegrityError(
                            f"ledger entry at line {line_number} must be an object"
                        )
                    entries.append(cast(dict[str, Any], decoded))
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise WORMIntegrityError(f"unable to read ledger: {path}") from exc
        return entries
