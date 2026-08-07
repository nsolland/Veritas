"""Veritas WORM audit log — hash-chained and append-only.

Every entry links to the previous via a canonical digest. Any modification
breaks the chain and fails ``verify()``.

Chain hashes alone only detect *accidental* tampering: an attacker who can
rewrite the ledger can also recompute every hash. ``anchor`` adds an external
commitment — an Ed25519 signature over the current tail hash by an operator
key the attacker does not hold — so ``verify_anchor`` fails on any rewrite or
append after the last anchoring point.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from copy import deepcopy
from datetime import UTC, datetime
from os import PathLike
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from veritas.digest import canonical_digest, stable_json

_ZERO_HASH: Final = "0" * 64
_RESERVED_FIELDS: Final = frozenset({"id", "prev", "hash"})
_ANCHOR_ALGORITHM: Final = "Ed25519"
Pathish = str | PathLike[str]


class WORMIntegrityError(ValueError):
    """Raised when an operation would violate ledger integrity."""


class WORMLog:
    """Append-only, tamper-evident receipt ledger."""

    def __init__(self, path: Pathish | None = None) -> None:
        self.path = os.fspath(path) if path is not None else None
        self._entries: list[dict[str, Any]] = []
        self._entry_ids: set[str] = set()
        self._tail_hash = _ZERO_HASH
        self._anchors: list[dict[str, Any]] = []
        self._anchors_persisted: int = 0

    def append(self, entry_id: str, payload: Mapping[str, Any]) -> str:
        if not isinstance(entry_id, str) or not entry_id.strip():
            raise WORMIntegrityError("entry_id is required")
        if entry_id in self._entry_ids:
            raise WORMIntegrityError(f"duplicate entry id: {entry_id}")
        reserved = _RESERVED_FIELDS.intersection(payload)
        if reserved:
            raise WORMIntegrityError(
                f"payload contains reserved fields: {', '.join(sorted(reserved))}"
            )

        entry = {"id": entry_id, "prev": self._tail_hash, **deepcopy(dict(payload))}
        digest = canonical_digest(entry)
        entry["hash"] = digest
        self._entries.append(entry)
        self._entry_ids.add(entry_id)
        self._tail_hash = digest
        return digest

    def read_all(self) -> list[dict[str, Any]]:
        return deepcopy(self._entries)

    def tail(self, n: int = 10) -> list[dict[str, Any]]:
        if n < 0:
            raise ValueError("tail size must be non-negative")
        return deepcopy(self._entries[-n:]) if n else []

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

    # ---- External anchoring (Ed25519 commitment over the tail hash) ----

    @property
    def anchors(self) -> list[dict[str, Any]]:
        return deepcopy(self._anchors)

    def anchor(self, private_key: bytes) -> str:
        """Sign the current tail hash with an operator Ed25519 key.

        Returns the anchor id. Any append or rewrite after this point breaks
        ``verify_anchor`` (the tail changes) until the chain is re-anchored.
        """
        key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        anchor_id = f"anchor-{len(self._anchors) + 1}"
        anchored_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        body = {
            "anchor_id": anchor_id,
            "algorithm": _ANCHOR_ALGORITHM,
            "tail_hash": self._tail_hash,
            "entry_count": len(self._entries),
            "anchored_at": anchored_at,
        }
        signature = key.sign(canonical_digest(body).encode("utf-8"))
        self._anchors.append({**body, "signature": signature.hex()})
        return anchor_id

    def verify_anchor(self, public_key: bytes) -> bool:
        """Verify the latest anchor covers the CURRENT chain tail.

        Returns True only if the chain is intact AND its tail is the exact tail
        the operator signed. A rewritten or appended chain fails closed.
        """
        if not self._anchors:
            return False
        if not self.verify():
            return False
        latest = self._anchors[-1]
        if latest.get("algorithm") != _ANCHOR_ALGORITHM:
            return False
        if latest.get("tail_hash") != self._tail_hash:
            return False
        if latest.get("entry_count") != len(self._entries):
            return False
        body = {
            "anchor_id": latest["anchor_id"],
            "algorithm": latest["algorithm"],
            "tail_hash": latest["tail_hash"],
            "entry_count": latest["entry_count"],
            "anchored_at": latest["anchored_at"],
        }
        try:
            public = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            public.verify(
                bytes.fromhex(latest["signature"]),
                canonical_digest(body).encode("utf-8"),
            )
            return True
        except (InvalidSignature, ValueError, KeyError):
            return False

    def persist(self, path: Pathish | None = None) -> None:
        destination_value = path if path is not None else self.path
        if destination_value is None:
            raise ValueError("no ledger path configured")
        if not self.verify():
            raise WORMIntegrityError("refusing to persist an invalid in-memory chain")

        destination = Path(destination_value)
        existing_entries: list[dict[str, Any]] = []
        if destination.exists():
            existing_entries = WORMLog.load(destination).read_all()
            if len(existing_entries) > len(self._entries):
                raise WORMIntegrityError("persisted ledger is longer than in-memory ledger")
            if existing_entries != self._entries[: len(existing_entries)]:
                raise WORMIntegrityError("persisted ledger diverges from in-memory chain")

        pending = self._entries[len(existing_entries) :]
        if pending:
            with destination.open("ab") as handle:
                for entry in pending:
                    handle.write(stable_json(entry) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        self.path = os.fspath(destination)

        anchors_path = Path(f"{destination}.anchors")
        pending_anchors = self._anchors[self._anchors_persisted :]
        if pending_anchors:
            with anchors_path.open("ab") as handle:
                for anchor in pending_anchors:
                    handle.write(stable_json(anchor) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._anchors_persisted = len(self._anchors)

    @classmethod
    def load(cls, path: Pathish) -> WORMLog:
        source = Path(path)
        entries = cls._read_entries(source)
        log = cls(path=source)
        log._entries = entries
        log._entry_ids = {
            entry["id"] for entry in entries if isinstance(entry.get("id"), str)
        }
        log._tail_hash = entries[-1].get("hash", _ZERO_HASH) if entries else _ZERO_HASH
        if not log.verify():
            raise WORMIntegrityError("ledger hash chain verification failed")

        anchors_path = Path(f"{source}.anchors")
        try:
            log._anchors = cls._read_entries(anchors_path)
            log._anchors_persisted = len(log._anchors)
        except FileNotFoundError:
            log._anchors = []
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
                        entry = json.loads(stripped)
                    except json.JSONDecodeError as exc:
                        raise WORMIntegrityError(
                            f"invalid ledger JSON at line {line_number}"
                        ) from exc
                    if not isinstance(entry, dict):
                        raise WORMIntegrityError(
                            f"ledger entry at line {line_number} must be an object"
                        )
                    entries.append(entry)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise WORMIntegrityError(f"unable to read ledger: {path}") from exc
        return entries
