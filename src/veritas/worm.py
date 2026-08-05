"""Veritas WORM audit log — SHA-256 hash-chained, append-only.

Every entry links to the previous via a canonical digest. Any modification
breaks the chain and fails ``verify()``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from veritas.digest import canonical_digest


class WORMLog:
    """Append-only, tamper-evident receipt ledger."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path
        self._entries: List[Dict[str, Any]] = []
        self._tail_hash = "0" * 64

    def append(self, entry_id: str, payload: Dict[str, Any]) -> str:
        """Append an entry; returns its digest."""
        entry = {
            "id": entry_id,
            "prev": self._tail_hash,
            **payload,
        }
        digest = canonical_digest(entry)
        entry["hash"] = digest
        self._tail_hash = digest
        self._entries.append(entry)
        return digest

    def read_all(self) -> List[Dict[str, Any]]:
        return list(self._entries)

    def tail(self, n: int = 10) -> List[Dict[str, Any]]:
        return self._entries[-n:]

    def verify(self) -> bool:
        prev = "0" * 64
        for entry in self._entries:
            if entry.get("prev") != prev:
                return False
            body = {k: v for k, v in entry.items() if k != "hash"}
            expected = canonical_digest(body)
            if entry.get("hash") != expected:
                return False
            prev = entry["hash"]
        return True

    def persist(self, path: Optional[str] = None) -> None:
        """Write the ledger as newline-delimited JSON to ``path``."""
        destination = path or self.path
        if not destination:
            raise ValueError("no ledger path configured")
        import json as _json

        with open(destination, "w", encoding="utf-8") as fh:
            for entry in self._entries:
                fh.write(_json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")

    @classmethod
    def load(cls, path: str) -> "WORMLog":
        import json as _json

        log = cls(path=path)
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                entry = _json.loads(line)
                log._entries.append(entry)
                log._tail_hash = entry.get("hash", "0" * 64)
        return log
