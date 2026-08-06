"""Canonical digest helpers for Veritas.

Strict RFC 8785 (JCS) canonicalization via ``jsoncanon``, so receipts are
byte-identical across runs and languages — the receipt layer's core promise.

Non-canonicalizable content (e.g. ``datetime`` objects, custom types) raises
``TypeError`` instead of being silently ``str()``-ed: a receipt that cannot be
canonically hashed must fail closed, never become an implementation-specific
digest.
"""

from __future__ import annotations

import hashlib
from typing import Any

from jsoncanon import canonicalize  # type: ignore[attr-defined]

CANONICALIZATION_ALGORITHM = "sha256-rfc8785-json"


def canonical_digest(value: Any) -> str:
    """Return ``sha256:<hex>`` over the RFC 8785 canonical form of ``value``."""
    return "sha256:" + hashlib.sha256(canonicalize(value)).hexdigest()


def stable_json(value: Any) -> bytes:
    """Return the RFC 8785 (JCS) canonical serialization of ``value`` (bytes)."""
    return canonicalize(value)
