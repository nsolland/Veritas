"""Canonical digest helpers for Veritas.

Deterministic SHA-256 over a stable JSON serialization, so receipts are
byte-identical across runs and languages.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

CANONICALIZATION_ALGORITHM = "sha256-stable-json"


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented as strict canonical JSON."""


def canonical_digest(value: Any) -> str:
    """Return ``sha256:<hex>`` over the stable-JSON serialization of ``value``."""
    return "sha256:" + hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def stable_json(value: Any) -> str:
    """Serialize strict JSON with sorted keys and compact separators.

    Unsupported Python objects and non-finite floats fail closed instead of
    being converted to implementation-specific strings or non-standard JSON.
    """
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError("value is not strict canonical JSON") from exc
