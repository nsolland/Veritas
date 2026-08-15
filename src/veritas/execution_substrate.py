from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from veritas.contracts import VeritasContractError

_FIELDS = frozenset(
    {
        "schema_version",
        "substrate_kind",
        "attested_workspace_digest",
        "substrate_attestation_digest",
        "attestation_evidence_digest",
        "substrate_id",
        "tee_type",
        "gpu_identity",
        "cc_mode",
        "measurement",
        "attestation_verifier",
        "attested_at",
        "valid_until",
        "max_attestation_age_seconds",
        "model_digest",
        "workload_digest",
        "verification_status",
        "confidentiality_protected",
        "integrity_protected",
        "isolation_enforced",
        "authority_effect",
        "can_issue_clearance",
    }
)
_HEX = set("0123456789abcdef")


def _canonical_binding_digest(value: Mapping[str, Any]) -> str:
    raw = json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _require_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise VeritasContractError(f"{name} is required")
    return value


def _require_digest(name: str, value: Any) -> str:
    text = _require_text(name, value)
    if not text.startswith("sha256:"):
        raise VeritasContractError(f"{name} must be a sha256 digest")
    suffix = text[7:]
    if len(suffix) != 64 or any(char not in _HEX for char in suffix):
        raise VeritasContractError(f"{name} must be a sha256 digest")
    return text


def _require_timestamp(name: str, value: Any) -> str:
    text = _require_text(name, value)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise VeritasContractError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise VeritasContractError(f"{name} must be timezone-aware")
    return text


@dataclass(frozen=True)
class ConfidentialExecutionEvidenceV1:
    payload: Mapping[str, Any]

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any]
    ) -> ConfidentialExecutionEvidenceV1:
        data = dict(value)
        missing = _FIELDS.difference(data)
        extra = set(data).difference(_FIELDS)
        if missing or extra:
            detail = []
            if missing:
                detail.append(f"missing: {', '.join(sorted(missing))}")
            if extra:
                detail.append(f"unexpected: {', '.join(sorted(extra))}")
            raise VeritasContractError(
                "invalid confidential execution evidence fields ("
                + "; ".join(detail)
                + ")"
            )
        cls._validate(data)
        return cls(payload=data)

    @staticmethod
    def _validate(data: Mapping[str, Any]) -> None:
        if data.get("schema_version") != "confidential_execution_binding.v1":
            raise VeritasContractError(
                "unsupported confidential execution binding schema"
            )
        if data.get("substrate_kind") != "TEE":
            raise VeritasContractError("confidential execution substrate_kind must be TEE")
        for name in (
            "substrate_id",
            "tee_type",
            "gpu_identity",
            "cc_mode",
            "measurement",
            "attestation_verifier",
            "verification_status",
        ):
            _require_text(name, data.get(name))
        for name in (
            "attested_workspace_digest",
            "substrate_attestation_digest",
            "attestation_evidence_digest",
        ):
            _require_digest(name, data.get(name))
        for name in ("model_digest", "workload_digest"):
            if data.get(name) is not None:
                _require_digest(name, data.get(name))
        _require_timestamp("attested_at", data.get("attested_at"))
        _require_timestamp("valid_until", data.get("valid_until"))
        max_age = data.get("max_attestation_age_seconds")
        if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age <= 0:
            raise VeritasContractError(
                "max_attestation_age_seconds must be a positive integer"
            )
        for name in (
            "confidentiality_protected",
            "integrity_protected",
            "isolation_enforced",
        ):
            if not isinstance(data.get(name), bool):
                raise VeritasContractError(f"{name} must be boolean")
        if data.get("authority_effect") != "NO_AUTHORITY_CREATION":
            raise VeritasContractError(
                "confidential execution evidence must not create authority"
            )
        if data.get("can_issue_clearance") is not False:
            raise VeritasContractError(
                "confidential execution evidence must not issue clearance"
            )

    @property
    def binding_digest(self) -> str:
        return _canonical_binding_digest(self.payload)

    def to_payload(self) -> dict[str, Any]:
        self._validate(self.payload)
        return dict(self.payload)
