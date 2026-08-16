from datetime import UTC, datetime

import pytest

from veritas.contracts import VeritasContractError
from veritas.incident import IncidentArtifactRefV1, IncidentEvidenceChainV1
from veritas.service import VeritasChainService
from veritas.worm import WORMLog


def _ref(name: str) -> IncidentArtifactRefV1:
    return IncidentArtifactRefV1(
        artifact_ref=name,
        artifact_digest=(name[0] if name[0] in "abcdef" else "a") * 64,
        artifact_type=name,
    )


def _chain(**overrides) -> IncidentEvidenceChainV1:
    args = {
        "chain_id": "chain-1",
        "tenant_id": "tenant-a",
        "incident_id": "incident-7",
        "subject_ref": "service/payments",
        "pre_state": _ref("pre-state"),
        "diagnostic_evidence": (_ref("diagnostic"),),
        "authorization": _ref("authorization"),
        "execution": _ref("execution"),
        "post_state": _ref("post-state"),
        "metadata": {"workflow_ref": "workflow-9"},
        "recorded_at": datetime(2026, 8, 16, 19, 0, tzinfo=UTC),
    }
    args.update(overrides)
    return IncidentEvidenceChainV1(**args)


def test_incident_chain_binds_all_evidence_stages_without_interpretation() -> None:
    payload = _chain().to_payload()
    assert payload["pre_state"]["artifact_ref"] == "pre-state"
    assert payload["diagnostic_evidence"][0]["artifact_ref"] == "diagnostic"
    assert payload["authorization"]["artifact_ref"] == "authorization"
    assert payload["execution"]["artifact_ref"] == "execution"
    assert payload["post_state"]["artifact_ref"] == "post-state"
    assert "classification" not in payload
    assert "conclusion" not in payload


def test_incident_chain_rejects_analysis_fields() -> None:
    with pytest.raises(VeritasContractError, match="analysis fields"):
        _chain(metadata={"severity": "SEV1"}).to_payload()


def test_incident_chain_is_append_only_and_findable() -> None:
    worm = WORMLog()
    service = VeritasChainService(worm)
    digest = service.store_incident_evidence_chain(_chain())

    assert len(digest) == 64
    assert service.verify_chain() is True
    assert service.find_entry("chain-1")["incident_id"] == "incident-7"
    assert service.find_entry("incident-7")["chain_id"] == "chain-1"
