# Veritas

Veritas is a receipt, attestation and verification layer for governed actions. It records observations, preserves provenance and verifies deterministic evidence bindings without interpreting what the observations mean or creating execution authority.

Record. Attest. Prove. No interpretation.

## Boundary

Veritas can sit behind any compatible enforcement/runtime layer that emits the required receipt and provenance bindings.

```text
authorization / decision provider
            |
            v
mechanical enforcement / execution
            |
            v
receipt / observation
            |
            v
Veritas record + verify
```

VALO Gateway, RACS and REHT are compatible producers/bindings used by the VALO stack. They are not required to use Veritas as a receipt verifier.

Veritas does not analyse, classify, conclude, grant authority, approve actions or authorize execution.

## Doctrine

- Attest, don't interpret. Veritas rejects analysis fields such as `classification`, `conclusion` and `evidence_sufficient` in completed evidence.
- Negative evidence is boundary-derived. Missing observations or log entries are never proof that an action did not occur.
- Append-only WORM. Every receipt links to the previous receipt through a canonical digest; modification breaks the chain.
- Deterministic digests. Stable canonical JSON is hashed so independent implementations can verify the same binding.
- Provenance-first. Observation packages carry source, authorization and handoff references with digests.
- Evidence is not authority. A valid receipt can establish integrity or continuity; it cannot grant current permission to execute.

## Contracts

- `ObservedEventV1` — a single observed event with provenance
- `ObservationPackageV1` — a governed observation package
- `BoundaryNegativeEvidenceV1` — boundary-derived negative evidence
- `CompletedEvidencePackageV1` — completed evidence without analysis claims
- `StoredEvidenceReportV1` — stored evidence report bound to a chain
- `FinalEvidenceBindingV1` — final follow-on evidence binding
- `ReceiptArchiveRecordV1` — immutable local-first receipt archive record
- `AccessibleReceiptArchiver` — append-only receipt archive with verifiable chain binding

## Quick start

```python
from veritas import VeritasChainService, WORMLog

service = VeritasChainService(WORMLog())
digest = service.store_observation_package(package)
assert service.verify_chain() is True
```

Verify a persisted ledger from the CLI:

```bash
veritas-verify ledger.jsonl
```

## Publication

See `PUBLICATION_STATUS.md`. The public surface is the portable receipt/verifier layer and compatible non-authoritative adapters. Production evidence, secrets and authorization logic are outside this repository boundary.

## Development

```bash
python -m pip install -e ".[dev]"
pytest -q
python -m ruff check src tests
python -m mypy src/veritas
```

PEP 668 systems: `PYTHONPATH=src python3 -m pytest -q`.

## License

MIT. See `LICENSE`.
