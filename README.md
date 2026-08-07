# Veritas — VALO Receipt Layer (LA6)

Veritas records and attests observations and follow-on receipts. It does not
analyse, classify, conclude, or authorize what the observations mean.

**Record. Attest. Prove. No interpretation.**

## Architecture position

```text
Speider (LA1) → BARO (LA2) → VAIG (LA3) → REHT (LA4) → RACS (LA5) → Execution → Veritas (LA6)
```

Veritas is the receipt layer that documents what actually happened, bound to the
authorization and evidence chain.

## Doctrine

- **Attest, don't interpret.** Veritas rejects analysis fields (`classification`,
  `conclusion`, `evidence_sufficient`) in completed evidence.
- **Negative evidence is boundary-derived.** Missing observations or missing log
  entries are never proof that an action did not occur. Negative evidence must
  bind the excluded action to an authorization, enforced execution boundary,
  enforcement record, coverage attestation, and explicit time window.
- **Append-only WORM.** Every receipt links to the previous via a canonical
  SHA-256 digest; any modification breaks the chain.
- **Deterministic digests.** RFC-8785-style stable JSON → SHA-256, so receipts
  are byte-identical across implementations.
- **Provenance-first.** Every observation package carries source, authorization
  and handoff references with digests.

## Contracts

- `ObservedEventV1` — a single observed event with provenance
- `ObservationPackageV1` — a governed observation package
- `BoundaryNegativeEvidenceV1` — boundary-derived negative evidence; never
  inferred from absence of observations
- `CompletedEvidencePackageV1` — completed evidence (rejects analysis fields)
- `StoredEvidenceReportV1` — stored evidence report bound to a chain
- `FinalEvidenceBindingV1` — final follow-on evidence binding

## Quick start

```python
from veritas import VeritasChainService, WORMLog

service = VeritasChainService(WORMLog())
digest = service.store_observation_package(package)  # → sha256:<hex>
assert service.verify_chain() is True
```

Verify a persisted ledger from the CLI:

```bash
veritas-verify ledger.jsonl
```

## Development

```bash
python -m pip install -e ".[dev]"
pytest -q
python -m ruff check src tests
python -m mypy src/veritas
```

PEP 668 systems: `PYTHONPATH=src python3 -m pytest -q`.

## License

MIT — VALO Contributors.
