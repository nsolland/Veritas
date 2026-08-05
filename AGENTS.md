# AGENTS.md — Veritas

> Machine-readable orientation for AI agents. Human/agent protocol overview is in
> `README.md`. This file is the agent task contract.

## Repository identity

- Stable ID: `valo.veritas`
- Canonical name: **Veritas** — VALO receipt layer (LA6)
- Public URL: https://github.com/nsolland/Veritas

## What this repo is

Veritas records and attests observations and follow-on receipts. It is the
receipt layer of the VALO governance stack
(`Speider → BARO → VAIG → REHT → RACS → Execution → Veritas`).

## Hard boundaries (do not cross)

- **Attest, don't interpret.** Veritas never analyses, classifies, concludes or
  authorizes. `CompletedEvidencePackageV1` rejects analysis fields
  (`classification`, `conclusion`, `evidence_sufficient`).
- **Append-only WORM.** Never mutate or rewrite a stored entry; any change
  breaks the chain (`verify()`).
- **Deterministic digests.** Use `canonical_digest` / `stable_json` from
  `veritas.digest`; never a non-canonical or non-sorted payload.
- **Provenance-first.** Observation packages must carry source, authorization
  and handoff references with digests.

## Where to work

- `src/veritas/contracts.py` — canonical receipt contracts (do not break
  compatibility without a version bump).
- `src/veritas/service.py` — chain service (record + verify).
- `src/veritas/worm.py` — WORM ledger.
- `tests/` — pytest suite.

## Conventions

- Python `>=3.11`, strict typing (mypy), ruff linting (both in CI).
- One issue = one branch (`hermes/…`) = one PR, targeting main.
- Contracts use frozen dataclasses with eager validation raising
  `VeritasContractError`.
- Timestamps are timezone-aware and serialized as UTC `Z`.

## Commands

```bash
python -m pip install -e ".[dev]"
pytest -q
python -m ruff check src tests
python -m mypy src/veritas
veritas-verify ledger.jsonl
```

PEP 668 environments: `PYTHONPATH=src python3 -m pytest -q`.
