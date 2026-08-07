# Claim — Boundary-derived negative evidence v1

- Owner: ChatGPT / Codex
- Repository: `nsolland/Veritas`
- Canonical base SHA: `a47d1bef01e163a9554607a9b7cc5a26f2089420`
- Branch: `feat/boundary-derived-negative-evidence`
- Draft PR: `#5`
- Delivery: make negative evidence admissible only when it is bound to an enforced execution boundary, never merely inferred from missing observations
- Owned files:
  - `.claims/boundary-derived-negative-evidence-v1.md`
  - `src/veritas/contracts.py`
  - `src/veritas/service.py`
  - `src/veritas/__init__.py`
  - `tests/test_veritas.py`
  - `README.md`
- Dependencies: existing REHT/RACS execution-boundary receipts/digests and Veritas WORM chain
- Verification: hosted CI on the resulting PR head
- Non-goals: creating authority, evaluating policy, proving semantic truth, inferring non-events from log absence, or changing REHT/RACS authority semantics
