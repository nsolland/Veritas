# Claim — Agent Skills binding v1

- Owner: ChatGPT / Codex
- Repository: `nsolland/Veritas`
- Canonical base SHA: `9f50524a2f6702277028b1d99915611bb0dcb238`
- Branch: `feat/agent-skills-binding`
- Draft PR: `#3`
- Build order: `agent-skills-binding-v1`
- Delivery: attest the exact Agent Skills binding used by a governed execution without interpreting or authorizing it
- Owned files:
  - `.claims/agent-skills-binding-v1.md`
  - `src/veritas/contracts.py`
  - `tests/test_veritas.py`
  - `src/veritas/worm.py` (pre-existing Ruff blocker required by the active CI gate)
  - `src/veritas/digest.py` (pre-existing mypy blockers required by the active CI gate)
- Dependencies: REHT/Gateway `skill_binding_digest` in RACS `sha256:<hex>` form and existing RFC 8785/WORM receipt chain
- Verification: UNVERIFIED until hosted checks complete
- Non-goals: skill admissibility, skill discovery/loading, authority, policy evaluation, or execution
