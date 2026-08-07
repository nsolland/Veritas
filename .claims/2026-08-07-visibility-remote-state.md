# Claim — repo-manifest visibility aligned to remote state

- Owner: opencode
- Repository: `nsolland/Veritas`
- Canonical base SHA: `a47d1bef01e163a9554607a9b7cc5a26f2089420`
- Branch: `fix/veritas-visibility-2026-08-07`
- Draft PR: `#6`
- Delivery: correct `repo-manifest.yaml` `visibility` from `public` to `private` to match actual GitHub remote state; keeps the repository profile consistent with the Index registry entry (`valo.veritas`, private)
- Owned files:
  - `.claims/2026-08-07-visibility-remote-state.md`
  - `repo-manifest.yaml`
- Dependencies: nsolland/Index#647; Index registry `valo.veritas` entry
- Verification: YAML parse OK; metadata-only; no runtime, test, schema or contract changes
- Non-goals: no architecture change, no authorization, no execution claim
