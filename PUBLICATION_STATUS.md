# Publication status

Status date: 2026-08-21

Veritas is being prepared as a public receipt, attestation and independent-verification library.

Its public role is deliberately narrow: record observations, preserve provenance, verify deterministic bindings and make tampering or broken receipt continuity detectable. It does not infer authority, approve actions, evaluate policy or decide what an observation means.

## Public surface

The intended public surface includes:

- receipt and observation contracts;
- deterministic canonicalization and digest verification;
- append-only/WORM chain verification;
- provenance and execution-handoff verification;
- the `veritas-verify` CLI;
- adapters for compatible execution evidence where those adapters do not create authority.

## Explicit exclusions

Public availability does not include or imply:

- authorization/evaluation logic;
- private tenant evidence or production ledgers;
- credentials, signing secrets or deployment configuration;
- PEACE, MCIP, Neuro Mesh or adaptive intelligence research.

Repository visibility is not a release by itself. A release requires an immutable version/tag, exact commit, declared license and green verification tests on that commit.
