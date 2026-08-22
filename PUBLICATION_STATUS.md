# Publication status

Status date: 2026-08-22

Veritas is a public receipt, attestation and independent-verification library.

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
- unrelated private research, product architecture or commercial implementation internals.

## Publication rule

This is a public repository: a branch push is already disclosure. New substantive material must therefore receive explicit human IP/publication review before the first public push. Merge-time CI is defense in depth, not the primary IP gate.

Repository visibility is not a versioned release by itself. A release requires an immutable version/tag, exact commit, declared license and green verification tests on that commit.
