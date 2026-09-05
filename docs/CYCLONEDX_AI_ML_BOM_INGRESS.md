# CycloneDX AI/ML-BOM evidence ingress

Status: architecture binding

Veritas accepts standards-based AI/ML supply-chain evidence as provenance-bound input. CycloneDX AI/ML-BOM is the first defined profile.

The purpose is not to make Veritas an AI inventory system or an authorization engine. The purpose is to give downstream decision layers a stable, verifiable evidence basis so equivalent facts can be compared on equivalent terms.

## System position

```text
CycloneDX AI/ML-BOM / external evidence
                |
                v
        Veritas ingest + bind
                |
                v
       canonical evidence state
                |
        +-------+-------+
        |               |
        v               v
     MAL/VAIG          reht
        |               |
        +-------+-------+
                |
                v
              RACS
                |
                v
             effect
                |
                v
        Veritas receipt
```

Veritas is therefore evidence-in and evidence-out:

- evidence-in: record, normalize only the transport/profile boundary, bind provenance, preserve the source artifact digest, and verify integrity;
- evidence-out: store the resulting execution receipt and its evidence/authorization bindings in the append-only chain.

Veritas does not infer whether a model is safe, compliant, admissible or authorized. Those conclusions remain outside the Veritas boundary.

## CycloneDX profile

A CycloneDX AI/ML-BOM can provide evidence about, among other things:

- model identity and version;
- package/repository identifiers;
- model architecture and configuration;
- datasets and lineage;
- software, hardware and framework dependencies;
- training and evaluation context;
- model pedigree such as fine-tuning, quantization, pruning and adapters;
- attestations and provenance references;
- declared intended use, limitations and related model-card information.

The source artifact is preserved as evidence. Veritas binds the raw artifact digest together with a canonical ingress envelope.

## Canonical ingress envelope

A standards-based evidence ingress should bind at least:

```text
profile                 e.g. cyclonedx-ai-ml-bom
profile_version         e.g. CycloneDX specVersion
source_artifact_digest  digest of the exact source artifact
subject_type            e.g. machine-learning-model
subject_id              stable model/component identifier
subject_version         exact version / commit / digest where available
provenance_refs         source, supplier, pedigree and handoff references
attestation_refs        referenced attestations, if present
observed_at             evidence observation time
ingested_at             Veritas ingestion time
```

Profile adapters may expose additional fields, but they must not silently reinterpret source claims.

## Apples-to-apples rule

Comparability is created by binding the same classes of facts to the same canonical evidence keys.

For example, two candidate models can be compared downstream using the same evidence dimensions:

```text
subject_id
subject_version
model pedigree
dependency identity/version
dataset lineage reference
attestation reference
source artifact digest
```

Veritas establishes that the compared values came from identified source artifacts and have not changed. It does not decide which candidate is better or whether either candidate may execute.

This distinction is deliberate:

```text
Veritas: what evidence is present, where it came from, and whether its binding is intact.
MAL/VAIG: what the evidence means for model/runtime admissibility or risk.
reht/RACS: whether the concrete governed action may proceed now.
Veritas: what actually happened and the resulting immutable receipt.
```

## Boundary requirements

1. The original source artifact digest MUST be retained.
2. Canonicalization MUST be deterministic.
3. Missing source fields MUST remain missing/unknown; adapters MUST NOT manufacture values.
4. Source assertions and Veritas observations MUST remain distinguishable.
5. Ingestion MUST NOT create execution authority.
6. A valid AI/ML-BOM MUST NOT by itself imply safety, compliance or permission.
7. Execution receipts MUST be linkable back to the evidence inputs used by the decision path.

## Initial source profile

Initial profile basis:

- OWASP CycloneDX, *Authoritative Guide to AI/ML-BOM*, First Edition, Revision 1, 10 June 2026.
- CycloneDX is standardized as ECMA-424.
- AI/ML-BOM is used as a descriptive supply-chain and model-transparency input, not as an authorization source.

This profile can be extended to other evidence standards without changing the Veritas doctrine.
