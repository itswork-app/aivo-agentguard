# ADR-0008: Independent Authorization Attestation

- **Status:** Accepted — G3 v0.1.0
- **Date:** 2026-11-16
- **Decision owners:** Project maintainer

## Context

G2 established that the permit signer cannot trust a runtime-supplied ALLOW assertion. A distinct authorization-attestation issuer is required, but its independence and evidence binding must be concrete enough to implement and test.

## Decision

Introduce a purpose-specific authorization-attestation issuer in a separate trust boundary from the runtime coordinator and permit signer. It independently validates authenticated identities, request/action digests, signed policy provenance, trusted context attestations and freshness, evaluator version, and a durable signed evidence receipt. It then independently recomputes the deterministic policy decision and issues an Ed25519 attestation only if the result is ALLOW and every binding matches.

The issuer must not merely sign a runtime assertion. The attestation binds exact tenant/principal/agent/request, request/action/policy/context digests, policy issuer/key, evaluator semantic version and artifact digest, durable decision event reference, evidence receipt, timestamps, and a one-time challenge nonce.

The permit signer verifies the attestation and exact equality with the proposed permit before signing. Enforcement independently verifies the attestation and current issuer status.

## Consequences

- Runtime compromise alone is insufficient to mint an attested ALLOW.
- The verifier becomes a high-value security boundary requiring separate identity, deployment, access control, and monitoring.
- Reusing the deterministic evaluator library may create common-mode defects; golden vectors, property tests, fuzzing, and later diverse implementation review are required.
- The attestation is a signed assertion backed by independent recomputation, not a formal proof of program correctness.
- A dedicated evidence receipt signing key is required and must be separate from all other key purposes.

## Alternatives rejected

- Permit signer blindly signs runtime ALLOW: does not address runtime compromise.
- Runtime and attestation issuer share credentials/process: no meaningful trust-boundary separation.
- LLM or model-generated rationale as proof: nondeterministic and non-authoritative.
