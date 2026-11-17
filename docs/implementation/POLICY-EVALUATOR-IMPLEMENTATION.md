# Deterministic Policy Evaluator — Implementation Contract

**Status:** Implemented foundation — pending CI and security review  
**Crate:** `agentguard-policy`  
**Gate:** G3.1 (stacked on G3 protocol foundation)

## Implemented

- Versioned, deny-unknown-fields policy, rule, selector, approval-profile, context, and request types.
- Detached Ed25519 policy signature verification over RFC 8785 canonical policy content.
- SHA-256 policy content digest with the `AIVO-AGENTGUARD-POLICY-V1\0` domain separator.
- Purpose-specific issuer-key resolver contract that binds both issuer identity and key ID.
- Exact-match subject/action/resource selectors; wildcard and pattern matching are rejected.
- AND semantics for conditions; typed equality, inequality, membership, presence, and ordered comparisons.
- Context freshness, explicit validity deadline, minimum trust class, and attestation flag checks using one caller-supplied evaluation timestamp.
- Deterministic deny-overrides, then require-approval, then allow, with default deny.
- Stable reason codes, sorted matched rule IDs, and sorted/deduplicated approval profile IDs.
- Typed errors for invalid policy, signature, request, missing/stale/untrusted context, and incompatible condition types.

## Trust boundary and non-claims

- The evaluator does not authenticate principals or independently establish context provenance. The runtime must provide identity assertions and context values already verified against configured trust registries.
- `attestation_verified` is an assertion from that trusted runtime boundary, not a self-authenticating proof. Public transport adapters must never accept it directly from an untrusted caller.
- The resolver must verify that the key belongs to the stated issuer and is currently trusted for policy signing. Key purpose and issuer-to-key mapping are external trust-store responsibilities.
- The evaluator does not perform approval quorum validation, evidence persistence, attestation issuance, permit signing, permit consumption, or side effects.
- A returned ALLOW is only a deterministic policy result. It is not an authorization permit and MUST NOT independently authorize execution.
- Approval profile metadata is structurally validated here; authenticated approval collection and quorum are separate lifecycle operations.
- Context timestamps are supplied as Unix seconds after strict canonical UTC parsing by the trusted adapter. The evaluator does not read or parse system time.

## Required follow-up

1. Bind this evaluator into the runtime coordinator and independently deployed attestation verifier.
2. Add source-registry-backed context verification and signed identity assertion verification.
3. Add differential/golden vectors and fuzz/property tests for canonicalization and combining semantics.
4. Add approval quorum and re-evaluation lifecycle implementation.
5. Add evidence append-before-response integration and verify that ALLOW never escapes without durable evidence.
6. Complete external security review before any production enablement.
