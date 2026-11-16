# G3 Specification Baseline — Authorization Proof and Permit Binding

**Status:** Proposed — product owner approval required  
**Version:** 0.1.0  
**Parent baselines:** G1 v0.1.0 and G2 v0.1.0  
**Branch:** `feat/g3-authorization-proof-permit-binding`

## 1. Objective

Close G2's explicitly deferred proof obligations by defining:
- independent deterministic authorization attestation;
- versioned permit envelope binding the attestation issuer and policy provenance;
- authenticated, bounded-freshness revocation status;
- enforceable negative-test and release criteria.

G3 is a protocol/specification gate. It does not implement runtime signing, enforcement, custody, or deployment.

## 2. Normative compatibility

- G1 v0.1.0 remains frozen and unchanged.
- G2 v0.1.0 remains the accepted architecture baseline.
- PermitEnvelopeV2 wraps the exact G1 v1 permit claims and signature; it does not add fields to or reinterpret the G1 permit.
- G3-required consumers reject standalone G1 v1 permits; no downgrade fallback.
- Any later change to G1 semantics requires an explicit versioned migration and owner approval.

## 3. Proposed normative decisions

1. Authorization-attestation issuer is a separate trust boundary from runtime coordinator and permit signer.
2. Attestation issuer independently validates all input provenance and independently recomputes the deterministic decision; runtime ALLOW assertion is never sufficient.
3. Attestation binds authenticated identities, request/action/policy/context digests, evaluator semantic and artifact versions, durable decision evidence, and a single-use challenge nonce.
4. PermitEnvelopeV2 binds frozen G1 permit, attestation, policy issuer/key provenance, and permit-envelope signature; both inner and outer permit-signing keys are checked.
5. Enforcement independently verifies all signatures and exact bindings.
6. Revocation snapshots are signed by a separate revocation authority, monotonic, rollback-resistant, and bounded to 30-second maximum age with 60-second maximum snapshot validity.
7. Required revocation status is checked at signing and immediately before permit consumption; unknown, stale, unavailable, revoked, compromised, or rolled-back status fails closed.
8. No G3 profile accepts legacy G1 permits without the v2 envelope.
9. All verification checks precede atomic tenant-scoped permit consumption; consumption precedes side effects.

## 4. Specification set

- `security/G3-AUTHORIZATION-ATTESTATION.md`
- `specifications/PERMIT-ENVELOPE-V2.md`
- `security/REVOCATION-STATUS-PROTOCOL.md`
- `testing/G3-ACCEPTANCE-TEST-PLAN.md`
- `testing/G3-TRACEABILITY.md`
- `security/G3-ADVERSARIAL-REVIEW.md`
- ADR-0008: authorization attestation and verifier isolation.
- ADR-0009: permit envelope v2 and revocation status.

## 5. Adversarial review

The current AI-assisted specification review is recorded in `security/G3-ADVERSARIAL-REVIEW.md`. It is a conditional pass for continued Draft review only, not Product Owner approval, third-party audit, implementation approval, or production authorization. Its limitations and unresolved questions remain binding.

## 6. Open review questions

- Whether a distinct independently implemented evaluator is required for high-assurance deployments, versus isolated re-execution of the same versioned deterministic engine.
- Whether revocation authority snapshots should be single-signer for initial OSS mode or threshold-signed for enterprise profiles.
- Concrete evaluator artifact attestation and reproducible-build evidence format.
- Evidence receipt signing and storage trust topology.
- Exact trusted-clock source and rollback-resistant high-water-mark storage implementation.

These questions do not permit a weaker default. Until resolved, the specified fail-closed behavior applies.

## 7. Exit criteria

- Product owner approves the G3 protocol baseline.
- ADRs accepted and cross-document consistency verified.
- Golden vectors and implementation-level test fixtures defined.
- Rust implementation maps every MUST to a typed API and test.
- G3 implementation tests pass before production enablement.
- No unresolved Critical/High security findings.
- External adapter and operational review remains required before production use.
