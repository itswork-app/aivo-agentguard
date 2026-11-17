# G3 Specification Baseline — Authorization Proof and Permit Binding

**Status:** Approved and frozen — Product Owner approval recorded 2026-11-17  
**Version:** 0.1.0  
**Parent baselines:** G1 v0.1.0 and G2 v0.1.0

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

## 3. Approved normative decisions

1. Authorization-attestation issuer is a separate trust boundary from runtime coordinator and permit signer.
2. Attestation issuer independently validates all input provenance and independently recomputes the deterministic decision; runtime ALLOW assertion is never sufficient.
3. Attestation binds authenticated identities, request/action/policy/context digests, evaluator semantic and artifact versions, durable decision evidence, and a single-use challenge nonce.
4. PermitEnvelopeV2 binds frozen G1 permit, attestation, policy issuer/key provenance, and permit-envelope signature; both inner and outer permit-signing keys are checked.
5. Enforcement independently verifies all signatures and exact bindings.
6. Revocation snapshots are signed by a separate revocation authority, monotonic, rollback-resistant, and bounded to 30-second maximum age with 60-second maximum snapshot validity.
7. Required revocation status is checked at signing and immediately before permit consumption; unknown, stale, unavailable, revoked, compromised, or rolled-back status fails closed.
8. No G3 profile accepts legacy G1 permits without the v2 envelope.
9. All verification checks precede atomic tenant-scoped permit consumption; consumption precedes side effects, as specified by ADR-0007.

## 4. Specification set

- `security/G3-AUTHORIZATION-ATTESTATION.md`
- `specifications/PERMIT-ENVELOPE-V2.md`
- `security/REVOCATION-STATUS-PROTOCOL.md`
- `testing/G3-ACCEPTANCE-TEST-PLAN.md`
- `testing/G3-TRACEABILITY.md`
- `security/G3-ADVERSARIAL-REVIEW.md`
- ADR-0007: atomic tenant-scoped single-use permit consumption.
- ADR-0008: authorization attestation and verifier isolation.
- ADR-0009: permit envelope v2 and revocation status.

## 5. Adversarial review and approval boundary

The review recorded in `security/G3-ADVERSARIAL-REVIEW.md` is an AI-assisted adversarial design review with the status **conditional pass for specification baseline freeze**. It is not a third-party audit, cryptographic implementation audit, penetration test, certification, or evidence that the G3 protocol has been implemented or executed.

Separately, the Product Owner approved the G3 protocol/specification baseline and the five product decisions on 2026-11-17. This approval freezes the documented design choices; it does not convert the conditional review into an unconditional security pass, waive the review's limitations, authorize production enforcement, or claim implementation readiness.

## 6. Approved product decisions

All five G3 open decisions are approved and recorded in `governance/G3-OPEN-DECISIONS.md`: independent evaluator strategy, revocation signing and recovery, evaluator artifact provenance, durable evidence receipt topology, and trusted time/rollback-resistant state. These decisions are normative for G3 v0.1.0.

Implementation details and operational evidence remain release gates; they are not represented as already implemented.

## 7. Exit criteria and implementation gates

- Product Owner approval of the G3 protocol baseline and all five open decisions is recorded.
- ADR-0007, ADR-0008, and ADR-0009 are accepted and their normative relationships are consistent across the specification set.
- Golden vectors and implementation-level test fixtures are defined; their definition is not evidence that runtime tests have passed.
- Rust implementation maps every MUST to a typed API and test.
- G3 implementation tests pass before production enablement.
- No unresolved Critical/High security findings remain after implementation-level review.
- External independent security review, adapter-specific assessment, and operational review remain required before production use.

**Current implementation status:** G3 is an approved specification baseline. Runtime signing, independent attestation, revocation enforcement, durable evidence receipt verification, trusted-time integration, and atomic permit consumption are not declared implemented by this document. No CI or implementation test result is implied by Product Owner approval.
