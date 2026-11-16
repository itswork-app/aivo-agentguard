# G3 Requirement-to-Test Traceability

**Status:** Proposed — implementation gate  
**Version:** 0.1.0

| Requirement | Normative source | Acceptance tests |
|---|---|---|
| G3-ATT-001 Attestation issuer is isolated from runtime and permit signer | G3 Authorization Attestation; ADR-0008 | Deployment identity/credential separation; negative configuration test |
| G3-ATT-002 Issuer independently validates signed policy, identities, context, and recomputes decision | G3 Authorization Attestation; ADR-0008 | Runtime ALLOW versus verifier DENY/REQUIRE_APPROVAL; invalid source/policy tests |
| G3-ATT-003 Attestation binds exact tenant, principal, agent, request/action/policy/context digests | G3 Authorization Attestation | Field mutation and cross-tenant substitution tests |
| G3-ATT-004 Durable evidence receipt is authenticated and exact-bound | G3 Authorization Attestation; Evidence Format | Missing, forged, non-durable, and mismatched receipt tests |
| G3-ATT-005 Attestation challenge is short-lived and single-use | G3 Authorization Attestation | Replay and concurrent challenge-consumption tests |
| G3-PER-001 G1 v1 claims remain unchanged inside v2 envelope | Permit Envelope v2; ADR-0009 | G1 golden vectors; exact inner payload compatibility tests |
| G3-PER-002 Outer envelope binds inner permit, attestation, and policy provenance | Permit Envelope v2 | Substitution, digest mismatch, and signature mutation tests |
| G3-PER-003 G3 enforcement rejects standalone G1 v1 permit | Permit Envelope v2; ADR-0009 | Downgrade/legacy-profile negative tests |
| G3-REV-001 Revocation snapshots are signed by a distinct authority | Revocation Status Protocol; ADR-0009 | Invalid signature and trust-root tests |
| G3-REV-002 Snapshot freshness, sequence, epoch, and rollback are enforced | Revocation Status Protocol | Age boundary, stale, rollback, lost high-water mark tests |
| G3-REV-003 All required keys, issuers, and exact policy version/digest are checked | Revocation Status Protocol; Permit Envelope v2 | Revoke-after-issue-before-consume tests |
| G3-REV-004 Missing, stale, unknown, or unavailable status fails closed | Revocation Status Protocol | Network partition, cache expiry, missing entry tests |
| G3-ENF-001 All verification precedes consume; consume precedes side effect | Permit Envelope v2; ADR-0007 | Side-effect counter remains zero on every failed check |
| G3-ENF-002 Consume is tenant-scoped and linearizable across replicas | ADR-0007; G3 Acceptance Test Plan | Concurrent multi-replica and cross-tenant collision tests |
| G3-CRYPTO-001 Canonical digests and signatures match cross-language vectors | ADR-0003; G3 Acceptance Test Plan | Rust/TypeScript/Python golden vectors and differential tests |

This matrix is a test obligation ledger. A row is not complete until the implementation test artifact and passing CI result are linked in the implementation PR.
