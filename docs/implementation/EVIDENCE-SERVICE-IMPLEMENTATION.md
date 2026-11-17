# Evidence Service Implementation Slice

**Status:** Implementation in progress — non-production
**Protocol baseline:** G1/G2 v0.1.0 and G3 v0.1.0
**Code:** `crates/agentguard-evidence`

## Implemented in this slice

- Typed V1 evidence event vocabulary and strict event/draft structures.
- RFC 8785 canonical payload serialization through the shared core crate.
- SHA-256 event hash using the frozen `AIVO-AGENTGUARD-EVENT-V1\0` domain separator.
- Genesis event previous hash fixed to 64 lowercase zeroes.
- Tenant-scoped stream head and compare-and-append storage interface.
- Storage contract requires a linearizable expected-head comparison and durable insert in one transaction.
- Read-back returns both the event and opaque durable commit identity.
- Receipt claims bind tenant, stream, sequence, event hash/type, request/action/policy/context digests, durable commit identity, commit timestamp, and dedicated evidence key ID.
- Receipt signature uses a dedicated evidence-receipt signing port and a versioned domain separator.
- Receipt is returned only after durable append, exact event read-back, hash verification, and commit identity equality.
- Receipt verification checks signature and retrieves the referenced event and commit identity again.

## Append protocol

1. Validate the draft and all receipt-required digests before writing.
2. Read the current tenant-scoped stream head.
3. Construct the next sequence and previous-event hash.
4. Compute the canonical event hash.
5. Atomically append only if the expected head still matches.
6. Require the adapter to report a durable commit identity.
7. Read the exact event back and verify event bytes/fields, event hash, and commit identity.
8. Construct canonical receipt claims and ask the dedicated signer to sign.
9. Return event, signed receipt, and receipt digest.

A failed step returns an error and must never be treated as an authorization permit. A committed event whose read-back or signing fails remains an evidence fact; it is not rolled back or mutated.

## Adapter requirements before production

- No concrete database adapter is included yet.
- Storage must implement durable linearizable compare-and-append, tenant isolation, unique event IDs, and read-after-commit consistency.
- The evidence signing service must use a dedicated purpose-specific key, isolated from policy, attestation, permit, challenge, and revocation keys.
- The signer must not accept caller-supplied key material or arbitrary signing purposes.
- The receipt verifier must resolve the key from the evidence-receipt purpose registry and check current revocation status.
- A production deployment must define replication durability, backup, retention, restore, privacy minimization, and operational monitoring.
- Signed checkpoints anchored outside the evidence store remain necessary to detect full-stream truncation or rewrite.
- The authorization-attestation issuer integration must verify receipt signature, exact decision-event bindings, and event read-back before issuing an attestation.

## Explicit non-claims

This crate does not provide a production database, a signing service, rollback-resistant storage, independent checkpoint anchoring, external audit, or certification. The interface contracts are not evidence that a concrete adapter satisfies them. Hash chaining does not prove source truth, event completeness before ingestion, or that an external action occurred.
