# G3 Evidence Service — Durable Append and Signed Receipt Contracts

**Status:** Interfaces and deterministic orchestration implemented; production adapters pending  
**Code:** `crates/agentguard-evidence`  
**Protocol:** Existing `agentguard.evidence-v1` event envelope

## Compatibility rule

The G3 service extends the G4.3 evidence implementation; it does not replace the v1 event schema. The schema identifier, typed actor reference, typed decision enum, sequence field, and event hash domain are preserved. An optional `context_digest` is omitted when absent, preserving the existing canonical payload and golden vector.

## Implemented contracts

- Tenant/stream head read port, keyed by an authenticated tenant ID supplied separately from the event request.
- Append orchestration rejects any event tenant that differs from the authenticated tenant context.
- Conditional append port requiring the expected head to match atomically.
- Durable commit identity returned by successful append.
- Exact event read-back before receipt signing.
- Dedicated evidence-purpose receipt signer port.
- Signed receipt claims binding tenant, stream, sequence, event hash/type, request/action/policy/context digests, durable commit identity, commit timestamp, and evidence key ID.
- Receipt signature verification and exact event read-back.
- Bounded optimistic retries for stream-head conflicts.

## Append and receipt sequence

1. Validate the decision event request and required digests.
2. Read the authenticated tenant/stream head.
3. Assign the next sequence and predecessor hash.
4. Seal the event using the existing G4.3 EVENT hash primitive.
5. Atomically append only if the expected head still matches.
6. Read the committed event back and verify its hash and commit identity.
7. Canonicalize receipt claims and request a signature from the dedicated evidence-purpose signer.
8. Return the event and receipt only after all checks succeed.

If signing fails after the durable append, the committed event remains an immutable fact. The service does not attempt rollback or deletion. The current interface does not yet expose a dedicated receipt-recovery-by-event-ID operation; adapter-level reconciliation is a production gate, not an already implemented retry guarantee.

## Adapter requirements before production

- Storage must provide durable linearizable compare-and-append across all replicas.
- Tenant identity used for storage partitioning must come from authenticated context, not caller-controlled event data.
- Unique event IDs must be enforced within the required tenant/stream scope.
- Read-after-commit must return the exact event and durable commit identity.
- The signer must use a dedicated key purpose and must not accept caller-supplied private key material or arbitrary signing domains.
- Enforcement and the attestation issuer must resolve the receipt key through the purpose-scoped registry and check current revocation state.
- Production deployment must define replication durability, backup, retention, restore, privacy minimization, and operational monitoring.
- Signed checkpoints anchored outside the evidence store remain necessary to detect full-stream truncation or rewrite.

## Explicit non-claims

No concrete database, signer, independent checkpoint anchor, authorization-attestation issuer, production deployment, external audit, or certification is included. Interface contracts are not proof of linearizability or durability.
