# ADR-0010: Authorization-Proof Replay and Revocation Checkpoint Binding

- **Status:** Proposed — requires maintainer approval before becoming normative
- **Decision date:** 2026-11-19
- **Decision owner:** Project maintainer

## Context

ADR-0007 requires tenant-scoped, linearizable, single-use permit consumption. G3 additionally binds a permit to a signed signing challenge and a signed authorization attestation. A permit-specific consume key alone does not prevent a trusted but faulty or compromised permit signer from issuing multiple distinct permit IDs against the same challenge and attestation.

The enforcement boundary also verifies a signed revocation snapshot and persists a monotonic high-water mark before consuming the permit. A revocation snapshot could advance in another enforcement replica after the local final check but before permit consumption unless the consume transaction compares the checkpoint it relied upon.

## Proposed decision

1. The tenant-scoped atomic consume record MUST bind:
   - permit ID and permit nonce;
   - signing challenge ID and digest;
   - authorization attestation ID and digest;
   - request/action/policy digests;
   - the exact revocation registry ID, epoch, sequence, and signed snapshot digest used by final verification.
2. The durable consume store MUST enforce linearizable uniqueness for the permit, challenge, and attestation identities within the authenticated tenant.
3. The consume transaction MUST atomically compare the supplied revocation checkpoint with the latest committed high-water mark for that registry before accepting the permit.
4. If the store cannot provide the uniqueness and checkpoint comparison in one transaction across all enforcement replicas, execution MUST fail closed.
5. A newly published revocation snapshot that has not yet been observed by the enforcement control plane cannot be rejected immediately. The maximum exposure is bounded by the configured revocation snapshot freshness/TTL and operational propagation SLO; deployments MUST state and test that bound.
6. A consumed permit remains a one-shot opaque capability. It MUST NOT be freely constructible or clonable by downstream callers.

## Consequences

- Reusing one challenge or attestation to mint multiple permit IDs cannot result in multiple successful consumes.
- A replica cannot consume against a revocation checkpoint already superseded in the shared high-water store.
- A single transactional storage boundary or equivalent coordination mechanism is required for production.
- These controls reduce replay and stale-checkpoint races but do not create exactly-once external side effects.
- Receipt signer failure after a durable event append still requires an explicit receipt recovery protocol.

## Alternatives considered

- Permit-ID-only uniqueness: rejected because it does not bind consumption to the authorization proof that justified issuance.
- Best-effort revocation recheck without atomic checkpoint comparison: rejected for production because another replica can persist a newer checkpoint between verification and consumption.
- Claiming instantaneous revocation after publication: rejected because an enforcement node cannot act on a revocation it has not yet observed.

## Implementation status

The G3 mainline reconciliation branch implements the proposed consume-record fields and adapter contract. This ADR remains Proposed; the implementation MUST NOT be treated as production-ready until the maintainer approves the decision and a concrete store proves the required cross-replica transaction semantics.
