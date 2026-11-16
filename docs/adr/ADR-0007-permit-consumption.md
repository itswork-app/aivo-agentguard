# ADR-0007: Atomic Single-Use Permit Consumption

- **Status:** Proposed — G2 security review required
- **Date:** 2026-11-16
- **Decision owners:** Project maintainer

## Context

A signed permit can be copied or submitted concurrently. Signature validation and expiry alone do not prevent duplicate execution. A consume store that is atomic only within one process or replica is insufficient when multiple enforcement replicas can accept the same permit.

## Proposed decision

The enforcement boundary MUST perform a durable, conditional, single-use consume operation before any protected side effect. The consume identity MUST be tenant-scoped: use a composite key of authenticated `tenant_id` and `permit_id`, or prove that permit IDs are globally unique within a cryptographically authenticated issuer namespace and enforce that namespace consistently. An untrusted tenant ID from the action payload MUST NOT select the consume namespace.

The consume operation MUST provide linearizable at-most-once acceptance for each consume identity across every enforcement replica. It must be a single atomic conditional insert/transition (or an equivalent primitive with the same guarantee), not a check-then-set sequence. If the store is unavailable, partitioned, inconsistent, or cannot establish the required global per-key atomicity, execution is denied. Eventual consistency and replica-local caches are not sufficient.

## Consequences

- Permit acceptance is at-most-once at the enforcement boundary across replicas, not merely within one process.
- A cross-tenant permit-ID collision cannot consume or block another tenant's permit when tenant-scoped keys are used.
- A crash after consumption but before the external side effect may leave an action unexecuted; this is safer than replay.
- A crash after the side effect but before outcome recording may produce UNKNOWN; adapters need external idempotency and reconciliation.
- Exactly-once external execution is not promised.
- A deployment ADR must select and test a store/consistency model that satisfies this invariant before implementation is production-enabled.

## Alternatives rejected

- In-memory cache: does not survive restart or coordinate replicas.
- Check-then-set without atomicity: vulnerable to concurrent replay.
- Eventual-consistency or replica-local consume state: permits concurrent replay across replicas.
- Consume after execution: allows duplicate side effects before the permit is marked used.
