# ADR-0007: Atomic Single-Use Permit Consumption

- **Status:** Proposed — G2 security review required
- **Date:** 2026-11-16
- **Decision owners:** Project maintainer

## Context

A signed permit can be copied or submitted concurrently. Signature validation and expiry alone do not prevent duplicate execution.

## Proposed decision

The enforcement boundary must atomically transition a permit ID from unconsumed to consumed in a durable store before performing a protected side effect. The operation is conditional and succeeds for at most one concurrent caller. If the store is unavailable, inconsistent, or cannot guarantee atomicity, execution is denied.

## Consequences

- Permit acceptance is at-most-once at the enforcement boundary.
- A crash after consumption but before the external side effect may leave an action unexecuted; this is safer than replay.
- A crash after the side effect but before outcome recording may produce UNKNOWN; adapters need external idempotency and reconciliation.
- Exactly-once external execution is not promised.
- Store implementation and consistency model require a separate deployment ADR.

## Alternatives rejected

- In-memory cache: does not survive restart or coordinate replicas.
- Check-then-set without atomicity: vulnerable to concurrent replay.
- Consume after execution: allows duplicate side effects before the permit is marked used.
