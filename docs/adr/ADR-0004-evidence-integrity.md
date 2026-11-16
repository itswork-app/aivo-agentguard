# ADR-0004: Append-Only Evidence and Hash Chains

- **Status:** Proposed
- **Date:** 2026-11-16
- **Decision owners:** Project maintainer

## Context

Auditors need to verify the order and integrity of lifecycle events. Mutable status rows do not provide a reproducible history.

## Proposed decision

Represent lifecycle facts as append-only events with per-stream sequence numbers and SHA-256 hash chaining over canonical event payloads. Storage exposes append and read/verify operations, not update or delete. Corrections are new events referencing prior event IDs.

The runtime must durably append the authorization decision event before returning an ALLOW permit. Independent signed checkpoints are recommended for deployments that need detection of full-stream truncation or rewrite.

## Consequences

- Event history can be verified offline.
- Storage must provide atomic sequence allocation and append.
- Hash chaining alone does not prove completeness, external truth, or availability.
- Privacy minimization and retention policies remain mandatory.
