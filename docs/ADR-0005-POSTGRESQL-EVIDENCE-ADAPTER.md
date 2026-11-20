# ADR-0005: PostgreSQL as the First Durable Evidence Adapter

**Status:** Proposed in PR #16; requires Product Owner acceptance before implementation
**Date:** 2026-11-20
**Decision scope:** First durable reference adapter for G4.4

## Context

G4.3 provides deterministic evidence sealing and stream verification plus an AppendOnlyEvidenceStore trait. It intentionally does not persist records. G4.4 requires atomic append, idempotency, tenant isolation, concurrent writer safety, durable acknowledgement, and crash recovery.

The first adapter should support a shared runtime deployment with multiple processes and concurrent writers while remaining straightforward to run locally and in CI. It must not couple the core evidence model to a single vendor.

## Decision

Recommend PostgreSQL as the first durable reference adapter, behind the existing storage trait. The adapter should use standard PostgreSQL transactions, constraints, and row-level locking/conditional updates. The evidence core remains database-agnostic.

This is a proposal for Product Owner acceptance. It does not authorize a production deployment or a claim of audited durability.

## Why PostgreSQL

- Per-stream serialization can be enforced transactionally with a stream-head row lock or compare-and-swap update.
- Unique constraints can enforce event sequence and event identity uniqueness under concurrency.
- Event insertion and stream-head advancement can commit atomically in one transaction.
- Tenant scoping can be enforced in adapter queries and strengthened with database roles and row-level security where the deployment model supports it.
- It supports multi-process and multi-instance runtime deployments without introducing a separate distributed lock service.
- It is widely available for local development, CI services, managed hosting, backup, restore, and operational inspection.

## Alternatives considered

### SQLite
Excellent for embedded/local-first use and simple development. Not selected as the first shared-runtime reference adapter because write serialization and multi-process deployment constraints make it a weaker initial fit for concurrent distributed agent runtimes. It may be added later as a separate adapter if offline/embedded operation becomes a product requirement.

### Redis
Not selected as the source of truth. It is useful for caches, ephemeral coordination, or rate limits, but evidence persistence requires durable relational constraints, transactional event/head updates, and straightforward audit/export semantics.

### Cloud-vendor-specific database APIs
Not selected as the core adapter contract because they risk coupling the open-source runtime to one provider. A provider may host PostgreSQL, but the reference implementation should target standard PostgreSQL behavior.

## Implementation constraints

1. Add one PostgreSQL adapter crate; do not add multiple storage backends in G4.4.
2. Use typed SQL queries and migrations checked into the repository.
3. Store canonical event bytes or an equivalent deterministic representation alongside indexed identity/hash columns. Define and test byte equality for idempotency.
4. Enforce unique (tenant_id, stream_id, sequence) and (tenant_id, stream_id, event_id).
5. In one transaction: authenticate tenant context at the service boundary, lock the stream head, resolve exact idempotent retry, verify expected sequence and predecessor, insert event, advance head, commit.
6. Use least-privilege database roles. The application role must not have UPDATE or DELETE privileges on committed evidence rows.
7. Document PostgreSQL durability settings relied upon; do not equate a successful client response with protection against every storage/region failure.
8. Test concurrent writers, duplicate retries, transaction rollback, connection loss during commit, restart, backup/restore, and tenant-crossing attempts.
9. Do not use Redis as a correctness lock or as the sole persistence layer.
10. Do not issue an ALLOW permit until the runtime has a confirmed durable evidence commit; unknown commit outcomes must fail closed pending reconciliation.

## Consequences

Positive:
- Strong transactional primitives for the G4.4 invariants.
- Good fit for multi-process deployments and tenant-scoped relational data.
- Keeps the evidence API and core Rust types portable.

Trade-offs:
- Requires a PostgreSQL service for integration tests and production deployments.
- Adds migration and connection-pool operational responsibilities.
- Database durability depends on configuration, hosting, backups, and recovery procedures; the adapter cannot promise more than the deployed database guarantees.

## Acceptance and follow-up

- Product Owner accepts or rejects PostgreSQL as the first reference backend.
- If accepted, implement the adapter in a separate feature branch and PR with migrations and the full G4.4 conformance suite.
- Run PostgreSQL integration tests in CI using a pinned major version.
- Keep signed checkpoints, multi-region consensus, and external security review as separate follow-up gates.