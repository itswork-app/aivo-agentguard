# ADR-0005: Approval Is Not Authorization; Permits Are Short-Lived and Single-Use

- **Status:** Accepted — product owner approved 2026-11-16
- **Date:** 2026-11-16
- **Decision owners:** Project maintainer

## Context

A human approval may become stale, be replayed, or be attached to a different action. A simple approval flag cannot safely authorize execution.

## Proposed decision

Keep approval and authorization as separate lifecycle facts. Approval is authenticated and bound to the tenant, request, exact action digest, policy digest, approval profile, approver, and expiry. Once quorum is met, the runtime must re-evaluate policy with current trusted context.

Only a fresh ALLOW produces a signed permit. The permit has a maximum 60-second lifetime (30 seconds by default), is bound to exact identities and digests, and must be atomically consumed once by the enforcement boundary before side effects.

## Consequences

- Approval cannot override a fresh DENY or bypass a changed policy.
- Permit replay and action substitution are rejected by a correctly implemented adapter.
- Consume-store availability becomes part of the enforcement trust boundary.
- Exactly-once external execution is not promised; adapters must use external idempotency and reconciliation where available.
