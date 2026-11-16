# Architecture Overview

**Status:** Draft — conceptual boundaries only

## Design intent

Separate deterministic policy evaluation from untrusted agent intent, approval workflows, execution adapters, and evidence storage.

## Proposed logical flow

1. **Action request:** adapter normalizes an agent's requested action into a versioned, typed request.
2. **Identity and context:** trusted assertions and provenance-bearing context are resolved outside the pure evaluator.
3. **Policy validation:** immutable policy bundle schema, digest, and signature are validated.
4. **Policy evaluation:** deterministic Rust core evaluates policy and returns a decision plus structured reason codes.
5. **Approval workflow:** only invoked for `REQUIRE_APPROVAL`; approval is independently authenticated and bound to the exact request, action, and policy.
6. **Re-evaluation:** after approval, current policy and fresh context are evaluated again. Only a new `ALLOW` may proceed.
7. **Permit issuance:** runtime durably records the decision and issues a signed, short-lived permit bound to the exact identities and action digest.
8. **Enforcement adapter:** verifies the permit and atomically consumes it once before the side effect.
9. **Evidence:** request, decision, approval, re-evaluation, permit consumption, and observed execution outcome are recorded as linked append-only events.

## Initial workspace boundaries

- `agentguard-core`: shared domain types and stable primitives.
- `agentguard-policy`: deterministic policy evaluation.
- `agentguard-evidence`: evidence event model and integrity primitives.
- `agentguard-runtime`: request lifecycle orchestration.
- `agentguard-enforcement`: enforcement contracts and adapter boundary.

These crates are scaffolding only; their public APIs are not frozen.

## Trust boundaries

- Agent input is untrusted.
- LLM output is untrusted and advisory.
- Policy bundles require versioning, canonical digests, and trusted signatures.
- Identity and approval assertions require independent verification.
- Context values require source provenance and freshness checks.
- Execution adapters are security-critical and must bind permits to exact action payloads and enforce single-use consumption.
- Evidence consumers must verify integrity rather than trust display output.

## Failure behavior

Unknown policy, invalid signature, stale context, missing identity, timeout, malformed action, unavailable evidence persistence, unavailable permit-consumption storage, or action-binding failure must not produce an executable ALLOW. Exact transport-level timeout and availability budgets remain deferred.

## Deferred decisions

Transport protocol, persistence backend, deployment key management, external checkpoint distribution, multi-tenant storage implementation, and adapter-specific execution guarantees require separate ADRs.
