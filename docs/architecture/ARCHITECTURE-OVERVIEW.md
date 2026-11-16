# Architecture Overview

**Status:** Draft — conceptual boundaries only

## Design intent

Separate deterministic policy evaluation from untrusted agent intent, approval workflows, execution adapters, and evidence storage.

## Proposed logical flow

1. **Action request:** adapter normalizes an agent's requested action into a versioned, typed request.
2. **Context resolution:** trusted inputs are assembled with provenance, freshness, and identity metadata.
3. **Policy evaluation:** deterministic Rust core evaluates policy and returns a decision plus structured reasons.
4. **Approval workflow:** only invoked for `REQUIRE_APPROVAL`; approval is recorded as a separate event.
5. **Re-evaluation:** policy is evaluated again against current context after approval. Only a fresh `ALLOW` can proceed.
6. **Enforcement adapter:** the execution boundary checks the authorization result and binds it to the exact action/request identity.
7. **Evidence:** decision, approval, re-evaluation, and execution outcome are recorded as linked append-only events.

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
- Policy bundles require versioning and integrity checks.
- Approval identity and authorization must be independently verified.
- Execution adapters are security-critical and must bind decisions to exact action payloads.
- Evidence consumers must verify integrity rather than trust display output.

## Failure behavior

Unknown policy, invalid signature, stale context, missing identity, timeout, malformed action, or evidence-binding failure must not produce an `ALLOW` result. Exact timeout and availability semantics remain to be specified.

## Deferred decisions

Transport protocol, persistence backend, cryptographic evidence format, policy language, multi-tenant isolation model, and adapter-specific guarantees require separate ADRs.
