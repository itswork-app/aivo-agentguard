# Authorization Contract

**Status:** Draft — provisional, not a stable API

## Request

An authorization request must identify, at minimum:

- schema version;
- tenant and requesting principal;
- agent identity;
- action type and canonical action payload or digest;
- policy identifier and version;
- context values with source and freshness metadata;
- unique request identifier and replay-protection material.

Exact field names and serialization are deferred to a versioned API specification.

## Decision

The policy engine returns one of:

| Decision | Meaning | May execute immediately? |
|---|---|---:|
| `ALLOW` | Current policy permits this exact action under evaluated context. | Only after enforcement verifies binding and freshness. |
| `DENY` | Policy prohibits the action or required trust conditions are not met. | No |
| `REQUIRE_APPROVAL` | An independent approval workflow is required. | No |

## Approval lifecycle

1. Record the approval requirement.
2. Authenticate and authorize the approver under a separately specified approval policy.
3. Bind approval to the exact request/action digest, policy version, and expiry.
4. Re-resolve time-sensitive context and re-evaluate policy.
5. Proceed only if the new decision is `ALLOW` and enforcement validates the binding.

Approval must never convert a previous `REQUIRE_APPROVAL` result directly into execution permission.

## Fail-closed conditions

Malformed input, unknown schema, unknown policy version, invalid identity, stale context, replay, failed integrity checks, or unavailable authoritative policy must never yield `ALLOW`.

## Evidence events

The lifecycle should produce linked events for request receipt, decision, approval request, approval result, post-approval re-evaluation, enforcement attempt, and observed execution outcome. Events must be append-only; corrections use compensating events.

## Not yet specified

Canonical encoding, cryptographic signatures, hash chaining, event storage, retention, privacy redaction, and transport semantics require dedicated specifications and ADRs.
