# API Contract v1

**Status:** Proposed — G1 product-owner review required  
**Version:** 0.1.0  
**Transport:** Rust library contract first; wire transport deferred

## 1. Contract principles

- All inputs and outputs are explicitly versioned.
- API calls are side-effect free except for named lifecycle transitions and evidence append.
- The policy evaluator is deterministic and has no implicit network, clock, randomness, or LLM dependency.
- Errors are typed and fail closed.
- No API accepts private keys, seed phrases, or signing secrets.

## 2. Core operations

### `authorize(request, trusted_context, policy_bundle)`

Validates and evaluates a request. Returns:
- `DecisionResult`: decision, stable reason codes, request/action/policy/context digests, evaluator version, evaluation timestamp.
- `AuthorizationPermit`: present only when decision is ALLOW and evidence has been durably recorded.
- `ApprovalRequirement`: present only when decision is REQUIRE_APPROVAL; includes required profile references and expiry.

### `record_approval(request_ref, approval_assertion)`

Verifies the approval identity assertion, eligibility, profile, request/action/policy binding, expiry, and duplicate status. Appends an approval event. Does not issue a permit.

### `reauthorize(request_ref, approval_set, fresh_context, current_policy)`

Verifies approval quorum and re-evaluates policy against current context and applicable current policy. Returns a new decision. Only a fresh ALLOW may issue a permit.

### `consume_permit(permit, actual_action, enforcement_context)`

Verifies permit signature, expiry, identities, policy and action digests, context constraints, and atomically consumes the permit ID. This operation is part of the trusted enforcement boundary and must complete before the side effect.

### `append_execution_outcome(permit_ref, outcome)`

Appends an observed outcome. Outcomes are `SUCCEEDED`, `FAILED`, or `UNKNOWN`; they describe what the adapter observed, not a guarantee from AgentGuard.

### `verify_evidence(stream)`

Verifies event schema, sequence, hash linkage, and checkpoint signatures when available. Reports integrity separately from completeness and external truth.

## 3. Typed error codes

- `INVALID_REQUEST`
- `UNSUPPORTED_SCHEMA_VERSION`
- `IDENTITY_UNVERIFIED`
- `POLICY_UNKNOWN`
- `POLICY_INVALID`
- `CONTEXT_MISSING`
- `CONTEXT_STALE`
- `CONTEXT_UNTRUSTED`
- `APPROVAL_INVALID`
- `APPROVAL_EXPIRED`
- `APPROVAL_QUORUM_NOT_MET`
- `PERMIT_INVALID`
- `PERMIT_EXPIRED`
- `PERMIT_REPLAYED`
- `ACTION_DIGEST_MISMATCH`
- `EVIDENCE_UNAVAILABLE`
- `CONSUME_STORE_UNAVAILABLE`
- `INTERNAL_ERROR`

Errors must never be converted to ALLOW. A typed error is distinct from a policy DENY, but both block execution.

## 4. Versioning and compatibility

Breaking changes require a new major contract version and migration notes. Additive optional fields may be introduced only when older consumers can safely ignore them. Unknown enum values and unknown schema versions are rejected by security-critical consumers.

## 5. Deferred transport mapping

HTTP, gRPC, MCP, and framework-specific SDK mappings are deferred. They must preserve the same authorization semantics and must not weaken identity, replay, expiry, evidence, or action-binding requirements.
