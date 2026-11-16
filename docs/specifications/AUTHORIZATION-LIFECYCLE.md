# Authorization Lifecycle and Permit Contract

**Status:** Approved — product owner accepted 2026-11-16  
**Version:** 0.1.0

## 1. Lifecycle

1. **Receive:** enforcement-facing adapter receives an action request and establishes authenticated tenant, principal, and agent identity.
2. **Normalize:** adapter creates the versioned request and canonical action representation.
3. **Validate:** runtime verifies schema, expiry, nonce, policy identity, context provenance, and required fields.
4. **Evaluate:** deterministic policy engine evaluates the immutable policy bundle.
5. **Record decision:** evidence event is appended before a decision is returned to the caller.
6. **Respond:**
   - DENY: no permit is issued.
   - REQUIRE_APPROVAL: no permit is issued; an approval workflow is started.
   - ALLOW: issue a signed, short-lived permit bound to the exact request.
7. **Approve (if required):** authenticate eligible approvers, validate profile quorum, expiry, and separation-of-duties rules; append approval events.
8. **Re-evaluate:** resolve fresh context and evaluate the currently active applicable policy again. If its digest differs from the policy digest to which approvals were bound, those approvals are invalid and a new approval cycle is required.
9. **Enforce:** adapter verifies permit signature, key ID, expiry, exact action digest, tenant/principal/agent binding, policy digest, and context requirements; then atomically consumes the one-time permit ID before side effects.
10. **Observe:** append the observed execution result or an explicit unknown outcome. Authorization success is not proof of execution success.

## 2. Permit

The permit is a signed capability, not a bearer approval. Its signed claims include:
- `permit_id`
- `schema_version`
- `tenant_id`
- `principal_id`
- `agent_id`
- `request_id`
- `action_digest`
- `policy_id`, `policy_version`, `policy_digest`
- `context_digest`
- `issued_at`, `expires_at`
- `nonce`
- `decision = ALLOW`
- `signing_key_id`

The proposed signature algorithm is Ed25519. The signature covers canonical permit claims. Key provisioning, rotation, and revocation are controlled outside the policy evaluator.

## 3. Permit lifetime

Default maximum permit lifetime is 30 seconds. A deployment may configure a shorter maximum but MUST NOT configure more than 60 seconds for this contract version. Context-specific validity may require a shorter lifetime. Expired or unverifiable permits fail closed.

## 4. Replay and atomic consumption

The enforcement adapter must perform a durable, atomic, single-use consume operation keyed by `permit_id` before performing the protected side effect. If the consume store is unavailable, the permit is rejected. A permit that has been consumed cannot be reused, even if the previous execution outcome is unknown.

This provides at-most-once permit acceptance at the enforcement boundary. It does not guarantee exactly-once execution in an external system. Integrations must use the external system's own idempotency and reconciliation facilities where available.

## 5. Time-of-check/time-of-use

The permit binds the exact action digest and a short expiry. The adapter must revalidate relevant execution preconditions as close as possible to the side effect. If the external system supports atomic preconditions, the adapter should use them. A compromised host or adapter can bypass in-process controls; this is an explicit residual risk.

## 6. Approval

An approval record must be authenticated independently and bound to the same tenant, request ID, action digest, policy digest, approval profile and version, approver identity, and expiry. Approval quorum and eligible roles are defined by the referenced approval profile. Each approver counts once per request and profile. Separation-of-duties rules are enforced from trusted identity assertions.

After quorum is satisfied, policy is evaluated again using current policy and fresh context. If the policy digest changed, the previous approval set cannot satisfy the new policy version. The new decision is authoritative. Approval never changes a DENY to ALLOW by itself.

## 7. Failure semantics

Missing policy, invalid signature, stale context, identity mismatch, malformed action, replay, expiry, unavailable consume store, or evidence persistence failure must not result in execution. An adapter must fail closed and surface a typed error. It must not silently retry a non-idempotent side effect.
