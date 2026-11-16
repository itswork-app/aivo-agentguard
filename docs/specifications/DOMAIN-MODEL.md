# Domain Model

**Status:** Approved — product owner accepted 2026-11-16  
**Version:** 0.1.0

## 1. Identity and tenancy

- **Tenant:** isolation boundary for policy, principals, requests, approvals, permits, and evidence.
- **Principal:** authenticated human or service identity requesting or operating an action.
- **Agent:** autonomous software identity acting on behalf of a principal or tenant.
- **Approver:** principal authorized by an approval profile to approve a specific request class.
- **Policy issuer:** trusted identity permitted to publish a policy bundle.

Authentication is external to the deterministic policy core. Integrations must pass authenticated identity assertions from a configured trust boundary. An unverified identity must never be treated as a valid principal.

## 2. Core entities

### AuthorizationRequest
A versioned request containing:
- `schema_version`
- `request_id` (globally unique within the issuer namespace)
- `tenant_id`
- `principal_id`
- `agent_id`
- `action`
- `policy_ref` (`policy_id`, `version`, `digest`)
- `context_snapshot`
- `issued_at`
- `expires_at`
- `nonce`

### Action
A typed action envelope containing:
- `action_type`: namespaced, stable action identifier.
- `resource`: target resource identifier and type.
- `payload`: canonical JSON-compatible action parameters.
- `network_ref`: optional opaque execution-domain identifier; interpreted only by the relevant adapter.

The core does not infer chain semantics from arbitrary payload fields.

### ContextSnapshot
A set of named, typed values. Each value carries:
- value;
- source identifier;
- observation timestamp;
- optional validity deadline;
- provenance or attestation reference.

A policy may declare a maximum age for each required context field. Missing, unverifiable, or stale required context fails closed.

### PolicyBundle
An immutable, versioned set of rules and approval-profile references. A policy digest identifies the canonical policy content, excluding detached signature metadata.

### DecisionRecord
The deterministic result of evaluating a request:
- decision;
- stable reason codes;
- request digest;
- action digest;
- policy digest and version;
- context digest;
- evaluated-at timestamp;
- evaluator version.

### ApprovalRecord
An independently authenticated approval bound to:
- approval ID;
- exact request and action digests;
- tenant and approver identity;
- approval profile;
- policy digest;
- issued-at and expiry;
- one-time nonce;
- verified authentication evidence reference.

An approval is an input to a subsequent evaluation, never an execution permit.

### AuthorizationPermit
A short-lived, signed capability issued only after a fresh ALLOW. It binds the exact request, action, policy, context, identities, nonce, and expiry. Enforcement must atomically consume its one-time identifier before side effects.

### EvidenceEvent
An append-only event describing one lifecycle fact. Each event is linked to the prior event in its tenant stream by sequence and hash.

## 3. Lifecycle states

The request lifecycle is event-driven. The following are derived states, not mutable authorization flags:

- RECEIVED
- REJECTED
- DENIED
- AWAITING_APPROVAL
- APPROVAL_RECORDED
- REEVALUATED_DENIED
- PERMITTED
- PERMIT_CONSUMED
- EXECUTION_OBSERVED
- EXECUTION_FAILED_OR_UNKNOWN
- EXPIRED

A request can never transition directly from AWAITING_APPROVAL to PERMITTED. It must pass through approval verification and a new policy evaluation.

## 4. Identity invariants

- Tenant identity is mandatory and cannot be inferred from an untrusted action payload.
- Principal and agent identities are distinct fields.
- Approval identity is distinct from requesting identity.
- A permit cannot be transferred between tenants, principals, agents, requests, or actions.
- Tenant identifiers are included in all persistence keys and evidence events.
- Authorization core does not authenticate users by trusting self-asserted IDs.

## 5. Money and numeric values

Authoritative financial quantities must not use binary floating-point. Monetary values are represented as integer minor units with an explicit currency and scale, or as canonical decimal strings with a declared scale. Integers exceeding the safe JSON integer range are serialized as strings.
