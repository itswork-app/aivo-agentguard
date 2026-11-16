# G2 Security Architecture

**Status:** Proposed — security review required  
**Version:** 0.1.0  
**Baseline:** G1 v0.1.0

## 1. Objective

Define the security architecture that implements the approved G1 authorization contract. This document is an architecture proposal, not a deployment guide or security certification.

## 2. Security domains

1. **Untrusted agent domain:** agent runtime, model output, tool arguments, and caller-controlled payloads.
2. **Identity boundary:** authenticates principals, agents, and tenants; issues verifiable identity assertions.
3. **Policy administration domain:** publishes immutable policy bundles and manages policy-issuer trust.
4. **Authorization domain:** validates requests and context, evaluates policy deterministically, records decisions, and issues permits.
5. **Approval domain:** authenticates eligible human approvers and records action-bound approval events.
6. **Enforcement domain:** validates and atomically consumes permits before protected side effects.
7. **Evidence domain:** persists append-only events and supports independent verification.
8. **External execution domain:** chain RPCs, smart contracts, APIs, and other systems. This domain is outside AgentGuard's direct trust.

## 3. High-level architecture

- Agent-facing adapters accept untrusted action proposals.
- Identity middleware resolves authenticated tenant, principal, and agent identities.
- Context adapters fetch external values and attach source provenance, timestamps, and attestations.
- Policy loader verifies schema, canonical digest, signer identity, signature, version, and revocation state.
- Rust policy core is a pure deterministic evaluator over validated immutable inputs.
- Runtime coordinates lifecycle transitions and persists decision evidence.
- Approval service is separate from the policy core and cannot mint permits.
- Permit issuer signs only a fresh ALLOW result after durable decision evidence.
- Enforcement adapter verifies exact action binding and atomically consumes permit ID before side effects.
- Evidence verifier validates schema, sequence, canonical digest, and hash chain.

## 4. Trust-boundary rules

- No agent or LLM output is trusted as identity, policy, approval, context attestation, or authorization.
- Authorization core has no network access, clock access, filesystem secrets, or signing private keys.
- Policy and permit signing operations are isolated from policy evaluation.
- The permit signer MUST NOT treat an unauthenticated runtime assertion such as `decision = ALLOW` as proof of authorization. Before signing, it must verify a cryptographically authenticated authorization attestation bound to the exact tenant, principal, agent, request, action digest, policy digest, context digest, decision, and durable decision-evidence reference. The attestation issuer must be a distinct trust boundary from the runtime coordinator and permit signer; it must independently validate the deterministic decision and its exact input/evidence binding rather than merely signing a runtime assertion. A runtime compromise must not silently become signing authority. The concrete proof/validation contract is a G3 prerequisite.
- The signer MUST verify attestation freshness and current issuer/key revocation state. If revocation state is unavailable or exceeds its configured freshness bound, signing fails closed.
- Enforcement must not trust a permit merely because it was returned by an in-process function; signature, claims, expiry, and single-use state are verified at the boundary.
- At permit consumption, enforcement MUST establish fresh, bounded revocation status for (a) the permit-signing key, (b) the authorization-attestation issuer and attestation, and (c) the policy issuer and policy version/digest. Revoked, compromised, unknown, unavailable, or stale status MUST reject the permit before any side effect. A permit's short TTL does not replace these checks.
- **G3 permit-binding prerequisite:** the frozen G1 v1 permit claims do not identify the authorization-attestation issuer or carry an attestation reference. G3 MUST define a versioned, cryptographically verifiable binding (for example, issuer ID/key ID plus attestation digest/reference in the permit or an authenticated envelope) and a trusted way to resolve the policy issuer and current policy-revocation status. This is a G3 contract extension; G1 v0.1.0 MUST NOT be silently modified. Until that binding and its verification are specified and tested, enforcement MUST fail closed and production enforcement is prohibited.
- Tenant identity is derived from authenticated identity context, never from an untrusted action payload.
- Every adapter must document bypass paths and external side-effect semantics.

## 5. Key separation

Distinct key purposes:
- Policy issuer signing key.
- Authorization-attestation issuer key, held outside the runtime coordinator and permit signer.
- Permit signing key.
- Optional evidence checkpoint signing key.
- Context source attestation keys (owned by external providers).

Keys MUST NOT be reused across purposes. Private keys remain outside the policy core and are not stored in policy bundles, evidence, logs, or SDK configuration. Key IDs and public keys are versioned and discoverable only through configured trust roots.

## 6. Data flows

### Authorization
Untrusted action → identity assertion → normalized request → context snapshot → verified policy → deterministic decision → durable decision evidence → (fresh ALLOW only) signed permit.

### Approval
REQUIRE_APPROVAL → approval request → independent approver authentication → action/policy-bound approval event → quorum verification → fresh context → fresh policy evaluation → decision.

### Enforcement
Permit + actual action → signature/claim verification → current policy/key/issuer revocation verification → atomic single-use consume → protected side effect → observed outcome evidence.

## 7. Failure and availability

All security-critical dependencies fail closed:
- Identity verification unavailable: reject.
- Policy or trust root unavailable: reject.
- Context source unavailable or stale: reject when policy requires it.
- Evidence append unavailable: do not issue ALLOW permit.
- Permit signing unavailable: do not issue permit.
- Permit consume store unavailable or unable to provide the required cross-replica atomicity: do not execute.
- Policy, attestation, or signing-key revocation status unavailable, unknown, or stale: do not execute.
- Unknown schema, algorithm, key ID, or version: reject.

Availability objectives and retry policies are deferred until a concrete deployment topology is selected. Retries must not duplicate side effects.

## 8. Isolation requirements

- Separate authorization evaluation from execution adapters.
- Separate policy signing and permit signing privileges.
- Tenant-scope all persistence keys and authorization queries.
- Avoid shared mutable policy state across tenants.
- Minimize raw payload retention and redact secrets.
- Apply least privilege to service identities and administrative operations.
- Use explicit network egress allowlists for adapters; core evaluator requires none.

## 9. Residual risks

Compromised host, root operator, adapter bypass, dishonest context provider, stolen signing key, misconfigured trust root, and external-system race conditions remain outside guarantees of the pure evaluator. Production claims require adapter-specific security review and operational controls.

## 10. G2 exit criteria

- Trust boundaries and data flows reviewed.
- Key lifecycle and signer compromise procedures documented.
- Threat scenarios mapped to mitigations and tests.
- Enforcement and replay guarantees precisely scoped.
- Privacy, tenancy, and evidence integrity reviewed.
- Review findings addressed and G3 prerequisites explicitly recorded.
- No deployment or production-readiness claim until later gates are met.
