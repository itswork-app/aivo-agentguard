# Security Requirements

**Status:** Approved — product owner accepted 2026-11-16  
**Version:** 0.1.0

## 1. Security invariants

- **SEC-001 Authority separation:** LLMs and agents cannot issue authoritative authorization decisions.
- **SEC-002 Default deny:** no matching ALLOW or any validation failure results in DENY.
- **SEC-003 Exact binding:** permit is bound to tenant, principal, agent, request, action digest, policy digest, context digest, nonce, and expiry.
- **SEC-004 Approval separation:** approval is not a permit; a fresh policy evaluation is mandatory.
- **SEC-005 Replay protection:** permits are single-use at a correctly implemented enforcement boundary.
- **SEC-006 Secret isolation:** private keys and signing secrets remain outside the core.
- **SEC-007 Evidence durability:** decision evidence must be durably appended before an ALLOW permit is returned.
- **SEC-008 Tenant isolation:** every security-sensitive lookup and evidence stream is tenant-scoped.
- **SEC-009 Deterministic evaluation:** same validated inputs and policy version produce same decision and reason codes.
- **SEC-010 Version strictness:** unknown schemas, policy versions, algorithms, or key IDs fail closed.

## 2. Trust boundaries

1. Agent and model output → untrusted request.
2. Identity provider / caller adapter → authenticated identity assertion.
3. Context providers → provenance-bearing external data.
4. Policy publisher → signed immutable policy bundle.
5. Approval service → authenticated, action-bound approval assertion.
6. Authorization runtime → signed permit issuer.
7. Enforcement adapter → trusted action binding and one-time consume.
8. Evidence store → append-only persistence and independent verification.

Every boundary requires explicit input validation and error behavior.

## 3. Threat mitigations

- Prompt injection: LLM output cannot alter policy or authorize an action.
- Agent compromise: all actions are evaluated independently of agent claims.
- Policy tampering: policy digest and signature validation against configured trust roots.
- Approval replay: approval is bound to request, action, policy, tenant, expiry, and unique approver.
- Permit replay: atomic single-use consume operation.
- Action substitution: canonical action digest is compared at enforcement.
- Stale context: source provenance, observation time, validity deadline, and max-age checks.
- Evidence mutation: append-only interface, hash chain, offline verifier, optional signed checkpoints.
- Tenant confusion: tenant-bound IDs and tenant-scoped storage and queries.
- Dependency compromise: minimal dependencies, review, lockfile, CI, and later supply-chain controls.
- Denial of service: fail closed; availability degradation is an accepted safety trade-off.

## 4. Residual risks

A compromised host, malicious privileged operator, bypassed adapter, dishonest context provider, external system race, or deleted unanchored evidence stream can defeat guarantees beyond the component's trust boundary. These must be documented rather than hidden by product claims.

## 5. Security validation required before production claims

- Threat-model review by an independent reviewer.
- Property tests for policy combining and canonicalization.
- Fuzz tests for request, policy, permit, and evidence parsers.
- Replay, substitution, stale-context, tenant-isolation, and approval-quorum adversarial tests.
- Review of cryptographic key lifecycle and dependency supply chain.
- Adapter-specific TOCTOU and bypass analysis.
