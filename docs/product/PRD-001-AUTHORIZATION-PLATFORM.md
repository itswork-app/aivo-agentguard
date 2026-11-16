# PRD-001: Agent Authorization Platform

**Status:** Proposed — G1 product-owner review required  
**Version:** 0.1.0  
**Date:** 2026-11-16  
**Audience:** Web3 infrastructure teams, autonomous-agent builders, security engineers

## 1. Problem

Autonomous agents can initiate consequential actions through APIs, wallets, smart-contract interfaces, and operational tools. Authorization is often fragmented across agent prompts, application code, wallet configuration, and protocol-specific checks. These controls are difficult to reproduce, audit, and enforce consistently.

AIVO AgentGuard provides a deterministic authorization boundary outside the agent. It evaluates a typed action against a versioned policy and trusted context, then returns a decision that an enforcement point must bind to the exact action.

## 2. Product outcome

A system integrator can:
1. Normalize an agent's proposed action into a versioned request.
2. Evaluate that request against an immutable, versioned policy.
3. Receive `ALLOW`, `DENY`, or `REQUIRE_APPROVAL` with stable reason codes.
4. Complete an independent approval workflow where required.
5. Re-evaluate policy against current context after approval.
6. Enforce a short-lived permit bound to the exact action.
7. Verify an append-only history of requests, decisions, approvals, and enforcement outcomes.

## 3. Initial customer and market

**Initial wedge:** Web3 teams building autonomous agents, agent frameworks, protocol operations tooling, and infrastructure that can initiate on-chain or off-chain actions.

**Geography:** Global. **Architecture:** chain-agnostic core, protocol-specific adapters at the boundary.

The Web3 wedge is a market-entry hypothesis, not a restriction on future integrations.

## 4. Personas

- **Agent platform engineer:** needs one reusable authorization interface across tools and agents.
- **Security engineer:** needs deterministic controls, deny-by-default behavior, and reproducible evidence.
- **Protocol / treasury operator:** needs explicit policy boundaries and human approval for high-impact actions.
- **Auditor / incident responder:** needs to reconstruct which policy and context produced a decision.

## 5. Product boundaries

### In scope for the research and specification baseline
- Deterministic policy evaluation in Rust.
- Versioned action, policy, context, decision, and evidence contracts.
- Approval lifecycle contract.
- Short-lived, action-bound authorization permit contract.
- Enforcement interface and replay-protection requirements.
- SDK and protocol-adapter contracts for later phases.
- Offline test vectors and adversarial test plan.

### Explicitly out of scope for this phase
- Production deployment or production security claims.
- Custody, generation, storage, recovery, or export of private keys or seed phrases.
- Signing or broadcasting live transactions.
- Wallet product, bridge, exchange, or proprietary blockchain.
- Trading, investment, or capital allocation.
- LLM-based authoritative authorization or autonomous policy mutation.
- Hosted SaaS control plane, billing, or enterprise support commitments.

## 6. Functional requirements

| ID | Requirement | Priority |
|---|---|---|
| FR-001 | Accept a typed, versioned authorization request with tenant, principal, agent, action, policy reference, context, request ID, and expiry. | MUST |
| FR-002 | Evaluate only validated, immutable policy bundles. | MUST |
| FR-003 | Return exactly one of ALLOW, DENY, REQUIRE_APPROVAL. | MUST |
| FR-004 | Apply deterministic deny-overrides policy combining and default deny. | MUST |
| FR-005 | Bind a successful permit to tenant, principal, agent, exact action digest, policy digest, context digest, request ID, nonce, and expiry. | MUST |
| FR-006 | Require approval to be separately authenticated, action-bound, expiring, and followed by fresh policy evaluation. | MUST |
| FR-007 | Reject expired, replayed, mismatched, or unverifiable permits at enforcement. | MUST |
| FR-008 | Append linked evidence for request, decision, approval, re-evaluation, enforcement, and observed outcome. | MUST |
| FR-009 | Provide stable machine-readable reason and error codes. | MUST |
| FR-010 | Provide offline verification of evidence-chain integrity. | SHOULD |
| FR-011 | Provide TypeScript and Python SDKs after core contracts stabilize. | LATER |
| FR-012 | Provide Web3 adapters after chain-agnostic contracts stabilize. | LATER |

## 7. Non-functional requirements

- **NFR-001 Determinism:** identical validated inputs and policy version produce identical decisions and reason codes.
- **NFR-002 Fail closed:** missing, malformed, stale, unknown, or unverifiable security inputs cannot produce ALLOW.
- **NFR-003 Action binding:** a permit cannot authorize a different action, tenant, principal, agent, or policy version.
- **NFR-004 Replay resistance:** a permit is accepted at most once by a correctly implemented enforcement adapter.
- **NFR-005 Auditability:** evidence events are append-only and hash-linked; integrity verification does not claim external truth.
- **NFR-006 Secret isolation:** the core never receives or stores signing secrets.
- **NFR-007 Portability:** core authorization semantics do not depend on a chain, cloud, database, or LLM.
- **NFR-008 Compatibility:** every externally consumed schema is explicitly versioned.
- **NFR-009 Privacy:** raw secrets are never recorded; sensitive payloads are minimized or redacted.
- **NFR-010 Testability:** core behavior is testable offline without wallets, RPC endpoints, or live transactions.

## 8. User-visible guarantees and limitations

AgentGuard can attest what its policy engine decided from the inputs it received. It cannot independently guarantee that external context is truthful, that an adapter cannot be bypassed, that a blockchain transaction will execute as simulated, or that a compromised host is safe. These limitations must be explicit in product and integration documentation.

## 9. Success measures for research

- 100% of published decision test vectors produce the specified outcome.
- Every ALLOW test has a matching exact-action permit and evidence record.
- All negative, stale-context, approval, replay, and tampering cases fail closed.
- No tests require a real wallet, private key, funded account, or live transaction.
- At least one independent reviewer can reproduce decisions from versioned inputs.

## 10. Release gates

- G1: product and normative contract approval.
- G2: security architecture and threat-model review.
- G3: technical contracts and executable conformance vectors.
- G4: core implementation with deterministic and adversarial tests.
- G5: SDKs and adapters.
- G6: independent security review before any production-readiness claim.

No later gate is implied to be complete by approval of this PRD.
