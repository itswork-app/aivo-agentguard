# Initial Threat Model

**Status:** Draft — not a security audit

## Security objectives

- Prevent unauthorized agent actions from crossing an enforcement boundary.
- Ensure decisions are deterministic, attributable, and bound to exact action inputs.
- Prevent agent or LLM output from changing policy authority.
- Preserve verifiable history of decisions, approvals, and execution outcomes.
- Keep signing credentials outside AgentGuard's trust boundary.

## Assets

1. Policy bundles, signatures, and policy version identifiers.
2. Agent, tenant, principal, and approver identities.
3. Action request payloads and context provenance.
4. Approval records and approver identity assertions.
5. Authorization decisions, signed permits, and their binding to actions.
6. Evidence events, sequence numbers, and integrity metadata.
7. Adapter configuration, permit-consumption state, and enforcement state.
8. Policy-issuer and permit-signer public trust configuration.

## Adversaries and failure sources

- Malicious or compromised agent.
- Prompt injection or manipulated LLM advisory output.
- Compromised or replayed approval assertion.
- Stale, spoofed, or incomplete context provider.
- Replay, mutation, substitution, or reordering of action requests.
- Compromised adapter, host, or misconfigured policy deployment.
- Compromised signing key or stale trust-root configuration.
- Dependency compromise, denial of service, clock error, and operator error.

## Initial mitigations

- Typed, versioned action, request, policy, and permit contracts.
- Deterministic deny-overrides evaluation with default deny.
- Policy and permit signatures with configured trust roots.
- Fresh policy re-evaluation after approval.
- SHA-256 domain-separated digests over canonical representations.
- Nonce, expiry, and exact request/action digest binding.
- Atomic one-time permit consumption before side effects.
- Strict separation of decision and execution.
- Append-only linked evidence, offline verification, and optional signed checkpoints.
- No custody of private keys or seed phrases.
- Dependency review, CI checks, fuzzing, and adversarial test cases.

## Residual risks and open questions

- Time-of-check/time-of-use races between permit validation and external execution.
- Compromised host or adapter can bypass in-process checks.
- A trusted context source can still provide false information.
- Clock compromise can undermine expiry and freshness checks.
- Hash chains without independently held checkpoints cannot detect all full-stream rewrites or truncation.
- Identity federation, signer key rotation, and revocation operations need implementation-specific controls.
- Denial of service may block legitimate actions; fail-closed behavior trades availability for safety.
- Cross-chain semantics and transaction simulation correctness require adapter-specific validation.

## Security posture statement

This document is an initial threat-model draft. It is not evidence of independent review, certification, or production readiness.
