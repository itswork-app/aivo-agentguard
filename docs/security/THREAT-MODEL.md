# Initial Threat Model

**Status:** Draft — not a security audit

## Security objectives

- Prevent unauthorized agent actions from crossing an enforcement boundary.
- Ensure decisions are deterministic, attributable, and bound to exact action inputs.
- Prevent agent or LLM output from changing policy authority.
- Preserve verifiable history of decisions, approvals, and execution outcomes.
- Keep signing credentials outside AgentGuard's trust boundary.

## Assets

1. Policy bundles and policy version identifiers.
2. Agent, tenant, and principal identities.
3. Action request payloads and context provenance.
4. Approval records and approver identity assertions.
5. Authorization decisions and their binding to actions.
6. Evidence events and integrity metadata.
7. Adapter configuration and enforcement state.

## Adversaries and failure sources

- Malicious or compromised agent.
- Prompt injection or manipulated LLM advisory output.
- Compromised or replayed approval token.
- Stale, spoofed, or incomplete context provider.
- Replay, mutation, substitution, or reordering of action requests.
- Compromised adapter or misconfigured policy deployment.
- Dependency compromise, denial of service, and operator error.

## Initial mitigations

- Typed, versioned action and policy contracts.
- Deterministic evaluation with explicit deny-by-default semantics.
- Fresh policy re-evaluation after approval.
- Nonce, expiry, and request/action digest binding (exact scheme TBD).
- Strict separation of decision and execution.
- Append-only linked evidence with independently verifiable integrity (format TBD).
- No custody of private keys or seed phrases.
- Dependency review, CI checks, fuzzing, and adversarial test cases.

## Residual risks and open questions

- Time-of-check/time-of-use races between re-evaluation and execution.
- Compromised host or adapter can bypass in-process checks.
- Identity federation and key rotation semantics are unspecified.
- Evidence integrity does not itself guarantee evidence availability or truthfulness of external inputs.
- Denial of service may block legitimate actions; fail-closed behavior trades availability for safety.
- Cross-chain semantics and transaction simulation correctness require adapter-specific validation.

## Security posture statement

This document is an initial threat-model draft. It is not evidence of independent review, certification, or production readiness.
