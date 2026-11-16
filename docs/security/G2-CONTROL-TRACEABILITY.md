# G2 Security Control Traceability

**Status:** Proposed — G2 security review required  
**Version:** 0.1.0

This matrix maps the G2 threat register to the approved G1 security invariants and the verification evidence required before implementation can be considered complete.

| Threat | Security invariants | Required verification |
|---|---|---|
| T-001 Action substitution | SEC-003 | Canonical action digest golden vectors; adapter compares actual action digest |
| T-002 LLM / prompt authority | SEC-001 | API surface review; tests prove model output cannot set decision or bypass policy |
| T-003 Unsafe policy | SEC-002, SEC-009, SEC-010 | Deny-overrides property tests; signed policy validation; policy review workflow |
| T-004 Policy rollback | SEC-010 | Monotonic version, revocation and rollback tests |
| T-005 Approval replay | SEC-004, SEC-003 | Request/action/policy/profile/tenant binding and expiry tests |
| T-006 Duplicate approver | SEC-004 | Quorum tests with duplicate principal and separation-of-duties cases |
| T-007 Context spoofing | SEC-002 | Source registry, trust class, attestation and freshness negative tests |
| T-008 Permit replay | SEC-005 | Concurrent consume test; exactly one successful consume |
| T-009 Permit signer compromise | SEC-006, SEC-010 | Key revocation and invalid-signature tests; incident simulation |
| T-010 Policy issuer compromise | SEC-010 | Trust-root rotation, revocation, and invalid signer tests |
| T-011 Tenant confusion | SEC-008 | Cross-tenant isolation and identifier substitution tests |
| T-012 Evidence rewrite | SEC-007 | Tamper, sequence gap, checkpoint and truncation tests |
| T-013 Evidence outage | SEC-007 | Fault injection proves no permit issued when append is unavailable |
| T-014 TOCTOU | SEC-003, SEC-005 | Adapter precondition and external idempotency tests |
| T-015 Supply-chain compromise | SEC-006 | Dependency audit, pinned workflow action review, build provenance |
| T-016 Privileged operator | SEC-006, SEC-007 | Privilege separation, dual-control review, independent checkpoint verification |
| T-017 Clock skew | SEC-002, SEC-010 | Future timestamp, rollback, skew boundary and expiry tests |
| T-018 Canonicalization differential | SEC-003, SEC-009 | Cross-language golden vectors and parser fuzzing |
| T-019 Denial of service | SEC-002 | Bounded evaluation, rate limiting, backpressure and fail-closed tests |
| T-020 Evidence privacy leak | SEC-006, SEC-007 | Forbidden-secret scanning, redaction tests, retention review |

## Required proof artifacts

1. Golden canonicalization vectors for request, action, policy, permit, and evidence.
2. A concurrency test demonstrating exactly one successful atomic permit consume.
3. Crash-injection results for consume-before-side-effect and side-effect-before-outcome-recording.
4. Key rotation, revocation, and compromised-key test results.
5. Cross-tenant authorization and evidence isolation tests.
6. Evidence tamper, sequence-gap, truncation, and signed-checkpoint verification results.
7. Parser fuzzing corpus and reproducible test output.
8. Adapter-specific bypass and TOCTOU assessment.

## Scope notes

This matrix is a verification plan, not evidence that the controls are already implemented or tested. G1's acceptance test plan defines contract behavior; this G2 matrix defines security proof obligations. All implementation evidence must be attached to a later implementation PR and release gate.
