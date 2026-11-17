# G3.2 Runtime Decision and Evidence Coordinator

Status: implementation slice in progress. The fail-closed storage-error test is implemented; CI validation is pending. This document describes the current library boundary; it is not a production-readiness claim.

## Scope

The `agentguard-runtime` crate composes the signed policy evaluator with the append-only evidence service:

1. Validate the evidence correlation metadata and fixed evidence-signer identity.
2. Evaluate the signed `PolicyBundleV1` against an authenticated `EvaluationRequestV1`.
3. Obtain one trusted UTC timestamp for the decision event and evidence receipt.
4. Create a `DECISION_RECORDED` event containing tenant, request, action, policy, and context digests plus a stable decision/reason code.
5. Append with bounded optimistic concurrency.
6. Read back the exact committed event and verify its hash and commit identity.
7. Sign the evidence receipt only after durable read-back succeeds.
8. Return the decision and receipt together. Any failure returns an error and exposes no decision result.

Both ALLOW and non-ALLOW outcomes are recorded. Only a later authorization-attestation issuer may decide whether a recorded ALLOW is eligible for attestation.

## Trust boundaries

The runtime coordinator does **not** authenticate the principal, establish tenant membership, independently verify context-source provenance, compute ingress digests, issue authorization attestations, issue permits, consume permits, or execute actions.

The ingress adapter MUST:
- authenticate the principal and agent using deployment-controlled identity;
- authorize tenant membership before invoking this coordinator;
- obtain context from trusted source adapters and verify source signatures/attestations;
- derive request/action/context digests from the exact canonical inputs;
- ensure `actor_ref`, request correlation IDs, and stream routing are server-controlled;
- prevent callers from supplying `attestation_verified` or other trust assertions directly.

The evidence signer MUST be isolated, purpose-scoped, and expose a fixed configured key ID. The evidence store MUST implement the linearizable compare-and-append and durable read-back contract documented by `agentguard-evidence`.

## Security invariants

- Policy evaluation errors are not converted to DENY or ALLOW; they abort the operation.
- Evidence storage, read-back, clock, and signer failures abort the operation.
- A decision is not returned until its evidence event is durably committed and verified.
- Event reason codes are stable protocol strings, not Rust debug formatting.
- Automated test asserts that a stream-head storage failure returns an error, exposes no policy decision, and does not invoke the evidence signer.
- Tenant ID for the event is taken from the evaluated request, never from a caller-supplied evidence field.
- ALLOW is a policy outcome, not an execution capability or authorization permit.
- Enforcement remains a separate boundary and must verify signed attestation, evidence receipt, revocation status, independently derived execution context, expiry, and atomic single-use permit consumption.

## Explicitly deferred

- Independent context-source registry and attestation verification service.
- Authorization-attestation issuer with evidence-receipt verification before signing.
- Approval authentication, quorum, expiry, separation-of-duties, and policy re-evaluation lifecycle.
- Concrete durable production adapters for evidence, key registry, clock, replay, revocation checkpoints, and permit consumption.
- Multi-node concurrency and crash-recovery integration tests against production adapters.
- End-to-end permit issuance-to-consumption tests, external side-effect adapter, and independent security review.

## Acceptance gates

This slice is acceptable only when CI passes formatting, Clippy with warnings denied, and locked workspace tests; tests demonstrate that evidence failure prevents a decision from being returned; concurrency and crash recovery are tested against a durable adapter; and the independent verifier/issuer boundary is reviewed. The PR must remain Draft until the required G3 ancestors are accepted and all applicable gates pass.

No production deployment, security certification, or SLSA assurance level is claimed.
