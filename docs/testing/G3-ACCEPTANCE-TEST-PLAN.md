# G3 Acceptance Test Plan — Authorization Proof and Permit Binding

**Status:** Proposed — implementation gate  
**Version:** 0.1.0  
**Purpose:** Define falsifiable tests for the G3 attestation, envelope, and revocation contracts. This file is a test specification, not evidence that tests have run.

## 1. Attestation issuer independence

- A runtime-supplied `ALLOW` with no attestation is rejected.
- A runtime-supplied `ALLOW` with a valid signature but no independent verifier recomputation is rejected.
- A verifier recomputes DENY or REQUIRE_APPROVAL while runtime claims ALLOW; no attestation is issued.
- A verifier recomputes ALLOW but any request/action/policy/context/identity digest differs; no attestation is issued.
- Wrong evaluator semantic version or artifact digest is rejected.
- Missing, non-durable, mismatched, or invalidly signed evidence receipt is rejected.
- Attestation issuer sharing runtime or permit-signer credentials is a deployment conformance failure.

## 2. Attestation schema and cryptography

- Unknown fields, duplicate fields, unsupported schema, malformed base64url, wrong key purpose, invalid Ed25519 signature, and non-canonical payload are rejected.
- Golden vectors reproduce the attestation digest and signature input exactly.
- Altering any signed claim invalidates signature or exact-binding verification.
- Expired/future-dated attestation and challenge nonce are rejected.
- Challenge nonce is single-use under concurrent requests.

## 3. PermitEnvelopeV2 binding

- Valid envelope verifies inner G1 signature, outer signature, and attestation signature.
- Revoking either the inner G1 permit-signing key or outer envelope-signing key rejects enforcement.
- Any mismatch in tenant, principal, agent, request, action, policy, context, decision, issuer, key ID, or digest is rejected.
- Substituting an attestation, policy provenance object, inner permit, or signature after envelope signing is rejected.
- Missing attestation binding or policy issuer provenance is rejected.
- Standalone G1 v1 permit is rejected by a G3-required enforcement profile.
- Unknown v2 envelope fields or unsupported versions are rejected; no downgrade fallback is attempted.
- Effective expiry is the earliest of permit, attestation, and envelope expiries.

## 4. Revocation protocol

- Valid signed fresh snapshot is accepted.
- Invalid signature, unknown registry, unknown subject, missing required entry, malformed entry, duplicate subject, and unsupported schema fail closed.
- Snapshot age at 29 seconds is accepted if all other bounds pass; age at 30 seconds boundary follows the strict implementation rule; age above 30 seconds is rejected.
- `next_update - this_update` above 60 seconds is rejected.
- Future timestamps beyond 5 seconds are rejected.
- Lower sequence, epoch rollback, or loss of persisted high-water mark stops enforcement.
- ACTIVE -> REVOKED or COMPROMISED after permit issuance causes enforcement rejection.
- RETIRED key cannot sign new artifacts; previously issued unexpired artifact behavior follows the specified transition rule.
- Revocation service outage, network partition, stale cache, or unavailable status rejects before side effect.

## 5. Enforcement ordering and race tests

- Revocation and all signature/binding checks occur before consume.
- Consume is tenant-scoped, durable, and linearizable across independent replicas as required by ADR-0007.
- Exactly one concurrent consume succeeds for the same tenant/permit identity.
- Same permit ID in separate tenants does not collide.
- Revocation between authorization and enforcement is detected before consume and side effect.
- Revocation after the final check but before the side effect is analyzed as a TOCTOU residual; deployment must minimize this window and external systems should support atomic preconditions where possible.
- Any failed check produces zero side effects and a typed rejection event.

## 6. Cross-language and robustness tests

- Rust reference implementation and TypeScript/Python SDKs reproduce all canonical digests and validation outcomes.
- Property-based tests cover field permutations, Unicode edge cases, numeric restrictions, timestamp boundaries, duplicate identifiers, and unknown fields.
- Fuzz parsers for attestation, envelope, and revocation snapshot formats.
- Differential tests ensure Rust and SDK implementations reject the same invalid inputs.

## 7. Release gate

G3 implementation is not accepted until:
- all MUST-level negative tests pass;
- golden vectors are checked into the repository;
- concurrency, replay, rollback, expiry, and revocation-partition tests pass;
- security-sensitive dependencies are reviewed and pinned;
- requirement-to-test traceability is complete;
- no unresolved Critical/High findings remain;
- no production-readiness claim is made without adapter-specific operational review.
