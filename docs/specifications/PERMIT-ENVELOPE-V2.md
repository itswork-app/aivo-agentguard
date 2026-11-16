# Permit Envelope v2

**Status:** Proposed — G3 review required  
**Version:** 0.1.0  
**Compatibility:** Wraps frozen G1 AuthorizationPermit v1 without changing its claims.

## 1. Purpose

G1 v0.1.0 defines the signed permit claims but does not expose the authorization-attestation issuer/reference required for independent enforcement-time revocation checks. G3 introduces a versioned outer envelope. The inner G1 permit claims and their v1 signature remain byte-for-byte governed by G1; no G1 normative field is added or reinterpreted.

A security-critical consumer configured for G3 MUST require this envelope. A standalone G1 v1 permit MUST NOT be accepted by a G3 enforcement profile.

## 2. Envelope structure

The canonical `PermitEnvelopeV2` contains exactly:

- `envelope_version`: literal `2`
- `permit_claims_v1`: complete frozen G1 permit claims
- `permit_signature_v1`: original G1 signature envelope
- `signing_challenge_v1`: complete permit-signer challenge token and signature
- `authorization_attestation_v1`: complete G3 attestation payload and signature
- `policy_provenance`: `policy_id`, `policy_version`, `policy_digest`, `policy_issuer_id`, `policy_signing_key_id`
- `attestation_binding`: `issuer_id`, `issuer_key_id`, `attestation_digest`
- `permit_signer_key_id`: purpose-specific permit-envelope signing key; may equal or differ from the inner G1 permit `signing_key_id`, but both keys MUST have permit-signing purpose and both are independently checked for revocation
- `issued_at`
- `expires_at`
- `envelope_signature`: Ed25519 signature over all preceding envelope fields

No unknown fields are accepted. The inner permit must have `decision = ALLOW`. The envelope expiry MUST NOT exceed the inner permit expiry or the attestation expiry.

## 3. Digests and signatures

The attestation digest is SHA-256 over the attestation's canonical signed payload and signature envelope, prefixed with `AIVO-AGENTGUARD-ATTESTATION-REF-V1\\0`.

The envelope signature is Ed25519 over canonical envelope fields excluding `envelope_signature`, prefixed with `AIVO-AGENTGUARD-PERMIT-ENVELOPE-V2\\0`. The envelope signer key MUST have permit-envelope signing purpose. It MUST be distinct from policy issuer, authorization-attestation issuer, evidence service, and context-source keys. The frozen inner G1 permit signature is verified independently; the outer signature does not replace it.

All canonicalization uses the G1 RFC 8785 and numeric restrictions. Algorithm negotiation is prohibited. Unknown schema versions or key purposes are rejected.

## 4. Exact binding invariants

The following fields MUST match exactly across inner permit, attestation, and envelope provenance:
- tenant, principal, agent, request ID;
- request digest and action digest;
- policy ID, version, and digest;
- context digest;
- decision `ALLOW`;
- issue/expiry bounds.

The policy issuer ID and policy signing key ID in the attestation and envelope MUST match the verified policy signature metadata. The inner G1 `signing_key_id` and outer `permit_signer_key_id` may be the same key or two distinct keys of the same permit-signing purpose; the consumer MUST verify both signatures and both key statuses. The attestation issuer ID/key ID in the binding MUST match the attestation's signed claims and verified signature. The attestation digest MUST be recomputed by the consumer; caller-supplied digest values are never trusted.

The envelope signature covers the challenge token, attestation bytes/reference, policy provenance, and inner permit signature, preventing substitution after signing. The consumer MUST verify the challenge token signature, signer key purpose, pending-request digest, and exact tenant/request/action/policy/context binding, then recompute its digest and compare it to the attestation. Challenge issue precedes attestation issue; attestation issue MUST be no later than inner permit issue; inner permit issue MUST be no later than envelope issue. Attestation issue MUST occur before challenge expiry. The envelope and inner permit must share the exact tenant/request/action/policy/context claims.

## 5. Enforcement verification order

The enforcement boundary MUST perform these checks before consuming the permit and before any external side effect:

1. Enforce configured envelope version and strict schema.
2. Verify the outer envelope signature and permit-envelope key purpose.
3. Verify the inner G1 permit signature and all G1 claims; verify its `signing_key_id` independently from the outer envelope key ID.
4. Verify the challenge token signature, key purpose, exact request binding, and challenge digest.
5. Verify the attestation digest and signature, including exact equality with challenge nonce and digest.
6. Verify exact field equality across all bindings.
7. Verify timestamp ordering and expiry bounds using trusted enforcement time.
8. Verify trusted, fresh revocation status for both inner G1 permit signer and outer permit-envelope signer, attestation issuer/key, policy issuer/key, and policy ID/version/digest.
9. Verify actual action digest and authenticated tenant/principal/agent match.
10. Atomically consume tenant-scoped permit identity using the G2 linearizable consume invariant.
11. Only after successful consumption may the adapter initiate the protected side effect.

The adapter MUST NOT execute on partial verification or continue in degraded/offline mode when a required trust or revocation dependency is unavailable.

## 6. Expiry

The effective expiry is the earliest of inner permit expiry, attestation expiry, and envelope expiry. It MUST NOT exceed 60 seconds from the original authorization decision; the default remains 30 seconds. The attestation challenge lifetime is separately limited to 30 seconds.

## 7. Version and migration rules

- G1 v1 remains frozen and valid only for legacy/non-G3 profiles explicitly configured as such.
- G3 profiles require PermitEnvelopeV2; no implicit fallback to G1 v1 is allowed.
- A consumer MUST NOT downgrade after encountering an unknown or invalid v2 envelope.
- Migration requires explicit configuration, telemetry, and tenant-level rollout. Production enforcement remains disabled until revocation status protocol and all required verification tests are implemented.
