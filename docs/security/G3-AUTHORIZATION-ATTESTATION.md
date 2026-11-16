# G3 Authorization Attestation Protocol

**Status:** Approved — normative G3 v0.1.0  
**Version:** 0.1.0  
**Depends on:** G1 v0.1.0; G2 v0.1.0  
**Normative scope:** Authorization attestation between independent verifier, permit signer, and enforcement boundary.

## 1. Purpose

An authorization attestation is a signed statement that a distinct authorization-attestation issuer independently verified a specific authorization decision. It is not a policy decision by itself, not a human approval, and not a permit. It cannot authorize execution without a valid permit envelope and successful enforcement-time checks.

The attestation exists to prevent a compromised runtime coordinator from turning an arbitrary `ALLOW` field into a signed permit.

## 2. Trust model and issuer independence

The authorization-attestation issuer MUST:
- run behind a distinct service identity and privilege boundary from the runtime coordinator and permit signer;
- obtain the exact validated request, action, immutable policy bundle, trusted context snapshot, and durable decision-evidence receipt through authenticated interfaces;
- independently validate all schemas, signatures, tenant/principal/agent identity bindings, source attestations, freshness limits, and policy provenance;
- independently execute the deterministic authorization algorithm over those inputs using a pinned evaluator version and configuration;
- require the recomputed decision to equal `ALLOW`;
- verify that the evidence receipt refers to the exact request/action/policy/context digests and a durable `DECISION_RECORDED` event;
- reject if any input is missing, ambiguous, stale, unverifiable, or differs from the runtime's proposed permit claims.

It MUST NOT merely accept or re-sign a runtime-provided decision, decision digest, or boolean. A signed runtime assertion is not proof of correct evaluation.

The issuer SHOULD run as a separately deployed process with a separate service identity, deployment pipeline, and access policy. It MUST NOT share runtime signing credentials or writable memory. A common deterministic library may be reused only if the verifier independently validates all inputs and invokes the evaluator itself. Common-mode evaluator defects remain a residual risk and require golden vectors, property tests, fuzzing, and later implementation review.

## 3. Attestation claims

The signed canonical payload MUST contain exactly these fields for version 1; unknown fields are rejected:

| Field | Type / rule |
|---|---|
| `schema_version` | Literal `1` |
| `attestation_id` | Unique opaque identifier |
| `issuer_id` | Stable authorization-attestation issuer identity |
| `issuer_key_id` | Purpose-specific Ed25519 key identifier |
| `tenant_id` | Authenticated tenant |
| `principal_id` | Authenticated principal |
| `agent_id` | Authenticated agent |
| `request_id` | Exact request identifier |
| `request_digest` | G1 canonical request digest |
| `action_digest` | G1 canonical action digest |
| `policy_id` | Stable policy identity |
| `policy_version` | Immutable policy version |
| `policy_digest` | G1 canonical policy digest |
| `policy_issuer_id` | Authenticated policy publisher identity |
| `policy_signing_key_id` | Policy-purpose key identifier |
| `context_digest` | G1 canonical context digest |
| `decision` | Literal `ALLOW`; all other values are invalid |
| `reason_codes_digest` | Digest of deterministic reason-code set |
| `evaluator_version` | Exact semantic evaluator version |
| `evaluator_artifact_digest` | Digest of verifier-approved evaluator artifact/build |
| `decision_event_ref` | Tenant, stream, sequence, event hash |
| `evidence_receipt_ref` | Durable append receipt identifier and digest |
| `issued_at` | Trusted UTC timestamp |
| `expires_at` | UTC timestamp; maximum 30 seconds after issue |
| `challenge_nonce` | Cryptographically random, single-use 256-bit challenge from permit signer |
| `challenge_digest` | Digest of the permit signer's authenticated challenge token |

The signature is Ed25519 over the canonical payload prefixed with the fixed domain separator `AIVO-AGENTGUARD-AUTH-ATTESTATION-V1\0`. The attestation's `challenge_nonce` and `challenge_digest` MUST match the verified challenge token exactly. The signature envelope contains `algorithm = Ed25519`, `key_id`, and unpadded base64url signature. Algorithm negotiation is prohibited.

## 4. Evidence receipt requirements

The evidence writer MUST return a receipt only after the decision event is durably committed. The receipt MUST bind tenant ID, stream ID, sequence, event hash, event type, request digest, action digest, policy digest, context digest, and storage commit identity. The receipt is authenticated by a dedicated evidence-service key purpose distinct from policy, attestation, and permit keys.

The attestation issuer MUST verify the receipt signature and exact field equality and MUST verify the referenced event through the configured evidence read interface. A receipt that only says "write accepted" without durable-commit semantics is insufficient.

## 5. Challenge and replay controls

Before attestation issuance, the permit signer creates a signed `SigningChallengeV1` token containing exactly: `schema_version`, `challenge_id`, `nonce`, `pending_signing_request_digest`, `tenant_id`, `request_digest`, `action_digest`, `policy_digest`, `context_digest`, `issued_at`, `expires_at`, and `signer_key_id`. Unknown fields are rejected. The token signature is Ed25519 over canonical claims prefixed with `AIVO-AGENTGUARD-SIGNING-CHALLENGE-V1\0`; the signature envelope uses the fixed Ed25519 algorithm and the same key ID. The token is signed with the permit-signing purpose and verified by the attestation issuer against the configured signer trust root. It MUST NOT contain private data beyond the minimum identifiers and digests.

The attestation includes the nonce and digest of the complete canonical challenge token plus signature envelope. The challenge is bound to one pending signing request and exact expected claims; the issuer MUST reject a challenge whose binding does not match the independently recomputed ALLOW result. The permit signer atomically consumes the challenge on successful attestation verification and rejects duplicate, expired, unknown, or mismatched challenges. Challenge lifetime MUST NOT exceed 30 seconds. The nonce is not a substitute for the permit's own single-use consumption.

The challenge token MUST be carried in PermitEnvelopeV2 so enforcement can verify its signature, key ID, exact binding, digest, and timestamp ordering. The envelope signer MUST include the token in the signed envelope payload. Challenge issue MUST precede attestation issue, and attestation issue MUST occur no later than challenge expiry.

The attestation MUST be bound to the exact claims that will appear in the G1 permit and G3 envelope. Any difference in tenant, principal, agent, request, action, policy, context, decision, evaluator version, evidence reference, or challenge binding rejects signing.

## 6. Verification and failure behavior

The permit signer verifies:
1. strict schema and canonical encoding;
2. attestation signature and trusted issuer/key purpose;
3. issuer and key status from a fresh authenticated revocation snapshot;
4. issue/expiry timestamps and challenge nonce;
5. exact equality with the proposed permit and policy provenance;
6. evidence receipt signature, digest binding, and durable event reference;
7. evaluator version/artifact digest allowlist.

Any failure returns a typed error and MUST NOT produce a permit envelope. Unknown issuer, key, evaluator version, or schema fails closed.

Enforcement independently verifies the attestation signature, binding, issuer identity, and current revocation status; it does not trust the permit signer to have performed these checks.

## 7. Security limitations

The attestation is an issuer's signed assertion backed by independent deterministic re-evaluation, not a zero-knowledge proof or formal proof of program correctness. It does not protect against simultaneous compromise of the verifier, its trust roots, or the underlying evaluator semantics. The product MUST NOT market it as cryptographic proof that an external action is safe.
