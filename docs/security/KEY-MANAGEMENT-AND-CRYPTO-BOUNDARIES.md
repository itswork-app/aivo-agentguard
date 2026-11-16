# Key Management and Cryptographic Boundaries

**Status:** Proposed — security review required  
**Version:** 0.1.0

## 1. Purpose and non-goals

Define key-purpose separation and lifecycle requirements. This document does not select a cloud KMS, HSM vendor, custody provider, or production deployment.

AgentGuard does not custody user wallet keys, seed phrases, or transaction-signing keys. Those are outside the product boundary.

## 2. Key classes

| Key class | Purpose | Private key owner |
|---|---|---|
| Policy issuer | Sign immutable policy bundles | Policy administrator's trusted signing boundary |
| Authorization attestation issuer | Attest a verified deterministic ALLOW result and its exact input/evidence binding | Isolated authorization-attestation boundary; not the runtime coordinator and not the permit signer |
| Permit signer | Sign short-lived ALLOW permits | Isolated AgentGuard permit-signing service |
| Evidence checkpoint | Sign exported evidence checkpoints | Independent evidence administration boundary |
| Context attestation | Attest context observations | External context provider |

Key reuse across purposes is prohibited. User wallet or transaction-signing keys must never be imported into AgentGuard.

## 3. Algorithms and formats

G1 proposes Ed25519 for policy and permit signatures and SHA-256 for domain-separated digests. G2 requires a cryptographic review of:
- library maturity and maintenance;
- constant-time behavior where relevant;
- key serialization and import/export constraints;
- signature verification behavior and malformed-input handling;
- key identifier collision and rotation handling;
- canonical message construction and test vectors.

No algorithm agility negotiation is allowed in the G1 v1 contract. A future algorithm change requires a versioned ADR and migration plan.

## 4. Key lifecycle

### Provisioning
- Generate keys in an approved isolated signing boundary.
- Never generate or persist production private keys in the policy evaluator.
- Register key ID, purpose, algorithm, public key, validity interval, and issuer identity.
- Provision trust roots out-of-band and record administrative evidence.

### Rotation
- Support overlapping public-key validity windows for verification.
- New permits are signed only by the active key.
- Old public keys remain available for verification of unexpired artifacts and retained evidence as required.
- Key rotation must not silently change policy semantics or tenant authorization.

### Revocation and compromise
- Maintain explicit key status: active, retired, revoked, compromised.
- A compromised key is immediately rejected for new trust decisions.
- Define whether already-issued permits are invalidated; the safe default is to reject permits signed by a compromised key even before their nominal expiry.
- Re-evaluate policy after any signer or trust-root compromise.
- Record incident, revocation, and recovery events in append-only evidence.
- Publish recovery instructions for trust-root replacement and tenant notification.

### Destruction
- Destroy retired private key material according to the signing boundary's approved lifecycle.
- Preserve public keys and key metadata for historical verification, subject to retention policy.
- Record destruction evidence without retaining secret material.

## 5. Signing service boundary

The policy evaluator must not possess signing private keys. The permit signer accepts a narrowly scoped, authenticated signing request only after the runtime has:
1. validated request, identity, policy, and context;
2. received a fresh ALLOW;
3. durably appended the decision event;
4. constructed the exact canonical permit claims.

The signer must independently validate request shape, allowed key purpose, expiry ceiling, decision value, and digest binding. It must not accept arbitrary bytes from an agent.

A bare runtime-supplied `ALLOW` field is insufficient. The signing request must include a cryptographically authenticated authorization attestation whose issuer is explicitly trusted by the signer and whose claims bind tenant, principal, agent, request, action digest, policy digest, context digest, decision, and durable decision-evidence reference. The signer verifies the attestation signature, issuer status, freshness, and exact claim equality before signing. The attestation design and issuer isolation are G3 contract work; until that contract is approved, no production signer may be implemented.

Revocation checks must have a defined freshness bound. If the signer cannot establish sufficiently fresh status for the policy issuer, authorization-attestation issuer, or permit-signing key, it MUST fail closed. Offline or partitioned operation must not silently extend revocation freshness.

## 6. Threat controls

- Use distinct service identities and access policies for policy and permit signing.
- Restrict signing operations to explicit purpose-specific APIs.
- Rate-limit and audit signing requests.
- Reject unknown key IDs, algorithms, purposes, and malformed encodings.
- Never log private key material or complete secret-bearing signing requests.
- Maintain a documented break-glass process with dual control where feasible.

## 7. Open decisions

- Software-backed signer versus HSM/KMS-backed signer for initial deployment.
- Whether offline policy signing is supported in v1.
- Public-key distribution and revocation propagation model.
- Permit signer high-availability and failover model.
- Checkpoint signer ownership and external anchoring mechanism.

These are intentionally unresolved pending threat review and deployment requirements.
