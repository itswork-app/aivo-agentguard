# G2 Adversarial Security Review

**Review type:** Second-pass adversarial architecture review  
**Review date:** 2026-11-16  
**Reviewed baseline:** G1 v0.1.0 at `62b7becf3c82110f5d737d7aa850f43483fed1d7`  
**Reviewed change:** PR #5, G2 Security Architecture  
**Review status:** Conditional pass for the G2 documentation scope after recorded remediations  
**Scope limitation:** This is an AI-assisted review performed in the same project workflow. It is not a third-party independent audit, penetration test, cryptographic implementation audit, or security certification.

## 1. Executive assessment

The G2 architecture is directionally sound in its separation of policy evaluation, signing authority, approval, enforcement, and evidence. The fail-closed posture and explicit distinction between at-most-once permit acceptance and exactly-once external execution are appropriate.

The review identified gaps that could undermine enforcement if left implicit. They are addressed in the G2 documents and ADRs listed below. The resulting G2 package is suitable for review/merge as a **design-stage architecture baseline only**, provided the G3 prerequisites remain explicit release blockers.

No claim is made that runtime controls exist or have been tested. PR #5 is documentation-only.

## 2. Findings and dispositions

### AG-G2-001 — Authorization-attestation issuer cannot be identified from the frozen G1 permit

- **Severity:** High
- **Affected documents:** G1 Authorization Lifecycle / API Contract; G2 Security Architecture; Key Management; ADR-0006
- **Attack preconditions:** An authorization attestation is used to authorize permit signing, but the enforcement boundary receives only a G1 v1 permit that does not identify the attestation issuer or carry a verifiable attestation reference.
- **Attack scenario:** An attestation issuer is compromised or revoked after permit issuance. Enforcement is required to check issuer revocation, but cannot reliably determine which issuer/key produced the attestation from the G1 permit claims. A check based only on the permit-signing key is insufficient.
- **Impact:** Revocation policy may be unenforceable at the final side-effect boundary; a compromised attestation issuer may remain implicitly trusted.
- **Disposition:** Addressed as an explicit G3 contract prerequisite. G3 must add a versioned cryptographic binding from the permit or authenticated envelope to the attestation issuer/key and attestation digest/reference. G1 v0.1.0 is not changed. Until this exists and is verified, enforcement must fail closed and production enforcement is prohibited.
- **Verification required:** Negative tests for missing, mismatched, revoked, unknown, stale, and forged attestation issuer bindings.

### AG-G2-002 — Policy issuer and policy-version revocation was not required at permit consumption

- **Severity:** Medium
- **Affected documents:** G2 Security Architecture; Key Management; Threat Analysis; Control Traceability
- **Attack preconditions:** A permit is issued under a policy that is subsequently revoked, or whose issuer is compromised, before the permit is consumed.
- **Attack scenario:** The permit remains cryptographically valid and within its short TTL. Enforcement checks only permit signer and attestation issuer status, not current policy issuer or policy-version status.
- **Impact:** A permit authorized under a policy that is no longer trusted may still cause a side effect.
- **Disposition:** Remediated in G2 documents. Enforcement must check current policy issuer and policy version/digest status as well as permit signer and attestation issuer. G3 must define a trusted policy-status lookup/binding and tests. Unknown, stale, unavailable, or revoked status fails closed.
- **Verification required:** Revoke policy issuer or policy digest after permit issuance and before consumption; enforcement must reject.

### AG-G2-003 — Permit-consume atomicity was not explicit across independent enforcement replicas

- **Severity:** High
- **Affected documents:** ADR-0007; Security Architecture; Threat Analysis; Control Traceability
- **Attack preconditions:** Multiple enforcement replicas share a consume store whose consistency is eventual, replica-local, or otherwise not linearizable per permit.
- **Attack scenario:** Two replicas concurrently read an unconsumed permit before either replica's write becomes visible to the other; both accept the permit and execute side effects.
- **Impact:** Duplicate protected side effects despite a nominal single-use permit.
- **Disposition:** Remediated in ADR-0007. The consume operation must be durable, conditional, tenant-scoped, and linearizable across all enforcement replicas. Eventual consistency and replica-local caches are explicitly insufficient. A deployment ADR must select and test a store that meets this invariant.
- **Verification required:** Concurrent cross-replica test with fault injection and partition/retry scenarios; exactly one consume may succeed.

### AG-G2-004 — Permit consume key was not explicitly tenant-scoped

- **Severity:** Medium
- **Affected documents:** ADR-0007; Threat Analysis; Control Traceability
- **Attack preconditions:** Permit IDs are not guaranteed globally unique and the consume store keys records by permit ID alone.
- **Attack scenario:** Two tenants produce the same permit ID. A consume in one tenant can collide with or block the other tenant's consume state.
- **Impact:** Cross-tenant denial of service or incorrect replay state; potential isolation failure if downstream lookups are also improperly scoped.
- **Disposition:** Remediated in ADR-0007. Use authenticated `tenant_id + permit_id` as the consume identity, or prove and enforce a globally unique issuer namespace. Never derive the tenant namespace from an untrusted action payload.
- **Verification required:** Same permit ID in two tenants must not collide or alter the other tenant's consume state.

### AG-G2-005 — Revocation freshness and distribution are not yet operationally specified

- **Severity:** Medium
- **Affected documents:** Key Management; Security Architecture
- **Attack preconditions:** Signing or enforcement depends on a revocation source whose maximum staleness, distribution, cache behavior, or partition handling is undefined.
- **Attack scenario:** A node accepts an old status response or silently extends a cache TTL during a control-plane outage.
- **Impact:** A revoked key or issuer remains trusted beyond the intended revocation window.
- **Disposition:** Explicitly deferred to G3. G2 now states that stale, missing, unknown, unavailable, or partitioned status fails closed and that offline operation cannot extend freshness. G3 must define maximum freshness windows, status authenticity, distribution, cache semantics, and partition behavior.
- **Verification required:** Boundary tests at, below, and above the freshness limit; partition and rollback tests.

## 3. Additional design checks

- **Approval separation:** G1 requires fresh policy evaluation after approval; approval alone never issues a permit.
- **Policy combining:** deny-overrides and REQUIRE_APPROVAL precedence remain unchanged.
- **Canonicalization:** RFC 8785 plus restricted numeric representation remains the G1 contract; cross-language vectors and parser fuzzing remain required proof artifacts.
- **Evidence:** durable append before permit issuance and explicit limitations of hash chains are preserved.
- **Secrets:** AgentGuard must not accept wallet private keys, seed phrases, or transaction-signing keys.
- **External execution:** at-most-once permit acceptance is not represented as exactly-once external execution.
- **LLM authority:** LLM and agent output remain advisory/untrusted, never authoritative.

## 4. Review limitations

This review did not:
- inspect or test a production runtime implementation;
- execute penetration tests or fuzzers;
- validate a concrete Ed25519 library or HSM/KMS integration;
- verify a deployed revocation distribution system;
- test database linearizability or cross-region failure behavior;
- inspect chain-specific adapters or external execution systems;
- certify compliance or production readiness.

CI passing confirms the configured repository checks, not the security properties above.

## 5. Merge recommendation

**Recommendation: CONDITIONAL PASS for merging PR #5 as a documentation-only G2 architecture baseline**, after confirming the recorded changes are present on the final PR head and CI is green.

Conditions:
1. The G3 prerequisites in AG-G2-001, AG-G2-002, and AG-G2-005 remain explicit and are not represented as implemented.
2. ADR-0007's tenant-scoped, linearizable consume invariant is normative for future implementations.
3. No production signing, enforcement deployment, wallet-key custody, or transaction broadcasting is authorized by this review.
4. The PR description and release notes state that this is a design baseline, not a security certification or third-party audit.

A separate external security review remains recommended before production deployment or any claim of independently audited security.
