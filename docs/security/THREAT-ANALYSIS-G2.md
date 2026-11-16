# G2 Threat Analysis

**Status:** Proposed — adversarial security review findings addressed; G3 proof obligations remain  
**Version:** 0.1.0

## 1. Method

This analysis uses assets, trust boundaries, attacker capabilities, attack paths, mitigations, and residual risk. It is a design-stage assessment, not a completed penetration test or formal certification.

## 2. Threat register

| ID | Threat / attack path | Impact | Primary controls | Residual risk |
|---|---|---|---|---|
| T-001 | Compromised agent changes action after authorization | Unauthorized side effect | Canonical action digest; exact permit binding; enforcement re-hash | Compromised adapter can bypass checks |
| T-002 | Prompt injection persuades LLM to claim authorization | Unauthorized action | LLM has no authority; independent deterministic evaluation | Integrator may bypass AgentGuard |
| T-003 | Broad or malicious policy allows dangerous action | Policy abuse | Signed immutable bundles; deny-overrides; policy review; test vectors | Authorized policy issuer can still make unsafe policy |
| T-004 | Policy rollback, issuer compromise, or policy revocation after permit issuance | Unauthorized action under a policy that is no longer trusted | Monotonic version and digest; current policy issuer and policy-status checks at signing and enforcement; fail closed on stale status | Exposure remains bounded by permit TTL only when revocation status is unavailable but still incorrectly treated as fresh; this is prohibited |
| T-005 | Approval replay or substitution | Unauthorized action | Bind approval to tenant, request, action, policy, profile, approver, expiry | Identity provider compromise |
| T-006 | Approval quorum manipulated by duplicate identities | Unauthorized action | Distinct principal enforcement; trusted role assertions | Weak identity proofing |
| T-007 | Context spoofing or stale data | Unsafe authorization | Source registry, provenance, trust class, freshness | Trusted source may be dishonest or compromised |
| T-008 | Permit replay | Duplicate side effect | Tenant-scoped permit identity; durable, linearizable atomic consume before side effect | Consume-store or adapter implementation defect |
| T-009 | Permit signer key compromise | Forged permits | Isolated signer, purpose separation, revocation, short expiry | Compromise before detection |
| T-010 | Policy issuer key compromise | Malicious policy publication | Key isolation, revocation, approval workflow, audit | Existing trust-root compromise |
| T-011 | Tenant ID confusion / IDOR | Cross-tenant access | Authenticated tenant context; tenant-scoped queries, consume keys, and evidence | Implementation mistakes |
| T-012 | Evidence deletion or stream rewrite | Loss of auditability | Append-only interface, hash chain, external signed checkpoints | No checkpoint means full truncation may be undetected |
| T-013 | Evidence store unavailable | Authorization outage | Fail closed before permit issuance | Availability loss |
| T-014 | TOCTOU between permit check and external action | Wrong state executed | Short TTL, action binding, adapter preconditions, external idempotency | External systems may lack atomic preconditions |
| T-015 | Dependency or build supply-chain compromise | Core compromise | Lockfile, pinned actions, dependency review, reproducible builds, provenance | Upstream compromise |
| T-016 | Malicious privileged operator | Policy/key/evidence tampering | Least privilege, dual control, independent checkpoints | Root-level control can defeat local controls |
| T-017 | Clock rollback or skew | Expiry/freshness bypass | Trusted time source, monotonic checks, bounded skew, fail closed | Host/time infrastructure compromise |
| T-018 | Parser/canonicalization differential | Digest mismatch or bypass | Single canonical spec, strict schemas, cross-language vectors, fuzzing | Uncovered implementation divergence |
| T-019 | Denial of service on authorization path | Legitimate actions blocked | Rate limits, bounded work, backpressure | Fail-closed design reduces availability |
| T-020 | Sensitive action/context data leaked via evidence | Privacy breach | Digest-first storage, allowlists, redaction, retention controls | Metadata can still be identifying |
| T-021 | Authorization-attestation issuer compromised or forged | Forged ALLOW attestation leads to permit issuance | Separate issuer trust boundary; signature and exact-claim verification; issuer identity/reference bound into permit or authenticated envelope; issuer revocation at signing and enforcement | Compromised issuer before revocation propagates |
| T-022 | Revocation state stale or unavailable at signing/enforcement | Compromised key, issuer, or policy remains trusted | Bounded revocation freshness; fail closed on stale, missing, unknown, or partitioned status; no offline freshness extension | Availability loss during control-plane outage |
| T-023 | Permit IDs collide across tenants or consume records are not tenant-scoped | Cross-tenant permit denial of service or incorrect replay state | Composite tenant/permit key or globally unique issuer-scoped ID; authenticated tenant binding | Incorrect storage-key construction |
| T-024 | Consume store provides only eventual or replica-local consistency | Same permit accepted concurrently by different enforcement replicas | Durable linearizable conditional consume across all enforcement replicas; fail closed when unavailable | Storage implementation or topology violates stated consistency |

## 3. Highest-risk controls requiring proof

1. Action canonicalization must be identical between authorization and enforcement.
2. Permit consumption must be durable, tenant-scoped, and linearizable across all enforcement replicas before side effects.
3. Identity and tenant context must be cryptographically or otherwise strongly authenticated.
4. Approval quorum must use distinct, eligible identities and immutable profile versions.
5. Policy, attestation, and permit-key revocation must be checked with bounded freshness at signing and enforcement.
6. Evidence append must be durable before permit issuance.
7. The permit signer must verify a cryptographically authenticated, exact-action-bound authorization attestation; a compromised runtime must not turn an arbitrary `ALLOW` field into a signed permit.
8. The permit or authenticated envelope must expose a verifiable attestation issuer binding so enforcement can check issuer revocation.
9. Adapter bypass and TOCTOU behavior must be assessed per integration.

## 4. Abuse cases

- Agent submits benign action, then substitutes a destination or amount at execution.
- Agent asks an LLM to produce fabricated approval evidence.
- Attacker replays an approval from a prior request after policy changes.
- Policy publisher signs an overly broad ALLOW rule.
- A policy issuer or policy version is revoked after permit issuance but before enforcement.
- Context source returns a stale balance or manipulated contract state.
- Attacker races two consumers against the same permit on different replicas.
- Two tenants receive the same permit ID and a non-tenant-scoped consume key causes cross-tenant collision.
- Operator deletes the evidence stream before checkpoint export.
- Attacker exploits differing JSON number parsing across Rust and TypeScript SDKs.

## 5. G2 validation plan

- Build abuse-case fixtures for every threat register entry.
- Verify each MUST security requirement maps to at least one adversarial test.
- Conduct canonicalization differential tests across Rust and a reference implementation.
- Model the atomic consume protocol under concurrent requests, cross-tenant collisions, and crash recovery.
- Review key rotation, policy revocation, attestation revocation, and compromised-key procedures.
- Conduct adversarial threat-model review before closing G2.

## 6. Residual-risk statement

AIVO AgentGuard cannot guarantee safety when a deployment bypasses its enforcement adapter, trusts a compromised identity or context provider, runs on a compromised host, or executes against an external system with non-atomic semantics. These limitations must be disclosed to integrators.
