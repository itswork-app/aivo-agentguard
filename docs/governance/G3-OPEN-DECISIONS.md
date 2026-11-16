# G3 Product Owner Decisions — Approved

**Status:** Approved — normative within G3 v0.1.0  
**Version:** 0.1.0  
**Approval:** Product Owner approval recorded 2026-11-17  
**Scope:** Decisions required to freeze G3 Authorization Proof and Permit Binding.

These decisions approve the defaults below. They do not authorize production deployment, live transaction execution, or claims of independent security certification.

## G3-OD-001 — Independent evaluator strategy

**Approved decision**
- OSS profile: run the same pinned deterministic Rust evaluator in a separately deployed verifier process with distinct service identity, credentials, deployment permissions, and read-only access to validated inputs.
- The verifier independently validates inputs and recomputes the decision; it does not accept runtime output as authoritative.
- High-assurance profile: support a separately implemented evaluator or independently maintained reference implementation, with differential testing against the Rust core.

**Rationale and limitation**
This is a practical OSS baseline while acknowledging common-mode implementation defects. Process and identity separation do not prove evaluator correctness. The OSS profile MUST NOT be described as diverse implementation or formal verification.

## G3-OD-002 — Revocation snapshot signing

**Approved decision**
- OSS profile: one online revocation snapshot signer in an isolated service, with a separately provisioned offline recovery root for signer replacement and registry-epoch transition.
- Enterprise/high-assurance profile: support threshold authorization for revocation updates and recovery operations.
- Revocation signer keys MUST NOT be reused for policy, attestation, permit, evidence, or context signing.

**Rationale and limitation**
Single-signer OSS mode retains concentrated control-plane risk; this risk MUST be disclosed. Recovery MUST use the separately provisioned trust anchor, not the compromised signer itself.

## G3-OD-003 — Evaluator artifact provenance

**Approved decision**
Use a signed in-toto/SLSA provenance statement for each approved evaluator artifact. The attestation issuer's allowlist record MUST bind:
- SHA-256 artifact digest;
- source repository and immutable commit;
- Cargo.lock digest;
- Rust toolchain version and target triple;
- builder identity and workflow identity;
- build invocation and provenance statement digest.

The verifier checks the artifact digest against an owner-approved release manifest. A version string alone is insufficient. No claim of a particular SLSA assurance level may be made unless independently demonstrated.

## G3-OD-004 — Evidence receipt topology

**Approved decision**
- Evidence append service returns a signed Ed25519 receipt only after durable commit.
- Receipt key is a dedicated evidence-service key purpose, separate from all policy, attestation, permit, context, and revocation keys.
- Receipt binds tenant, stream, sequence, event hash, event type, request/action/policy/context digests, and durable commit reference.
- Attestation issuer verifies receipt signature and reads back the referenced event before issuing ALLOW attestation.
- Production deployment MUST define replication durability, backup, retention, and restore semantics; a database acknowledgement without the specified durability guarantee is insufficient.

## G3-OD-005 — Trusted time and rollback-resistant state

**Approved decision**
- Use trusted UTC wall time for signed timestamps and a monotonic clock for in-process elapsed-time measurement.
- Time synchronization SHOULD use authenticated Network Time Security (NTS) where supported, or an equivalently controlled trusted time source.
- Maximum clock skew remains 5 seconds; uncertainty or loss of trusted time fails closed.
- Persist revocation epoch, sequence, snapshot digest, and update timestamp in storage protected against ordinary process rollback. High-assurance deployments SHOULD anchor this high-water mark in a separate trusted control plane or hardware-backed monotonic facility.
- Monotonic time MUST NOT be serialized as a cross-host timestamp.

## Approval record

The Product Owner approved all five maintainer recommendations on 2026-11-17. These decisions are normative for G3 v0.1.0. Implementation must satisfy the associated acceptance tests and traceability obligations. Operational recovery, trusted-time integration, artifact verification, and durable evidence semantics remain implementation/release gates; approval of this document does not claim those controls are already implemented.
