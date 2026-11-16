# G3 Open Decisions — Maintainer Recommendations

**Status:** Proposed — Product Owner approval required  
**Version:** 0.1.0  
**Scope:** Decisions needed to freeze G3 v0.1.0; recommendations do not become normative until approved.

## G3-OD-001 — Independent evaluator strategy

**Recommendation**
- OSS profile: run the same pinned deterministic Rust evaluator in a separately deployed verifier process with distinct service identity, credentials, deployment permissions, and read-only access to validated inputs.
- The verifier independently validates inputs and recomputes the decision; it does not accept runtime output as authoritative.
- High-assurance profile: support a separately implemented evaluator or independently maintained reference implementation, with differential testing against the Rust core.

**Rationale**
This gives a practical initial OSS architecture without duplicating the entire policy engine immediately, while acknowledging common-mode implementation defects. Separate process/identity prevents runtime compromise from directly asserting ALLOW but does not prove evaluator correctness.

**Approval boundary**
The OSS default must not be described as diverse implementation or formal verification.

## G3-OD-002 — Revocation snapshot signing

**Recommendation**
- OSS profile: one online revocation snapshot signer in an isolated service, with a separately provisioned offline recovery root for signer replacement and registry-epoch transition.
- Enterprise/high-assurance profile: support threshold authorization for revocation updates and recovery operations.
- Revocation signer keys must not be reused for policy, attestation, permit, evidence, or context signing.

**Rationale**
A single signer minimizes deployment complexity for OSS while preserving an independent recovery path. Threshold authorization is a stronger enterprise control where multiple administrators are available.

**Approval boundary**
Single-signer OSS mode retains a concentrated control-plane risk and must be disclosed.

## G3-OD-003 — Evaluator artifact provenance

**Recommendation**
Use a signed in-toto/SLSA provenance statement for each approved evaluator artifact. The attestation issuer's allowlist record must bind:
- SHA-256 artifact digest;
- source repository and immutable commit;
- Cargo.lock digest;
- Rust toolchain version and target triple;
- builder identity and workflow identity;
- build invocation and provenance statement digest.

The verifier checks the artifact digest against an owner-approved release manifest. A version string alone is insufficient. No claim of a particular SLSA assurance level is made unless independently demonstrated.

## G3-OD-004 — Evidence receipt topology

**Recommendation**
- Evidence append service returns a signed Ed25519 receipt only after durable commit.
- Receipt key is a dedicated evidence-service key purpose and separate from all policy, attestation, permit, context, and revocation keys.
- Receipt binds tenant, stream, sequence, event hash, event type, request/action/policy/context digests, and durable commit reference.
- Attestation issuer verifies receipt signature and reads back the referenced event before issuing ALLOW attestation.
- Production deployment must define replication durability, backup, retention, and restore semantics; a database acknowledgement without the specified durability guarantee is insufficient.

## G3-OD-005 — Trusted time and rollback-resistant state

**Recommendation**
- Use trusted UTC wall time for signed timestamps and a monotonic clock for in-process elapsed-time measurement.
- Time synchronization should use authenticated Network Time Security (NTS) where supported, or an equivalently controlled trusted time source.
- Maximum clock skew remains 5 seconds; uncertainty or loss of trusted time fails closed.
- Persist revocation epoch, sequence, snapshot digest, and update timestamp in storage protected against ordinary process rollback. High-assurance deployments should anchor this high-water mark in a separate trusted control plane or hardware-backed monotonic facility.
- Monotonic time must not be serialized as a cross-host timestamp.

## Approval record

No decision above is approved by this document. The Product Owner must explicitly accept or amend each recommendation before G3 baseline freeze. Until then, G3 remains Draft and the stricter fail-closed behavior applies.
