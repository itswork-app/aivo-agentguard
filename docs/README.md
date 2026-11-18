# Documentation Index

## Product and architecture
- `product/PRODUCT-CHARTER.md`: superseded G0 bootstrap charter; normative product requirements are in PRD-001.
- `product/PRD-001-AUTHORIZATION-PLATFORM.md`: product requirements and release gates.
- `architecture/ARCHITECTURE-OVERVIEW.md`: conceptual component boundaries, trust boundaries, and failure behavior.

## Security and governance
- `security/THREAT-MODEL.md`: assets, threats, mitigations, and residual risks.
- `security/SECURITY-REQUIREMENTS.md`: approved G1 security invariants.
- `security/SECURITY-ARCHITECTURE-G2.md`: proposed security domains, trust boundaries, data flows, and failure behavior.
- `security/KEY-MANAGEMENT-AND-CRYPTO-BOUNDARIES.md`: signer separation, key lifecycle, and revocation requirements.
- `security/THREAT-ANALYSIS-G2.md`: G2 threat register, abuse cases, and validation plan.
- `security/G2-CONTROL-TRACEABILITY.md`: threat-to-control mapping and required proof artifacts.
- `security/G2-ADVERSARIAL-REVIEW.md`: findings, dispositions, limitations, and conditional merge recommendation from the G2 adversarial review.
- `security/G3-AUTHORIZATION-ATTESTATION.md`: independent deterministic verification and signed authorization-attestation protocol.
- `security/REVOCATION-STATUS-PROTOCOL.md`: signed, monotonic, bounded-freshness revocation snapshots.
- `security/G3-ADVERSARIAL-REVIEW.md`: AI-assisted specification review, findings, remediations, and limitations.
- `governance/PROJECT-GOVERNANCE.md`: maintainer authority, decision-making, and change controls.
- `governance/LICENSE-DECISION.md`: approved Apache License 2.0 decision.
- `governance/G1-SPECIFICATION-BASELINE.md`: G1 specification set and freeze criteria.
- `governance/G3-SPECIFICATION-BASELINE.md`: approved and frozen G3 authorization-proof and permit-binding baseline.
- `governance/G3-OPEN-DECISIONS.md`: approved G3 Product Owner decisions for evaluator isolation, revocation, provenance, evidence, and trusted time.

## Specifications
- `specifications/DOMAIN-MODEL.md`: identity, request, policy, approval, permit, and evidence entities.
- `specifications/POLICY-SCHEMA.md`: declarative policy and deterministic combining semantics.
- `specifications/AUTHORIZATION-CONTRACT.md`: initial authorization boundary contract.
- `specifications/AUTHORIZATION-LIFECYCLE.md`: approval, re-evaluation, permit, and enforcement lifecycle.
- `specifications/CONTEXT-TRUST-MODEL.md`: context provenance and freshness requirements.
- `specifications/EVIDENCE-FORMAT.md`: append-only evidence and hash-chain envelope.
- `specifications/API-CONTRACT-V1.md`: transport-neutral Rust API contract.
- `specifications/PERMIT-ENVELOPE-V2.md`: versioned outer envelope binding the frozen G1 permit to G3 attestation and policy provenance.

## Decisions, tests, and traceability
- `adr/ADR-0001-deterministic-authorization-core.md`: deterministic authorization core.
- `adr/ADR-0002-policy-combining.md`: deny-overrides combining algorithm.
- `adr/ADR-0003-canonicalization-and-digests.md`: canonicalization and digest rules.
- `adr/ADR-0004-evidence-integrity.md`: append-only evidence integrity.
- `adr/ADR-0005-approval-and-permit.md`: approval and short-lived permit separation.
- `adr/ADR-0006-signer-isolation.md`: separation of signing authority from policy evaluation.
- `adr/ADR-0007-permit-consumption.md`: tenant-scoped, linearizable single-use permit consumption.
- `adr/ADR-0008-authorization-attestation.md`: independent authorization-attestation issuer.
- `adr/ADR-0009-permit-envelope-and-revocation.md`: v2 permit envelope and signed revocation snapshots.
- `adr/ADR-0010-authorization-proof-replay-and-revocation-checkpoint.md`: proposed one-time challenge/attestation consumption and atomic revocation-checkpoint binding.
- `testing/G3-ACCEPTANCE-TEST-PLAN.md`: negative, replay, revocation, and enforcement test requirements.
- `testing/G3-TRACEABILITY.md`: G3 requirements mapped to acceptance tests.
- `testing/ACCEPTANCE-TEST-PLAN.md`: offline contract and adversarial test matrix.
- `traceability/REQUIREMENTS-TRACEABILITY.md`: requirements mapped to specifications and tests.

## Document status rules

- **Draft:** under development; not normative.
- **Proposed:** awaiting explicit maintainer approval.
- **Approved:** normative within its stated scope; changes require a documented decision.
- **Superseded:** retained for history and replaced by a newer approved document.

A document's status must be explicit in its header. Code must not silently override an approved specification.
