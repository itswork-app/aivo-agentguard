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
- `governance/PROJECT-GOVERNANCE.md`: maintainer authority, decision-making, and change controls.
- `governance/LICENSE-DECISION.md`: approved Apache License 2.0 decision.
- `governance/G1-SPECIFICATION-BASELINE.md`: G1 specification set and freeze criteria.

## Specifications
- `specifications/DOMAIN-MODEL.md`: identity, request, policy, approval, permit, and evidence entities.
- `specifications/POLICY-SCHEMA.md`: declarative policy and deterministic combining semantics.
- `specifications/AUTHORIZATION-CONTRACT.md`: initial authorization boundary contract.
- `specifications/AUTHORIZATION-LIFECYCLE.md`: approval, re-evaluation, permit, and enforcement lifecycle.
- `specifications/CONTEXT-TRUST-MODEL.md`: context provenance and freshness requirements.
- `specifications/EVIDENCE-FORMAT.md`: append-only evidence and hash-chain envelope.
- `specifications/API-CONTRACT-V1.md`: transport-neutral Rust API contract.

## Decisions, tests, and traceability
- `adr/ADR-0001-deterministic-authorization-core.md`: deterministic authorization core.
- `adr/ADR-0002-policy-combining.md`: deny-overrides combining algorithm.
- `adr/ADR-0003-canonicalization-and-digests.md`: canonicalization and digest rules.
- `adr/ADR-0004-evidence-integrity.md`: append-only evidence integrity.
- `adr/ADR-0005-approval-and-permit.md`: approval and short-lived permit separation.
- `adr/ADR-0006-signer-isolation.md`: separation of signing authority from policy evaluation.
- `adr/ADR-0007-permit-consumption.md`: tenant-scoped, linearizable single-use permit consumption.
- `testing/ACCEPTANCE-TEST-PLAN.md`: offline contract and adversarial test matrix.
- `traceability/REQUIREMENTS-TRACEABILITY.md`: requirements mapped to specifications and tests.

## Document status rules

- **Draft:** under development; not normative.
- **Proposed:** awaiting explicit maintainer approval.
- **Approved:** normative within its stated scope; changes require a documented decision.
- **Superseded:** retained for history and replaced by a newer approved document.

A document's status must be explicit in its header. Code must not silently override an approved specification.
