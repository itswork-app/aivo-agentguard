# Requirements Traceability

**Status:** Approved — product owner accepted 2026-11-16

| Requirement | Specification | Acceptance coverage |
|---|---|---|
| FR-001 request envelope | DOMAIN-MODEL, API-CONTRACT-V1 | Request validation, schema rejection |
| FR-002 immutable policy | POLICY-SCHEMA | Policy signature and version tests |
| FR-003 three decisions | POLICY-SCHEMA | Decision matrix |
| FR-004 deny-overrides | ADR-0002, POLICY-SCHEMA | Conflict and shuffled-order tests |
| FR-005 exact action permit | AUTHORIZATION-LIFECYCLE, ADR-0003 | Action substitution and binding tests |
| FR-006 approval then re-evaluate | AUTHORIZATION-LIFECYCLE | Approval lifecycle tests |
| FR-007 replay rejection | AUTHORIZATION-LIFECYCLE | Single-use and replay tests |
| FR-008 append-only evidence | EVIDENCE-FORMAT, ADR-0004 | Chain integrity and correction tests |
| FR-009 stable reason codes | POLICY-SCHEMA, API-CONTRACT-V1 | Golden output vectors |
| FR-010 offline verification | EVIDENCE-FORMAT | Tamper and sequence tests |
| NFR-001 deterministic output | POLICY-SCHEMA, ADR-0002 | Property tests |
| NFR-002 fail closed | SECURITY-REQUIREMENTS | Negative and adversarial tests |
| NFR-003 exact binding | AUTHORIZATION-LIFECYCLE | Permit binding matrix |
| NFR-004 replay resistance | AUTHORIZATION-LIFECYCLE | Atomic consume tests |
| NFR-005 auditability | EVIDENCE-FORMAT | Evidence verifier tests |
| NFR-006 secret isolation | PRD-001, SECURITY-REQUIREMENTS | Static/API surface review |
| NFR-007 portability | API-CONTRACT-V1 | Offline core tests |
| NFR-008 schema versioning | API-CONTRACT-V1 | Unknown-version rejection |
| NFR-009 privacy | EVIDENCE-FORMAT | Redaction and forbidden-secret tests |
| NFR-010 offline testability | ACCEPTANCE-TEST-PLAN | CI fixture-only execution |

A requirement is not complete merely because it is documented. Implementation status is tracked separately in later phase plans.
