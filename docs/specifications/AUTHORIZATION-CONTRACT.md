# Authorization Contract — Bootstrap Record

**Status:** Superseded by G1 specification set  
**Superseded by:** `AUTHORIZATION-LIFECYCLE.md`, `POLICY-SCHEMA.md`, `DOMAIN-MODEL.md`, and `API-CONTRACT-V1.md`

This document records the initial G0 authorization principles. It is retained for project history and must not be treated as the complete or current normative contract.

The enduring invariants are:
- The authorization boundary exposes `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`.
- `REQUIRE_APPROVAL` is not permission to execute.
- Approval must be authenticated and bound to the exact request and action.
- Policy must be re-evaluated against current trusted context after approval.
- Only a fresh `ALLOW` may produce a permit.
- Missing, malformed, stale, unknown, or unverifiable inputs fail closed.
- Evidence is append-only; corrections use linked events.

The G1 documents define the proposed request envelope, policy schema, combining algorithm, canonicalization, permit lifecycle, evidence format, and API contract. They remain Proposed until explicit product-owner approval.
