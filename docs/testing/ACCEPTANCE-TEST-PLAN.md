# Acceptance Test Plan — G1 Contract

**Status:** Proposed — G1 product-owner review required

## 1. Test principles

All G1 contract tests must run offline. No real wallet, private key, funded account, live RPC, or transaction broadcast is permitted. Test fixtures use synthetic identities, policies, actions, context, and signing keys.

## 2. Policy decision matrix

| Case | Expected |
|---|---|
| One matching ALLOW, all required context valid | ALLOW |
| No matching rule | DENY |
| Matching DENY only | DENY |
| Matching ALLOW and DENY | DENY |
| Matching ALLOW and REQUIRE_APPROVAL | REQUIRE_APPROVAL |
| Matching multiple REQUIRE_APPROVAL profiles | REQUIRE_APPROVAL; all profiles required |
| Unknown policy schema | DENY / typed validation error |
| Invalid policy signature | DENY / typed validation error |
| Missing required context | DENY |
| Stale or untrusted context | DENY |
| Incompatible condition types | DENY |
| Rule order shuffled | Identical decision and reason codes |

## 3. Approval tests

- Approval bound to another request or action is rejected.
- Approval bound to another tenant or policy digest is rejected.
- Expired approval is rejected.
- Duplicate approval from one principal does not satisfy quorum twice.
- Quorum incomplete does not issue a permit.
- Quorum complete triggers fresh policy evaluation.
- Fresh DENY after approval remains DENY.
- Fresh REQUIRE_APPROVAL remains approval-required.
- Only fresh ALLOW can issue a permit.

## 4. Permit and enforcement tests

- Valid permit for exact action can be consumed once.
- Reuse of consumed permit is rejected.
- Expired permit is rejected.
- Wrong tenant, principal, agent, request, policy, or action digest is rejected.
- Altered permit signature is rejected.
- Unknown key ID or algorithm is rejected.
- Consume-store unavailable fails closed.
- Action substitution between authorization and execution is rejected.
- Execution outcome UNKNOWN is recorded if the adapter cannot determine external result.

## 5. Evidence tests

- First event uses the specified genesis previous hash.
- Sequence increments atomically.
- Event hash reproduces from canonical bytes.
- Tampered event payload is detected.
- Reordered or missing event is detected within the available stream.
- Correction event preserves prior event and references it.
- Evidence persistence failure prevents ALLOW permit issuance.
- Verifier reports integrity separately from completeness and external truth.

## 6. Property and fuzz tests

- Policy rule ordering does not change output.
- Adding a matching DENY cannot produce a less restrictive outcome.
- Invalid or missing security inputs never produce ALLOW.
- Canonicalization is stable across key order and equivalent accepted representations.
- Fuzz parsers for policy, request, permit, and evidence inputs.
- Tenant identifiers never cross-contaminate policy or evidence lookup.

## 7. Traceability

See `docs/traceability/REQUIREMENTS-TRACEABILITY.md` for requirement-to-test mapping.
