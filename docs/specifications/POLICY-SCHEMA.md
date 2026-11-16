# Policy Schema and Evaluation Semantics

**Status:** Proposed — G1 product-owner review required  
**Version:** 0.1.0

## 1. Design constraints

Policy is declarative data, not executable code. Version 1 policies MUST NOT contain scripts, expressions that invoke functions, network references, dynamic imports, or LLM-generated runtime decisions. Evaluation must be deterministic and side-effect free.

A policy bundle is immutable once published. A change creates a new version and digest.

## 2. Policy bundle

A bundle contains:
- `schema_version`: exact schema identifier.
- `policy_id`: stable policy identifier.
- `version`: immutable semantic or monotonic version.
- `issuer_id`: trusted policy publisher.
- `created_at`: UTC timestamp.
- `rules`: ordered only for presentation; evaluation is set-based and does not depend on array order.
- `approval_profiles`: separately governed approval profiles.
- `signature`: detached signature metadata, not included in the policy content digest.

Unknown schema versions, duplicate rule IDs, invalid selectors, unsupported operators, or invalid signatures make a bundle invalid. An invalid bundle is not partially evaluated.

## 3. Rule shape

Each rule contains:
- `rule_id`: unique within the bundle.
- `effect`: `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`.
- `subjects`: optional selectors for principal and agent identity.
- `actions`: one or more exact action types. Wildcards and pattern matching are excluded from v1.
- `resources`: optional resource selectors.
- `conditions`: an AND-set of typed predicates.
- `approval_profile_id`: required only for `REQUIRE_APPROVAL`.

An omitted selector means unrestricted for that selector dimension, not unrestricted authorization. A rule still must match its action selector. A condition list with zero entries evaluates true.

## 4. Approval profile

An approval profile contains:
- `profile_id` and immutable `version`;
- `min_approvals` (positive integer);
- eligible principal IDs and/or trusted role identifiers;
- `max_approval_age_seconds`;
- separation-of-duties setting (whether requester and approver may be the same principal);
- whether agent owner/operator principals are excluded;
- profile issuer and integrity digest.

Each approval must come from a distinct eligible principal. Duplicate approval by one principal counts once. Missing, invalid, or ambiguous profile configuration fails closed. The identity/role assertion must come from a configured trusted identity boundary.

## 5. Version 1 condition operators

- Equality: `eq`, `neq`
- Set membership: `in`, `not_in`
- Presence: `exists`
- Ordered comparison for compatible typed values: `gt`, `gte`, `lt`, `lte`

No implicit type coercion is permitted. Comparing incompatible types makes the policy evaluation invalid and therefore fails closed. String comparison uses exact Unicode scalar sequence; locale-sensitive collation is prohibited. Numeric comparisons use bounded integers or canonical decimal values with explicit scale.

## 6. Deterministic combining algorithm

For a validated request and policy bundle:

1. Validate request schema, identity assertions, policy reference, action canonicalization, context provenance, and freshness.
2. Select all rules whose subject, action, resource, and conditions match.
3. If any matching rule has effect DENY, return DENY.
4. Otherwise, if any matching rule has effect REQUIRE_APPROVAL, return REQUIRE_APPROVAL and the distinct matching approval profile IDs.
5. Otherwise, if one or more matching rules have effect ALLOW, return ALLOW.
6. If no rule matches, return DENY with `NO_MATCHING_ALLOW_RULE`.
7. Any validation or evaluation error returns DENY with a stable failure reason; it must never be converted to ALLOW.

Rule array order, map insertion order, host locale, wall-clock access inside the evaluator, randomness, and LLM output must not affect the result.

If multiple distinct approval profiles match, all required profiles must be satisfied. A policy update that changes the policy digest invalidates approvals bound to the previous digest. A new approval cycle is required against the new policy.

## 7. Context freshness

A policy can require context fields with a maximum age. At evaluation, every required field must:
- exist;
- have a trusted source;
- have a valid observation timestamp;
- not be past its validity deadline;
- satisfy the configured maximum age and minimum trust class.

The evaluator receives a single explicit evaluation time from the trusted runtime. It does not read the system clock itself. Missing or stale context returns DENY.

## 8. Policy integrity

Policy bundles are identified by SHA-256 over canonical policy content. The proposed trust envelope uses Ed25519 signatures from configured policy-issuer keys. Trust roots and key rotation are managed outside the policy document and must be provisioned through a trusted administrative channel. Invalid or unknown signer keys fail closed.

## 9. Stable reason codes

Initial reason codes include:
- `ALLOW_RULE_MATCHED`
- `DENY_RULE_MATCHED`
- `APPROVAL_PROFILE_REQUIRED`
- `NO_MATCHING_ALLOW_RULE`
- `REQUEST_INVALID`
- `IDENTITY_UNVERIFIED`
- `POLICY_UNKNOWN`
- `POLICY_INVALID`
- `CONTEXT_MISSING`
- `CONTEXT_STALE`
- `CONTEXT_UNTRUSTED`
- `CONDITION_TYPE_MISMATCH`
- `SCHEMA_UNSUPPORTED`

Reason codes are machine-readable. Human-readable messages are explanatory only and are not inputs to authorization.
