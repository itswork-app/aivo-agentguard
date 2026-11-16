# ADR-0002: Deterministic Policy Combining

- **Status:** Accepted — product owner approved 2026-11-16
- **Date:** 2026-11-16
- **Decision owners:** Project maintainer

## Context

A request may match multiple policy rules. Rule ordering must not create hidden authorization behavior, and conflicting rules must resolve predictably.

## Proposed decision

Use a deterministic deny-overrides combiner:
1. Any matching DENY results in DENY.
2. Otherwise, any matching REQUIRE_APPROVAL results in REQUIRE_APPROVAL.
3. Otherwise, one or more matching ALLOW rules result in ALLOW.
4. No matching rule results in DENY.

All matching approval profiles must be satisfied. Invalid policy or condition evaluation fails closed. Rule list order has no semantic effect.

## Consequences

- Policy evaluation is independent of rule ordering.
- A restrictive rule cannot be bypassed by a later permissive rule.
- Policy authors must scope rules carefully; tests must cover conflicting matches.
- A policy with no matching allow is denied by default.

## Alternatives rejected

- First-match: sensitive to array order and easy to misconfigure.
- Allow-overrides: can let a broad allow defeat a restrictive deny.
- Last-match: sensitive to serialization and editing order.
