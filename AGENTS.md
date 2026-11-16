# Repository Engineering Instructions

## Source of truth

Approved specifications and ADRs under `docs/` define intended behavior. If code and an approved specification conflict, stop and raise the discrepancy; do not silently redefine the contract in code.

## Non-negotiable invariants

1. The policy engine is deterministic for identical versioned inputs.
2. Decisions are exactly `ALLOW`, `DENY`, or `REQUIRE_APPROVAL` at the authorization boundary.
3. `REQUIRE_APPROVAL` is not permission to execute. After approval, re-evaluate the applicable policy against current context before execution.
4. Missing, malformed, stale, or unverifiable authorization inputs fail closed.
5. LLMs and probabilistic models are advisory only and cannot issue authoritative decisions.
6. Evidence is append-only; corrections are represented by new linked events, not destructive mutation.
7. The core must not hold, derive, or expose signing secrets.
8. No live transactions, deployment, or capital allocation during the research-only phase.

## Rust standards

- Keep unsafe Rust forbidden unless an ADR explicitly approves a narrowly scoped exception.
- Prefer small modules, explicit types, exhaustive enums, and typed errors.
- Do not use floating-point values for authoritative financial quantities.
- Pin and review dependencies before security-sensitive use.
- Add unit, integration, property, and fuzz tests as appropriate.

## Change workflow

- Read relevant specs and ADRs before editing.
- Update tests and docs with behavior changes.
- Record architectural changes in an ADR.
- Run formatting, Clippy, and workspace tests.
- Never claim a check passed unless it was actually executed in CI or a local environment.
