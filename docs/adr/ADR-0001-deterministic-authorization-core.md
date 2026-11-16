# ADR-0001: Deterministic Authorization Core

- **Status:** Proposed
- **Date:** 2026-11-16
- **Decision owners:** Project maintainer

## Context

Autonomous agents can request consequential actions, while LLM outputs and agent intent are probabilistic and potentially adversarial. Authorization must therefore be independent of model-generated recommendations and reproducible from explicit inputs.

## Proposed decision

Implement the authoritative authorization core in Rust with deterministic evaluation over versioned policy and typed action/context inputs. The authorization boundary exposes exactly three outcomes: `ALLOW`, `DENY`, and `REQUIRE_APPROVAL`.

`REQUIRE_APPROVAL` does not authorize execution. After an approval event, the system must re-evaluate policy against current context; only a fresh `ALLOW` may proceed.

## Consequences

- Policy evaluation can be unit-tested and replayed from captured inputs.
- LLMs remain advisory and outside the authority path.
- Approval, execution, and evidence are separate lifecycle events.
- Adapters must bind the authorization result to the exact action being executed.
- The design prioritizes safety over availability when trusted inputs are missing.

## Alternatives considered

- Letting an LLM directly decide whether an action is safe: rejected because it is non-deterministic and cannot be the authority boundary.
- Embedding authorization separately in every adapter: rejected because it fragments policy semantics and auditability.
- Allowing approval to directly authorize execution: rejected because context and policy may change between request and execution.

## Open items

Define policy language, input canonicalization, decision explanation schema, approval identity, replay protection, and TOCTOU mitigation in follow-on specifications.
