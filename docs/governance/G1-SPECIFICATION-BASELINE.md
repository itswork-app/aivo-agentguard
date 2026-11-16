# G1 Specification Baseline

**Status:** Proposed — product-owner approval required  
**Baseline:** 0.1.0  
**Date:** 2026-11-16

## Purpose

G1 turns the G0 product and architecture direction into a coherent, testable contract set. This baseline is proposed for approval; it is not frozen until the product owner explicitly accepts it and the PR is merged.

## Normative decisions proposed

1. Rust is the authoritative deterministic policy core.
2. Authorization decisions are exactly ALLOW, DENY, and REQUIRE_APPROVAL.
3. Default deny; deny-overrides combining; approval-required is more restrictive than allow.
4. Policy is immutable, versioned, declarative data; no embedded scripts or LLM authority.
5. Requests and actions are canonicalized; digests use SHA-256 with type-specific domain separation.
6. Context is provenance-bearing and freshness-checked; untrusted caller claims cannot satisfy trusted policy inputs.
7. Approval is a separate authenticated event and always followed by fresh policy evaluation.
8. Only a fresh ALLOW issues a signed, short-lived permit bound to exact action and identity claims.
9. Permit acceptance is single-use at the enforcement boundary; failure to atomically consume fails closed.
10. Evidence is append-only, hash-linked, privacy-minimized, and durably persisted before an ALLOW permit is returned.
11. Core contracts are chain-agnostic; Web3-specific semantics belong in adapters.
12. No key custody, live signing, live transaction broadcasting, deployment, or capital allocation in the research phase.

## Specification set

- PRD-001: product requirements.
- DOMAIN-MODEL: identity and domain entities.
- POLICY-SCHEMA: policy bundle and combining algorithm.
- AUTHORIZATION-LIFECYCLE: approval, permit, and enforcement lifecycle.
- CONTEXT-TRUST-MODEL: context provenance and freshness.
- EVIDENCE-FORMAT: event envelope and integrity.
- API-CONTRACT-V1: transport-neutral API surface.
- SECURITY-REQUIREMENTS: security invariants.
- ADR-0002 through ADR-0005: policy combining, canonicalization, evidence, and approval/permit decisions.
- ACCEPTANCE-TEST-PLAN and REQUIREMENTS-TRACEABILITY: verification plan.

## Freeze criteria

G1 may be marked Approved only when:
- all documents agree on terminology, status, and decision semantics;
- every MUST requirement maps to an acceptance test;
- all unresolved security-critical questions are either decided or explicitly deferred with a safe default;
- the product owner accepts the scope and normative decisions;
- the approved baseline version and commit are recorded.

## Deferred to later gates

- Concrete Rust public type signatures and serialization implementation.
- Exact signed identity assertion format and identity-provider integrations.
- Key custody/rotation implementation for policy issuer and permit signer (keys remain outside the core).
- Durable store implementation and database selection.
- HTTP, gRPC, MCP, TypeScript, and Python wire/SDK bindings.
- Chain-specific adapters and transaction semantics.
- External signed checkpoint distribution and independent security review.

These deferrals do not weaken the normative fail-closed requirements.
