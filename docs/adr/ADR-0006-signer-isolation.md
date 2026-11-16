# ADR-0006: Isolate Signing Authority from the Policy Evaluator

- **Status:** Proposed — G2 security review required
- **Date:** 2026-11-16
- **Decision owners:** Project maintainer

## Context

The deterministic evaluator should be small, reproducible, and free of secret-bearing privileges. Combining evaluation and signing would expand the impact of parser, policy, or memory-safety defects.

## Proposed decision

The policy evaluator never holds private signing keys. Policy bundle signing, permit signing, and evidence checkpoint signing are separate key purposes and separate service boundaries. The permit signer accepts only a narrowly typed signing request after runtime validation and durable decision evidence. A runtime-supplied decision field alone is not sufficient: the signer must verify a cryptographically authenticated authorization attestation, exact claim binding, issuer trust status, and freshness before signing. The attestation issuer and protocol are G3 contract work; production signing is prohibited until that contract is specified and reviewed.

## Consequences

- A policy evaluation compromise alone does not expose permit signing keys.
- The signing service becomes a security-critical component and must validate the permit claim envelope independently.
- Key lifecycle and availability require separate operational design.
- No wallet transaction-signing key is accepted or stored by AgentGuard.

## Alternatives rejected

- Embed all private keys in the runtime process: excessive blast radius.
- Reuse one signing key for policies, permits, and evidence: weak purpose separation and incident isolation.
