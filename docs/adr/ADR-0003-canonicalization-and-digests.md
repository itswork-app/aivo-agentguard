# ADR-0003: Canonicalization and Action Digests

- **Status:** Proposed
- **Date:** 2026-11-16
- **Decision owners:** Project maintainer

## Context

Policy, request, action, permit, and evidence integrity require stable digests across implementations. Ordinary JSON serialization can differ by key order, number representation, or escaping.

## Proposed decision

Use RFC 8785 JSON Canonicalization Scheme for canonical JSON structures, with stricter AgentGuard numeric rules:
- Floating-point values are prohibited in security-relevant policy and action fields.
- Integers must be within the interoperable safe integer range; larger values are decimal strings with explicit semantic type and scale.
- Monetary values are integer minor units with explicit currency and scale, or canonical decimal strings with explicit scale.
- Strings are validated as Unicode and are not locale-folded during authorization.
- Unknown fields are rejected in security-critical schema versions unless explicitly declared as extension data.

Compute SHA-256 over domain-separated canonical bytes for request, action, policy, permit, and evidence digests. Each digest type uses a distinct fixed domain separator.

## Consequences

- Cross-language adapters can reproduce digests from the same validated structure.
- SDKs must share published test vectors.
- Canonicalization rules become part of the compatibility contract.
- Digest equality proves byte-equivalent canonical content, not truth or authenticity of the content.
