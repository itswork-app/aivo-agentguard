# ADR-0009: Versioned Permit Envelope and Revocation Snapshots

- **Status:** Proposed — G3 review required
- **Date:** 2026-11-16
- **Decision owners:** Project maintainer

## Context

Frozen G1 v1 permit claims do not identify the authorization-attestation issuer or provide a verifiable attestation reference. Enforcement also needs fresh policy, attestation, permit-key, and evidence-receipt status to reject compromised or revoked trust anchors.

## Decision

Introduce PermitEnvelopeV2 as an outer signed envelope around the exact frozen G1 v1 permit claims/signature, the G3 authorization attestation, and explicit policy/attestation provenance. The outer signature binds all components and their digests. G1 v0.1.0 is not modified.

A G3 enforcement profile requires PermitEnvelopeV2 and rejects standalone G1 v1 permits. No downgrade fallback is permitted.

Introduce signed revocation snapshots from a dedicated revocation authority whose keys are provisioned out-of-band and are separate from every key class whose status they publish. Snapshots are monotonic, rollback-resistant, and have a maximum age of 30 seconds and maximum validity interval of 60 seconds. Unknown, stale, unavailable, revoked, compromised, or rolled-back status fails closed. No offline grace period is allowed.

At enforcement, verify envelope, inner permit, attestation, exact claim bindings, policy provenance, revocation status, time, actual action, and authenticated identities before atomic tenant-scoped consumption. Only after successful consumption may a side effect begin.

## Consequences

- The G1 permit contract remains immutable and compatible for explicitly configured legacy profiles.
- G3 profiles require an explicit migration and reject v1-only permit downgrade.
- Revocation control-plane availability becomes a prerequisite for execution.
- Consumers need rollback-resistant storage for registry epoch and sequence high-water marks.
- A revocation authority compromise is a high-impact control-plane incident and requires out-of-band recovery.
- The final revocation check cannot make an external chain transaction atomic with revocation; adapters must minimize the check-to-side-effect interval and use external preconditions where supported.

## Alternatives rejected

- Add attestation fields directly to frozen G1 v1 permit claims: silently breaks the approved baseline.
- Trust an unversioned sidecar: ambiguous downgrade and substitution risks.
- Use unsigned or transport-only revocation responses: enables spoofing and rollback.
- Permit stale/offline revocation cache: silently extends trust after compromise.
