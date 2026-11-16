# Context Trust and Freshness Model

**Status:** Approved — product owner accepted 2026-11-16  
**Version:** 0.1.0

## 1. Purpose

Policy decisions often depend on data outside AgentGuard: balances, contract state, sanctions lists, spending limits, account ownership, simulation results, or operational status. The authorization engine must not treat caller-supplied values as trusted merely because they are well-formed.

## 2. Context value envelope

Every context value used by a policy includes:
- `field_id`: stable namespaced field identifier.
- `value`: value matching the registered field type.
- `source_id`: configured source identity.
- `observed_at`: observation timestamp.
- `valid_until`: optional explicit deadline.
- `attestation_ref`: optional signed provenance or source response reference.
- `schema_version`: field contract version.

The source registry defines allowed types, trust level, maximum age, attestation requirements, and whether a field may influence authorization.

## 3. Trust classes

- **T0 — Untrusted:** agent or caller claims; never sufficient for an authorization-critical field.
- **T1 — Authenticated source:** authenticated transport and source identity, but no cryptographic attestation of the underlying fact.
- **T2 — Attested source:** response or value is cryptographically signed by a configured trusted source, with replay and freshness checks.
- **T3 — Locally authoritative:** value is produced by a trusted local control plane or verified state source under an explicit trust configuration.

A policy declares the minimum trust class required for each authorization-critical field. Trust class is configuration, not a numeric score that can be averaged.

## 4. Freshness rules

- The runtime supplies one trusted evaluation timestamp to the evaluator.
- The evaluator does not read the system clock or call external sources.
- Each field must meet its registered maximum age and explicit validity deadline.
- Future-dated observations beyond configured clock skew are rejected.
- Missing source identity, invalid attestation, expired value, or insufficient trust class fails closed.
- Before permit enforcement, the adapter revalidates any execution preconditions whose freshness window or external state can change.

## 5. Provenance and source registry

Source registration is an administrative trust operation. AgentGuard does not automatically trust a source because it is named in a request. Source keys and trust roots are provisioned out-of-band and have explicit rotation and revocation procedures.

## 6. Limitations

A cryptographically authenticated source can still provide false data. Freshness does not prove truth. A compromised source, host, clock, or trust-root configuration remains a residual risk. Integrators must document which sources are authoritative for each field.
