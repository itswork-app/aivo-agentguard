# Project Governance

**Status:** Draft

## Maintainer authority

The repository owner currently acts as project maintainer and is responsible for scope, releases, security response, and final merge decisions. Additional maintainers must be explicitly appointed and documented.

## Decision process

- Small, reversible changes may be proposed through issues and pull requests.
- Architectural, security, API, licensing, and scope changes require a written rationale and an ADR or governance decision.
- Security-sensitive changes require tests and explicit review before merge.
- Draft specifications do not become normative until a maintainer records approval and status.

## Change control

- Use focused branches and pull requests.
- Require CI to pass before merge once branch protection is configured.
- Do not merge unresolved critical security findings.
- Preserve decision history; supersede documents rather than silently rewriting material decisions.

## Releases

No stable release or compatibility promise exists yet. Versioning and release signing policy will be defined before the first public release.

## Funding and commercial model

The project is open-source-first. Grants, sponsorship, and future commercial support are hypotheses to evaluate separately. No token issuance or token-based fundraising is planned.

## Governance maturity

This is a bootstrap policy, not a legal entity governance instrument. It will be revisited before accepting external maintainers or making production security claims.
