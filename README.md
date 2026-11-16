# AIVO AgentGuard

Deterministic authorization infrastructure for autonomous agents.

AIVO AgentGuard is an open-source, Web3-first research and engineering project focused on policy-based authorization of agent actions across execution environments.

> **Project status:** Research and specification phase. Not production-ready. Do not use to authorize real funds, sign transactions, or protect production systems.

## Project principles

- Deterministic authorization decisions: `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`.
- Policy evaluation is authoritative; language models may provide advisory signals only.
- Fail closed when policy, identity, context, or enforcement state is unavailable.
- Approval is not authorization: after approval, policy must be evaluated again before execution.
- Append-only, integrity-verifiable evidence for decisions and execution outcomes.
- Chain-agnostic core with Web3 adapters at the boundary.

## Scope

Initial focus: research, threat modeling, specifications, test design, and core development. No deployment, capital allocation, token issuance, or live crypto transactions are in scope for the initial phase.

## Documentation

See `docs/README.md` for the documentation index. Approved specifications and ADRs define intended behavior; documents marked Draft or Proposed are not frozen normative contracts.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE). Contributions are submitted under the same license terms. The license does not grant rights to project trademarks or names.
