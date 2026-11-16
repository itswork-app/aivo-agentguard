# Product Charter

**Status:** Superseded — historical G0 bootstrap charter; normative product requirements are maintained in PRD-001 v0.1.0.
**Product:** AIVO AgentGuard

## Mission

Provide an open, deterministic authorization layer that lets autonomous agents request permission for consequential actions while keeping policy authority outside the agent and outside probabilistic model output.

## Initial market hypothesis

Web3 infrastructure and application teams operating autonomous agents are the first discovery segment. The product is intended to be chain-agnostic and globally usable; Web3 is the initial integration wedge, not a permanent architectural limitation.

## Core contract

The authorization boundary returns one of:

- `ALLOW`: the action is authorized under the evaluated policy and context.
- `DENY`: the action is not authorized.
- `REQUIRE_APPROVAL`: a separate approval workflow is required; this result is not permission to execute.

After approval, the system must re-evaluate policy against current context before execution. Approval cannot override a subsequent denial or expired/stale context.

## Product principles

- Deterministic and explainable policy evaluation.
- Fail-closed enforcement.
- Separation of policy decision, approval, execution, and evidence.
- Credential isolation: AgentGuard does not custody signing secrets.
- Append-only, integrity-verifiable audit evidence.
- Chain-agnostic core; protocol-specific adapters at the edge.
- LLMs may propose or summarize, but cannot make authoritative authorization decisions.

## Phase-1 scope

Research, product specification, threat modeling, API and data contracts, test harnesses, and a minimal Rust core. Initial adapters and SDKs are subsequent gated work.

## Explicit non-goals for the research phase

- Production deployment or operational security guarantees.
- Live signing, broadcasting, or execution of crypto transactions.
- Custody, storage, or recovery of private keys or seed phrases.
- Token issuance, token sale, fundraising through a token, or proprietary chain.
- Allocation or use of trading/investment capital.
- Autonomous policy changes by an LLM.

## Success criteria for research

A reviewer can understand the threat model, reproduce policy decisions from versioned inputs, verify evidence linkage, and run adversarial tests without connecting a wallet or executing a live transaction.

## Open questions

- Which Web3 agent frameworks and execution surfaces should be first-class adapters?
- What is the minimal approval identity and quorum model?
- Which evidence integrity format best supports offline verification?
