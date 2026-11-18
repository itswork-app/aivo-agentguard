# Evidence Event and Integrity Format

**Status:** Approved — product owner accepted 2026-11-16  
**Version:** 0.1.0

## 1. Goals and limits

Evidence provides a tamper-evident, append-only history of AgentGuard lifecycle events. It supports reconstruction and integrity verification. A valid hash chain does not prove that external inputs were truthful, that an event was never omitted before ingestion, or that an external action actually occurred.

## 2. Event envelope

Each event contains:
- `schema_version`
- `event_id`
- `tenant_id`
- `stream_id`
- `sequence` (strictly increasing within a stream)
- `occurred_at` (UTC timestamp supplied by trusted runtime)
- `event_type`
- `request_id`
- `actor_ref` (typed identity reference)
- `request_digest` (when applicable)
- `action_digest` (when applicable)
- `policy_digest` (when applicable)
- `context_digest` (optional; included when the authorization context is part of the recorded decision)
- `decision` and stable reason codes (when applicable)
- `previous_event_hash`
- `event_hash`

## 3. Hash construction

The canonical event payload excludes `event_hash` and transport/storage metadata. The optional `context_digest` field is omitted from canonical payloads when absent, preserving existing v1 event hashes. The first event in a stream uses a fixed all-zero previous hash. Each subsequent event includes the prior event hash. Compute:

`event_hash = SHA-256(domain_separator || canonical_event_payload)`

The domain separator is the fixed UTF-8 string `AIVO-AGENTGUARD-EVENT-V1\0`. Canonical serialization follows RFC 8785 JSON Canonicalization Scheme, with the numeric restrictions in the canonicalization ADR. Hash values are lowercase hexadecimal strings.

## 4. Append-only behavior

The storage interface exposes append and read/verify operations only. It must not expose update or delete operations for committed events. Corrections are represented by a new event referencing the event being corrected. Per-stream sequence allocation and append must be atomic.

Before returning an ALLOW permit, the decision evidence event must be durably appended. If evidence cannot be durably written, no permit is issued.

## 5. Privacy and minimization

- Never store private keys, seed phrases, access tokens, passwords, or signing secrets.
- Do not persist raw action payloads by default; persist digests and explicitly allowlisted metadata.
- Redact or omit personal and commercially sensitive context unless required for a documented audit purpose.
- Hashes of low-entropy personal data can be reversible by guessing; hashing alone is not anonymization.
- Retention and deletion requirements must be defined by the deploying organization and applicable law. Append-only integrity must not be used to justify retaining unnecessary personal data.

## 6. Independent verification and checkpoints

An offline verifier checks schema, sequence continuity, previous-hash links, event hashes, and optional signed checkpoints. To make history truncation or full-stream rewrite detectable by an independent party, deployments should export signed checkpoints to a separately controlled system. Checkpoint signing and external anchoring are deferred to a dedicated ADR.

## 7. Event types

Initial event vocabulary:
- `REQUEST_RECEIVED`
- `DECISION_RECORDED`
- `APPROVAL_REQUESTED`
- `APPROVAL_RECORDED`
- `APPROVAL_REJECTED`
- `POLICY_REEVALUATED`
- `PERMIT_ISSUED`
- `PERMIT_CONSUMED`
- `ENFORCEMENT_REJECTED`
- `EXECUTION_OBSERVED`
- `EXECUTION_FAILED`
- `EXECUTION_UNKNOWN`
- `EVIDENCE_CORRECTION`

Events are facts, not mutable status rows.
