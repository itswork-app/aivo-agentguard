# Revocation Status Protocol

**Status:** Proposed — G3 review required  
**Version:** 0.1.0

## 1. Purpose and scope

Define authenticated, rollback-resistant, bounded-freshness status data used by permit signers and enforcement boundaries. Status covers:
- policy issuer signing keys;
- policy identities, versions, and digests;
- authorization-attestation issuer keys and issuer identities;
- signing-challenge keys (permit-signing purpose; covered by the inner/outer permit signer status entries);
- G1 inner permit signing keys;
- PermitEnvelopeV2 outer signing keys;
- evidence-service signing keys where evidence receipts are relied upon.

A status response is not trusted merely because it arrives over authenticated transport. It must be signed by a configured revocation authority.

## 2. Status model

Key status values:
- `ACTIVE`: may sign and verify within declared validity.
- `RETIRED`: MUST NOT sign new artifacts; existing artifacts may be accepted only if issued before retirement, unexpired, and not otherwise revoked.
- `REVOKED`: reject new and existing artifacts.
- `COMPROMISED`: reject new and existing artifacts immediately.
- `UNKNOWN`: reject.

Policy status values:
- `ACTIVE`: policy version/digest is currently trusted.
- `SUSPENDED`: reject new permits and enforcement.
- `REVOKED`: reject new permits and enforcement.
- `UNKNOWN`: reject.

Status is scoped to the exact subject type and immutable subject identifier. Revoking a policy digest does not implicitly revoke every version of a policy unless an explicit policy-level entry says so.

## 3. Signed snapshot format

A snapshot contains:
- `schema_version` (literal 1)
- `registry_id`
- `registry_epoch`
- `sequence` (strictly increasing within registry epoch)
- `issued_at`
- `this_update`
- `next_update`
- `entries` (sorted by subject type and identifier; duplicates rejected)
- `signing_key_id`
- `signature`

Each entry contains `subject_type`, `subject_id`, `status`, `effective_at`, and optional `reason_code`. For a current snapshot, `effective_at` MUST be no later than `this_update`; scheduled future status transitions are not supported in v1. Raw secrets or personal details MUST NOT appear in status entries.

The snapshot signature is Ed25519 over canonical snapshot fields excluding signature, prefixed with `AIVO-AGENTGUARD-REVOCATION-SNAPSHOT-V1\\0`. Revocation authority keys are provisioned out-of-band and MUST be separate from all keys whose status they publish.

## 4. Freshness and rollback rules

G3 default maximum snapshot age is **30 seconds**. Maximum allowed `next_update - this_update` is **60 seconds**. A deployment may configure stricter limits but MUST NOT relax these defaults for a G3 enforcement profile.

Consumers MUST verify:
- snapshot signature and pinned registry identity;
- `issued_at <= this_update <= next_update`;
- `issued_at <= now + 5 seconds`;
- `this_update <= now + 5 seconds`;
- `now <= next_update`;
- `now - this_update <= 30 seconds` (exactly 30 seconds is accepted; any greater age is rejected);
- `next_update - this_update <= 60 seconds`;
- sequence is not lower than the highest previously accepted sequence for the registry epoch;
- registry epoch is trusted and cannot be reset by an untrusted response;
- all required subjects have explicit entries or are explicitly covered by a signed registry policy that defines default status. Missing status is UNKNOWN and fails closed.

A consumer MUST persist the highest accepted sequence and epoch in rollback-resistant storage. If that state is lost, rolled back, or cannot be verified, the consumer MUST stop enforcement until re-bootstrap from an out-of-band trusted checkpoint. Clock uncertainty beyond the configured 5-second skew fails closed.

## 5. Required lookup set

At permit signing and again immediately before permit consumption, the consumer MUST resolve status for:
1. inner G1 permit signing key;
2. outer PermitEnvelopeV2 signing key;
3. authorization-attestation issuer identity and signing key;
4. policy issuer identity and signing key;
5. exact policy ID/version/digest;
6. evidence receipt signing key, if the receipt is part of the attestation validation chain.

The attestation issuer itself must also check the policy issuer/key and policy digest before issuing an attestation.

A status cache is acceptable only while the signed snapshot remains within all freshness bounds. Cache TTL MUST NOT extend `next_update` or the 30-second maximum age. Network failure, partition, unknown subject, malformed response, stale snapshot, signature error, or rollback MUST reject. There is no offline grace period.

## 6. Status transition semantics

- `ACTIVE -> RETIRED`: stop issuing new artifacts immediately; existing artifacts may remain valid only to their own expiry and only while current status is fresh.
- `ACTIVE|RETIRED -> REVOKED|COMPROMISED`: reject immediately, regardless of artifact expiry.
- `SUSPENDED -> ACTIVE`: requires a new signed status snapshot with higher sequence and explicit authority.
- A status cannot be downgraded or removed by omission. Removal requires a new registry epoch established through an out-of-band recovery procedure and audited administrative event.

## 7. Operational controls and residual risks

The revocation authority signing key is itself a trust root and MUST NOT be considered revocable solely by a snapshot signed by that same key. Bootstrap and emergency replacement require an out-of-band root procedure, a separately controlled recovery key or threshold authority, and an audited registry-epoch transition. The recovery trust anchor must be provisioned independently by each enforcement deployment.

Revocation authority key compromise can undermine status distribution. Use isolated keys, dual-control administrative workflows, immutable audit events, and documented emergency rotation. A stale or unavailable control plane reduces availability by design. This protocol does not promise uninterrupted offline execution.
