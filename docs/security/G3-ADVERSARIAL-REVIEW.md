# G3 Adversarial Specification Review

**Review type:** AI-assisted adversarial design review  
**Review date:** 2026-11-16  
**Reviewed scope:** G3 Authorization Attestation, PermitEnvelopeV2, Revocation Status Protocol, ADR-0008/0009, acceptance tests, and traceability  
**Status:** Conditional pass for specification baseline freeze; implementation and production gates remain  
**Limitations:** This is a second-pass review in the same project workflow, not a third-party audit, cryptographic implementation audit, penetration test, or certification.

## 1. Executive assessment

G3 addresses the principal G2 gaps: independent decision verification, explicit permit-to-attestation binding, and current revocation status at enforcement. The review identified several protocol-level ambiguity/replay risks. They were corrected in the current branch before this report was added.

The documents are still proposals. Passing repository CI validates the existing Rust workspace checks; it does not execute the G3 protocol or prove its security properties.

## 2. Findings and dispositions

### G3-REV-001 — Same-sequence snapshot equivocation

- **Severity:** High
- **Attack preconditions:** A consumer accepts a revocation snapshot sequence equal to its stored high-water mark without checking that the snapshot bytes/digest are identical.
- **Attack scenario:** A validly signed but different snapshot reuses the current sequence and removes or changes a revocation entry. A consumer that only rejects lower sequences may accept the altered state as an equal-sequence update.
- **Impact:** Revocation rollback or equivocation despite nominal sequence checking.
- **Disposition:** Addressed. Consumers persist registry epoch, sequence, canonical snapshot digest, and this_update. New snapshots require strictly increasing sequence. Equal-sequence replay is idempotent only if the canonical digest is identical; same-sequence/different-digest and this_update rollback are rejected.
- **Verification:** Same-sequence same-digest replay accepted idempotently; same-sequence different digest rejected; older sequence and timestamp rollback rejected.

### G3-ATT-002 — Challenge digest was not independently reconstructable at enforcement

- **Severity:** High
- **Attack preconditions:** Attestation contains a challenge digest, but the enforcement boundary does not receive the signed challenge token itself.
- **Attack scenario:** Enforcement cannot verify the challenge signer, request binding, nonce, or challenge timestamp; it must trust the permit signer or attestation issuer's statement about the challenge.
- **Impact:** Challenge-to-request binding and timestamp ordering cannot be independently checked at the final boundary.
- **Disposition:** Addressed. PermitEnvelopeV2 carries the complete signed SigningChallengeV1 token. Enforcement verifies its signature, signer purpose, request binding, digest, expiry, and exact match to the attestation.
- **Verification:** Mutated token, mismatched digest, wrong signer key, expired token, and cross-request replay are rejected.

### G3-PER-003 — Inner G1 permit signing key status was not explicit

- **Severity:** Medium
- **Attack preconditions:** Inner G1 permit signature and outer envelope signature use distinct key IDs, but only the outer key's revocation state is checked.
- **Attack scenario:** The inner permit signer is revoked while the outer envelope signer remains active; enforcement validates only the outer key and accepts the nested permit.
- **Impact:** Revoked inner signing authority remains effective.
- **Disposition:** Addressed. Inner G1 and outer envelope signing keys are both independently verified and included in the required revocation lookup set. They may be the same or distinct keys of the same permit-signing purpose.
- **Verification:** Revocation of either key independently rejects enforcement.

### G3-REV-004 — Incomplete snapshot coverage and default-status ambiguity

- **Severity:** Medium
- **Attack preconditions:** Consumer cannot distinguish an intentionally omitted subject from a missing status record, or wildcard/default entries can mask omissions.
- **Attack scenario:** A revoked issuer is omitted from a snapshot while a broad default rule returns ACTIVE.
- **Impact:** Missing revocation information may be interpreted as trusted.
- **Disposition:** Addressed. V1 requires an explicit exact-match entry for every required subject; wildcard, prefix, and implicit default entries are prohibited. Missing subject is UNKNOWN and fails closed.
- **Verification:** Missing exact entry and wildcard/default status forms are rejected.

### G3-REV-005 — Revocation authority recovery trust root

- **Severity:** Medium
- **Attack preconditions:** The revocation authority signing key is compromised and the system relies on that same key to publish its own revocation.
- **Attack scenario:** A compromised authority signs a snapshot that continues to mark itself and compromised issuers as ACTIVE.
- **Impact:** Revocation channel cannot recover from compromise using its own authority.
- **Disposition:** Addressed as an explicit out-of-band recovery requirement. A separately controlled recovery key or threshold authority and audited registry-epoch transition are required. Concrete deployment and operational implementation remain a release blocker.
- **Verification:** Recovery drill must replace the registry epoch using the separately provisioned recovery trust anchor.

### G3-CRYPTO-006 — Domain-separator escaping ambiguity

- **Severity:** Medium
- **Attack preconditions:** Documentation or implementations interpret a domain separator as two literal backslashes followed by zero rather than one NUL byte.
- **Attack scenario:** Independent implementations produce different signature preimages despite believing they implement the same protocol.
- **Impact:** Interoperability failure or signature-verification differential.
- **Disposition:** Addressed. G3 domain-separator notation is normalized to the single backslash-zero escape convention used by the frozen G1 canonicalization ADR. Golden vectors remain mandatory before implementation.
- **Verification:** Golden byte-level vectors must assert the exact UTF-8 prefix including one trailing NUL byte.

## 3. Product Owner decisions and implementation gates

The Product Owner approved all five G3 recommendations on 2026-11-17. The approved choices are recorded in `governance/G3-OPEN-DECISIONS.md` and incorporated into the G3 v0.1.0 baseline. No product-level decision remains open in that register.

The following remain implementation and release gates, not unresolved specification choices:
- Implement and test isolated verifier deployment and evaluator artifact allowlisting.
- Implement revocation signer isolation, offline recovery, and enterprise threshold-authorization capability.
- Verify signed provenance against the owner-approved artifact manifest.
- Implement durable evidence receipts, read-back verification, and documented replication/backup/restore semantics.
- Integrate trusted UTC time, monotonic elapsed-time measurement, and rollback-resistant high-water-mark storage.
- Produce byte-exact golden vectors, including NUL-terminated domain-separator prefixes.

No implementation gate permits weakening fail-closed behavior.

## 4. Review limitations

This review did not:
- execute a protocol implementation or production signer;
- validate a concrete Ed25519 library, KMS/HSM, or key custody design;
- perform network penetration testing or cryptographic implementation review;
- prove database linearizability or rollback-resistant storage;
- validate an actual trusted time source;
- test a chain-specific adapter or external transaction side effect.

## 5. Recommendation

**CONDITIONAL PASS for G3 specification baseline freeze.** The identified specification findings are addressed, and Product Owner approval of all five design decisions is recorded. This review does not validate an implementation. G3 may proceed to implementation planning and review, but production enforcement remains prohibited until implementation-level tests/golden vectors, operational controls, and the required external independent security review are complete.

This review is AI-assisted and must not be represented as an external independent audit or certification.
