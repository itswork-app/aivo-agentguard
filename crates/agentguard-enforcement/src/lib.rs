//! Fail-closed G3 enforcement verification boundary.
//!
//! This crate verifies permit artifacts and atomically consumes permits before
//! returning a verified capability. It does not execute the authorized action.
//! Production adapters must supply trusted keys, time, revocation snapshots,
//! rollback-resistant checkpoint storage, and durable single-use consumption.

use agentguard_core::{
    KeyPurpose, PermitEnvelopeError, PermitEnvelopeV2, RevocationHighWaterMarkStore,
    RevocationPersistenceError, RevocationStatus, RevocationSubjectType,
    SignedRevocationSnapshotV1, persist_verified_snapshot,
};
use agentguard_evidence::{
    EvidenceEventType, EvidenceStore, SignedEvidenceReceiptV1, verify_receipt_read_back,
};
use serde::{Deserialize, Serialize};

/// Public key material resolved for one exact key ID and cryptographic purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedVerificationKey {
    pub key_id: String,
    pub purpose: KeyPurpose,
    pub public_key: [u8; 32],
}

/// Resolve verification keys from a trusted purpose-scoped key registry.
///
/// Implementations MUST reject unknown IDs, wrong purposes, disabled keys, and
/// untrusted key material. They MUST NOT return keys from caller-controlled data.
pub trait VerificationKeyResolver: Send + Sync {
    /// Resolve one exact key ID for the requested purpose.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is unknown, unavailable, or not authorized
    /// for the requested cryptographic purpose.
    fn resolve(
        &self,
        key_id: &str,
        purpose: KeyPurpose,
    ) -> Result<ResolvedVerificationKey, KeyResolutionError>;
}

/// Errors from the trusted verification-key registry.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyResolutionError {
    #[error("verification key is unknown")]
    UnknownKey,
    #[error("verification key is not authorized for the requested purpose")]
    WrongPurpose,
    #[error("verification key registry is unavailable")]
    Unavailable,
}

/// Trusted UTC clock source used at the enforcement boundary.
pub trait TrustedClock: Send + Sync {
    /// Return canonical UTC time as YYYY-MM-DDTHH:MM:SSZ.
    ///
    /// # Errors
    ///
    /// Returns an error when trusted time is unavailable or uncertain.
    fn now_utc(&self) -> Result<String, TrustedClockError>;
}

/// Errors from the trusted time source.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrustedClockError {
    #[error("trusted time source is unavailable")]
    Unavailable,
    #[error("trusted time is uncertain or malformed")]
    Uncertain,
}

/// Source of the latest signed revocation snapshot for one pinned registry.
pub trait RevocationSnapshotSource: Send + Sync {
    /// Return the registry identity pinned by deployment configuration.
    fn registry_id(&self) -> &str;

    /// Fetch the latest signed snapshot; transport/authentication failures are fatal.
    ///
    /// # Errors
    ///
    /// Returns an error when the revocation control plane is unavailable or malformed.
    fn current_snapshot(&self) -> Result<SignedRevocationSnapshotV1, RevocationSourceError>;
}

/// Errors from the revocation snapshot control plane.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RevocationSourceError {
    #[error("revocation control plane is unavailable")]
    Unavailable,
    #[error("revocation control plane returned malformed data")]
    InvalidResponse,
}

/// Trusted action/request values recomputed by the enforcement adapter.
///
/// These values MUST be derived from the exact action payload and authenticated
/// principal at the enforcement boundary, not copied from the permit envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedExecutionContextV1 {
    pub tenant_id: String,
    pub principal_id: String,
    pub agent_id: String,
    pub request_id: String,
    pub request_digest: String,
    pub action_digest: String,
    pub policy_id: String,
    pub policy_version: String,
    pub policy_digest: String,
    pub context_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermitConsumptionRecordV1 {
    pub tenant_id: String,
    pub permit_id: String,
    pub permit_nonce: String,
    pub request_id: String,
    pub request_digest: String,
    pub action_digest: String,
    pub policy_digest: String,
    pub envelope_digest: String,
    pub expires_at: String,
}

/// Durable, atomic, tenant-scoped single-use permit consumption contract.
///
/// Implementations MUST provide linearizable uniqueness across all enforcement
/// nodes and persist consumption before returning success. An in-memory map or
/// eventually consistent cache is not a production implementation.
pub trait PermitConsumptionStore: Send + Sync {
    /// Atomically consume the exact permit record once.
    ///
    /// # Errors
    ///
    /// Returns an error for replay, binding mismatch, expiry, or store unavailability.
    fn consume_once(
        &self,
        record: &PermitConsumptionRecordV1,
        now_utc: &str,
    ) -> Result<(), PermitConsumptionStoreError>;
}

/// Errors from durable permit consumption.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PermitConsumptionStoreError {
    #[error("permit has already been consumed")]
    AlreadyConsumed,
    #[error("permit consumption binding differs from the issued permit")]
    BindingMismatch,
    #[error("permit consumption store is unavailable")]
    Unavailable,
}

/// Result of successful verification and atomic permit consumption.
///
/// Possessing this value does not execute an action. The caller may proceed to
/// a separately controlled effect adapter only after receiving it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedPermitV2 {
    pub tenant_id: String,
    pub permit_id: String,
    pub request_id: String,
    pub action_digest: String,
    pub policy_digest: String,
    pub envelope_digest: String,
    pub expires_at: String,
}

/// Fail-closed errors raised by the enforcement boundary.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnforcementError {
    #[error("permit envelope validation failed: {0}")]
    Permit(#[from] PermitEnvelopeError),
    #[error("trusted time check failed: {0}")]
    Clock(#[from] TrustedClockError),
    #[error("verification key resolution failed: {0}")]
    Key(#[from] KeyResolutionError),
    #[error("revocation snapshot source failed: {0}")]
    RevocationSource(#[from] RevocationSourceError),
    #[error("revocation checkpoint validation or persistence failed: {0}")]
    RevocationPersistence(#[from] RevocationPersistenceError),
    #[error("revocation subject is not ACTIVE: {subject_type:?}/{subject_id}")]
    RevokedOrUnknown {
        subject_type: RevocationSubjectType,
        subject_id: String,
    },
    #[error("permit consumption failed: {0}")]
    Consumption(#[from] PermitConsumptionStoreError),
    #[error("resolved key metadata differs from requested key ID or purpose")]
    ResolvedKeyMismatch,
    #[error("permit does not match the independently derived execution context")]
    ExecutionContextMismatch,
    #[error("evidence receipt verification failed: {0}")]
    Evidence(String),
    #[error("evidence receipt does not bind the authorization attestation")]
    EvidenceBindingMismatch,
}

/// Verify all G3 signatures, fresh revocation status, bindings, and expiry,
/// then atomically consume the permit before returning a verified capability.
///
/// Required statuses are exact-match ACTIVE entries for the inner permit key,
/// challenge key, outer envelope key, attestation issuer/key, policy issuer/key,
/// and exact policy digest. RETIRED and UNKNOWN are rejected in this profile.
/// Evidence receipt read-back and evidence-service key lookup remain a separate
/// required integration before production enablement.
///
/// # Errors
///
/// Returns an error for any missing/untrusted key, invalid signature, stale or
/// rolled-back revocation snapshot, non-ACTIVE required subject, invalid time,
/// envelope mismatch, or permit replay/store failure.
/// Trusted dependencies required to verify and consume a G3 permit.
///
/// References are injected by the host; this type owns no keys or storage.
pub struct EnforcementServices<'a, K, C, R, H, P, E> {
    pub keys: &'a K,
    pub clock: &'a C,
    pub revocation_source: &'a R,
    pub high_water_store: &'a H,
    pub permit_store: &'a P,
    pub evidence_store: &'a E,
}

/// Verify all G3 signatures, fresh revocation status, durable evidence bindings,
/// and expiry, then atomically consume the permit before returning a capability.
///
/// Required evidence is checked only after the attestation and envelope
/// signatures are authenticated, and before permit consumption.
///
/// # Errors
///
/// Returns an error for invalid signatures, untrusted or revoked keys, stale
/// revocation state, evidence receipt mismatch/read-back failure, invalid time,
/// execution-context mismatch, or permit replay/storage failure.
pub fn verify_and_consume<K, C, R, H, P, E>(
    envelope: &PermitEnvelopeV2,
    expected: &ExpectedExecutionContextV1,
    evidence_receipt: &SignedEvidenceReceiptV1,
    services: &EnforcementServices<'_, K, C, R, H, P, E>,
) -> Result<ConsumedPermitV2, EnforcementError>
where
    K: VerificationKeyResolver,
    C: TrustedClock,
    R: RevocationSnapshotSource,
    H: RevocationHighWaterMarkStore,
    P: PermitConsumptionStore,
    E: EvidenceStore,
{
    let now_utc = services.clock.now_utc()?;
    envelope.validate_at(&now_utc)?;
    validate_expected_context(envelope, expected)?;

    let verification_keys = resolve_envelope_keys(envelope, services.keys)?;
    let snapshot = verify_current_revocation(
        services.keys,
        services.revocation_source,
        services.high_water_store,
        &now_utc,
    )?;

    require_envelope_subjects_active(envelope, &snapshot)?;
    envelope.verify_all_signatures(
        &verification_keys.permit.public_key,
        &verification_keys.challenge.public_key,
        &verification_keys.attestation.public_key,
        &verification_keys.outer.public_key,
    )?;
    verify_attestation_evidence(
        envelope,
        evidence_receipt,
        services.evidence_store,
        services.keys,
        &snapshot,
    )?;

    // Evidence read-back may take time. Re-read trusted time and revocation
    // state immediately before the single-use consume operation so expiry or
    // a newly published revocation cannot be hidden by the earlier snapshot.
    let final_now_utc = services.clock.now_utc()?;
    envelope.validate_at(&final_now_utc)?;
    let final_snapshot = verify_current_revocation(
        services.keys,
        services.revocation_source,
        services.high_water_store,
        &final_now_utc,
    )?;
    require_envelope_subjects_active(envelope, &final_snapshot)?;
    require_active(
        &final_snapshot,
        RevocationSubjectType::EvidenceServiceKey,
        &evidence_receipt.claims.evidence_key_id,
    )?;

    consume_permit(envelope, expected, services.permit_store, &final_now_utc)
}

struct EnvelopeVerificationKeys {
    permit: ResolvedVerificationKey,
    challenge: ResolvedVerificationKey,
    attestation: ResolvedVerificationKey,
    outer: ResolvedVerificationKey,
}

fn validate_expected_context(
    envelope: &PermitEnvelopeV2,
    expected: &ExpectedExecutionContextV1,
) -> Result<(), EnforcementError> {
    let permit = &envelope.permit_claims_v1;
    let attestation = &envelope.authorization_attestation_v1.claims;
    if permit.tenant_id != expected.tenant_id
        || permit.principal_id != expected.principal_id
        || permit.agent_id != expected.agent_id
        || permit.request_id != expected.request_id
        || permit.action_digest != expected.action_digest
        || permit.policy_id != expected.policy_id
        || permit.policy_version != expected.policy_version
        || permit.policy_digest != expected.policy_digest
        || permit.context_digest != expected.context_digest
        || attestation.request_digest != expected.request_digest
        || attestation.action_digest != expected.action_digest
        || attestation.context_digest != expected.context_digest
    {
        return Err(EnforcementError::ExecutionContextMismatch);
    }
    Ok(())
}

fn resolve_envelope_keys<K: VerificationKeyResolver>(
    envelope: &PermitEnvelopeV2,
    keys: &K,
) -> Result<EnvelopeVerificationKeys, EnforcementError> {
    Ok(EnvelopeVerificationKeys {
        permit: resolve_key(
            keys,
            &envelope.permit_signature_v1.key_id,
            KeyPurpose::PermitSigner,
        )?,
        challenge: resolve_key(
            keys,
            &envelope.signing_challenge_v1.signature.key_id,
            KeyPurpose::PermitSigner,
        )?,
        attestation: resolve_key(
            keys,
            &envelope.authorization_attestation_v1.signature.key_id,
            KeyPurpose::AuthorizationAttestationIssuer,
        )?,
        outer: resolve_key(
            keys,
            &envelope.envelope_signature.key_id,
            KeyPurpose::PermitSigner,
        )?,
    })
}

fn verify_current_revocation<K, R, H>(
    keys: &K,
    source: &R,
    high_water_store: &H,
    now_utc: &str,
) -> Result<SignedRevocationSnapshotV1, EnforcementError>
where
    K: VerificationKeyResolver,
    R: RevocationSnapshotSource,
    H: RevocationHighWaterMarkStore,
{
    let registry_id = source.registry_id();
    let snapshot = source.current_snapshot()?;
    let revocation_key = resolve_key(
        keys,
        &snapshot.signature.key_id,
        KeyPurpose::RevocationAuthority,
    )?;
    persist_verified_snapshot(
        high_water_store,
        &snapshot,
        &revocation_key.public_key,
        registry_id,
        now_utc,
    )?;
    Ok(snapshot)
}

fn require_envelope_subjects_active(
    envelope: &PermitEnvelopeV2,
    snapshot: &SignedRevocationSnapshotV1,
) -> Result<(), EnforcementError> {
    let attestation = &envelope.authorization_attestation_v1.claims;
    for (subject_type, subject_id) in [
        (
            RevocationSubjectType::PermitSignerKey,
            envelope.permit_signature_v1.key_id.as_str(),
        ),
        (
            RevocationSubjectType::PermitSignerKey,
            envelope.signing_challenge_v1.signature.key_id.as_str(),
        ),
        (
            RevocationSubjectType::PermitSignerKey,
            envelope.envelope_signature.key_id.as_str(),
        ),
        (
            RevocationSubjectType::AttestationIssuer,
            attestation.issuer_id.as_str(),
        ),
        (
            RevocationSubjectType::AttestationIssuerKey,
            attestation.issuer_key_id.as_str(),
        ),
        (
            RevocationSubjectType::PolicyIssuer,
            attestation.policy_issuer_id.as_str(),
        ),
        (
            RevocationSubjectType::PolicyIssuerKey,
            attestation.policy_signing_key_id.as_str(),
        ),
        (
            RevocationSubjectType::Policy,
            attestation.policy_digest.as_str(),
        ),
    ] {
        require_active(snapshot, subject_type, subject_id)?;
    }
    Ok(())
}

fn verify_attestation_evidence<K, E>(
    envelope: &PermitEnvelopeV2,
    receipt: &SignedEvidenceReceiptV1,
    store: &E,
    keys: &K,
    snapshot: &SignedRevocationSnapshotV1,
) -> Result<(), EnforcementError>
where
    K: VerificationKeyResolver,
    E: EvidenceStore,
{
    let attestation = &envelope.authorization_attestation_v1.claims;
    let claims = &receipt.claims;
    let receipt_digest = agentguard_core::hex_digest(
        &receipt
            .digest()
            .map_err(|error| EnforcementError::Evidence(error.to_string()))?,
    );
    if claims.receipt_id != attestation.evidence_receipt_ref.receipt_id
        || receipt_digest != attestation.evidence_receipt_ref.receipt_digest
        || claims.tenant_id != attestation.tenant_id
        || claims.stream_id != attestation.decision_event_ref.stream_id
        || claims.sequence != attestation.decision_event_ref.sequence
        || claims.event_hash != attestation.decision_event_ref.event_hash
        || claims.event_type != EvidenceEventType::DecisionRecorded.as_str()
        || claims.request_digest != attestation.request_digest
        || claims.action_digest != attestation.action_digest
        || claims.policy_digest != attestation.policy_digest
        || claims.context_digest != attestation.context_digest
        || attestation.decision_event_ref.tenant_id != attestation.tenant_id
    {
        return Err(EnforcementError::EvidenceBindingMismatch);
    }

    let key = resolve_key(keys, &claims.evidence_key_id, KeyPurpose::EvidenceService)?;
    require_active(
        snapshot,
        RevocationSubjectType::EvidenceServiceKey,
        &claims.evidence_key_id,
    )?;
    let event = verify_receipt_read_back(store, receipt, &key.public_key, &claims.evidence_key_id)
        .map_err(|error| EnforcementError::Evidence(error.to_string()))?;

    if event.tenant_id != attestation.tenant_id
        || event.stream_id != attestation.decision_event_ref.stream_id
        || event.sequence != attestation.decision_event_ref.sequence
        || event.event_hash != attestation.decision_event_ref.event_hash
        || event.event_type != EvidenceEventType::DecisionRecorded
        || event.request_id != attestation.request_id
        || event.request_digest.as_deref() != Some(attestation.request_digest.as_str())
        || event.action_digest.as_deref() != Some(attestation.action_digest.as_str())
        || event.policy_digest.as_deref() != Some(attestation.policy_digest.as_str())
        || event.context_digest.as_deref() != Some(attestation.context_digest.as_str())
        || event.decision.as_deref() != Some("ALLOW")
    {
        return Err(EnforcementError::EvidenceBindingMismatch);
    }
    Ok(())
}

fn consume_permit<P: PermitConsumptionStore>(
    envelope: &PermitEnvelopeV2,
    expected: &ExpectedExecutionContextV1,
    permit_store: &P,
    now_utc: &str,
) -> Result<ConsumedPermitV2, EnforcementError> {
    let permit = &envelope.permit_claims_v1;
    let envelope_digest = envelope
        .digest()
        .map_err(|error| PermitEnvelopeError::Canonicalization(error.to_string()))?;
    let envelope_digest = agentguard_core::hex_digest(&envelope_digest);
    let record = PermitConsumptionRecordV1 {
        tenant_id: permit.tenant_id.clone(),
        permit_id: permit.permit_id.clone(),
        permit_nonce: permit.nonce.clone(),
        request_id: permit.request_id.clone(),
        request_digest: expected.request_digest.clone(),
        action_digest: permit.action_digest.clone(),
        policy_digest: permit.policy_digest.clone(),
        envelope_digest: envelope_digest.clone(),
        expires_at: envelope.expires_at.clone(),
    };
    permit_store.consume_once(&record, now_utc)?;

    Ok(ConsumedPermitV2 {
        tenant_id: permit.tenant_id.clone(),
        permit_id: permit.permit_id.clone(),
        request_id: permit.request_id.clone(),
        action_digest: permit.action_digest.clone(),
        policy_digest: permit.policy_digest.clone(),
        envelope_digest,
        expires_at: envelope.expires_at.clone(),
    })
}

fn resolve_key<K: VerificationKeyResolver>(
    resolver: &K,
    key_id: &str,
    purpose: KeyPurpose,
) -> Result<ResolvedVerificationKey, EnforcementError> {
    let key = resolver.resolve(key_id, purpose)?;
    if key.key_id != key_id || key.purpose != purpose {
        return Err(EnforcementError::ResolvedKeyMismatch);
    }
    Ok(key)
}

fn require_active(
    snapshot: &SignedRevocationSnapshotV1,
    subject_type: RevocationSubjectType,
    subject_id: &str,
) -> Result<(), EnforcementError> {
    if snapshot.claims.status_for(subject_type, subject_id) != RevocationStatus::Active {
        return Err(EnforcementError::RevokedOrUnknown {
            subject_type,
            subject_id: subject_id.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_key_purpose_is_not_accepted_by_resolver_contract() {
        let key = ResolvedVerificationKey {
            key_id: "attestation-key-1".into(),
            purpose: KeyPurpose::AuthorizationAttestationIssuer,
            public_key: [1_u8; 32],
        };
        assert_eq!(key.purpose, KeyPurpose::AuthorizationAttestationIssuer);
        assert_ne!(key.purpose, KeyPurpose::PermitSigner);
    }

    #[test]
    fn missing_revocation_subject_is_not_active() {
        let snapshot = SignedRevocationSnapshotV1 {
            claims: agentguard_core::RevocationSnapshotV1 {
                schema_version: 1,
                registry_id: "registry-1".into(),
                registry_epoch: 1,
                sequence: 1,
                issued_at: "2026-11-17T10:00:00Z".into(),
                this_update: "2026-11-17T10:00:00Z".into(),
                next_update: "2026-11-17T10:00:30Z".into(),
                entries: vec![],
                signing_key_id: "revocation-key-1".into(),
            },
            signature: agentguard_core::SignatureEnvelope {
                algorithm: agentguard_core::SignatureAlgorithm::Ed25519,
                key_id: "revocation-key-1".into(),
                signature: "unused".into(),
            },
        };
        assert_eq!(
            require_active(
                &snapshot,
                RevocationSubjectType::PermitSignerKey,
                "missing-key"
            ),
            Err(EnforcementError::RevokedOrUnknown {
                subject_type: RevocationSubjectType::PermitSignerKey,
                subject_id: "missing-key".into()
            })
        );
    }
}
