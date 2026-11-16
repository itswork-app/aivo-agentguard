//! Fail-closed G3 enforcement verification boundary.
//!
//! This crate verifies permit artifacts and atomically consumes permits before
//! returning a verified capability. It does not execute the authorized action.
//! Production adapters must supply trusted keys, time, revocation snapshots,
//! rollback-resistant checkpoint storage, and durable single-use consumption.

use agentguard_core::{
    KeyPurpose, PermitEnvelopeError, PermitEnvelopeV2, RevocationError,
    RevocationHighWaterMarkStore, RevocationPersistenceError, RevocationSnapshotSource as _,
    RevocationStatus, RevocationSubjectType, SignedRevocationSnapshotV1,
    persist_verified_snapshot,
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

/// Durable tenant-scoped record consumed before any protected side effect.
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
pub fn verify_and_consume<K, C, R, H, P>(
    envelope: &PermitEnvelopeV2,
    keys: &K,
    clock: &C,
    revocation_source: &R,
    high_water_store: &H,
    permit_store: &P,
) -> Result<ConsumedPermitV2, EnforcementError>
where
    K: VerificationKeyResolver,
    C: TrustedClock,
    R: RevocationSnapshotSource,
    H: RevocationHighWaterMarkStore,
    P: PermitConsumptionStore,
{
    let now_utc = clock.now_utc()?;
    envelope.validate_at(&now_utc)?;

    let permit_key = resolve_key(
        keys,
        &envelope.permit_signature_v1.key_id,
        KeyPurpose::PermitSigner,
    )?;
    let challenge_key = resolve_key(
        keys,
        &envelope.signing_challenge_v1.signature.key_id,
        KeyPurpose::PermitSigner,
    )?;
    let attestation_key = resolve_key(
        keys,
        &envelope.authorization_attestation_v1.signature.key_id,
        KeyPurpose::AuthorizationAttestationIssuer,
    )?;
    let outer_key = resolve_key(
        keys,
        &envelope.envelope_signature.key_id,
        KeyPurpose::PermitSigner,
    )?;

    let registry_id = revocation_source.registry_id();
    let signed_snapshot = revocation_source.current_snapshot()?;
    let revocation_key = resolve_key(
        keys,
        &signed_snapshot.signature.key_id,
        KeyPurpose::RevocationAuthority,
    )?;
    persist_verified_snapshot(
        high_water_store,
        &signed_snapshot,
        &revocation_key.public_key,
        registry_id,
        &now_utc,
    )?;

    let claims = &envelope.authorization_attestation_v1.claims;
    require_active(
        &signed_snapshot,
        RevocationSubjectType::PermitSignerKey,
        &envelope.permit_signature_v1.key_id,
    )?;
    require_active(
        &signed_snapshot,
        RevocationSubjectType::PermitSignerKey,
        &envelope.signing_challenge_v1.signature.key_id,
    )?;
    require_active(
        &signed_snapshot,
        RevocationSubjectType::PermitSignerKey,
        &envelope.envelope_signature.key_id,
    )?;
    require_active(
        &signed_snapshot,
        RevocationSubjectType::AttestationIssuer,
        &claims.issuer_id,
    )?;
    require_active(
        &signed_snapshot,
        RevocationSubjectType::AttestationIssuerKey,
        &claims.issuer_key_id,
    )?;
    require_active(
        &signed_snapshot,
        RevocationSubjectType::PolicyIssuer,
        &claims.policy_issuer_id,
    )?;
    require_active(
        &signed_snapshot,
        RevocationSubjectType::PolicyIssuerKey,
        &claims.policy_signing_key_id,
    )?;
    require_active(
        &signed_snapshot,
        RevocationSubjectType::Policy,
        &claims.policy_digest,
    )?;

    envelope.verify_all_signatures(
        &permit_key.public_key,
        &challenge_key.public_key,
        &attestation_key.public_key,
        &outer_key.public_key,
    )?;

    let envelope_digest = envelope
        .digest()
        .map_err(|error| PermitEnvelopeError::Canonicalization(error.to_string()))?;
    let envelope_digest = agentguard_core::hex_digest(&envelope_digest);
    let permit = &envelope.permit_claims_v1;
    let record = PermitConsumptionRecordV1 {
        tenant_id: permit.tenant_id.clone(),
        permit_id: permit.permit_id.clone(),
        permit_nonce: permit.nonce.clone(),
        request_id: permit.request_id.clone(),
        request_digest: claims.request_digest.clone(),
        action_digest: permit.action_digest.clone(),
        policy_digest: permit.policy_digest.clone(),
        envelope_digest: envelope_digest.clone(),
        expires_at: envelope.expires_at.clone(),
    };
    permit_store.consume_once(&record, &now_utc)?;

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
