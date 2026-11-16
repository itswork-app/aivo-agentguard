//! Signed revocation snapshot validation and rollback progression checks.
//!
//! Persistence is intentionally abstract: callers must implement the high-water
//! mark store with durable, rollback-resistant, atomic compare-and-set semantics.

use serde::{Deserialize, Serialize};

use crate::{
    CanonicalizationError, CryptoError, SignatureEnvelope, canonical_json, domain_digest,
    hex_digest, verify_ed25519,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevocationStatus {
    Active,
    Suspended,
    Retired,
    Revoked,
    Compromised,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationSubjectType {
    PolicyIssuer,
    PolicyIssuerKey,
    Policy,
    AttestationIssuer,
    AttestationIssuerKey,
    PermitSignerKey,
    EvidenceServiceKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEntryV1 {
    pub subject_type: RevocationSubjectType,
    pub subject_id: String,
    pub status: RevocationStatus,
    pub effective_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationSnapshotV1 {
    pub schema_version: u8,
    pub registry_id: String,
    pub registry_epoch: u64,
    pub sequence: u64,
    pub issued_at: String,
    pub this_update: String,
    pub next_update: String,
    pub entries: Vec<RevocationEntryV1>,
    pub signing_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRevocationSnapshotV1 {
    pub claims: RevocationSnapshotV1,
    pub signature: SignatureEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationHighWaterMark {
    pub registry_id: String,
    pub registry_epoch: u64,
    pub sequence: u64,
    pub snapshot_digest: String,
    pub this_update: String,
}

/// Errors from the durable rollback-resistant high-water-mark store contract.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RevocationStoreError {
    #[error("revocation state store is unavailable")]
    Unavailable,
    #[error("revocation state store contains corrupt or unverifiable state")]
    CorruptState,
    #[error("revocation state changed concurrently; retry from a fresh read")]
    CompareAndSetConflict,
    #[error("revocation checkpoint is already initialized")]
    AlreadyInitialized,
}

/// Persistence contract for revocation monotonic state.
///
/// Implementations MUST provide durable, rollback-resistant storage. The
/// compare-and-set operation MUST be linearizable across all enforcement nodes.
/// A plain in-memory map or eventually consistent cache does not satisfy this
/// contract and MUST NOT be used as the production implementation.
pub trait RevocationHighWaterMarkStore: Send + Sync {
    /// Load the current trusted checkpoint for one pinned registry.
    ///
    /// # Errors
    ///
    /// Returns an error when the store is unavailable or persisted state is corrupt.
    fn load(
        &self,
        registry_id: &str,
    ) -> Result<Option<RevocationHighWaterMark>, RevocationStoreError>;

    /// Initialize an empty registry checkpoint from an out-of-band trusted source.
    ///
    /// This operation MUST be restricted to the separately authorized recovery
    /// or bootstrap control plane, not ordinary network snapshot ingestion.
    ///
    /// # Errors
    ///
    /// Returns an error when the store is unavailable, corrupt, or already initialized.
    fn initialize_from_trusted_checkpoint(
        &self,
        checkpoint: &RevocationHighWaterMark,
    ) -> Result<(), RevocationStoreError>;

    /// Atomically replace the expected checkpoint with the next checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the store is unavailable, corrupt, or the expected
    /// checkpoint no longer matches the current state.
    fn compare_and_set(
        &self,
        expected: &RevocationHighWaterMark,
        next: &RevocationHighWaterMark,
    ) -> Result<(), RevocationStoreError>;
}

/// Errors while verifying and persisting a new revocation snapshot.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RevocationPersistenceError {
    #[error("revocation state has no trusted bootstrap checkpoint")]
    Uninitialized,
    #[error("revocation validation failed: {0}")]
    Validation(#[from] RevocationError),
    #[error("revocation state persistence failed: {0}")]
    Store(#[from] RevocationStoreError),
}

/// Verify a signed snapshot and atomically advance the trusted high-water mark.
///
/// Returns false for an exact idempotent replay and true when the checkpoint
/// was advanced. It never initializes missing state from an ordinary network snapshot.
///
/// # Errors
///
/// Returns an error for invalid signatures, stale snapshots, registry mismatch,
/// missing trusted bootstrap state, rollback/equivocation, or storage failures.
pub fn persist_verified_snapshot<S: RevocationHighWaterMarkStore>(
    store: &S,
    snapshot: &SignedRevocationSnapshotV1,
    public_key: &[u8; 32],
    expected_registry_id: &str,
    now_utc: &str,
) -> Result<bool, RevocationPersistenceError> {
    let candidate = snapshot.verified_high_water_mark(public_key, expected_registry_id, now_utc)?;
    let previous = store
        .load(expected_registry_id)?
        .ok_or(RevocationPersistenceError::Uninitialized)?;
    let should_advance = validate_progression(Some(&previous), &candidate)?;
    if !should_advance {
        return Ok(false);
    }
    store.compare_and_set(&previous, &candidate)?;
    Ok(true)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RevocationError {
    #[error("invalid revocation snapshot schema or field")]
    InvalidShape,
    #[error("revocation snapshot entries are not strictly sorted or contain duplicates")]
    EntriesNotCanonical,
    #[error("revocation snapshot contains an invalid or wildcard subject")]
    InvalidSubject,
    #[error("revocation snapshot is stale, not yet valid, or outside clock skew")]
    StaleOrFuture,
    #[error("revocation snapshot signature key ID mismatch")]
    KeyIdMismatch,
    #[error("revocation snapshot registry does not match the pinned registry")]
    RegistryMismatch,
    #[error("revocation snapshot signature verification failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("revocation snapshot canonicalization failed: {0}")]
    Canonicalization(String),
    #[error("registry epoch changed without trusted out-of-band re-bootstrap")]
    EpochTransition,
    #[error("revocation snapshot sequence rollback")]
    SequenceRollback,
    #[error("same sequence has a different snapshot digest")]
    SequenceEquivocation,
    #[error("snapshot update timestamp rolled back")]
    UpdateRollback,
}

impl RevocationSnapshotV1 {
    /// Return only an exact subject match. Missing subjects are UNKNOWN and fail closed.
    #[must_use]
    pub fn status_for(
        &self,
        subject_type: RevocationSubjectType,
        subject_id: &str,
    ) -> RevocationStatus {
        self.entries
            .iter()
            .find(|entry| entry.subject_type == subject_type && entry.subject_id == subject_id)
            .map_or(RevocationStatus::Unknown, |entry| entry.status)
    }

    /// Validate schema, canonical ordering, and bounded freshness against trusted UTC time.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed snapshots, invalid subjects, unsorted entries,
    /// stale/future timestamps, or timestamps outside the allowed skew.
    pub fn validate_at(&self, now_utc: &str) -> Result<(), RevocationError> {
        if self.schema_version != 1
            || self.registry_id.is_empty()
            || self.registry_id.trim() != self.registry_id
            || self.registry_epoch == 0
            || self.sequence == 0
            || self.signing_key_id.is_empty()
            || self.signing_key_id.trim() != self.signing_key_id
            || self.entries.is_empty()
        {
            return Err(RevocationError::InvalidShape);
        }
        let issued = parse_timestamp(&self.issued_at)?;
        let updated = parse_timestamp(&self.this_update)?;
        let next = parse_timestamp(&self.next_update)?;
        let now = parse_timestamp(now_utc)?;
        if issued > updated
            || updated > next
            || issued > now + 5
            || updated > now + 5
            || now > next
            || now - updated > 30
            || next - updated > 60
        {
            return Err(RevocationError::StaleOrFuture);
        }

        let mut previous: Option<(&str, &str)> = None;
        for entry in &self.entries {
            if entry.subject_id.is_empty()
                || entry.subject_id.trim() != entry.subject_id
                || entry.subject_id.contains('*')
                || entry.subject_id.contains('?')
            {
                return Err(RevocationError::InvalidSubject);
            }
            let effective = parse_timestamp(&entry.effective_at)?;
            if effective > updated {
                return Err(RevocationError::InvalidShape);
            }
            if let Some(prior) = previous {
                let current = (
                    subject_type_key(entry.subject_type),
                    entry.subject_id.as_str(),
                );
                if current <= prior {
                    return Err(RevocationError::EntriesNotCanonical);
                }
            }
            previous = Some((
                subject_type_key(entry.subject_type),
                entry.subject_id.as_str(),
            ));
        }
        Ok(())
    }
}

impl SignedRevocationSnapshotV1 {
    /// Build the exact domain-separated message signed by the revocation authority.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical JSON serialization fails.
    pub fn signing_message(&self) -> Result<Vec<u8>, CanonicalizationError> {
        let canonical = canonical_json(&self.claims)?;
        let mut message = b"AIVO-AGENTGUARD-REVOCATION-SNAPSHOT-V1\0".to_vec();
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    /// Compute the canonical digest of the complete signed snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical JSON serialization fails.
    pub fn digest(&self) -> Result<[u8; 32], CanonicalizationError> {
        let canonical = canonical_json(self)?;
        Ok(domain_digest(
            b"AIVO-AGENTGUARD-REVOCATION-SNAPSHOT-REF-V1\0",
            &canonical,
        ))
    }

    /// Verify freshness, signature key binding, and Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error for registry mismatch, invalid snapshot shape, stale
    /// status, key mismatch, canonicalization failure, or signature verification failure.
    pub fn verify_at(
        &self,
        public_key: &[u8; 32],
        expected_registry_id: &str,
        now_utc: &str,
    ) -> Result<(), RevocationError> {
        if expected_registry_id.is_empty() || self.claims.registry_id != expected_registry_id {
            return Err(RevocationError::RegistryMismatch);
        }
        self.claims.validate_at(now_utc)?;
        self.signature
            .validate_shape()
            .map_err(|_| RevocationError::KeyIdMismatch)?;
        if self.signature.key_id != self.claims.signing_key_id
            || self.signature.algorithm != crate::SignatureAlgorithm::Ed25519
        {
            return Err(RevocationError::KeyIdMismatch);
        }
        let message = self
            .signing_message()
            .map_err(|error| RevocationError::Canonicalization(error.to_string()))?;
        verify_ed25519(public_key, &self.signature, &message)?;
        Ok(())
    }

    /// Derive the rollback-protection checkpoint for this signed snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical digest generation fails.
    fn high_water_mark(&self) -> Result<RevocationHighWaterMark, RevocationError> {
        Ok(RevocationHighWaterMark {
            registry_id: self.claims.registry_id.clone(),
            registry_epoch: self.claims.registry_epoch,
            sequence: self.claims.sequence,
            snapshot_digest: hex_digest(
                &self
                    .digest()
                    .map_err(|error| RevocationError::Canonicalization(error.to_string()))?,
            ),
            this_update: self.claims.this_update.clone(),
        })
    }

    /// Verify the signed snapshot against the pinned registry and derive its checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for registry mismatch, stale status, invalid signature,
    /// malformed claims, or canonicalization failure.
    pub fn verified_high_water_mark(
        &self,
        public_key: &[u8; 32],
        expected_registry_id: &str,
        now_utc: &str,
    ) -> Result<RevocationHighWaterMark, RevocationError> {
        self.verify_at(public_key, expected_registry_id, now_utc)?;
        self.high_water_mark()
    }
}

/// Check monotonic progression before atomically persisting a new high-water mark.
///
/// Exact same-sequence/same-digest replay is idempotent. Registry epoch changes
/// require a separate trusted recovery/bootstrap operation and are never
/// accepted through an ordinary snapshot update.
///
/// # Errors
///
/// Returns an error for registry/epoch changes, sequence rollback, same-sequence
/// equivocation, or update-time rollback.
pub fn validate_progression(
    previous: Option<&RevocationHighWaterMark>,
    candidate: &RevocationHighWaterMark,
) -> Result<bool, RevocationError> {
    let Some(previous) = previous else {
        // First-use bootstrap must be seeded from an out-of-band trusted checkpoint.
        return Err(RevocationError::InvalidShape);
    };
    validate_high_water_mark(previous)?;
    validate_high_water_mark(candidate)?;
    if candidate.registry_id != previous.registry_id
        || candidate.registry_epoch != previous.registry_epoch
    {
        return Err(RevocationError::EpochTransition);
    }
    if candidate.sequence < previous.sequence {
        return Err(RevocationError::SequenceRollback);
    }
    if candidate.sequence == previous.sequence {
        if candidate.snapshot_digest != previous.snapshot_digest {
            return Err(RevocationError::SequenceEquivocation);
        }
        if candidate.this_update != previous.this_update {
            return Err(RevocationError::UpdateRollback);
        }
        return Ok(false);
    }
    if candidate.this_update < previous.this_update {
        return Err(RevocationError::UpdateRollback);
    }
    Ok(true)
}

fn subject_type_key(subject_type: RevocationSubjectType) -> &'static str {
    match subject_type {
        RevocationSubjectType::AttestationIssuer => "attestation_issuer",
        RevocationSubjectType::AttestationIssuerKey => "attestation_issuer_key",
        RevocationSubjectType::EvidenceServiceKey => "evidence_service_key",
        RevocationSubjectType::PermitSignerKey => "permit_signer_key",
        RevocationSubjectType::Policy => "policy",
        RevocationSubjectType::PolicyIssuer => "policy_issuer",
        RevocationSubjectType::PolicyIssuerKey => "policy_issuer_key",
    }
}

fn validate_high_water_mark(mark: &RevocationHighWaterMark) -> Result<(), RevocationError> {
    if mark.registry_id.is_empty()
        || mark.registry_id.trim() != mark.registry_id
        || mark.registry_epoch == 0
        || mark.sequence == 0
        || mark.snapshot_digest.len() != 64
        || !mark
            .snapshot_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RevocationError::InvalidShape);
    }
    parse_timestamp(&mark.this_update)?;
    Ok(())
}

fn parse_timestamp(value: &str) -> Result<i64, RevocationError> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes
            .iter()
            .enumerate()
            .any(|(i, byte)| !matches!(i, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit())
    {
        return Err(RevocationError::InvalidShape);
    }
    let number =
        |range: std::ops::Range<usize>| -> i64 { value[range].parse::<i64>().unwrap_or_default() };
    let year = number(0..4);
    let month = number(5..7);
    let day = number(8..10);
    let hour = number(11..13);
    let minute = number(14..16);
    let second = number(17..19);
    if year < 1
        || !(1..=12).contains(&month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return Err(RevocationError::InvalidShape);
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day < 1 || day > month_days {
        return Err(RevocationError::InvalidShape);
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mark(epoch: u64, sequence: u64, digest: &str, updated: &str) -> RevocationHighWaterMark {
        RevocationHighWaterMark {
            registry_id: "registry-1".into(),
            registry_epoch: epoch,
            sequence,
            snapshot_digest: digest.into(),
            this_update: updated.into(),
        }
    }

    #[test]
    fn verifies_signed_snapshot_and_pinned_registry_before_checkpoint() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[23_u8; 32]);
        let claims = RevocationSnapshotV1 {
            schema_version: 1,
            registry_id: "registry-1".into(),
            registry_epoch: 1,
            sequence: 1,
            issued_at: "2026-11-17T10:00:00Z".into(),
            this_update: "2026-11-17T10:00:00Z".into(),
            next_update: "2026-11-17T10:00:30Z".into(),
            entries: vec![RevocationEntryV1 {
                subject_type: RevocationSubjectType::PermitSignerKey,
                subject_id: "permit-key-1".into(),
                status: RevocationStatus::Active,
                effective_at: "2026-11-17T10:00:00Z".into(),
                reason_code: None,
            }],
            signing_key_id: "revocation-key-1".into(),
        };
        let canonical = canonical_json(&claims).unwrap();
        let mut message = b"AIVO-AGENTGUARD-REVOCATION-SNAPSHOT-V1\0".to_vec();
        message.extend_from_slice(&canonical);
        let signature = signing_key.sign(&message);
        let signed = SignedRevocationSnapshotV1 {
            claims,
            signature: SignatureEnvelope {
                algorithm: crate::SignatureAlgorithm::Ed25519,
                key_id: "revocation-key-1".into(),
                signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            },
        };

        let checkpoint = signed
            .verified_high_water_mark(
                signing_key.verifying_key().as_bytes(),
                "registry-1",
                "2026-11-17T10:00:10Z",
            )
            .unwrap();
        assert_eq!(checkpoint.registry_id, "registry-1");
        assert_eq!(checkpoint.sequence, 1);
        assert_eq!(checkpoint.snapshot_digest.len(), 64);
        assert_eq!(
            signed.verify_at(
                signing_key.verifying_key().as_bytes(),
                "another-registry",
                "2026-11-17T10:00:10Z"
            ),
            Err(RevocationError::RegistryMismatch)
        );
    }

    #[test]
    fn exact_subject_lookup_returns_unknown_when_missing() {
        let snapshot = RevocationSnapshotV1 {
            schema_version: 1,
            registry_id: "registry-1".into(),
            registry_epoch: 1,
            sequence: 1,
            issued_at: "2026-11-17T10:00:00Z".into(),
            this_update: "2026-11-17T10:00:00Z".into(),
            next_update: "2026-11-17T10:00:30Z".into(),
            entries: vec![RevocationEntryV1 {
                subject_type: RevocationSubjectType::PermitSignerKey,
                subject_id: "permit-key-1".into(),
                status: RevocationStatus::Active,
                effective_at: "2026-11-17T10:00:00Z".into(),
                reason_code: None,
            }],
            signing_key_id: "revocation-key-1".into(),
        };
        assert_eq!(
            snapshot.status_for(RevocationSubjectType::PermitSignerKey, "permit-key-1"),
            RevocationStatus::Active
        );
        assert_eq!(
            snapshot.status_for(RevocationSubjectType::PermitSignerKey, "missing-key"),
            RevocationStatus::Unknown
        );
    }

    #[test]
    fn missing_trusted_bootstrap_checkpoint_fails_closed() {
        assert_eq!(
            validate_progression(None, &mark(2, 1, &"aa".repeat(32), "2026-11-17T10:00:00Z")),
            Err(RevocationError::InvalidShape)
        );
    }

    #[test]
    fn snapshot_entries_must_follow_lexicographic_subject_type_order() {
        let snapshot = RevocationSnapshotV1 {
            schema_version: 1,
            registry_id: "registry-1".into(),
            registry_epoch: 1,
            sequence: 1,
            issued_at: "2026-11-17T10:00:00Z".into(),
            this_update: "2026-11-17T10:00:00Z".into(),
            next_update: "2026-11-17T10:00:30Z".into(),
            entries: vec![
                RevocationEntryV1 {
                    subject_type: RevocationSubjectType::Policy,
                    subject_id: "policy-digest".into(),
                    status: RevocationStatus::Active,
                    effective_at: "2026-11-17T10:00:00Z".into(),
                    reason_code: None,
                },
                RevocationEntryV1 {
                    subject_type: RevocationSubjectType::AttestationIssuer,
                    subject_id: "issuer-1".into(),
                    status: RevocationStatus::Active,
                    effective_at: "2026-11-17T10:00:00Z".into(),
                    reason_code: None,
                },
            ],
            signing_key_id: "revocation-key-1".into(),
        };
        assert_eq!(
            snapshot.validate_at("2026-11-17T10:00:10Z"),
            Err(RevocationError::EntriesNotCanonical)
        );
    }

    #[test]
    fn exact_duplicate_snapshot_is_idempotent() {
        let prior = mark(2, 7, &"aa".repeat(32), "2026-11-17T10:00:00Z");
        let next = mark(2, 7, &"aa".repeat(32), "2026-11-17T10:00:00Z");
        assert_eq!(validate_progression(Some(&prior), &next), Ok(false));
    }

    #[test]
    fn same_sequence_with_different_digest_is_rejected() {
        let prior = mark(2, 7, &"aa".repeat(32), "2026-11-17T10:00:00Z");
        let next = mark(2, 7, &"bb".repeat(32), "2026-11-17T10:00:00Z");
        assert_eq!(
            validate_progression(Some(&prior), &next),
            Err(RevocationError::SequenceEquivocation)
        );
    }

    #[test]
    fn rollback_and_untrusted_epoch_change_are_rejected() {
        let prior = mark(2, 7, &"aa".repeat(32), "2026-11-17T10:00:00Z");
        assert_eq!(
            validate_progression(
                Some(&prior),
                &mark(2, 6, &"bb".repeat(32), "2026-11-17T10:00:00Z")
            ),
            Err(RevocationError::SequenceRollback)
        );
        assert_eq!(
            validate_progression(
                Some(&prior),
                &mark(3, 8, &"cc".repeat(32), "2026-11-17T10:00:01Z")
            ),
            Err(RevocationError::EpochTransition)
        );
    }
}
