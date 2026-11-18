//! Append-only evidence event integrity primitives.
//!
//! This crate prepares and verifies evidence records. It does not provide a
//! durable store; production adapters must implement atomic durable append.

use agentguard_canonical::{DigestDomain, MAX_SAFE_INTEGER, digest_hex};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const GENESIS_PREVIOUS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceEventType {
    #[serde(rename = "REQUEST_RECEIVED")]
    RequestReceived,
    #[serde(rename = "DECISION_RECORDED")]
    DecisionRecorded,
    #[serde(rename = "APPROVAL_REQUESTED")]
    ApprovalRequested,
    #[serde(rename = "APPROVAL_RECORDED")]
    ApprovalRecorded,
    #[serde(rename = "APPROVAL_REJECTED")]
    ApprovalRejected,
    #[serde(rename = "POLICY_REEVALUATED")]
    PolicyReevaluated,
    #[serde(rename = "PERMIT_ISSUED")]
    PermitIssued,
    #[serde(rename = "PERMIT_CONSUMED")]
    PermitConsumed,
    #[serde(rename = "ENFORCEMENT_REJECTED")]
    EnforcementRejected,
    #[serde(rename = "EXECUTION_OBSERVED")]
    ExecutionObserved,
    #[serde(rename = "EXECUTION_FAILED")]
    ExecutionFailed,
    #[serde(rename = "EXECUTION_UNKNOWN")]
    ExecutionUnknown,
    #[serde(rename = "EVIDENCE_CORRECTION")]
    EvidenceCorrection,
}

impl EvidenceEventType {
    /// Stable wire name for evidence receipt binding.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestReceived => "REQUEST_RECEIVED",
            Self::DecisionRecorded => "DECISION_RECORDED",
            Self::ApprovalRequested => "APPROVAL_REQUESTED",
            Self::ApprovalRecorded => "APPROVAL_RECORDED",
            Self::ApprovalRejected => "APPROVAL_REJECTED",
            Self::PolicyReevaluated => "POLICY_REEVALUATED",
            Self::PermitIssued => "PERMIT_ISSUED",
            Self::PermitConsumed => "PERMIT_CONSUMED",
            Self::EnforcementRejected => "ENFORCEMENT_REJECTED",
            Self::ExecutionObserved => "EXECUTION_OBSERVED",
            Self::ExecutionFailed => "EXECUTION_FAILED",
            Self::ExecutionUnknown => "EXECUTION_UNKNOWN",
            Self::EvidenceCorrection => "EVIDENCE_CORRECTION",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorRefV1 {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionOutcome {
    #[serde(rename = "ALLOW")]
    Allow,
    #[serde(rename = "DENY")]
    Deny,
    #[serde(rename = "REQUIRE_APPROVAL")]
    RequireApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEventDraftV1 {
    pub schema_version: String,
    pub event_id: String,
    pub tenant_id: String,
    pub stream_id: String,
    pub sequence: u64,
    pub occurred_at: String,
    pub event_type: EvidenceEventType,
    pub request_id: String,
    pub actor_ref: ActorRefV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<DecisionOutcome>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correction_of_event_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEventV1 {
    pub schema_version: String,
    pub event_id: String,
    pub tenant_id: String,
    pub stream_id: String,
    pub sequence: u64,
    pub occurred_at: String,
    pub event_type: EvidenceEventType,
    pub request_id: String,
    pub actor_ref: ActorRefV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<DecisionOutcome>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correction_of_event_id: Option<String>,
    pub previous_event_hash: String,
    pub event_hash: String,
}

#[derive(Serialize)]
struct EventHashPreimage<'a> {
    schema_version: &'a str,
    event_id: &'a str,
    tenant_id: &'a str,
    stream_id: &'a str,
    sequence: u64,
    occurred_at: &'a str,
    event_type: EvidenceEventType,
    request_id: &'a str,
    actor_ref: &'a ActorRefV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_digest: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_digest: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_digest: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context_digest: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<DecisionOutcome>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reason_codes: &'a Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    correction_of_event_id: &'a Option<String>,
    previous_event_hash: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceError {
    InvalidSchemaVersion,
    EmptyRequiredField,
    InvalidTimestamp,
    InvalidSequence,
    InvalidDigest,
    InvalidPreviousHash,
    InvalidEventHash,
    SequenceDiscontinuity,
    StreamMismatch,
    TenantMismatch,
    PreviousHashMismatch,
    EventHashMismatch,
    Canonicalization,
    Serialization,
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidSchemaVersion => "unsupported evidence schema version",
            Self::EmptyRequiredField => "required evidence field is empty",
            Self::InvalidTimestamp => "occurred_at must be a UTC RFC 3339 timestamp ending in Z",
            Self::InvalidSequence => "evidence sequence must be greater than zero",
            Self::InvalidDigest => "digest must be 64 lowercase hexadecimal characters",
            Self::InvalidPreviousHash => "previous event hash is malformed",
            Self::InvalidEventHash => "event hash is malformed",
            Self::SequenceDiscontinuity => "evidence sequence is not contiguous",
            Self::StreamMismatch => "evidence stream identity changed",
            Self::TenantMismatch => "evidence tenant identity changed",
            Self::PreviousHashMismatch => "previous event hash does not match",
            Self::EventHashMismatch => "event hash verification failed",
            Self::Canonicalization => "evidence canonicalization failed",
            Self::Serialization => "evidence serialization failed",
        };
        f.write_str(message)
    }
}
impl std::error::Error for EvidenceError {}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_utc_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || !value.is_ascii() {
        return false;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }
    for (start, end) in [(0, 4), (5, 7), (8, 10), (11, 13), (14, 16), (17, 19)] {
        if !bytes[start..end].iter().all(u8::is_ascii_digit) {
            return false;
        }
    }
    let number = |start: usize, end: usize| value[start..end].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0 || day > days_in_month || hour > 23 || minute > 59 || second > 60 {
        return false;
    }
    let suffix = &bytes[19..];
    if suffix == b"Z" {
        return true;
    }
    suffix.len() >= 3
        && suffix[0] == b'.'
        && suffix[suffix.len() - 1] == b'Z'
        && suffix[1..suffix.len() - 1].iter().all(u8::is_ascii_digit)
}

fn validate_draft(draft: &EvidenceEventDraftV1) -> Result<(), EvidenceError> {
    if draft.schema_version != "agentguard.evidence-v1" {
        return Err(EvidenceError::InvalidSchemaVersion);
    }
    if [
        draft.event_id.as_str(),
        draft.tenant_id.as_str(),
        draft.stream_id.as_str(),
        draft.request_id.as_str(),
        draft.actor_ref.kind.as_str(),
        draft.actor_ref.id.as_str(),
    ]
    .iter()
    .any(|value| value.trim().is_empty())
    {
        return Err(EvidenceError::EmptyRequiredField);
    }
    if draft.sequence == 0 || draft.sequence > MAX_SAFE_INTEGER {
        return Err(EvidenceError::InvalidSequence);
    }
    if !is_utc_rfc3339(&draft.occurred_at) {
        return Err(EvidenceError::InvalidTimestamp);
    }
    for digest in [
        &draft.request_digest,
        &draft.action_digest,
        &draft.policy_digest,
        &draft.context_digest,
    ]
    .into_iter()
    .flatten()
    {
        if !is_lower_hex_digest(digest) {
            return Err(EvidenceError::InvalidDigest);
        }
    }
    if draft
        .correction_of_event_id
        .as_ref()
        .is_some_and(|id| id.trim().is_empty())
        || draft
            .reason_codes
            .iter()
            .any(|reason| reason.trim().is_empty())
    {
        return Err(EvidenceError::EmptyRequiredField);
    }
    Ok(())
}

fn hash_preimage(event: &EvidenceEventV1) -> Result<Vec<u8>, EvidenceError> {
    let payload = EventHashPreimage {
        schema_version: &event.schema_version,
        event_id: &event.event_id,
        tenant_id: &event.tenant_id,
        stream_id: &event.stream_id,
        sequence: event.sequence,
        occurred_at: &event.occurred_at,
        event_type: event.event_type,
        request_id: &event.request_id,
        actor_ref: &event.actor_ref,
        request_digest: &event.request_digest,
        action_digest: &event.action_digest,
        policy_digest: &event.policy_digest,
        context_digest: &event.context_digest,
        decision: event.decision,
        reason_codes: &event.reason_codes,
        correction_of_event_id: &event.correction_of_event_id,
        previous_event_hash: &event.previous_event_hash,
    };
    serde_json::to_vec(&payload).map_err(|_| EvidenceError::Serialization)
}

/// Seals a draft against a predecessor hash. The caller must obtain that hash
/// from an atomically serialized stream append operation; this function is not
/// storage or concurrency control.
///
/// # Errors
///
/// Returns an error when the draft violates the event schema, the predecessor
/// hash is malformed, serialization fails, or canonical hashing rejects input.
pub fn seal_event(
    draft: EvidenceEventDraftV1,
    previous_event_hash: &str,
) -> Result<EvidenceEventV1, EvidenceError> {
    validate_draft(&draft)?;
    if !is_lower_hex_digest(previous_event_hash) {
        return Err(EvidenceError::InvalidPreviousHash);
    }
    if (draft.sequence == 1 && previous_event_hash != GENESIS_PREVIOUS_HASH)
        || (draft.sequence > 1 && previous_event_hash == GENESIS_PREVIOUS_HASH)
    {
        return Err(EvidenceError::PreviousHashMismatch);
    }
    let mut event = EvidenceEventV1 {
        schema_version: draft.schema_version,
        event_id: draft.event_id,
        tenant_id: draft.tenant_id,
        stream_id: draft.stream_id,
        sequence: draft.sequence,
        occurred_at: draft.occurred_at,
        event_type: draft.event_type,
        request_id: draft.request_id,
        actor_ref: draft.actor_ref,
        request_digest: draft.request_digest,
        action_digest: draft.action_digest,
        policy_digest: draft.policy_digest,
        context_digest: draft.context_digest,
        decision: draft.decision,
        reason_codes: draft.reason_codes,
        correction_of_event_id: draft.correction_of_event_id,
        previous_event_hash: previous_event_hash.to_owned(),
        event_hash: String::new(),
    };
    event.event_hash = digest_hex(DigestDomain::Event, &hash_preimage(&event)?)
        .map_err(|_| EvidenceError::Canonicalization)?;
    Ok(event)
}

/// Verifies a sealed event without trusting its stored hash.
///
/// # Errors
///
/// Returns an error when event fields or hash encodings are invalid, or when
/// the recomputed event digest does not match the stored digest.
pub fn verify_event(event: &EvidenceEventV1) -> Result<(), EvidenceError> {
    let draft = EvidenceEventDraftV1 {
        schema_version: event.schema_version.clone(),
        event_id: event.event_id.clone(),
        tenant_id: event.tenant_id.clone(),
        stream_id: event.stream_id.clone(),
        sequence: event.sequence,
        occurred_at: event.occurred_at.clone(),
        event_type: event.event_type,
        request_id: event.request_id.clone(),
        actor_ref: event.actor_ref.clone(),
        request_digest: event.request_digest.clone(),
        action_digest: event.action_digest.clone(),
        policy_digest: event.policy_digest.clone(),
        context_digest: event.context_digest.clone(),
        decision: event.decision,
        reason_codes: event.reason_codes.clone(),
        correction_of_event_id: event.correction_of_event_id.clone(),
    };
    validate_draft(&draft)?;
    if !is_lower_hex_digest(&event.previous_event_hash) {
        return Err(EvidenceError::InvalidPreviousHash);
    }
    if (event.sequence == 1 && event.previous_event_hash != GENESIS_PREVIOUS_HASH)
        || (event.sequence > 1 && event.previous_event_hash == GENESIS_PREVIOUS_HASH)
    {
        return Err(EvidenceError::PreviousHashMismatch);
    }
    if !is_lower_hex_digest(&event.event_hash) {
        return Err(EvidenceError::InvalidEventHash);
    }
    let expected = digest_hex(DigestDomain::Event, &hash_preimage(event)?)
        .map_err(|_| EvidenceError::Canonicalization)?;
    if expected != event.event_hash {
        return Err(EvidenceError::EventHashMismatch);
    }
    Ok(())
}

/// Verifies an ordered complete stream from genesis. It detects mutation,
/// reordering, middle deletion, duplication, and broken links. Tail truncation
/// and full rewrite require an independently retained signed checkpoint.
///
/// # Errors
///
/// Returns an error when sequence continuity, tenant/stream identity,
/// predecessor linkage, event schema, or event digest verification fails.
pub fn verify_stream(events: &[EvidenceEventV1]) -> Result<(), EvidenceError> {
    let Some(first) = events.first() else {
        return Ok(());
    };
    if first.sequence != 1 {
        return Err(EvidenceError::SequenceDiscontinuity);
    }
    if first.previous_event_hash != GENESIS_PREVIOUS_HASH {
        return Err(EvidenceError::PreviousHashMismatch);
    }
    let tenant_id = &first.tenant_id;
    let stream_id = &first.stream_id;
    let mut previous_hash = GENESIS_PREVIOUS_HASH;
    for (index, event) in events.iter().enumerate() {
        let expected_sequence =
            u64::try_from(index + 1).map_err(|_| EvidenceError::SequenceDiscontinuity)?;
        if event.sequence != expected_sequence {
            return Err(EvidenceError::SequenceDiscontinuity);
        }
        if &event.tenant_id != tenant_id {
            return Err(EvidenceError::TenantMismatch);
        }
        if &event.stream_id != stream_id {
            return Err(EvidenceError::StreamMismatch);
        }
        if event.previous_event_hash != previous_hash {
            return Err(EvidenceError::PreviousHashMismatch);
        }
        verify_event(event)?;
        previous_hash = &event.event_hash;
    }
    Ok(())
}

/// Storage boundary for append-only evidence adapters.
///
/// Implementations MUST make append a durable atomic conditional operation:
/// the event must be verified, its tenant/stream key must be authenticated by
/// the caller, its sequence must be exactly the next stream sequence, and its
/// predecessor must equal the currently committed tail (or genesis for the
/// first event). Concurrent writers must not both append the same sequence.
/// Implementations MUST reject duplicate event IDs within the stream and MUST
/// NOT expose mutation or deletion of committed events through this interface.
///
/// This trait specifies a contract; it does not prove that an implementation's
/// database or deployment topology satisfies durability or linearizability.
pub trait AppendOnlyEvidenceStore {
    type Error;

    /// Atomically commits one sealed event without changing prior records.
    ///
    /// # Errors
    ///
    /// Returns the adapter's error when validation, a concurrent append
    /// conflict, storage durability, or the underlying transaction fails.
    fn append(&self, event: EvidenceEventV1) -> Result<(), Self::Error>;

    /// Reads the complete stream in ascending sequence order.
    ///
    /// # Errors
    ///
    /// Returns the adapter's error when the stream cannot be read completely
    /// or the storage backend cannot establish a consistent read.
    fn read_stream(
        &self,
        tenant_id: &str,
        stream_id: &str,
    ) -> Result<Vec<EvidenceEventV1>, Self::Error>;
}

// ---- Durable evidence service and signed receipt contracts (G3) ----

use agentguard_core::{
    SignatureAlgorithm, SignatureEnvelope, canonical_json, domain_digest, hex_digest,
    verify_ed25519,
};
use thiserror::Error;

pub const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"AIVO-AGENTGUARD-EVIDENCE-RECEIPT-V1\\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceStreamHead {
    pub sequence: u64,
    pub event_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCommitRef {
    pub commit_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvidenceEvent {
    pub event: EvidenceEventV1,
    pub commit: DurableCommitRef,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvidenceStoreError {
    #[error("stream head conflict")]
    HeadConflict,
    #[error("evidence storage unavailable")]
    Unavailable,
    #[error("duplicate evidence event")]
    Duplicate,
    #[error("evidence storage rejected operation")]
    Rejected,
}

/// Implementations MUST atomically compare the expected tenant/stream head,
/// durably append the event, and return a stable commit identity. They MUST
/// reject duplicate event IDs and MUST NOT expose mutation/deletion operations.
pub trait EvidenceStore: Send + Sync {
    /// Read the latest committed sequence and hash for one authenticated stream.
    ///
    /// # Errors
    /// Returns an error when storage is unavailable or the stream head cannot be read.
    fn read_head(
        &self,
        tenant_id: &str,
        stream_id: &str,
    ) -> Result<Option<EvidenceStreamHead>, EvidenceStoreError>;

    /// Commit an event only when the current head exactly matches `expected`.
    ///
    /// # Errors
    /// Returns a conflict or storage error when the conditional durable append fails.
    fn append_if_head_matches(
        &self,
        event: &EvidenceEventV1,
        expected: Option<&EvidenceStreamHead>,
    ) -> Result<DurableCommitRef, EvidenceStoreError>;

    /// Read one exact committed event and its durable commit identity.
    ///
    /// # Errors
    /// Returns an error when storage is unavailable or the event cannot be read consistently.
    fn read_event(
        &self,
        tenant_id: &str,
        stream_id: &str,
        sequence: u64,
    ) -> Result<Option<StoredEvidenceEvent>, EvidenceStoreError>;
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvidenceSignerError {
    #[error("evidence signer unavailable")]
    Unavailable,
    #[error("evidence signer rejected request")]
    Rejected,
    #[error("evidence signer returned invalid signature envelope")]
    InvalidResponse,
}

/// Dedicated evidence-purpose signer. The implementation owns the private key;
/// this crate accepts no key material and exposes no signing secret.
pub trait EvidenceReceiptSigner: Send + Sync {
    /// Sign one domain-separated evidence receipt message using the dedicated evidence key.
    ///
    /// # Errors
    /// Returns an error when the signer is unavailable or rejects the signing request.
    fn sign_receipt(&self, message: &[u8]) -> Result<SignatureEnvelope, EvidenceSignerError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReceiptClaimsV1 {
    pub schema_version: u8,
    pub receipt_id: String,
    pub tenant_id: String,
    pub stream_id: String,
    pub sequence: u64,
    pub event_hash: String,
    pub event_type: String,
    pub request_digest: String,
    pub action_digest: String,
    pub policy_digest: String,
    pub context_digest: String,
    pub storage_commit_id: String,
    pub committed_at: String,
    pub evidence_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEvidenceReceiptV1 {
    pub claims: EvidenceReceiptClaimsV1,
    pub signature: SignatureEnvelope,
}

impl SignedEvidenceReceiptV1 {
    /// Compute the domain-separated digest of the complete signed receipt.
    ///
    /// # Errors
    /// Returns an error if canonical receipt serialization fails.
    pub fn digest(&self) -> Result<[u8; 32], EvidenceServiceError> {
        let bytes = canonical_json(self).map_err(|_| EvidenceServiceError::Canonicalization)?;
        Ok(domain_digest(
            b"AIVO-AGENTGUARD-EVIDENCE-RECEIPT-DIGEST-V1\\0",
            &bytes,
        ))
    }

    /// Verify the receipt signature and its exact evidence-key identity.
    ///
    /// # Errors
    /// Returns an error for invalid claims, key mismatch, canonicalization, or signature failure.
    pub fn verify_signature(
        &self,
        public_key: &[u8; 32],
        expected_key_id: &str,
    ) -> Result<(), EvidenceServiceError> {
        validate_receipt(&self.claims)?;
        if self.signature.key_id != expected_key_id
            || self.claims.evidence_key_id != expected_key_id
            || self.signature.algorithm != SignatureAlgorithm::Ed25519
        {
            return Err(EvidenceServiceError::ReceiptKeyMismatch);
        }
        let claims =
            canonical_json(&self.claims).map_err(|_| EvidenceServiceError::Canonicalization)?;
        verify_ed25519(
            public_key,
            &self.signature,
            &domain_message(RECEIPT_SIGNATURE_DOMAIN, &claims),
        )
        .map_err(|_| EvidenceServiceError::InvalidSignature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceAppendResult {
    pub event: EvidenceEventV1,
    pub receipt: SignedEvidenceReceiptV1,
    pub receipt_digest: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvidenceServiceError {
    #[error("evidence store failed")]
    Store,
    #[error("evidence receipt signer failed")]
    Signer,
    #[error("evidence canonicalization failed")]
    Canonicalization,
    #[error("evidence cryptographic verification failed")]
    InvalidSignature,
    #[error("invalid evidence receipt")]
    InvalidReceipt,
    #[error("receipt does not bind committed event")]
    ReceiptBindingMismatch,
    #[error("receipt signer key mismatch")]
    ReceiptKeyMismatch,
    #[error("committed event read-back mismatch")]
    ReadBackMismatch,
    #[error("stream contention exceeded retry budget")]
    Contention,
    #[error("invalid evidence event")]
    InvalidEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceAppendRequestV1 {
    pub event_id: String,
    pub tenant_id: String,
    pub stream_id: String,
    pub occurred_at: String,
    pub event_type: EvidenceEventType,
    pub request_id: String,
    pub actor_ref: ActorRefV1,
    pub request_digest: Option<String>,
    pub action_digest: Option<String>,
    pub policy_digest: Option<String>,
    pub context_digest: Option<String>,
    pub decision: Option<DecisionOutcome>,
    pub reason_codes: Vec<String>,
    pub correction_of_event_id: Option<String>,
}

/// Atomically append a decision event under an independently authenticated tenant, verify durable read-back, then obtain a signed receipt.
///
/// # Errors
/// Returns an error for invalid event data, storage contention/failure, read-back mismatch,
/// canonicalization failure, or receipt signer failure.
fn validate_append_request(
    authenticated_tenant_id: &str,
    request: &EvidenceAppendRequestV1,
) -> Result<(), EvidenceServiceError> {
    if authenticated_tenant_id.is_empty()
        || authenticated_tenant_id.trim() != authenticated_tenant_id
        || request.tenant_id != authenticated_tenant_id
        || request.event_type != EvidenceEventType::DecisionRecorded
        || request.decision.is_none()
        || request.request_digest.is_none()
        || request.action_digest.is_none()
        || request.policy_digest.is_none()
        || request.context_digest.is_none()
    {
        return Err(EvidenceServiceError::InvalidEvent);
    }
    for value in [
        request.event_id.as_str(),
        request.tenant_id.as_str(),
        request.stream_id.as_str(),
        request.request_id.as_str(),
        request.actor_ref.kind.as_str(),
        request.actor_ref.id.as_str(),
    ] {
        if value.is_empty() || value.trim() != value || value.len() > 256 {
            return Err(EvidenceServiceError::InvalidEvent);
        }
    }
    Ok(())
}

fn build_append_event(
    request: &EvidenceAppendRequestV1,
    head: Option<&EvidenceStreamHead>,
) -> Result<EvidenceEventV1, EvidenceServiceError> {
    let (sequence, previous_hash) = match head {
        Some(value) => (
            value
                .sequence
                .checked_add(1)
                .ok_or(EvidenceServiceError::InvalidEvent)?,
            value.event_hash.clone(),
        ),
        None => (1, GENESIS_PREVIOUS_HASH.to_owned()),
    };
    let draft = EvidenceEventDraftV1 {
        schema_version: "agentguard.evidence-v1".to_owned(),
        event_id: request.event_id.clone(),
        tenant_id: request.tenant_id.clone(),
        stream_id: request.stream_id.clone(),
        sequence,
        occurred_at: request.occurred_at.clone(),
        event_type: request.event_type,
        request_id: request.request_id.clone(),
        actor_ref: request.actor_ref.clone(),
        request_digest: request.request_digest.clone(),
        action_digest: request.action_digest.clone(),
        policy_digest: request.policy_digest.clone(),
        context_digest: request.context_digest.clone(),
        decision: request.decision,
        reason_codes: request.reason_codes.clone(),
        correction_of_event_id: request.correction_of_event_id.clone(),
    };
    seal_event(draft, &previous_hash).map_err(|_| EvidenceServiceError::InvalidEvent)
}

fn create_signed_receipt<K: EvidenceReceiptSigner>(
    signer: &K,
    event: &EvidenceEventV1,
    commit: &DurableCommitRef,
    receipt_id: &str,
    committed_at: &str,
    evidence_key_id: &str,
) -> Result<SignedEvidenceReceiptV1, EvidenceServiceError> {
    let claims = EvidenceReceiptClaimsV1 {
        schema_version: 1,
        receipt_id: receipt_id.to_owned(),
        tenant_id: event.tenant_id.clone(),
        stream_id: event.stream_id.clone(),
        sequence: event.sequence,
        event_hash: event.event_hash.clone(),
        event_type: event.event_type.as_str().to_owned(),
        request_digest: event
            .request_digest
            .clone()
            .ok_or(EvidenceServiceError::InvalidEvent)?,
        action_digest: event
            .action_digest
            .clone()
            .ok_or(EvidenceServiceError::InvalidEvent)?,
        policy_digest: event
            .policy_digest
            .clone()
            .ok_or(EvidenceServiceError::InvalidEvent)?,
        context_digest: event
            .context_digest
            .clone()
            .ok_or(EvidenceServiceError::InvalidEvent)?,
        storage_commit_id: commit.commit_id.clone(),
        committed_at: committed_at.to_owned(),
        evidence_key_id: evidence_key_id.to_owned(),
    };
    validate_receipt(&claims)?;
    let claims_bytes =
        canonical_json(&claims).map_err(|_| EvidenceServiceError::Canonicalization)?;
    let signature = signer
        .sign_receipt(&domain_message(RECEIPT_SIGNATURE_DOMAIN, &claims_bytes))
        .map_err(|_| EvidenceServiceError::Signer)?;
    if signature.algorithm != SignatureAlgorithm::Ed25519
        || signature.key_id != evidence_key_id
        || signature.validate_shape().is_err()
    {
        return Err(EvidenceServiceError::ReceiptKeyMismatch);
    }
    Ok(SignedEvidenceReceiptV1 { claims, signature })
}

/// Atomically append a decision event, verify durable read-back, then obtain a signed receipt.
///
/// # Errors
/// Returns an error for invalid event data, storage contention/failure, read-back mismatch,
/// canonicalization failure, or receipt signer failure.
/// Append and verify a decision event without issuing a receipt.
///
/// This supports DENY and `REQUIRE_APPROVAL` decisions, which must be durably
/// recorded but do not authorize protected execution.
///
/// # Errors
/// Returns an error for invalid event data, storage contention/failure, or read-back mismatch.
pub fn append_event_durably<S: EvidenceStore>(
    store: &S,
    authenticated_tenant_id: &str,
    request: &EvidenceAppendRequestV1,
) -> Result<StoredEvidenceEvent, EvidenceServiceError> {
    validate_append_request(authenticated_tenant_id, request)?;

    for _ in 0..8 {
        let head = store
            .read_head(authenticated_tenant_id, &request.stream_id)
            .map_err(|_| EvidenceServiceError::Store)?;
        let event = build_append_event(request, head.as_ref())?;
        let commit = match store.append_if_head_matches(&event, head.as_ref()) {
            Ok(value) => value,
            Err(EvidenceStoreError::HeadConflict) => continue,
            Err(_) => return Err(EvidenceServiceError::Store),
        };
        if commit.commit_id.is_empty() || commit.commit_id.trim() != commit.commit_id {
            return Err(EvidenceServiceError::Store);
        }
        let stored = store
            .read_event(&event.tenant_id, &event.stream_id, event.sequence)
            .map_err(|_| EvidenceServiceError::Store)?
            .ok_or(EvidenceServiceError::ReadBackMismatch)?;
        verify_event(&stored.event).map_err(|_| EvidenceServiceError::ReadBackMismatch)?;
        if stored.event != event || stored.commit != commit {
            return Err(EvidenceServiceError::ReadBackMismatch);
        }
        return Ok(stored);
    }
    Err(EvidenceServiceError::Contention)
}

/// Atomically append an ALLOW decision, verify durable read-back, then obtain a signed receipt.
///
/// # Errors
/// Returns an error for invalid event data, storage contention/failure, read-back mismatch,
/// canonicalization failure, or receipt signer failure.
pub fn append_with_durable_receipt<S: EvidenceStore, K: EvidenceReceiptSigner>(
    store: &S,
    authenticated_tenant_id: &str,
    signer: &K,
    request: &EvidenceAppendRequestV1,
    receipt_id: &str,
    committed_at: &str,
    evidence_key_id: &str,
) -> Result<EvidenceAppendResult, EvidenceServiceError> {
    validate_append_request(authenticated_tenant_id, request)?;
    if request.decision != Some(DecisionOutcome::Allow)
        || [receipt_id, evidence_key_id]
            .iter()
            .any(|value| value.is_empty() || value.trim() != *value || value.len() > 256)
        || !is_utc_rfc3339(committed_at)
    {
        return Err(EvidenceServiceError::InvalidEvent);
    }

    let stored = append_event_durably(store, authenticated_tenant_id, request)?;
    let receipt = create_signed_receipt(
        signer,
        &stored.event,
        &stored.commit,
        receipt_id,
        committed_at,
        evidence_key_id,
    )?;
    let receipt_digest = hex_digest(&receipt.digest()?);
    Ok(EvidenceAppendResult {
        event: stored.event,
        receipt,
        receipt_digest,
    })
}

/// Verify a signed receipt and read back the exact durable event it references.
///
/// # Errors
///
/// Returns an error for invalid signatures, missing events, commit mismatch, or event-binding failure.
pub fn verify_receipt_read_back<S: EvidenceStore>(
    store: &S,
    receipt: &SignedEvidenceReceiptV1,
    public_key: &[u8; 32],
    expected_key_id: &str,
) -> Result<EvidenceEventV1, EvidenceServiceError> {
    receipt.verify_signature(public_key, expected_key_id)?;
    let claims = &receipt.claims;
    let stored = store
        .read_event(&claims.tenant_id, &claims.stream_id, claims.sequence)
        .map_err(|_| EvidenceServiceError::Store)?
        .ok_or(EvidenceServiceError::ReadBackMismatch)?;
    if stored.commit.commit_id != claims.storage_commit_id {
        return Err(EvidenceServiceError::ReceiptBindingMismatch);
    }
    let event = stored.event;
    verify_event(&event).map_err(|_| EvidenceServiceError::ReadBackMismatch)?;
    if event.tenant_id != claims.tenant_id
        || event.stream_id != claims.stream_id
        || event.sequence != claims.sequence
        || event.event_hash != claims.event_hash
        || event.event_type.as_str() != claims.event_type
        || event.request_digest.as_deref() != Some(claims.request_digest.as_str())
        || event.action_digest.as_deref() != Some(claims.action_digest.as_str())
        || event.policy_digest.as_deref() != Some(claims.policy_digest.as_str())
        || event.context_digest.as_deref() != Some(claims.context_digest.as_str())
        || event.decision != Some(DecisionOutcome::Allow)
    {
        return Err(EvidenceServiceError::ReceiptBindingMismatch);
    }
    Ok(event)
}

fn validate_receipt(c: &EvidenceReceiptClaimsV1) -> Result<(), EvidenceServiceError> {
    if c.schema_version != 1 || c.sequence == 0 {
        return Err(EvidenceServiceError::InvalidReceipt);
    }
    for value in [
        c.receipt_id.as_str(),
        c.tenant_id.as_str(),
        c.stream_id.as_str(),
        c.event_type.as_str(),
        c.storage_commit_id.as_str(),
        c.evidence_key_id.as_str(),
    ] {
        if value.is_empty() || value.trim() != value || value.len() > 256 {
            return Err(EvidenceServiceError::InvalidReceipt);
        }
    }
    for value in [
        c.event_hash.as_str(),
        c.request_digest.as_str(),
        c.action_digest.as_str(),
        c.policy_digest.as_str(),
        c.context_digest.as_str(),
    ] {
        if !is_lower_hex_digest(value) {
            return Err(EvidenceServiceError::InvalidReceipt);
        }
    }
    if !is_utc_rfc3339(&c.committed_at) {
        return Err(EvidenceServiceError::InvalidReceipt);
    }
    Ok(())
}

fn domain_message(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + payload.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(payload);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        collections::BTreeMap,
        sync::{
            Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };

    fn draft(sequence: u64, event_id: &str) -> EvidenceEventDraftV1 {
        EvidenceEventDraftV1 {
            schema_version: "agentguard.evidence-v1".to_owned(),
            event_id: event_id.to_owned(),
            tenant_id: "tenant-1".to_owned(),
            stream_id: "stream-1".to_owned(),
            sequence,
            occurred_at: "2026-11-19T00:00:00Z".to_owned(),
            event_type: if sequence == 1 {
                EvidenceEventType::RequestReceived
            } else {
                EvidenceEventType::DecisionRecorded
            },
            request_id: "request-1".to_owned(),
            actor_ref: ActorRefV1 {
                kind: "service".to_owned(),
                id: "runtime".to_owned(),
            },
            request_digest: None,
            action_digest: None,
            policy_digest: None,
            context_digest: None,
            decision: if sequence == 1 {
                None
            } else {
                Some(DecisionOutcome::Allow)
            },
            reason_codes: Vec::new(),
            correction_of_event_id: None,
        }
    }

    fn two_event_stream() -> Vec<EvidenceEventV1> {
        let first = seal_event(draft(1, "event-1"), GENESIS_PREVIOUS_HASH).unwrap();
        let second = seal_event(draft(2, "event-2"), &first.event_hash).unwrap();
        vec![first, second]
    }

    #[test]
    fn seals_and_verifies_complete_stream() {
        let events = two_event_stream();
        assert_eq!(verify_stream(&events), Ok(()));
        assert_eq!(verify_event(&events[0]), Ok(()));
    }

    #[test]
    fn sealing_is_deterministic() {
        let first = seal_event(draft(1, "event-1"), GENESIS_PREVIOUS_HASH).unwrap();
        let second = seal_event(draft(1, "event-1"), GENESIS_PREVIOUS_HASH).unwrap();
        assert_eq!(first.event_hash, second.event_hash);
        assert_eq!(
            first.event_hash,
            "b87836865744006e46c8e3911d7b3f35ce188e6f38aa9df82c559edba22e12a8"
        );
    }

    #[test]
    fn optional_context_digest_preserves_legacy_hash_and_binds_when_present() {
        let absent = seal_event(draft(1, "event-1"), GENESIS_PREVIOUS_HASH).unwrap();
        assert_eq!(
            absent.event_hash,
            "b87836865744006e46c8e3911d7b3f35ce188e6f38aa9df82c559edba22e12a8"
        );

        let mut with_context = draft(1, "event-1");
        with_context.context_digest = Some("a".repeat(64));
        let bound = seal_event(with_context, GENESIS_PREVIOUS_HASH).unwrap();
        assert_ne!(absent.event_hash, bound.event_hash);
        assert_eq!(verify_event(&bound), Ok(()));
    }

    #[test]
    fn detects_payload_and_hash_tampering() {
        let mut events = two_event_stream();
        events[0].request_id = "tampered".to_owned();
        assert_eq!(
            verify_stream(&events),
            Err(EvidenceError::EventHashMismatch)
        );
        let mut events = two_event_stream();
        events[1].event_hash.replace_range(0..1, "f");
        assert_eq!(
            verify_stream(&events),
            Err(EvidenceError::EventHashMismatch)
        );
    }

    #[test]
    fn detects_predecessor_tampering() {
        let mut events = two_event_stream();
        events[1].previous_event_hash = GENESIS_PREVIOUS_HASH.to_owned();
        assert_eq!(
            verify_stream(&events),
            Err(EvidenceError::PreviousHashMismatch)
        );
    }

    #[test]
    fn detects_deletion_reordering_and_duplicates() {
        let events = two_event_stream();
        assert_eq!(
            verify_stream(&events[1..]),
            Err(EvidenceError::SequenceDiscontinuity)
        );
        assert_eq!(
            verify_stream(&[events[1].clone(), events[0].clone()]),
            Err(EvidenceError::SequenceDiscontinuity)
        );
        assert_eq!(
            verify_stream(&[events[0].clone(), events[0].clone()]),
            Err(EvidenceError::SequenceDiscontinuity)
        );
    }

    #[test]
    fn detects_tenant_and_stream_mixing() {
        let mut events = two_event_stream();
        events[1].tenant_id = "tenant-2".to_owned();
        assert_eq!(verify_stream(&events), Err(EvidenceError::TenantMismatch));
        let mut events = two_event_stream();
        events[1].stream_id = "stream-2".to_owned();
        assert_eq!(verify_stream(&events), Err(EvidenceError::StreamMismatch));
    }

    #[test]
    fn enforces_genesis_only_for_the_first_sequence() {
        let non_genesis = "1".repeat(64);
        assert_eq!(
            seal_event(draft(1, "event-1"), &non_genesis),
            Err(EvidenceError::PreviousHashMismatch)
        );
        assert_eq!(
            seal_event(draft(2, "event-2"), GENESIS_PREVIOUS_HASH),
            Err(EvidenceError::PreviousHashMismatch)
        );
    }

    #[test]
    fn rejects_malformed_hashes_and_invalid_drafts() {
        let mut event = seal_event(draft(1, "event-1"), GENESIS_PREVIOUS_HASH).unwrap();
        event.previous_event_hash = "bad".to_owned();
        assert_eq!(
            verify_event(&event),
            Err(EvidenceError::InvalidPreviousHash)
        );
        let mut invalid = draft(1, "event-1");
        invalid.sequence = 0;
        assert_eq!(
            seal_event(invalid, GENESIS_PREVIOUS_HASH),
            Err(EvidenceError::InvalidSequence)
        );
        let mut invalid = draft(1, "event-1");
        invalid.occurred_at = "2026-99-99T99:99:99Z".to_owned();
        assert_eq!(
            seal_event(invalid, GENESIS_PREVIOUS_HASH),
            Err(EvidenceError::InvalidTimestamp)
        );
        let mut invalid = draft(1, "event-1");
        invalid.sequence = MAX_SAFE_INTEGER + 1;
        assert_eq!(
            seal_event(invalid, GENESIS_PREVIOUS_HASH),
            Err(EvidenceError::InvalidSequence)
        );
        let mut invalid = draft(1, "event-1");
        invalid.request_digest = Some("A".repeat(64));
        assert_eq!(
            seal_event(invalid, GENESIS_PREVIOUS_HASH),
            Err(EvidenceError::InvalidDigest)
        );
    }

    #[test]
    fn durable_append_rejects_tenant_not_bound_to_authenticated_context() {
        let request = EvidenceAppendRequestV1 {
            event_id: "event-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            stream_id: "stream-1".to_owned(),
            occurred_at: "2026-11-19T00:00:00Z".to_owned(),
            event_type: EvidenceEventType::DecisionRecorded,
            request_id: "request-1".to_owned(),
            actor_ref: ActorRefV1 {
                kind: "service".to_owned(),
                id: "runtime".to_owned(),
            },
            request_digest: Some("a".repeat(64)),
            action_digest: Some("b".repeat(64)),
            policy_digest: Some("c".repeat(64)),
            context_digest: Some("d".repeat(64)),
            decision: Some(DecisionOutcome::Allow),
            reason_codes: Vec::new(),
            correction_of_event_id: None,
        };
        assert_eq!(
            validate_append_request("tenant-2", &request),
            Err(EvidenceServiceError::InvalidEvent)
        );
        assert_eq!(validate_append_request("tenant-1", &request), Ok(()));
    }

    #[test]
    fn flat_event_json_round_trips_and_rejects_unknown_fields() {
        let event = seal_event(draft(1, "event-1"), GENESIS_PREVIOUS_HASH).unwrap();
        let bytes = serde_json::to_vec(&event).unwrap();
        assert_eq!(
            serde_json::from_slice::<EvidenceEventV1>(&bytes).unwrap(),
            event
        );
        assert!(
            serde_json::from_slice::<EvidenceEventV1>(
                br#"{"schema_version":"agentguard.evidence-v1","unknown":true}"#
            )
            .is_err()
        );
    }
    #[derive(Default)]
    struct MemoryEvidenceStore {
        streams: Mutex<BTreeMap<(String, String), Vec<StoredEvidenceEvent>>>,
        conflict_once: AtomicBool,
    }

    impl EvidenceStore for MemoryEvidenceStore {
        fn read_head(
            &self,
            tenant_id: &str,
            stream_id: &str,
        ) -> Result<Option<EvidenceStreamHead>, EvidenceStoreError> {
            let streams = self
                .streams
                .lock()
                .map_err(|_| EvidenceStoreError::Unavailable)?;
            Ok(streams
                .get(&(tenant_id.to_owned(), stream_id.to_owned()))
                .and_then(|events| events.last())
                .map(|stored| EvidenceStreamHead {
                    sequence: stored.event.sequence,
                    event_hash: stored.event.event_hash.clone(),
                }))
        }

        fn append_if_head_matches(
            &self,
            event: &EvidenceEventV1,
            expected: Option<&EvidenceStreamHead>,
        ) -> Result<DurableCommitRef, EvidenceStoreError> {
            if self.conflict_once.swap(false, Ordering::SeqCst) {
                return Err(EvidenceStoreError::HeadConflict);
            }
            verify_event(event).map_err(|_| EvidenceStoreError::Rejected)?;
            let mut streams = self
                .streams
                .lock()
                .map_err(|_| EvidenceStoreError::Unavailable)?;
            let key = (event.tenant_id.clone(), event.stream_id.clone());
            let events = streams.entry(key).or_default();
            let actual = events.last().map(|stored| EvidenceStreamHead {
                sequence: stored.event.sequence,
                event_hash: stored.event.event_hash.clone(),
            });
            if actual.as_ref() != expected {
                return Err(EvidenceStoreError::HeadConflict);
            }
            let expected_sequence = actual.map_or(1, |head| head.sequence.saturating_add(1));
            if event.sequence != expected_sequence
                || events
                    .iter()
                    .any(|stored| stored.event.event_id == event.event_id)
            {
                return Err(EvidenceStoreError::Duplicate);
            }
            let commit = DurableCommitRef {
                commit_id: format!("commit-{}", event.sequence),
            };
            events.push(StoredEvidenceEvent {
                event: event.clone(),
                commit: commit.clone(),
            });
            Ok(commit)
        }

        fn read_event(
            &self,
            tenant_id: &str,
            stream_id: &str,
            sequence: u64,
        ) -> Result<Option<StoredEvidenceEvent>, EvidenceStoreError> {
            let streams = self
                .streams
                .lock()
                .map_err(|_| EvidenceStoreError::Unavailable)?;
            Ok(streams
                .get(&(tenant_id.to_owned(), stream_id.to_owned()))
                .and_then(|events| {
                    events
                        .iter()
                        .find(|stored| stored.event.sequence == sequence)
                })
                .cloned())
        }
    }

    struct TestReceiptSigner {
        signing_key: SigningKey,
        key_id: String,
    }

    impl EvidenceReceiptSigner for TestReceiptSigner {
        fn sign_receipt(&self, message: &[u8]) -> Result<SignatureEnvelope, EvidenceSignerError> {
            let signature = self.signing_key.sign(message);
            Ok(SignatureEnvelope {
                algorithm: SignatureAlgorithm::Ed25519,
                key_id: self.key_id.clone(),
                signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            })
        }
    }

    struct FailingReceiptSigner;

    impl EvidenceReceiptSigner for FailingReceiptSigner {
        fn sign_receipt(&self, _message: &[u8]) -> Result<SignatureEnvelope, EvidenceSignerError> {
            Err(EvidenceSignerError::Unavailable)
        }
    }

    fn append_request() -> EvidenceAppendRequestV1 {
        EvidenceAppendRequestV1 {
            event_id: "decision-event-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            stream_id: "decision-stream-1".to_owned(),
            occurred_at: "2026-11-19T00:00:00Z".to_owned(),
            event_type: EvidenceEventType::DecisionRecorded,
            request_id: "request-1".to_owned(),
            actor_ref: ActorRefV1 {
                kind: "agent".to_owned(),
                id: "agent-1".to_owned(),
            },
            request_digest: Some("a".repeat(64)),
            action_digest: Some("b".repeat(64)),
            policy_digest: Some("c".repeat(64)),
            context_digest: Some("d".repeat(64)),
            decision: Some(DecisionOutcome::Allow),
            reason_codes: vec!["ALLOW_RULE_MATCHED".to_owned()],
            correction_of_event_id: None,
        }
    }

    fn test_receipt_signer() -> TestReceiptSigner {
        TestReceiptSigner {
            signing_key: SigningKey::from_bytes(&[42_u8; 32]),
            key_id: "evidence-key-1".to_owned(),
        }
    }

    #[test]
    fn durable_receipt_is_signed_only_after_atomic_append_and_readback() {
        let store = MemoryEvidenceStore::default();
        let signer = test_receipt_signer();
        let public_key = signer.signing_key.verifying_key().to_bytes();
        let result = append_with_durable_receipt(
            &store,
            "tenant-1",
            &signer,
            &append_request(),
            "receipt-1",
            "2026-11-19T00:00:01Z",
            "evidence-key-1",
        )
        .unwrap();

        assert_eq!(result.event.sequence, 1);
        assert_eq!(
            verify_receipt_read_back(&store, &result.receipt, &public_key, "evidence-key-1")
                .unwrap(),
            result.event
        );
    }

    #[test]
    fn durable_append_retries_head_conflict_without_duplicate_sequence() {
        let store = MemoryEvidenceStore::default();
        store.conflict_once.store(true, Ordering::SeqCst);
        let signer = test_receipt_signer();
        let result = append_with_durable_receipt(
            &store,
            "tenant-1",
            &signer,
            &append_request(),
            "receipt-1",
            "2026-11-19T00:00:01Z",
            "evidence-key-1",
        )
        .unwrap();

        assert_eq!(result.event.sequence, 1);
        assert_eq!(
            store
                .read_head("tenant-1", "decision-stream-1")
                .unwrap()
                .unwrap()
                .sequence,
            1
        );
    }

    #[test]
    fn deny_and_approval_decisions_are_durable_without_execution_receipts() {
        let store = MemoryEvidenceStore::default();

        let mut deny = append_request();
        deny.event_id = "deny-event-1".to_owned();
        deny.decision = Some(DecisionOutcome::Deny);
        let deny_event = append_event_durably(&store, "tenant-1", &deny).unwrap();
        assert_eq!(deny_event.event.decision, Some(DecisionOutcome::Deny));
        assert_eq!(deny_event.event.sequence, 1);

        let mut approval = append_request();
        approval.event_id = "approval-event-1".to_owned();
        approval.decision = Some(DecisionOutcome::RequireApproval);
        let approval_event = append_event_durably(&store, "tenant-1", &approval).unwrap();
        assert_eq!(
            approval_event.event.decision,
            Some(DecisionOutcome::RequireApproval)
        );
        assert_eq!(approval_event.event.sequence, 2);
    }

    #[test]
    fn signer_failure_does_not_rollback_committed_evidence() {
        let store = MemoryEvidenceStore::default();
        let result = append_with_durable_receipt(
            &store,
            "tenant-1",
            &FailingReceiptSigner,
            &append_request(),
            "receipt-1",
            "2026-11-19T00:00:01Z",
            "evidence-key-1",
        );
        assert_eq!(result, Err(EvidenceServiceError::Signer));
        assert_eq!(
            store
                .read_head("tenant-1", "decision-stream-1")
                .unwrap()
                .unwrap()
                .sequence,
            1
        );
    }

    #[test]
    fn receipt_claim_tampering_invalidates_signature() {
        let store = MemoryEvidenceStore::default();
        let signer = test_receipt_signer();
        let public_key = signer.signing_key.verifying_key().to_bytes();
        let mut result = append_with_durable_receipt(
            &store,
            "tenant-1",
            &signer,
            &append_request(),
            "receipt-1",
            "2026-11-19T00:00:01Z",
            "evidence-key-1",
        )
        .unwrap();
        result.receipt.claims.action_digest = "e".repeat(64);
        assert_eq!(
            verify_receipt_read_back(&store, &result.receipt, &public_key, "evidence-key-1"),
            Err(EvidenceServiceError::InvalidSignature)
        );
    }
}
