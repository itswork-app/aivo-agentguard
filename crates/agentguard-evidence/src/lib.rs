//! Append-only evidence events, hash-chain verification, and durable receipts.
//! Storage and signing are explicit ports; private keys never enter this crate.

use agentguard_core::{
    CanonicalizationError, CryptoError, SignatureAlgorithm, SignatureEnvelope, canonical_json,
    domain_digest, hex_digest, verify_ed25519,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const EVENT_HASH_DOMAIN: &[u8] = b"AIVO-AGENTGUARD-EVENT-V1\0";
pub const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"AIVO-AGENTGUARD-EVIDENCE-RECEIPT-V1\0";

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
pub struct EvidenceEventDraftV1 {
    pub schema_version: u8,
    pub event_id: String,
    pub tenant_id: String,
    pub stream_id: String,
    pub occurred_at: String,
    pub event_type: EvidenceEventType,
    pub request_id: String,
    pub actor_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(default)]
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEventV1 {
    pub schema_version: u8,
    pub event_id: String,
    pub tenant_id: String,
    pub stream_id: String,
    pub sequence: u64,
    pub occurred_at: String,
    pub event_type: EvidenceEventType,
    pub request_id: String,
    pub actor_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    pub previous_event_hash: String,
    pub event_hash: String,
}

#[derive(Serialize)]
struct HashPayload<'a> {
    schema_version: u8,
    event_id: &'a str,
    tenant_id: &'a str,
    stream_id: &'a str,
    sequence: u64,
    occurred_at: &'a str,
    event_type: EvidenceEventType,
    request_id: &'a str,
    actor_ref: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_digest: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_digest: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_digest: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context_digest: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: &'a Option<String>,
    reason_codes: &'a [String],
    previous_event_hash: &'a str,
}

impl EvidenceEventV1 {
    fn hash_payload(&self) -> HashPayload<'_> {
        HashPayload {
            schema_version: self.schema_version,
            event_id: &self.event_id,
            tenant_id: &self.tenant_id,
            stream_id: &self.stream_id,
            sequence: self.sequence,
            occurred_at: &self.occurred_at,
            event_type: self.event_type,
            request_id: &self.request_id,
            actor_ref: &self.actor_ref,
            request_digest: &self.request_digest,
            action_digest: &self.action_digest,
            policy_digest: &self.policy_digest,
            context_digest: &self.context_digest,
            decision: &self.decision,
            reason_codes: &self.reason_codes,
            previous_event_hash: &self.previous_event_hash,
        }
    }

    ///
    /// # Errors
    /// Returns an error if canonical event serialization fails.
    pub fn recompute_hash(&self) -> Result<String, EvidenceError> {
        let bytes = canonical_json(&self.hash_payload())?;
        Ok(hex_digest(&domain_digest(EVENT_HASH_DOMAIN, &bytes)))
    }

    ///
    /// # Errors
    /// Returns an error if event fields or the computed hash are invalid.
    pub fn verify_integrity(&self) -> Result<(), EvidenceError> {
        validate_event(self)?;
        if self.recompute_hash()? != self.event_hash {
            return Err(EvidenceError::EventHashMismatch);
        }
        Ok(())
    }
}

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

/// Implementations must atomically compare the expected head, allocate by
/// inserting the supplied next event, and durably commit it. No update/delete
/// method is part of this interface. A successful append is a durable commit.
pub trait EvidenceStore: Send + Sync {
    /// Read the current committed stream head.
    ///
    /// # Errors
    /// Returns an error if the evidence store is unavailable or the stream cannot be read.
    fn read_head(
        &self,
        tenant_id: &str,
        stream_id: &str,
    ) -> Result<Option<EvidenceStreamHead>, EvidenceStoreError>;
    /// Atomically append the event if the expected stream head still matches.
    ///
    /// # Errors
    /// Returns a conflict when another writer advanced the stream, or a storage error.
    fn append_if_head_matches(
        &self,
        event: &EvidenceEventV1,
        expected: Option<&EvidenceStreamHead>,
    ) -> Result<DurableCommitRef, EvidenceStoreError>;
    /// Read an event and its durable commit identity by exact stream sequence.
    ///
    /// # Errors
    /// Returns an error if the evidence store is unavailable or the read fails.
    fn read_event(
        &self,
        tenant_id: &str,
        stream_id: &str,
        sequence: u64,
    ) -> Result<Option<StoredEvidenceEvent>, EvidenceStoreError>;
}

/// Dedicated evidence-purpose signer; production implementations isolate its
/// private key and authorize only receipt-signing requests.
pub trait EvidenceReceiptSigner: Send + Sync {
    /// Sign the supplied domain-separated receipt message.
    ///
    /// # Errors
    /// Returns an error if the signer is unavailable or rejects the request.
    fn sign_receipt(&self, message: &[u8]) -> Result<SignatureEnvelope, EvidenceSignerError>;
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
    /// Compute a domain-separated digest of the complete signed receipt.
    ///
    /// # Errors
    /// Returns an error if canonical receipt serialization fails.
    pub fn digest(&self) -> Result<[u8; 32], EvidenceError> {
        let bytes = canonical_json(self)?;
        Ok(domain_digest(
            b"AIVO-AGENTGUARD-EVIDENCE-RECEIPT-DIGEST-V1\0",
            &bytes,
        ))
    }

    /// Caller resolves this key from the evidence-receipt purpose registry and
    /// checks its current revocation status before verification.
    ///
    /// # Errors
    /// Returns an error if claims, key identity, signature encoding, or signature are invalid.
    pub fn verify_signature(
        &self,
        public_key: &[u8; 32],
        expected_key_id: &str,
    ) -> Result<(), EvidenceError> {
        validate_receipt(&self.claims)?;
        if self.signature.key_id != expected_key_id
            || self.claims.evidence_key_id != expected_key_id
            || self.signature.algorithm != SignatureAlgorithm::Ed25519
        {
            return Err(EvidenceError::ReceiptKeyMismatch);
        }
        let claims = canonical_json(&self.claims)?;
        let message = domain_message(RECEIPT_SIGNATURE_DOMAIN, &claims);
        verify_ed25519(public_key, &self.signature, &message)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceAppendResult {
    pub event: EvidenceEventV1,
    pub receipt: SignedEvidenceReceiptV1,
    pub receipt_digest: String,
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("canonicalization failed: {0}")]
    Canonicalization(#[from] CanonicalizationError),
    #[error("storage failed: {0}")]
    Store(#[from] EvidenceStoreError),
    #[error("signer failed: {0}")]
    Signer(#[from] EvidenceSignerError),
    #[error("signature verification failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("invalid evidence event")]
    InvalidEvent,
    #[error("invalid evidence receipt")]
    InvalidReceipt,
    #[error("event hash mismatch")]
    EventHashMismatch,
    #[error("committed event read-back mismatch")]
    ReadBackMismatch,
    #[error("receipt does not bind committed event")]
    ReceiptBindingMismatch,
    #[error("receipt signer key mismatch")]
    ReceiptKeyMismatch,
    #[error("stream contention exceeded retry budget")]
    Contention,
}

/// Append with bounded optimistic retries. Receipt signing happens only after
/// durable commit and exact read-back verification have succeeded.
///
/// # Errors
/// Returns an error for invalid input, storage failure, failed read-back, or signer failure.
pub fn append_with_durable_receipt<S: EvidenceStore, K: EvidenceReceiptSigner>(
    store: &S,
    signer: &K,
    draft: &EvidenceEventDraftV1,
    receipt_id: &str,
    committed_at: &str,
    evidence_key_id: &str,
) -> Result<EvidenceAppendResult, EvidenceError> {
    validate_draft(draft)?;
    identifier(receipt_id)?;
    identifier(evidence_key_id)?;
    timestamp(committed_at)?;

    for _ in 0..8 {
        let head = store.read_head(&draft.tenant_id, &draft.stream_id)?;
        let (sequence, previous_event_hash) = match &head {
            Some(value) => (
                value
                    .sequence
                    .checked_add(1)
                    .ok_or(EvidenceError::InvalidEvent)?,
                value.event_hash.clone(),
            ),
            None => (1, "0".repeat(64)),
        };
        let mut event = from_draft(draft, sequence, previous_event_hash);
        event.event_hash = event.recompute_hash()?;
        event.verify_integrity()?;
        let commit = match store.append_if_head_matches(&event, head.as_ref()) {
            Ok(value) => value,
            Err(EvidenceStoreError::HeadConflict) => continue,
            Err(error) => return Err(error.into()),
        };
        identifier(&commit.commit_id)?;

        let stored = store
            .read_event(&event.tenant_id, &event.stream_id, event.sequence)?
            .ok_or(EvidenceError::ReadBackMismatch)?;
        stored.event.verify_integrity()?;
        if stored.event != event || stored.commit != commit {
            return Err(EvidenceError::ReadBackMismatch);
        }

        let claims =
            make_receipt_claims(&event, &commit, receipt_id, committed_at, evidence_key_id)?;
        let bytes = canonical_json(&claims)?;
        let signature = signer.sign_receipt(&domain_message(RECEIPT_SIGNATURE_DOMAIN, &bytes))?;
        if signature.algorithm != SignatureAlgorithm::Ed25519
            || signature.key_id != evidence_key_id
            || signature.validate_shape().is_err()
        {
            return Err(EvidenceError::ReceiptKeyMismatch);
        }
        let receipt = SignedEvidenceReceiptV1 { claims, signature };
        let receipt_digest = hex_digest(&receipt.digest()?);
        return Ok(EvidenceAppendResult {
            event,
            receipt,
            receipt_digest,
        });
    }
    Err(EvidenceError::Contention)
}

/// Verify receipt signature and retrieve the exact referenced event from the
/// evidence store. Caller must independently check key purpose and revocation.
///
/// # Errors
/// Returns an error if the receipt signature, durable commit reference, or event binding is invalid.
pub fn verify_receipt_read_back<S: EvidenceStore>(
    store: &S,
    receipt: &SignedEvidenceReceiptV1,
    public_key: &[u8; 32],
    expected_key_id: &str,
) -> Result<EvidenceEventV1, EvidenceError> {
    receipt.verify_signature(public_key, expected_key_id)?;
    let claims = &receipt.claims;
    let stored = store
        .read_event(&claims.tenant_id, &claims.stream_id, claims.sequence)?
        .ok_or(EvidenceError::ReadBackMismatch)?;
    if stored.commit.commit_id != claims.storage_commit_id {
        return Err(EvidenceError::ReceiptBindingMismatch);
    }
    let event = stored.event;
    event.verify_integrity()?;
    if event.event_hash != claims.event_hash
        || event.event_type.as_str() != claims.event_type
        || event.request_digest.as_deref() != Some(claims.request_digest.as_str())
        || event.action_digest.as_deref() != Some(claims.action_digest.as_str())
        || event.policy_digest.as_deref() != Some(claims.policy_digest.as_str())
        || event.context_digest.as_deref() != Some(claims.context_digest.as_str())
    {
        return Err(EvidenceError::ReceiptBindingMismatch);
    }
    Ok(event)
}

fn from_draft(
    d: &EvidenceEventDraftV1,
    sequence: u64,
    previous_event_hash: String,
) -> EvidenceEventV1 {
    EvidenceEventV1 {
        schema_version: d.schema_version,
        event_id: d.event_id.clone(),
        tenant_id: d.tenant_id.clone(),
        stream_id: d.stream_id.clone(),
        sequence,
        occurred_at: d.occurred_at.clone(),
        event_type: d.event_type,
        request_id: d.request_id.clone(),
        actor_ref: d.actor_ref.clone(),
        request_digest: d.request_digest.clone(),
        action_digest: d.action_digest.clone(),
        policy_digest: d.policy_digest.clone(),
        context_digest: d.context_digest.clone(),
        decision: d.decision.clone(),
        reason_codes: d.reason_codes.clone(),
        previous_event_hash,
        event_hash: String::new(),
    }
}

fn make_receipt_claims(
    e: &EvidenceEventV1,
    c: &DurableCommitRef,
    receipt_id: &str,
    committed_at: &str,
    key_id: &str,
) -> Result<EvidenceReceiptClaimsV1, EvidenceError> {
    Ok(EvidenceReceiptClaimsV1 {
        schema_version: 1,
        receipt_id: receipt_id.into(),
        tenant_id: e.tenant_id.clone(),
        stream_id: e.stream_id.clone(),
        sequence: e.sequence,
        event_hash: e.event_hash.clone(),
        event_type: e.event_type.as_str().into(),
        request_digest: required_digest(e.request_digest.as_ref())?,
        action_digest: required_digest(e.action_digest.as_ref())?,
        policy_digest: required_digest(e.policy_digest.as_ref())?,
        context_digest: required_digest(e.context_digest.as_ref())?,
        storage_commit_id: c.commit_id.clone(),
        committed_at: committed_at.into(),
        evidence_key_id: key_id.into(),
    })
}

fn required_digest(value: Option<&String>) -> Result<String, EvidenceError> {
    let v = value.ok_or(EvidenceError::InvalidReceipt)?;
    digest(v)?;
    Ok(v.clone())
}
fn validate_draft(d: &EvidenceEventDraftV1) -> Result<(), EvidenceError> {
    if d.schema_version != 1
        || d.reason_codes.len() > 64
        || d.reason_codes.iter().any(|v| v.is_empty() || v.len() > 128)
        || d.decision
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 32)
    {
        return Err(EvidenceError::InvalidEvent);
    }
    for v in [
        &d.event_id,
        &d.tenant_id,
        &d.stream_id,
        &d.request_id,
        &d.actor_ref,
    ] {
        identifier(v)?;
    }
    timestamp(&d.occurred_at)?;
    for v in [
        &d.request_digest,
        &d.action_digest,
        &d.policy_digest,
        &d.context_digest,
    ]
    .into_iter()
    .flatten()
    {
        digest(v)?;
    }
    Ok(())
}
fn validate_event(e: &EvidenceEventV1) -> Result<(), EvidenceError> {
    if e.sequence == 0 {
        return Err(EvidenceError::InvalidEvent);
    }
    digest(&e.previous_event_hash)?;
    validate_draft(&EvidenceEventDraftV1 {
        schema_version: e.schema_version,
        event_id: e.event_id.clone(),
        tenant_id: e.tenant_id.clone(),
        stream_id: e.stream_id.clone(),
        occurred_at: e.occurred_at.clone(),
        event_type: e.event_type,
        request_id: e.request_id.clone(),
        actor_ref: e.actor_ref.clone(),
        request_digest: e.request_digest.clone(),
        action_digest: e.action_digest.clone(),
        policy_digest: e.policy_digest.clone(),
        context_digest: e.context_digest.clone(),
        decision: e.decision.clone(),
        reason_codes: e.reason_codes.clone(),
    })
}
fn validate_receipt(c: &EvidenceReceiptClaimsV1) -> Result<(), EvidenceError> {
    if c.schema_version != 1 || c.sequence == 0 {
        return Err(EvidenceError::InvalidReceipt);
    }
    for v in [
        &c.receipt_id,
        &c.tenant_id,
        &c.stream_id,
        &c.event_type,
        &c.storage_commit_id,
        &c.evidence_key_id,
    ] {
        identifier(v).map_err(|_| EvidenceError::InvalidReceipt)?;
    }
    for v in [
        &c.event_hash,
        &c.request_digest,
        &c.action_digest,
        &c.policy_digest,
        &c.context_digest,
    ] {
        digest(v).map_err(|_| EvidenceError::InvalidReceipt)?;
    }
    timestamp(&c.committed_at).map_err(|_| EvidenceError::InvalidReceipt)
}
fn identifier(v: &str) -> Result<(), EvidenceError> {
    if v.is_empty() || v.len() > 256 || v.trim() != v || v.chars().any(char::is_control) {
        return Err(EvidenceError::InvalidEvent);
    }
    Ok(())
}
fn digest(v: &str) -> Result<(), EvidenceError> {
    if v.len() != 64
        || !v
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(EvidenceError::InvalidEvent);
    }
    Ok(())
}
fn timestamp(v: &str) -> Result<(), EvidenceError> {
    let b = v.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
        || b.iter()
            .enumerate()
            .any(|(i, x)| ![4, 7, 10, 13, 16, 19].contains(&i) && !x.is_ascii_digit())
    {
        return Err(EvidenceError::InvalidEvent);
    }
    Ok(())
}
fn domain_message(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(domain.len() + payload.len());
    v.extend_from_slice(domain);
    v.extend_from_slice(payload);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    fn draft() -> EvidenceEventDraftV1 {
        EvidenceEventDraftV1 {
            schema_version: 1,
            event_id: "event-1".into(),
            tenant_id: "tenant-1".into(),
            stream_id: "stream-1".into(),
            occurred_at: "2026-11-17T01:00:00Z".into(),
            event_type: EvidenceEventType::DecisionRecorded,
            request_id: "request-1".into(),
            actor_ref: "agent:agent-1".into(),
            request_digest: Some("a".repeat(64)),
            action_digest: Some("b".repeat(64)),
            policy_digest: Some("c".repeat(64)),
            context_digest: Some("d".repeat(64)),
            decision: Some("ALLOW".into()),
            reason_codes: vec!["POLICY_MATCH".into()],
        }
    }
    #[test]
    fn event_hash_is_stable_and_excludes_its_own_field() {
        let mut event = from_draft(&draft(), 1, "0".repeat(64));
        event.event_hash = event.recompute_hash().unwrap();
        event.verify_integrity().unwrap();
        let original = event.event_hash.clone();
        event.event_hash = "e".repeat(64);
        assert_ne!(event.recompute_hash().unwrap(), event.event_hash);
        event.event_hash = original;
        event.verify_integrity().unwrap();
    }
    #[test]
    fn genesis_uses_zero_hash() {
        let event = from_draft(&draft(), 1, "0".repeat(64));
        assert_eq!(event.previous_event_hash, "0".repeat(64));
    }
    #[test]
    fn rejects_bad_digest_and_timestamp() {
        assert!(digest(&"A".repeat(64)).is_err());
        assert!(timestamp("2026-11-17T01:00:00+00:00").is_err());
        assert!(timestamp("2026-11-17T01:00:00.1Z").is_err());
    }
    #[test]
    fn event_names_are_stable() {
        assert_eq!(
            EvidenceEventType::DecisionRecorded.as_str(),
            "DECISION_RECORDED"
        );
        assert_eq!(
            EvidenceEventType::ExecutionUnknown.as_str(),
            "EXECUTION_UNKNOWN"
        );
    }
}
