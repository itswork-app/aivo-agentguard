//! Append-only evidence event integrity primitives.
//!
//! This crate prepares and verifies evidence records. It does not provide a
//! durable store; production adapters must implement atomic durable append.

use agentguard_canonical::{DigestDomain, digest_hex};
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
    if draft.sequence == 0 {
        return Err(EvidenceError::InvalidSequence);
    }
    if !draft.occurred_at.ends_with('Z')
        || !draft.occurred_at.is_ascii()
        || draft.occurred_at.len() < 20
    {
        return Err(EvidenceError::InvalidTimestamp);
    }
    for digest in [
        &draft.request_digest,
        &draft.action_digest,
        &draft.policy_digest,
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
pub fn seal_event(
    draft: EvidenceEventDraftV1,
    previous_event_hash: &str,
) -> Result<EvidenceEventV1, EvidenceError> {
    validate_draft(&draft)?;
    if !is_lower_hex_digest(previous_event_hash) {
        return Err(EvidenceError::InvalidPreviousHash);
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
        decision: event.decision,
        reason_codes: event.reason_codes.clone(),
        correction_of_event_id: event.correction_of_event_id.clone(),
    };
    validate_draft(&draft)?;
    if !is_lower_hex_digest(&event.previous_event_hash) {
        return Err(EvidenceError::InvalidPreviousHash);
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(verify_stream(&events), Err(EvidenceError::EventHashMismatch));
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
        invalid.request_digest = Some("A".repeat(64));
        assert_eq!(
            seal_event(invalid, GENESIS_PREVIOUS_HASH),
            Err(EvidenceError::InvalidDigest)
        );
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
}
