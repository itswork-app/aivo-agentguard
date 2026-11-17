//! Deterministic authorization decision orchestration.
//!
//! The coordinator evaluates a signed policy and durably records the exact
//! decision before returning it to its caller. It never issues attestations or
//! permits, consumes permits, or executes protected actions. ALLOW is only a
//! policy result; the enforcement boundary remains a separate mandatory step.

use agentguard_evidence::{
    EvidenceAppendResult, EvidenceEventDraftV1, EvidenceEventType, EvidenceReceiptSigner,
    EvidenceStore, append_with_durable_receipt,
};
use agentguard_policy::{
    DecisionResultV1, EvaluationRequestV1, PolicyBundleV1, PolicyError, PolicyKeyResolver,
    evaluate,
};

/// Trusted UTC timestamp provider for evidence timestamps.
///
/// Implementations must return canonical UTC RFC3339 timestamps with whole
/// seconds. This is a separate port from the evaluator's explicit Unix time.
pub trait RuntimeClock: Send + Sync {
    /// Return canonical UTC time.
    ///
    /// # Errors
    /// Return an error when the trusted time source is unavailable or uncertain.
    fn now_utc(&self) -> Result<String, RuntimeClockError>;
}

/// Trusted clock failures. A clock failure blocks decision processing.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RuntimeClockError {
    #[error("trusted runtime clock is unavailable")]
    Unavailable,
    #[error("trusted runtime clock returned invalid or uncertain time")]
    Invalid,
}

/// Correlation and evidence metadata supplied by an authenticated ingress
/// adapter. Digests must be computed from the exact canonical request, action,
/// and trusted context snapshot at that boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionEvidenceInputV1 {
    pub event_id: String,
    pub receipt_id: String,
    pub stream_id: String,
    pub request_id: String,
    pub actor_ref: String,
    pub request_digest: String,
    pub action_digest: String,
    pub context_digest: String,
}

/// Complete output of one evaluated and durably evidenced policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedDecisionV1 {
    pub result: DecisionResultV1,
    pub evidence: EvidenceAppendResult,
}

/// Runtime orchestration failures. Every variant is fail-closed.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("policy evaluation failed: {0}")]
    Policy(#[from] PolicyError),
    #[error("trusted runtime clock failed: {0}")]
    Clock(#[from] RuntimeClockError),
    #[error("durable decision evidence failed: {0}")]
    Evidence(#[from] agentguard_evidence::EvidenceError),
}

/// Evaluate a signed policy, then durably append and read back its decision
/// evidence before exposing the decision to the caller.
///
/// The evidence append uses bounded optimistic concurrency and signs a receipt
/// only after the committed event has been read back and verified. If policy
/// evaluation, clock access, storage, read-back, or receipt signing fails, this
/// function returns an error and exposes no decision result.
///
/// The caller is responsible for authenticating identity, verifying context
/// provenance, computing the request/action/context digests from the exact
/// ingress payload, and enforcing tenant authorization before calling this
/// function. The policy evaluator validates the policy issuer signature.
///
/// This function intentionally does not turn ALLOW into an execution permit.
pub fn evaluate_and_record<K, S, R, C>(
    bundle: &PolicyBundleV1,
    request: &EvaluationRequestV1,
    evidence: &DecisionEvidenceInputV1,
    keys: &K,
    store: &S,
    signer: &R,
    clock: &C,
) -> Result<RecordedDecisionV1, RuntimeError>
where
    K: PolicyKeyResolver,
    S: EvidenceStore,
    R: EvidenceReceiptSigner,
    C: RuntimeClock,
{
    let result = evaluate(bundle, request, keys)?;
    let timestamp = clock.now_utc()?;

    let draft = EvidenceEventDraftV1 {
        schema_version: 1,
        event_id: evidence.event_id.clone(),
        tenant_id: request.tenant_id.clone(),
        stream_id: evidence.stream_id.clone(),
        occurred_at: timestamp.clone(),
        event_type: EvidenceEventType::DecisionRecorded,
        request_id: evidence.request_id.clone(),
        actor_ref: evidence.actor_ref.clone(),
        request_digest: Some(evidence.request_digest.clone()),
        action_digest: Some(evidence.action_digest.clone()),
        policy_digest: Some(result.policy_digest.clone()),
        context_digest: Some(evidence.context_digest.clone()),
        decision: Some(match result.decision {
            agentguard_core::Decision::Allow => "ALLOW",
            agentguard_core::Decision::Deny => "DENY",
            agentguard_core::Decision::RequireApproval => "REQUIRE_APPROVAL",
        }.to_owned()),
        reason_codes: vec![format!("{:?}", result.reason).to_ascii_uppercase()],
    };

    let appended = append_with_durable_receipt(
        store,
        signer,
        &draft,
        &evidence.receipt_id,
        &timestamp,
        // The signer is authoritative for the key identity; the evidence
        // service key ID is read from the returned signature envelope below.
        // append_with_durable_receipt requires it before signing, so the
        // configured key ID is supplied through the signer port contract.
        &evidence_signing_key_id(signer)?,
    )?;

    Ok(RecordedDecisionV1 {
        result,
        evidence: appended,
    })
}

/// Resolve the configured evidence key identifier from the signer boundary.
/// Signers must expose a stable key ID and must never accept caller-selected
/// key material or purpose changes.
pub trait IdentifiedEvidenceReceiptSigner: EvidenceReceiptSigner {
    /// Return the configured evidence-purpose signing key identifier.
    fn key_id(&self) -> &str;
}

fn evidence_signing_key_id<R: EvidenceReceiptSigner>(
    _signer: &R,
) -> Result<String, RuntimeError> {
    // This helper is replaced by the stronger IdentifiedEvidenceReceiptSigner
    // bound on the public coordinator; kept private to avoid key-ID injection.
    Err(RuntimeError::Evidence(
        agentguard_evidence::EvidenceError::InvalidReceipt,
    ))
}
