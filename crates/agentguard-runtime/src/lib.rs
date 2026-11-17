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
    DecisionResultV1, EvaluationRequestV1, PolicyBundleV1, PolicyError, PolicyKeyResolver, evaluate,
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
    R: IdentifiedEvidenceReceiptSigner,
    C: RuntimeClock,
{
    if evidence.actor_ref.trim().is_empty()
        || evidence.actor_ref.trim() != evidence.actor_ref
        || evidence.request_id.trim().is_empty()
        || evidence.request_id.trim() != evidence.request_id
        || evidence.event_id.trim().is_empty()
        || evidence.event_id.trim() != evidence.event_id
        || evidence.receipt_id.trim().is_empty()
        || evidence.receipt_id.trim() != evidence.receipt_id
        || evidence.stream_id.trim().is_empty()
        || evidence.stream_id.trim() != evidence.stream_id
    {
        return Err(RuntimeError::Evidence(
            agentguard_evidence::EvidenceError::InvalidEvent,
        ));
    }
    if signer.key_id().trim().is_empty() || signer.key_id().trim() != signer.key_id() {
        return Err(RuntimeError::Evidence(
            agentguard_evidence::EvidenceError::InvalidReceipt,
        ));
    }
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
        decision: Some(
            match result.decision {
                agentguard_core::Decision::Allow => "ALLOW",
                agentguard_core::Decision::Deny => "DENY",
                agentguard_core::Decision::RequireApproval => "REQUIRE_APPROVAL",
            }
            .to_owned(),
        ),
        reason_codes: vec![
            match result.reason {
                agentguard_policy::DecisionReason::AllowRuleMatched => "ALLOW_RULE_MATCHED",
                agentguard_policy::DecisionReason::DenyRuleMatched => "DENY_RULE_MATCHED",
                agentguard_policy::DecisionReason::ApprovalProfileRequired => {
                    "APPROVAL_PROFILE_REQUIRED"
                }
                agentguard_policy::DecisionReason::NoMatchingAllowRule => "NO_MATCHING_ALLOW_RULE",
            }
            .to_owned(),
        ],
    };

    let appended = append_with_durable_receipt(
        store,
        signer,
        &draft,
        &evidence.receipt_id,
        &timestamp,
        signer.key_id(),
    )?;

    Ok(RecordedDecisionV1 {
        result,
        evidence: appended,
    })
}

/// Evidence signer with a fixed, purpose-scoped key identity.
/// Implementations must expose a stable key ID and must never accept
/// caller-selected key material or purpose changes.
pub trait IdentifiedEvidenceReceiptSigner: EvidenceReceiptSigner {
    /// Return the configured evidence-purpose signing key identifier.
    fn key_id(&self) -> &str;
}


#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_core::{SignatureAlgorithm, SignatureEnvelope, canonical_json};
    use agentguard_evidence::{
        DurableCommitRef, EvidenceEventV1, EvidenceSignerError,
        EvidenceStoreError, EvidenceStreamHead, StoredEvidenceEvent,
    };
    use agentguard_policy::{
        PolicyKeyError, PolicyRuleV1, ResourceSelectorV1, RuleEffect, SubjectSelectorV1,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};
    use serde::Serialize;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct TestKeys([u8; 32]);

    impl PolicyKeyResolver for TestKeys {
        fn resolve_policy_issuer_key(
            &self,
            issuer_id: &str,
            key_id: &str,
        ) -> Result<[u8; 32], PolicyKeyError> {
            if issuer_id == "issuer-1" && key_id == "policy-key-1" {
                Ok(self.0)
            } else {
                Err(PolicyKeyError::Unknown)
            }
        }
    }

    #[derive(Serialize)]
    struct PolicyContent<'a> {
        schema_version: u8,
        policy_id: &'a str,
        version: &'a str,
        issuer_id: &'a str,
        created_at: &'a str,
        rules: &'a [PolicyRuleV1],
        approval_profiles: &'a [agentguard_policy::ApprovalProfileV1],
    }

    fn signed_policy() -> (PolicyBundleV1, EvaluationRequestV1, TestKeys) {
        let signing = SigningKey::from_bytes(&[42_u8; 32]);
        let rules = vec![PolicyRuleV1 {
            rule_id: "allow-read".into(),
            effect: RuleEffect::Allow,
            subjects: SubjectSelectorV1::default(),
            actions: vec!["wallet.read".into()],
            resources: ResourceSelectorV1::default(),
            conditions: vec![],
            approval_profile_id: None,
        }];
        let approval_profiles = vec![];
        let content = PolicyContent {
            schema_version: 1,
            policy_id: "policy-1",
            version: "1",
            issuer_id: "issuer-1",
            created_at: "2026-11-17T00:00:00Z",
            rules: &rules,
            approval_profiles: &approval_profiles,
        };
        let canonical = canonical_json(&content).unwrap();
        let bundle = PolicyBundleV1 {
            schema_version: 1,
            policy_id: "policy-1".into(),
            version: "1".into(),
            issuer_id: "issuer-1".into(),
            created_at: "2026-11-17T00:00:00Z".into(),
            rules,
            approval_profiles,
            signature: SignatureEnvelope {
                algorithm: SignatureAlgorithm::Ed25519,
                key_id: "policy-key-1".into(),
                signature: URL_SAFE_NO_PAD.encode(signing.sign(&canonical).to_bytes()),
            },
        };
        let request = EvaluationRequestV1 {
            schema_version: 1,
            tenant_id: "tenant-1".into(),
            principal_id: "principal-1".into(),
            agent_id: "agent-1".into(),
            action_type: "wallet.read".into(),
            resource_type: "wallet".into(),
            resource_id: "wallet-1".into(),
            evaluated_at_unix_seconds: 1_800_000_000,
            context: Default::default(),
        };
        (
            bundle,
            request,
            TestKeys(*signing.verifying_key().as_bytes()),
        )
    }

    struct FailingStore;

    impl EvidenceStore for FailingStore {
        fn read_head(
            &self,
            _tenant_id: &str,
            _stream_id: &str,
        ) -> Result<Option<EvidenceStreamHead>, EvidenceStoreError> {
            Err(EvidenceStoreError::Unavailable)
        }

        fn append_if_head_matches(
            &self,
            _event: &EvidenceEventV1,
            _expected: Option<&EvidenceStreamHead>,
        ) -> Result<DurableCommitRef, EvidenceStoreError> {
            unreachable!("append must not run when reading the stream head fails")
        }

        fn read_event(
            &self,
            _tenant_id: &str,
            _stream_id: &str,
            _sequence: u64,
        ) -> Result<Option<StoredEvidenceEvent>, EvidenceStoreError> {
            unreachable!("read-back must not run when append does not commit")
        }
    }

    struct TestSigner {
        called: AtomicBool,
    }

    impl EvidenceReceiptSigner for TestSigner {
        fn sign_receipt(&self, _message: &[u8]) -> Result<SignatureEnvelope, EvidenceSignerError> {
            self.called.store(true, Ordering::SeqCst);
            Err(EvidenceSignerError::Unavailable)
        }
    }

    impl IdentifiedEvidenceReceiptSigner for TestSigner {
        fn key_id(&self) -> &str {
            "evidence-key-1"
        }
    }

    struct TestClock;

    impl RuntimeClock for TestClock {
        fn now_utc(&self) -> Result<String, RuntimeClockError> {
            Ok("2026-11-17T01:00:00Z".into())
        }
    }

    #[test]
    fn storage_failure_never_returns_a_policy_decision_or_signs_a_receipt() {
        let (bundle, request, keys) = signed_policy();
        let signer = TestSigner {
            called: AtomicBool::new(false),
        };
        let evidence = DecisionEvidenceInputV1 {
            event_id: "event-1".into(),
            receipt_id: "receipt-1".into(),
            stream_id: "stream-1".into(),
            request_id: "request-1".into(),
            actor_ref: "agent:agent-1".into(),
            request_digest: "a".repeat(64),
            action_digest: "b".repeat(64),
            context_digest: "c".repeat(64),
        };

        let result = evaluate_and_record(
            &bundle,
            &request,
            &evidence,
            &keys,
            &FailingStore,
            &signer,
            &TestClock,
        );

        assert!(matches!(
            result,
            Err(RuntimeError::Evidence(agentguard_evidence::EvidenceError::Store(
                EvidenceStoreError::Unavailable
            )))
        ));
        assert!(!signer.called.load(Ordering::SeqCst));
    }
}
