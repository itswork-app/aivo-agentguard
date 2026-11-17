//! Deterministic, side-effect-free policy validation and evaluation.
//!
//! This crate does not authenticate principals, fetch context, read clocks,
//! persist evidence, issue permits, or execute actions. Its caller supplies
//! authenticated request identity, verified context provenance, and one
//! trusted evaluation timestamp.

use std::collections::{BTreeMap, BTreeSet};

pub use agentguard_core::Decision;
use agentguard_core::{
    SignatureEnvelope, canonical_json, domain_digest, hex_digest, verify_ed25519,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Exact schema version supported by this evaluator.
pub const POLICY_SCHEMA_VERSION: u8 = 1;
/// Evaluator semantic version recorded in decision evidence.
pub const EVALUATOR_VERSION: &str = "0.1.0";
const POLICY_DOMAIN: &[u8] = b"AIVO-AGENTGUARD-POLICY-V1\0";

/// Policy signing-key resolver. Implementations must resolve only trusted
/// policy-issuer keys and reject disabled, unknown, or wrong-purpose keys.
pub trait PolicyKeyResolver: Send + Sync {
    /// Resolve the public key for the exact policy issuer key identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is unknown, unavailable, or not trusted.
    fn resolve_policy_issuer_key(
        &self,
        issuer_id: &str,
        key_id: &str,
    ) -> Result<[u8; 32], PolicyKeyError>;
}

/// Failure to resolve a trusted policy issuer key.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyKeyError {
    #[error("policy issuer key is unknown")]
    Unknown,
    #[error("policy issuer key is unavailable")]
    Unavailable,
}

/// Immutable policy content. The detached signature is intentionally excluded
/// from the content digest and signature message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundleV1 {
    pub schema_version: u8,
    pub policy_id: String,
    pub version: String,
    pub issuer_id: String,
    pub created_at: String,
    pub rules: Vec<PolicyRuleV1>,
    #[serde(default)]
    pub approval_profiles: Vec<ApprovalProfileV1>,
    pub signature: SignatureEnvelope,
}

/// Declarative rule. Rule ordering never affects evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRuleV1 {
    pub rule_id: String,
    pub effect: RuleEffect,
    #[serde(default)]
    pub subjects: SubjectSelectorV1,
    pub actions: Vec<String>,
    #[serde(default)]
    pub resources: ResourceSelectorV1,
    #[serde(default)]
    pub conditions: Vec<ConditionV1>,
    #[serde(default)]
    pub approval_profile_id: Option<String>,
}

/// Supported policy effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleEffect {
    Allow,
    Deny,
    RequireApproval,
}

/// Exact principal and agent selectors. Empty lists mean unrestricted only
/// within that selector dimension; an action selector is always mandatory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectSelectorV1 {
    #[serde(default)]
    pub principal_ids: Vec<String>,
    #[serde(default)]
    pub agent_ids: Vec<String>,
}

/// Exact resource selectors. Empty lists mean unrestricted resource matching.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSelectorV1 {
    #[serde(default)]
    pub resource_types: Vec<String>,
    #[serde(default)]
    pub resource_ids: Vec<String>,
}

/// Approval profile reference metadata. Full approval authentication and quorum
/// verification are separate lifecycle operations, not policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalProfileV1 {
    pub profile_id: String,
    pub version: String,
    pub min_approvals: u32,
    pub eligible_principal_ids: Vec<String>,
    pub eligible_role_ids: Vec<String>,
    pub max_approval_age_seconds: u64,
    pub allow_requester_approval: bool,
    pub exclude_agent_owners: bool,
}

/// Typed condition operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Eq,
    Neq,
    In,
    NotIn,
    Exists,
    Gt,
    Gte,
    Lt,
    Lte,
}

/// Required trust level for a context field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustClass {
    T0,
    T1,
    T2,
    T3,
}

/// One typed predicate over a context field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionV1 {
    pub field_id: String,
    pub operator: ConditionOperator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default)]
    pub max_age_seconds: Option<u64>,
    #[serde(default)]
    pub minimum_trust: Option<TrustClass>,
    #[serde(default)]
    pub require_attestation: bool,
}

/// Context value with provenance supplied by the trusted runtime boundary.
/// Timestamps are Unix seconds after strict parsing of canonical UTC input by
/// the adapter; this evaluator never reads a clock or parses host-local time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextValueV1 {
    pub value: Value,
    pub source_id: String,
    pub observed_at_unix_seconds: u64,
    #[serde(default)]
    pub valid_until_unix_seconds: Option<u64>,
    pub trust_class: TrustClass,
    #[serde(default)]
    pub attestation_verified: bool,
}

/// Authenticated request facts and trusted context snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationRequestV1 {
    pub schema_version: u8,
    pub tenant_id: String,
    pub principal_id: String,
    pub agent_id: String,
    pub action_type: String,
    pub resource_type: String,
    pub resource_id: String,
    pub evaluated_at_unix_seconds: u64,
    pub context: BTreeMap<String, ContextValueV1>,
}

/// Stable machine-readable reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionReason {
    AllowRuleMatched,
    DenyRuleMatched,
    ApprovalProfileRequired,
    NoMatchingAllowRule,
}

/// Deterministic policy evaluation output. It contains no permit and grants no
/// execution capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionResultV1 {
    pub decision: Decision,
    pub reason: DecisionReason,
    pub matched_rule_ids: Vec<String>,
    pub required_approval_profile_ids: Vec<String>,
    pub policy_digest: String,
    pub policy_id: String,
    pub policy_version: String,
    pub evaluator_version: String,
}

/// Validation/evaluation errors are distinct from policy DENY. Every error
/// blocks execution and must never be converted to ALLOW by callers.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("unsupported policy schema version")]
    UnsupportedPolicySchema,
    #[error("unsupported request schema version")]
    UnsupportedRequestSchema,
    #[error("policy issuer identity or metadata is invalid")]
    InvalidPolicyMetadata,
    #[error("policy contains duplicate or invalid rule identifiers")]
    InvalidRuleIdentifier,
    #[error("policy contains an invalid action or selector")]
    InvalidSelector,
    #[error("policy contains an invalid approval profile reference")]
    InvalidApprovalProfile,
    #[error("policy condition operator/value shape is invalid")]
    InvalidCondition,
    #[error("policy canonicalization failed")]
    Canonicalization,
    #[error("policy signature is invalid")]
    InvalidSignature,
    #[error("policy issuer key resolution failed: {0}")]
    KeyResolution(#[from] PolicyKeyError),
    #[error("request identity or action fields are invalid")]
    InvalidRequest,
    #[error("required context field is missing")]
    ContextMissing,
    #[error("required context field is stale or future-dated")]
    ContextStale,
    #[error("required context field does not meet provenance requirements")]
    ContextUntrusted,
    #[error("condition compares incompatible value types")]
    ConditionTypeMismatch,
}

/// Validate and verify the immutable policy bundle, then evaluate it.
///
/// The key resolver is purpose-specific; the signature is verified over RFC
/// 8785 canonical policy content, excluding detached signature metadata.
///
/// # Errors
///
/// Returns a typed error for invalid schema, signature, policy structure,
/// request, context provenance/freshness, or incompatible condition types.
pub fn evaluate<K: PolicyKeyResolver>(
    bundle: &PolicyBundleV1,
    request: &EvaluationRequestV1,
    keys: &K,
) -> Result<DecisionResultV1, PolicyError> {
    validate_bundle(bundle)?;
    validate_request(request)?;

    let content = policy_content(bundle);
    let canonical = canonical_json(&content).map_err(|_| PolicyError::Canonicalization)?;
    let digest = hex_digest(&domain_digest(POLICY_DOMAIN, &canonical));

    if bundle.signature.key_id.trim() != bundle.signature.key_id
        || bundle.signature.key_id.is_empty()
        || bundle.signature.algorithm != agentguard_core::SignatureAlgorithm::Ed25519
    {
        return Err(PolicyError::InvalidSignature);
    }
    let public_key = keys.resolve_policy_issuer_key(&bundle.issuer_id, &bundle.signature.key_id)?;
    verify_ed25519(&public_key, &bundle.signature, &canonical)
        .map_err(|_| PolicyError::InvalidSignature)?;

    let mut matched = Vec::new();
    let mut deny = false;
    let mut approval_profiles = BTreeSet::new();
    let mut allow = false;

    for rule in &bundle.rules {
        if !matches_selectors(rule, request) {
            continue;
        }
        if conditions_match(rule, request)? {
            matched.push(rule.rule_id.clone());
            match rule.effect {
                RuleEffect::Deny => deny = true,
                RuleEffect::RequireApproval => {
                    if let Some(profile_id) = &rule.approval_profile_id {
                        approval_profiles.insert(profile_id.clone());
                    }
                }
                RuleEffect::Allow => allow = true,
            }
        }
    }

    matched.sort();
    let (decision, reason, required_approval_profile_ids) = if deny {
        (Decision::Deny, DecisionReason::DenyRuleMatched, Vec::new())
    } else if !approval_profiles.is_empty() {
        (
            Decision::RequireApproval,
            DecisionReason::ApprovalProfileRequired,
            approval_profiles.into_iter().collect(),
        )
    } else if allow {
        (
            Decision::Allow,
            DecisionReason::AllowRuleMatched,
            Vec::new(),
        )
    } else {
        (
            Decision::Deny,
            DecisionReason::NoMatchingAllowRule,
            Vec::new(),
        )
    };

    Ok(DecisionResultV1 {
        decision,
        reason,
        matched_rule_ids: matched,
        required_approval_profile_ids,
        policy_digest: digest,
        policy_id: bundle.policy_id.clone(),
        policy_version: bundle.version.clone(),
        evaluator_version: EVALUATOR_VERSION.to_owned(),
    })
}

fn policy_content(bundle: &PolicyBundleV1) -> PolicyContentV1 {
    PolicyContentV1 {
        schema_version: bundle.schema_version,
        policy_id: bundle.policy_id.clone(),
        version: bundle.version.clone(),
        issuer_id: bundle.issuer_id.clone(),
        created_at: bundle.created_at.clone(),
        rules: bundle.rules.clone(),
        approval_profiles: bundle.approval_profiles.clone(),
    }
}

#[derive(Serialize)]
struct PolicyContentV1 {
    schema_version: u8,
    policy_id: String,
    version: String,
    issuer_id: String,
    created_at: String,
    rules: Vec<PolicyRuleV1>,
    approval_profiles: Vec<ApprovalProfileV1>,
}

fn validate_bundle(bundle: &PolicyBundleV1) -> Result<(), PolicyError> {
    if bundle.schema_version != POLICY_SCHEMA_VERSION {
        return Err(PolicyError::UnsupportedPolicySchema);
    }
    if !valid_identifier(&bundle.policy_id)
        || !valid_identifier(&bundle.version)
        || !valid_identifier(&bundle.issuer_id)
        || bundle.created_at.is_empty()
        || bundle.created_at.trim() != bundle.created_at
        || bundle.rules.is_empty()
    {
        return Err(PolicyError::InvalidPolicyMetadata);
    }

    let mut rule_ids = BTreeSet::new();
    for rule in &bundle.rules {
        if !valid_identifier(&rule.rule_id) || !rule_ids.insert(rule.rule_id.clone()) {
            return Err(PolicyError::InvalidRuleIdentifier);
        }
        if rule.actions.is_empty()
            || rule.actions.iter().any(|item| !valid_selector(item))
            || rule
                .subjects
                .principal_ids
                .iter()
                .any(|item| !valid_identifier(item))
            || rule
                .subjects
                .agent_ids
                .iter()
                .any(|item| !valid_identifier(item))
            || rule
                .resources
                .resource_types
                .iter()
                .any(|item| !valid_selector(item))
            || rule
                .resources
                .resource_ids
                .iter()
                .any(|item| !valid_selector(item))
        {
            return Err(PolicyError::InvalidSelector);
        }
        match (rule.effect, rule.approval_profile_id.as_deref()) {
            (RuleEffect::RequireApproval, Some(profile)) if valid_identifier(profile) => {}
            (RuleEffect::RequireApproval, _) | (_, Some(_)) => {
                return Err(PolicyError::InvalidApprovalProfile);
            }
            _ => {}
        }
        for condition in &rule.conditions {
            if !valid_identifier(&condition.field_id) || !valid_condition_shape(condition) {
                return Err(PolicyError::InvalidCondition);
            }
        }
    }

    let mut profile_ids = BTreeSet::new();
    for profile in &bundle.approval_profiles {
        if !valid_identifier(&profile.profile_id)
            || !valid_identifier(&profile.version)
            || profile.min_approvals == 0
            || !profile_ids.insert(profile.profile_id.clone())
            || (profile.eligible_principal_ids.is_empty() && profile.eligible_role_ids.is_empty())
            || profile
                .eligible_principal_ids
                .iter()
                .any(|id| !valid_identifier(id))
            || profile
                .eligible_role_ids
                .iter()
                .any(|id| !valid_identifier(id))
        {
            return Err(PolicyError::InvalidApprovalProfile);
        }
    }
    for rule in &bundle.rules {
        if let Some(profile_id) = &rule.approval_profile_id {
            if !profile_ids.contains(profile_id) {
                return Err(PolicyError::InvalidApprovalProfile);
            }
        }
    }

    // Reject floats and integers outside the protocol's interoperable safe range.
    canonical_json(&policy_content(bundle)).map_err(|_| PolicyError::Canonicalization)?;
    Ok(())
}

fn validate_request(request: &EvaluationRequestV1) -> Result<(), PolicyError> {
    if request.schema_version != 1 {
        return Err(PolicyError::UnsupportedRequestSchema);
    }
    if !valid_identifier(&request.tenant_id)
        || !valid_identifier(&request.principal_id)
        || !valid_identifier(&request.agent_id)
        || !valid_selector(&request.action_type)
        || !valid_selector(&request.resource_type)
        || !valid_selector(&request.resource_id)
    {
        return Err(PolicyError::InvalidRequest);
    }
    Ok(())
}

fn valid_condition_shape(condition: &ConditionV1) -> bool {
    match condition.operator {
        ConditionOperator::Exists => condition.value.is_none(),
        ConditionOperator::In | ConditionOperator::NotIn => {
            matches!(condition.value, Some(Value::Array(_)))
        }
        _ => condition.value.is_some(),
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_selector(value: &str) -> bool {
    valid_identifier(value) && !value.contains('*') && !value.contains('?')
}

fn matches_selectors(rule: &PolicyRuleV1, request: &EvaluationRequestV1) -> bool {
    (rule.subjects.principal_ids.is_empty()
        || rule.subjects.principal_ids.contains(&request.principal_id))
        && (rule.subjects.agent_ids.is_empty()
            || rule.subjects.agent_ids.contains(&request.agent_id))
        && rule.actions.contains(&request.action_type)
        && (rule.resources.resource_types.is_empty()
            || rule
                .resources
                .resource_types
                .contains(&request.resource_type))
        && (rule.resources.resource_ids.is_empty()
            || rule.resources.resource_ids.contains(&request.resource_id))
}

fn conditions_match(
    rule: &PolicyRuleV1,
    request: &EvaluationRequestV1,
) -> Result<bool, PolicyError> {
    for condition in &rule.conditions {
        let Some(context) = request.context.get(&condition.field_id) else {
            return Err(PolicyError::ContextMissing);
        };
        if context.source_id.is_empty() || context.source_id.trim() != context.source_id {
            return Err(PolicyError::ContextUntrusted);
        }
        if context.observed_at_unix_seconds > request.evaluated_at_unix_seconds
            || context
                .valid_until_unix_seconds
                .is_some_and(|deadline| request.evaluated_at_unix_seconds > deadline)
            || condition.max_age_seconds.is_some_and(|max_age| {
                request.evaluated_at_unix_seconds - context.observed_at_unix_seconds > max_age
            })
        {
            return Err(PolicyError::ContextStale);
        }
        if condition
            .minimum_trust
            .is_some_and(|minimum| context.trust_class < minimum)
            || (condition.require_attestation && !context.attestation_verified)
        {
            return Err(PolicyError::ContextUntrusted);
        }
        if !condition_matches_value(condition, &context.value)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn condition_matches_value(condition: &ConditionV1, actual: &Value) -> Result<bool, PolicyError> {
    let Some(expected) = condition.value.as_ref() else {
        return Ok(condition.operator == ConditionOperator::Exists);
    };
    match condition.operator {
        ConditionOperator::Eq | ConditionOperator::Neq => {
            if !same_scalar_type(actual, expected) {
                return Err(PolicyError::ConditionTypeMismatch);
            }
            Ok(if condition.operator == ConditionOperator::Eq {
                actual == expected
            } else {
                actual != expected
            })
        }
        ConditionOperator::In | ConditionOperator::NotIn => {
            let Value::Array(values) = expected else {
                return Err(PolicyError::InvalidCondition);
            };
            if values.iter().any(|value| !same_scalar_type(actual, value)) {
                return Err(PolicyError::ConditionTypeMismatch);
            }
            let contains = values.iter().any(|value| value == actual);
            Ok(if condition.operator == ConditionOperator::In {
                contains
            } else {
                !contains
            })
        }
        ConditionOperator::Gt
        | ConditionOperator::Gte
        | ConditionOperator::Lt
        | ConditionOperator::Lte => compare_ordered(actual, expected, condition.operator),
        ConditionOperator::Exists => Err(PolicyError::InvalidCondition),
    }
}

fn compare_ordered(
    actual: &Value,
    expected: &Value,
    operator: ConditionOperator,
) -> Result<bool, PolicyError> {
    let ordering = match (actual, expected) {
        (Value::String(left), Value::String(right)) => left.cmp(right),
        (Value::Number(left), Value::Number(right)) => {
            let left = integer_value(left).ok_or(PolicyError::ConditionTypeMismatch)?;
            let right = integer_value(right).ok_or(PolicyError::ConditionTypeMismatch)?;
            left.cmp(&right)
        }
        _ => return Err(PolicyError::ConditionTypeMismatch),
    };
    Ok(match operator {
        ConditionOperator::Gt => ordering.is_gt(),
        ConditionOperator::Gte => !ordering.is_lt(),
        ConditionOperator::Lt => ordering.is_lt(),
        ConditionOperator::Lte => !ordering.is_gt(),
        _ => return Err(PolicyError::InvalidCondition),
    })
}

fn same_scalar_type(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::String(_), Value::String(_))
        | (Value::Bool(_), Value::Bool(_))
        | (Value::Null, Value::Null) => true,
        (Value::Number(left), Value::Number(right)) => {
            integer_value(left).is_some() && integer_value(right).is_some()
        }
        _ => false,
    }
}

fn integer_value(value: &serde_json::Number) -> Option<i128> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_core::{SignatureAlgorithm, canonical_json};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};

    struct TestKeys([u8; 32]);

    impl PolicyKeyResolver for TestKeys {
        fn resolve_policy_issuer_key(
            &self,
            issuer_id: &str,
            key_id: &str,
        ) -> Result<[u8; 32], PolicyKeyError> {
            if issuer_id == "org-policy-issuer" && key_id == "policy-key-1" {
                Ok(self.0)
            } else {
                Err(PolicyKeyError::Unknown)
            }
        }
    }

    fn fixture() -> (PolicyBundleV1, EvaluationRequestV1, TestKeys) {
        let signing = SigningKey::from_bytes(&[42_u8; 32]);
        let mut bundle = PolicyBundleV1 {
            schema_version: 1,
            policy_id: "treasury-policy".into(),
            version: "1".into(),
            issuer_id: "org-policy-issuer".into(),
            created_at: "2026-11-17T00:00:00Z".into(),
            rules: vec![PolicyRuleV1 {
                rule_id: "allow-read".into(),
                effect: RuleEffect::Allow,
                subjects: SubjectSelectorV1::default(),
                actions: vec!["wallet.read".into()],
                resources: ResourceSelectorV1::default(),
                conditions: vec![ConditionV1 {
                    field_id: "account.status".into(),
                    operator: ConditionOperator::Eq,
                    value: Some(Value::String("active".into())),
                    max_age_seconds: Some(30),
                    minimum_trust: Some(TrustClass::T2),
                    require_attestation: true,
                }],
                approval_profile_id: None,
            }],
            approval_profiles: vec![],
            signature: SignatureEnvelope {
                algorithm: SignatureAlgorithm::Ed25519,
                key_id: "policy-key-1".into(),
                signature: String::new(),
            },
        };
        let content = policy_content(&bundle);
        let canonical = canonical_json(&content).unwrap();
        bundle.signature.signature = URL_SAFE_NO_PAD.encode(signing.sign(&canonical).to_bytes());

        let request = EvaluationRequestV1 {
            schema_version: 1,
            tenant_id: "tenant-1".into(),
            principal_id: "principal-1".into(),
            agent_id: "agent-1".into(),
            action_type: "wallet.read".into(),
            resource_type: "wallet".into(),
            resource_id: "wallet-1".into(),
            evaluated_at_unix_seconds: 100,
            context: BTreeMap::from([(
                "account.status".into(),
                ContextValueV1 {
                    value: Value::String("active".into()),
                    source_id: "ledger-service".into(),
                    observed_at_unix_seconds: 90,
                    valid_until_unix_seconds: Some(120),
                    trust_class: TrustClass::T2,
                    attestation_verified: true,
                },
            )]),
        };
        (
            bundle,
            request,
            TestKeys(*signing.verifying_key().as_bytes()),
        )
    }

    #[test]
    fn verified_matching_allow_returns_allow() {
        let (bundle, request, keys) = fixture();
        let result = evaluate(&bundle, &request, &keys).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.reason, DecisionReason::AllowRuleMatched);
        assert_eq!(result.matched_rule_ids, vec!["allow-read"]);
        assert_eq!(result.policy_digest.len(), 64);
    }

    #[test]
    fn deny_overrides_allow_independent_of_rule_order() {
        let (mut bundle, request, keys) = fixture();
        let mut deny = bundle.rules[0].clone();
        deny.rule_id = "deny-read".into();
        deny.effect = RuleEffect::Deny;
        bundle.rules.push(deny);
        resign(&mut bundle, &[42_u8; 32]);
        assert_eq!(
            evaluate(&bundle, &request, &keys).unwrap().decision,
            Decision::Deny
        );
        bundle.rules.reverse();
        resign(&mut bundle, &[42_u8; 32]);
        assert_eq!(
            evaluate(&bundle, &request, &keys).unwrap().decision,
            Decision::Deny
        );
    }

    #[test]
    fn approval_overrides_allow_and_deduplicates_profiles() {
        let (mut bundle, request, keys) = fixture();
        bundle.approval_profiles.push(ApprovalProfileV1 {
            profile_id: "two-person".into(),
            version: "1".into(),
            min_approvals: 2,
            eligible_principal_ids: vec!["approver-1".into(), "approver-2".into()],
            eligible_role_ids: vec![],
            max_approval_age_seconds: 300,
            allow_requester_approval: false,
            exclude_agent_owners: true,
        });
        let mut approval = bundle.rules[0].clone();
        approval.rule_id = "approval-required".into();
        approval.effect = RuleEffect::RequireApproval;
        approval.approval_profile_id = Some("two-person".into());
        bundle.rules.push(approval);
        resign(&mut bundle, &[42_u8; 32]);
        let result = evaluate(&bundle, &request, &keys).unwrap();
        assert_eq!(result.decision, Decision::RequireApproval);
        assert_eq!(result.required_approval_profile_ids, vec!["two-person"]);
    }

    #[test]
    fn stale_or_untrusted_context_fails_closed_as_typed_error() {
        let (bundle, mut request, keys) = fixture();
        request
            .context
            .get_mut("account.status")
            .unwrap()
            .observed_at_unix_seconds = 1;
        assert_eq!(
            evaluate(&bundle, &request, &keys),
            Err(PolicyError::ContextStale)
        );

        request
            .context
            .get_mut("account.status")
            .unwrap()
            .observed_at_unix_seconds = 90;
        request
            .context
            .get_mut("account.status")
            .unwrap()
            .trust_class = TrustClass::T1;
        assert_eq!(
            evaluate(&bundle, &request, &keys),
            Err(PolicyError::ContextUntrusted)
        );
    }

    #[test]
    fn altered_policy_content_invalidates_signature() {
        let (mut bundle, request, keys) = fixture();
        bundle.rules[0].actions[0] = "wallet.transfer".into();
        assert_eq!(
            evaluate(&bundle, &request, &keys),
            Err(PolicyError::InvalidSignature)
        );
    }

    #[test]
    fn no_matching_rule_is_default_deny() {
        let (bundle, mut request, keys) = fixture();
        request.action_type = "wallet.transfer".into();
        let result = evaluate(&bundle, &request, &keys).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.reason, DecisionReason::NoMatchingAllowRule);
    }

    #[test]
    fn equality_rejects_cross_type_comparison() {
        let (mut bundle, request, keys) = fixture();
        bundle.rules[0].conditions[0].value = Some(Value::Number(serde_json::Number::from(1)));
        resign(&mut bundle, &[42_u8; 32]);
        assert_eq!(
            evaluate(&bundle, &request, &keys),
            Err(PolicyError::ConditionTypeMismatch)
        );
    }

    #[test]
    fn issuer_identity_is_bound_by_the_trust_resolver() {
        let (mut bundle, request, keys) = fixture();
        bundle.issuer_id = "attacker-controlled-issuer".into();
        resign(&mut bundle, &[42_u8; 32]);
        assert_eq!(
            evaluate(&bundle, &request, &keys),
            Err(PolicyError::KeyResolution(PolicyKeyError::Unknown))
        );
    }

    #[test]
    fn condition_type_mismatch_does_not_become_a_non_match() {
        let (mut bundle, request, keys) = fixture();
        bundle.rules[0].conditions[0].operator = ConditionOperator::In;
        bundle.rules[0].conditions[0].value = Some(Value::Array(vec![
            Value::String("active".into()),
            Value::Number(serde_json::Number::from(1)),
        ]));
        resign(&mut bundle, &[42_u8; 32]);
        assert_eq!(
            evaluate(&bundle, &request, &keys),
            Err(PolicyError::ConditionTypeMismatch)
        );
    }

    fn resign(bundle: &mut PolicyBundleV1, secret: &[u8; 32]) {
        let signing = SigningKey::from_bytes(secret);
        let canonical = canonical_json(&policy_content(bundle)).unwrap();
        bundle.signature.signature = URL_SAFE_NO_PAD.encode(signing.sign(&canonical).to_bytes());
    }
}
