//! Pure, deterministic policy combining for the `AgentGuard` v1 policy contract.
//!
//! This module deliberately performs no authentication, clock reads, I/O,
//! canonicalization, signing, or evidence persistence. Callers must validate
//! identity assertions, context provenance/freshness, and policy authenticity
//! before invoking the evaluator.

use std::collections::{BTreeMap, BTreeSet};

pub use agentguard_core::Decision;

/// Exact schema identifier supported by this evaluator.
pub const POLICY_SCHEMA_V1: &str = "agentguard.policy.v1";

/// A validated-at-boundary policy bundle. The evaluator still checks structural
/// invariants so malformed in-memory values fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBundle {
    pub schema_version: String,
    pub policy_id: String,
    pub version: u64,
    pub rules: Vec<PolicyRule>,
}

/// One declarative policy rule. Rule order has no authorization semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub rule_id: String,
    pub effect: RuleEffect,
    /// Empty means unrestricted for the principal/agent dimension.
    pub subjects: Vec<SubjectSelector>,
    /// Exact namespaced action types; empty is invalid.
    pub actions: Vec<String>,
    /// Empty means unrestricted for the resource dimension.
    pub resources: Vec<String>,
    /// All predicates must match. An empty list evaluates true.
    pub conditions: Vec<Condition>,
    /// Required only for `REQUIRE_APPROVAL`.
    pub approval_profile_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEffect {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectSelector {
    Principal(String),
    Agent(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRequest<'a> {
    pub principal_id: &'a str,
    pub agent_id: &'a str,
    pub action_type: &'a str,
    pub resource: &'a str,
    pub context: &'a BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    pub field: String,
    pub operator: Operator,
    /// EXISTS uses Some(Bool) to state the expected presence.
    /// `IN/NOT_IN` use `Set`; all other operators use a scalar.
    pub expected: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
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

/// No floating-point representation is available by design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Integer(i64),
    String(String),
    Set(Vec<Value>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    AllowRuleMatched,
    DenyRuleMatched,
    ApprovalProfileRequired,
    NoMatchingAllowRule,
    PolicySchemaUnsupported,
    PolicyInvalid,
    ConditionTypeMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionResult {
    pub decision: Decision,
    pub reason: ReasonCode,
    /// Sorted and deduplicated profile IDs; populated only for approval.
    pub approval_profile_ids: Vec<String>,
}

impl DecisionResult {
    fn new(decision: Decision, reason: ReasonCode) -> Self {
        Self {
            decision,
            reason,
            approval_profile_ids: Vec::new(),
        }
    }

    fn deny(reason: ReasonCode) -> Self {
        Self::new(Decision::Deny, reason)
    }
}

/// Evaluates a policy bundle using deny-overrides semantics.
///
/// Validation failures return a DENY result with a stable reason code. This
/// function is deterministic for identical inputs and does not consult ambient
/// state. It is not a substitute for the upstream trust/provenance checks.
#[must_use]
pub fn evaluate(bundle: &PolicyBundle, request: &PolicyRequest<'_>) -> DecisionResult {
    if bundle.schema_version != POLICY_SCHEMA_V1 {
        return DecisionResult::deny(ReasonCode::PolicySchemaUnsupported);
    }
    if bundle.policy_id.trim().is_empty()
        || bundle.version == 0
        || bundle.rules.iter().any(|rule| {
            rule.rule_id.trim().is_empty()
                || rule.actions.is_empty()
                || rule.actions.iter().any(|action| action.trim().is_empty())
                || rule.subjects.iter().any(|subject| match subject {
                    SubjectSelector::Principal(id) | SubjectSelector::Agent(id) => {
                        id.trim().is_empty()
                    }
                })
                || rule
                    .resources
                    .iter()
                    .any(|resource| resource.trim().is_empty())
                || match rule.effect {
                    RuleEffect::RequireApproval => rule
                        .approval_profile_id
                        .as_ref()
                        .is_none_or(|id| id.trim().is_empty()),
                    RuleEffect::Allow | RuleEffect::Deny => rule.approval_profile_id.is_some(),
                }
        })
    {
        return DecisionResult::deny(ReasonCode::PolicyInvalid);
    }

    let mut rule_ids = BTreeSet::new();
    if bundle
        .rules
        .iter()
        .any(|rule| !rule_ids.insert(rule.rule_id.as_str()))
    {
        return DecisionResult::deny(ReasonCode::PolicyInvalid);
    }

    let mut matched_allow = false;
    let mut matched_approval = BTreeSet::new();

    for rule in &bundle.rules {
        if !rule_matches(rule, request) {
            continue;
        }
        match rule.effect {
            RuleEffect::Deny => return DecisionResult::deny(ReasonCode::DenyRuleMatched),
            RuleEffect::RequireApproval => {
                if let Some(profile) = &rule.approval_profile_id {
                    matched_approval.insert(profile.clone());
                }
            }
            RuleEffect::Allow => matched_allow = true,
        }
    }

    if !matched_approval.is_empty() {
        return DecisionResult {
            decision: Decision::RequireApproval,
            reason: ReasonCode::ApprovalProfileRequired,
            approval_profile_ids: matched_approval.into_iter().collect(),
        };
    }
    if matched_allow {
        DecisionResult::new(Decision::Allow, ReasonCode::AllowRuleMatched)
    } else {
        DecisionResult::deny(ReasonCode::NoMatchingAllowRule)
    }
}

fn rule_matches(rule: &PolicyRule, request: &PolicyRequest<'_>) -> bool {
    let subject_matches = rule.subjects.is_empty()
        || rule.subjects.iter().any(|selector| match selector {
            SubjectSelector::Principal(id) => id == request.principal_id,
            SubjectSelector::Agent(id) => id == request.agent_id,
        });
    let action_matches = rule
        .actions
        .iter()
        .any(|action| action == request.action_type);
    let resource_matches = rule.resources.is_empty()
        || rule
            .resources
            .iter()
            .any(|resource| resource == request.resource);
    subject_matches
        && action_matches
        && resource_matches
        && rule
            .conditions
            .iter()
            .all(|condition| condition_matches(condition, request.context))
}

fn condition_matches(condition: &Condition, context: &BTreeMap<String, Value>) -> bool {
    let actual = context.get(&condition.field);
    match condition.operator {
        Operator::Exists => match &condition.expected {
            Value::Bool(expected) => actual.is_some() == *expected,
            _ => false,
        },
        Operator::Eq => actual.is_some_and(|value| value == &condition.expected),
        Operator::Neq => actual.is_some_and(|value| value != &condition.expected),
        Operator::In | Operator::NotIn => {
            let Some(actual) = actual else { return false };
            let Value::Set(values) = &condition.expected else {
                return false;
            };
            let contains = values.iter().any(|value| value == actual);
            if condition.operator == Operator::In {
                contains
            } else {
                !contains
            }
        }
        Operator::Gt | Operator::Gte | Operator::Lt | Operator::Lte => {
            let Some(actual) = actual else { return false };
            match (actual, &condition.expected) {
                (Value::Integer(left), Value::Integer(right)) => match condition.operator {
                    Operator::Gt => left > right,
                    Operator::Gte => left >= right,
                    Operator::Lt => left < right,
                    Operator::Lte => left <= right,
                    _ => false,
                },
                (Value::String(left), Value::String(right)) => match condition.operator {
                    Operator::Gt => left > right,
                    Operator::Gte => left >= right,
                    Operator::Lt => left < right,
                    Operator::Lte => left <= right,
                    _ => false,
                },
                _ => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, effect: RuleEffect) -> PolicyRule {
        PolicyRule {
            rule_id: id.into(),
            effect,
            subjects: vec![],
            actions: vec!["wallet.transfer".into()],
            resources: vec![],
            conditions: vec![],
            approval_profile_id: (effect == RuleEffect::RequireApproval)
                .then(|| "finance-2p".into()),
        }
    }

    fn bundle(rules: Vec<PolicyRule>) -> PolicyBundle {
        PolicyBundle {
            schema_version: POLICY_SCHEMA_V1.into(),
            policy_id: "treasury".into(),
            version: 1,
            rules,
        }
    }

    fn request(context: &BTreeMap<String, Value>) -> PolicyRequest<'_> {
        PolicyRequest {
            principal_id: "user-1",
            agent_id: "agent-1",
            action_type: "wallet.transfer",
            resource: "wallet-1",
            context,
        }
    }

    #[test]
    fn allow_requires_matching_allow_rule() {
        let context = BTreeMap::new();
        assert_eq!(
            evaluate(
                &bundle(vec![rule("a", RuleEffect::Allow)]),
                &request(&context)
            )
            .decision,
            Decision::Allow
        );
        assert_eq!(
            evaluate(&bundle(vec![]), &request(&context)).reason,
            ReasonCode::NoMatchingAllowRule
        );
    }

    #[test]
    fn deny_overrides_allow_independent_of_rule_order() {
        let context = BTreeMap::new();
        let allow = rule("allow", RuleEffect::Allow);
        let deny = rule("deny", RuleEffect::Deny);
        let first = evaluate(
            &bundle(vec![allow.clone(), deny.clone()]),
            &request(&context),
        );
        let second = evaluate(&bundle(vec![deny, allow]), &request(&context));
        assert_eq!(first, second);
        assert_eq!(first.decision, Decision::Deny);
        assert_eq!(first.reason, ReasonCode::DenyRuleMatched);
    }

    #[test]
    fn approval_overrides_allow_and_profiles_are_sorted_unique() {
        let context = BTreeMap::new();
        let mut second = rule("approval-2", RuleEffect::RequireApproval);
        second.approval_profile_id = Some("z-profile".into());
        let mut first = rule("approval-1", RuleEffect::RequireApproval);
        first.approval_profile_id = Some("a-profile".into());
        let result = evaluate(
            &bundle(vec![rule("allow", RuleEffect::Allow), second, first]),
            &request(&context),
        );
        assert_eq!(result.decision, Decision::RequireApproval);
        assert_eq!(result.approval_profile_ids, vec!["a-profile", "z-profile"]);
    }

    #[test]
    fn unknown_schema_and_duplicate_rule_ids_fail_closed() {
        let context = BTreeMap::new();
        let mut unknown = bundle(vec![rule("a", RuleEffect::Allow)]);
        unknown.schema_version = "future".into();
        assert_eq!(
            evaluate(&unknown, &request(&context)).reason,
            ReasonCode::PolicySchemaUnsupported
        );
        assert_eq!(
            evaluate(
                &bundle(vec![
                    rule("a", RuleEffect::Allow),
                    rule("a", RuleEffect::Deny)
                ]),
                &request(&context)
            )
            .reason,
            ReasonCode::PolicyInvalid
        );
    }

    #[test]
    fn selectors_and_conditions_are_exact() {
        let mut context = BTreeMap::new();
        context.insert("amount_minor".into(), Value::Integer(500));
        let mut policy_rule = rule("limited", RuleEffect::Allow);
        policy_rule.subjects = vec![SubjectSelector::Principal("user-1".into())];
        policy_rule.resources = vec!["wallet-1".into()];
        policy_rule.conditions = vec![Condition {
            field: "amount_minor".into(),
            operator: Operator::Lte,
            expected: Value::Integer(1_000),
        }];
        assert_eq!(
            evaluate(&bundle(vec![policy_rule]), &request(&context)).decision,
            Decision::Allow
        );
        context.insert("amount_minor".into(), Value::String("500".into()));
        assert_eq!(
            evaluate(&bundle(vec![rule_with_condition()]), &request(&context)).decision,
            Decision::Deny
        );
    }

    fn rule_with_condition() -> PolicyRule {
        let mut value = rule("typed", RuleEffect::Allow);
        value.conditions = vec![Condition {
            field: "amount_minor".into(),
            operator: Operator::Lte,
            expected: Value::Integer(1_000),
        }];
        value
    }

    #[test]
    fn invalid_rule_configurations_fail_closed() {
        let context = BTreeMap::new();

        let mut empty_actions = rule("empty-actions", RuleEffect::Allow);
        empty_actions.actions.clear();
        assert_eq!(
            evaluate(&bundle(vec![empty_actions]), &request(&context)).decision,
            Decision::Deny
        );

        let mut missing_approval_profile = rule("missing-profile", RuleEffect::RequireApproval);
        missing_approval_profile.approval_profile_id = None;
        assert_eq!(
            evaluate(&bundle(vec![missing_approval_profile]), &request(&context)).decision,
            Decision::Deny
        );

        let mut unexpected_approval_profile = rule("unexpected-profile", RuleEffect::Allow);
        unexpected_approval_profile.approval_profile_id = Some("finance-2p".into());
        assert_eq!(
            evaluate(
                &bundle(vec![unexpected_approval_profile]),
                &request(&context)
            )
            .decision,
            Decision::Deny
        );
    }

    #[test]
    fn typed_condition_operators_have_exact_semantics() {
        let mut context = BTreeMap::new();
        context.insert("mode".into(), Value::String("production".into()));
        context.insert("amount".into(), Value::Integer(500));
        context.insert("enabled".into(), Value::Bool(true));

        let mut policy_rule = rule("typed-conditions", RuleEffect::Allow);
        policy_rule.conditions = vec![
            Condition {
                field: "mode".into(),
                operator: Operator::Eq,
                expected: Value::String("production".into()),
            },
            Condition {
                field: "mode".into(),
                operator: Operator::Neq,
                expected: Value::String("staging".into()),
            },
            Condition {
                field: "mode".into(),
                operator: Operator::In,
                expected: Value::Set(vec![
                    Value::String("production".into()),
                    Value::String("staging".into()),
                ]),
            },
            Condition {
                field: "mode".into(),
                operator: Operator::NotIn,
                expected: Value::Set(vec![Value::String("development".into())]),
            },
            Condition {
                field: "enabled".into(),
                operator: Operator::Exists,
                expected: Value::Bool(true),
            },
            Condition {
                field: "amount".into(),
                operator: Operator::Gt,
                expected: Value::Integer(499),
            },
            Condition {
                field: "amount".into(),
                operator: Operator::Gte,
                expected: Value::Integer(500),
            },
            Condition {
                field: "amount".into(),
                operator: Operator::Lt,
                expected: Value::Integer(501),
            },
            Condition {
                field: "amount".into(),
                operator: Operator::Lte,
                expected: Value::Integer(500),
            },
        ];

        assert_eq!(
            evaluate(&bundle(vec![policy_rule.clone()]), &request(&context)).decision,
            Decision::Allow
        );

        context.insert("amount".into(), Value::String("500".into()));
        assert_eq!(
            evaluate(&bundle(vec![policy_rule]), &request(&context)).decision,
            Decision::Deny
        );
    }

    #[test]
    fn agent_and_resource_selectors_are_exact() {
        let context = BTreeMap::new();
        let mut policy_rule = rule("agent-resource", RuleEffect::Allow);
        policy_rule.subjects = vec![SubjectSelector::Agent("agent-1".into())];
        policy_rule.resources = vec!["wallet-1".into()];

        assert_eq!(
            evaluate(&bundle(vec![policy_rule.clone()]), &request(&context)).decision,
            Decision::Allow
        );

        let wrong_agent = PolicyRequest {
            principal_id: "user-1",
            agent_id: "agent-2",
            action_type: "wallet.transfer",
            resource: "wallet-1",
            context: &context,
        };
        assert_eq!(
            evaluate(&bundle(vec![policy_rule.clone()]), &wrong_agent).decision,
            Decision::Deny
        );

        let wrong_resource = PolicyRequest {
            principal_id: "user-1",
            agent_id: "agent-1",
            action_type: "wallet.transfer",
            resource: "wallet-2",
            context: &context,
        };
        assert_eq!(
            evaluate(&bundle(vec![policy_rule]), &wrong_resource).decision,
            Decision::Deny
        );
     }
}
