//! Shared domain types for AIVO `AgentGuard`.
//!
//! This crate is scaffolding. Public contracts are provisional until their
//! corresponding specifications are approved.

/// Authorization outcomes at the policy boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The policy permits the exact action under the evaluated context.
    Allow,
    /// The policy prohibits the action or a required trust condition failed.
    Deny,
    /// A separate approval workflow is required; this is not execution permission.
    RequireApproval,
}
