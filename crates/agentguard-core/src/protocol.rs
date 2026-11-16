//! Versioned protocol primitives shared by G1/G2/G3 implementations.

use serde::{Deserialize, Serialize};

/// Authorization outcomes at the policy boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
}

/// Cryptographic key purpose. Keys are never interchangeable across purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    PolicyIssuer,
    AuthorizationAttestationIssuer,
    PermitSigner,
    EvidenceService,
    ContextSource,
    RevocationAuthority,
}

/// Fixed-algorithm signature envelope. Algorithm negotiation is intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub algorithm: SignatureAlgorithm,
    pub key_id: String,
    /// Unpadded base64url Ed25519 signature.
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    Ed25519,
}

impl SignatureEnvelope {
    pub fn validate_shape(&self) -> Result<(), ProtocolShapeError> {
        if self.key_id.is_empty() || self.key_id.trim() != self.key_id {
            return Err(ProtocolShapeError::InvalidKeyId);
        }
        if self.signature.is_empty() {
            return Err(ProtocolShapeError::EmptySignature);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolShapeError {
    #[error("key identifier is empty or contains surrounding whitespace")]
    InvalidKeyId,
    #[error("signature is empty")]
    EmptySignature,
}
