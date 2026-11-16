//! Versioned protocol primitives shared by G1/G2/G3 implementations.

use serde::{Deserialize, Serialize};

use crate::{CanonicalizationError, SignatureEnvelope, canonical_json, domain_digest};

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

/// Signature algorithm fixed by protocol version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    Ed25519,
}

impl SignatureEnvelope {
    /// Validate fields that can be checked without resolving a trust-store key.
    ///
    /// # Errors
    ///
    /// Returns an error when the key identifier is empty/whitespace-padded or
    /// the signature string is empty.
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

/// Permit-signer challenge claims. All fields are mandatory and unknown fields
/// are rejected during deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningChallengeV1 {
    pub schema_version: u8,
    pub challenge_id: String,
    /// 32-byte cryptographically random nonce, lowercase hexadecimal.
    pub nonce: String,
    pub pending_signing_request_digest: String,
    pub tenant_id: String,
    pub request_digest: String,
    pub action_digest: String,
    pub policy_digest: String,
    pub context_digest: String,
    pub issued_at: String,
    pub expires_at: String,
    pub signer_key_id: String,
}

/// Complete challenge token carried by PermitEnvelopeV2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSigningChallengeV1 {
    pub claims: SigningChallengeV1,
    pub signature: SignatureEnvelope,
}

/// Durable decision-event reference included in an authorization attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionEventRef {
    pub tenant_id: String,
    pub stream_id: String,
    pub sequence: u64,
    pub event_hash: String,
}

/// Durable append receipt reference included in an authorization attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReceiptRef {
    pub receipt_id: String,
    pub receipt_digest: String,
}

/// Authorization attestation claims. The only admissible decision is ALLOW.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationAttestationV1 {
    pub schema_version: u8,
    pub attestation_id: String,
    pub issuer_id: String,
    pub issuer_key_id: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub agent_id: String,
    pub request_id: String,
    pub request_digest: String,
    pub action_digest: String,
    pub policy_id: String,
    pub policy_version: String,
    pub policy_digest: String,
    pub policy_issuer_id: String,
    pub policy_signing_key_id: String,
    pub context_digest: String,
    pub decision: Decision,
    pub reason_codes_digest: String,
    pub evaluator_version: String,
    pub evaluator_artifact_digest: String,
    pub decision_event_ref: DecisionEventRef,
    pub evidence_receipt_ref: EvidenceReceiptRef,
    pub issued_at: String,
    pub expires_at: String,
    pub challenge_nonce: String,
    pub challenge_digest: String,
}

/// Complete signed authorization attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorizationAttestationV1 {
    pub claims: AuthorizationAttestationV1,
    pub signature: SignatureEnvelope,
}

/// Typed shape-validation errors. These errors do not imply cryptographic trust.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolShapeError {
    #[error("key identifier is empty or contains surrounding whitespace")]
    InvalidKeyId,
    #[error("signature is empty")]
    EmptySignature,
    #[error("unsupported schema version")]
    UnsupportedSchemaVersion,
    #[error("required identifier is empty or contains surrounding whitespace")]
    InvalidIdentifier,
    #[error("digest or nonce must be exactly 32 bytes encoded as lowercase hexadecimal")]
    InvalidDigest,
    #[error("timestamp must be canonical UTC RFC3339 with whole seconds")]
    InvalidTimestamp,
    #[error("expiry must be after issue time and within the protocol lifetime")]
    InvalidLifetime,
    #[error("authorization attestation decision must be ALLOW")]
    DecisionNotAllowed,
    #[error("challenge and attestation bindings do not match")]
    ChallengeBindingMismatch,
}

impl SigningChallengeV1 {
    /// Validate structural invariants and the maximum 30-second challenge TTL.
    pub fn validate(&self) -> Result<(), ProtocolShapeError> {
        if self.schema_version != 1 {
            return Err(ProtocolShapeError::UnsupportedSchemaVersion);
        }
        for value in [
            &self.challenge_id, &self.tenant_id, &self.signer_key_id,
        ] {
            validate_identifier(value)?;
        }
        for value in [
            &self.nonce,
            &self.pending_signing_request_digest,
            &self.request_digest,
            &self.action_digest,
            &self.policy_digest,
            &self.context_digest,
        ] {
            validate_hex_digest(value)?;
        }
        validate_lifetime(&self.issued_at, &self.expires_at, 30)
    }
}

impl SignedSigningChallengeV1 {
    /// Validate claims and enforce signature-key ID equality.
    pub fn validate_shape(&self) -> Result<(), ProtocolShapeError> {
        self.claims.validate()?;
        self.signature
            .validate_shape()
            .map_err(|_| ProtocolShapeError::InvalidKeyId)?;
        if self.signature.algorithm != SignatureAlgorithm::Ed25519
            || self.signature.key_id != self.claims.signer_key_id
        {
            return Err(ProtocolShapeError::InvalidKeyId);
        }
        Ok(())
    }

    /// Digest the complete canonical challenge token including its signature envelope.
    pub fn digest(&self) -> Result<[u8; 32], CanonicalizationError> {
        let bytes = canonical_json(self)?;
        Ok(domain_digest(
            b"AIVO-AGENTGUARD-SIGNING-CHALLENGE-REF-V1\0",
            &bytes,
        ))
    }
}

impl AuthorizationAttestationV1 {
    /// Validate all claim-shape invariants and the maximum 30-second attestation TTL.
    pub fn validate(&self) -> Result<(), ProtocolShapeError> {
        if self.schema_version != 1 {
            return Err(ProtocolShapeError::UnsupportedSchemaVersion);
        }
        if self.decision != Decision::Allow {
            return Err(ProtocolShapeError::DecisionNotAllowed);
        }
        for value in [
            &self.attestation_id, &self.issuer_id, &self.issuer_key_id,
            &self.tenant_id, &self.principal_id, &self.agent_id, &self.request_id,
            &self.policy_id, &self.policy_version, &self.policy_issuer_id,
            &self.policy_signing_key_id, &self.evaluator_version,
            &self.decision_event_ref.tenant_id, &self.decision_event_ref.stream_id,
            &self.evidence_receipt_ref.receipt_id,
        ] {
            validate_identifier(value)?;
        }
        for value in [
            &self.request_digest, &self.action_digest, &self.policy_digest,
            &self.context_digest, &self.reason_codes_digest,
            &self.evaluator_artifact_digest, &self.decision_event_ref.event_hash,
            &self.evidence_receipt_ref.receipt_digest, &self.challenge_nonce,
            &self.challenge_digest,
        ] {
            validate_hex_digest(value)?;
        }
        if self.decision_event_ref.tenant_id != self.tenant_id {
            return Err(ProtocolShapeError::ChallengeBindingMismatch);
        }
        validate_lifetime(&self.issued_at, &self.expires_at, 30)
    }
}

impl SignedAuthorizationAttestationV1 {
    /// Validate claims and require the signature key ID to match the signed issuer key ID.
    pub fn validate_shape(&self) -> Result<(), ProtocolShapeError> {
        self.claims.validate()?;
        self.signature
            .validate_shape()
            .map_err(|_| ProtocolShapeError::InvalidKeyId)?;
        if self.signature.algorithm != SignatureAlgorithm::Ed25519
            || self.signature.key_id != self.claims.issuer_key_id
        {
            return Err(ProtocolShapeError::InvalidKeyId);
        }
        Ok(())
    }
}

fn validate_identifier(value: &str) -> Result<(), ProtocolShapeError> {
    if value.is_empty() || value.trim() != value || value.len() > 256 {
        return Err(ProtocolShapeError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_hex_digest(value: &str) -> Result<(), ProtocolShapeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolShapeError::InvalidDigest);
    }
    Ok(())
}

/// Accepts canonical UTC whole-second timestamps and validates calendar fields.
fn parse_timestamp(value: &str) -> Result<i64, ProtocolShapeError> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(i, byte)| {
            !matches!(i, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return Err(ProtocolShapeError::InvalidTimestamp);
    }

    let number = |range: std::ops::Range<usize>| -> i64 {
        value[range].parse::<i64>().unwrap_or_default()
    };
    let year = number(0..4);
    let month = number(5..7);
    let day = number(8..10);
    let hour = number(11..13);
    let minute = number(14..16);
    let second = number(17..19);

    if !(1..=12).contains(&month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return Err(ProtocolShapeError::InvalidTimestamp);
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day < 1 || day > month_days {
        return Err(ProtocolShapeError::InvalidTimestamp);
    }

    // Days since 1970-01-01, using the Gregorian calendar.
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;

    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn validate_lifetime(
    issued_at: &str,
    expires_at: &str,
    max_seconds: u64,
) -> Result<(), ProtocolShapeError> {
    let issued = parse_timestamp(issued_at)?;
    let expires = parse_timestamp(expires_at)?;
    let lifetime = expires - issued;
    if lifetime <= 0 || lifetime > i64::try_from(max_seconds).unwrap_or(i64::MAX) {
        return Err(ProtocolShapeError::InvalidLifetime);
    }
    Ok(())
}

