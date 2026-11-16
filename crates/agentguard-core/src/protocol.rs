//! Versioned protocol primitives shared by G1/G2/G3 implementations.

use serde::{Deserialize, Serialize};

use crate::{CanonicalizationError, canonical_json, domain_digest, hex_digest, verify_ed25519};

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

/// Complete challenge token carried by `PermitEnvelopeV2`.
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
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported versions, malformed identifiers/digests,
    /// invalid UTC timestamps, or a challenge lifetime outside the 30-second limit.
    pub fn validate(&self) -> Result<(), ProtocolShapeError> {
        if self.schema_version != 1 {
            return Err(ProtocolShapeError::UnsupportedSchemaVersion);
        }
        for value in [&self.challenge_id, &self.tenant_id, &self.signer_key_id] {
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
    ///
    /// # Errors
    ///
    /// Returns an error when claims are malformed or the signature key ID differs.
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

    /// Build the exact signed message for the challenge claims.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical JSON serialization fails.
    pub fn signing_message(&self) -> Result<Vec<u8>, CanonicalizationError> {
        let canonical = canonical_json(&self.claims)?;
        let mut message = b"AIVO-AGENTGUARD-SIGNING-CHALLENGE-V1\0".to_vec();
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    /// Verify the challenge signature using a caller-resolved permit-purpose key.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid claims, serialization failure, or an invalid signature.
    pub fn verify_signature(
        &self,
        public_key: &[u8; 32],
    ) -> Result<(), ChallengeVerificationError> {
        self.validate_shape()
            .map_err(ChallengeVerificationError::InvalidShape)?;
        let message = self
            .signing_message()
            .map_err(ChallengeVerificationError::Canonicalization)?;
        verify_ed25519(public_key, &self.signature, &message)
            .map_err(ChallengeVerificationError::Crypto)
    }

    /// Digest the complete canonical challenge token including its signature envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical JSON serialization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported versions, non-ALLOW decisions, malformed
    /// identifiers/digests, tenant mismatch, or an invalid attestation lifetime.
    pub fn validate(&self) -> Result<(), ProtocolShapeError> {
        if self.schema_version != 1 {
            return Err(ProtocolShapeError::UnsupportedSchemaVersion);
        }
        if self.decision != Decision::Allow {
            return Err(ProtocolShapeError::DecisionNotAllowed);
        }
        for value in [
            &self.attestation_id,
            &self.issuer_id,
            &self.issuer_key_id,
            &self.tenant_id,
            &self.principal_id,
            &self.agent_id,
            &self.request_id,
            &self.policy_id,
            &self.policy_version,
            &self.policy_issuer_id,
            &self.policy_signing_key_id,
            &self.evaluator_version,
            &self.decision_event_ref.tenant_id,
            &self.decision_event_ref.stream_id,
            &self.evidence_receipt_ref.receipt_id,
        ] {
            validate_identifier(value)?;
        }
        for value in [
            &self.request_digest,
            &self.action_digest,
            &self.policy_digest,
            &self.context_digest,
            &self.reason_codes_digest,
            &self.evaluator_artifact_digest,
            &self.decision_event_ref.event_hash,
            &self.evidence_receipt_ref.receipt_digest,
            &self.challenge_nonce,
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
    ///
    /// # Errors
    ///
    /// Returns an error when claims are malformed or the signature key ID differs.
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

    /// Build the exact signed message for the attestation claims.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical JSON serialization fails.
    pub fn signing_message(&self) -> Result<Vec<u8>, CanonicalizationError> {
        let canonical = canonical_json(&self.claims)?;
        let mut message = b"AIVO-AGENTGUARD-AUTH-ATTESTATION-V1\0".to_vec();
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    /// Verify the attestation signature using a caller-resolved issuer-purpose key.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid claims, serialization failure, or an invalid signature.
    pub fn verify_signature(
        &self,
        public_key: &[u8; 32],
    ) -> Result<(), AttestationVerificationError> {
        self.validate_shape()
            .map_err(AttestationVerificationError::InvalidShape)?;
        let message = self
            .signing_message()
            .map_err(AttestationVerificationError::Canonicalization)?;
        verify_ed25519(public_key, &self.signature, &message)
            .map_err(AttestationVerificationError::Crypto)
    }

    /// Digest the complete canonical attestation and signature envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical JSON serialization fails.
    pub fn digest(&self) -> Result<[u8; 32], CanonicalizationError> {
        let canonical = canonical_json(self)?;
        Ok(domain_digest(
            b"AIVO-AGENTGUARD-ATTESTATION-REF-V1\0",
            &canonical,
        ))
    }

    /// Require exact challenge, tenant, request, action, policy and context binding.
    ///
    /// # Errors
    ///
    /// Returns an error when the challenge or attestation is malformed or any
    /// bound field, digest, or timestamp ordering differs.
    pub fn validate_challenge_binding(
        &self,
        challenge: &SignedSigningChallengeV1,
    ) -> Result<(), ProtocolShapeError> {
        self.validate_shape()?;
        challenge.validate_shape()?;
        let challenge_digest = challenge
            .digest()
            .map_err(|_| ProtocolShapeError::ChallengeBindingMismatch)?;
        let challenge_digest_hex = hex_digest(&challenge_digest);
        let c = &challenge.claims;
        let a = &self.claims;
        if a.challenge_nonce != c.nonce
            || a.challenge_digest != challenge_digest_hex
            || a.tenant_id != c.tenant_id
            || a.request_digest != c.request_digest
            || a.action_digest != c.action_digest
            || a.policy_digest != c.policy_digest
            || a.context_digest != c.context_digest
            || a.issued_at < c.issued_at
            || a.issued_at > c.expires_at
        {
            return Err(ProtocolShapeError::ChallengeBindingMismatch);
        }
        Ok(())
    }
}

/// Errors verifying a signed challenge token.
#[derive(Debug, thiserror::Error)]
pub enum ChallengeVerificationError {
    #[error("challenge shape is invalid: {0}")]
    InvalidShape(#[from] ProtocolShapeError),
    #[error("challenge canonicalization failed: {0}")]
    Canonicalization(#[from] CanonicalizationError),
    #[error("challenge signature verification failed: {0}")]
    Crypto(#[from] crate::CryptoError),
}

/// Errors verifying a signed authorization attestation.
#[derive(Debug, thiserror::Error)]
pub enum AttestationVerificationError {
    #[error("attestation shape is invalid: {0}")]
    InvalidShape(#[from] ProtocolShapeError),
    #[error("attestation canonicalization failed: {0}")]
    Canonicalization(#[from] CanonicalizationError),
    #[error("attestation signature verification failed: {0}")]
    Crypto(#[from] crate::CryptoError),
}

pub(crate) fn validate_identifier(value: &str) -> Result<(), ProtocolShapeError> {
    if value.is_empty() || value.trim() != value || value.len() > 256 {
        return Err(ProtocolShapeError::InvalidIdentifier);
    }
    Ok(())
}

pub(crate) fn validate_hex_digest(value: &str) -> Result<(), ProtocolShapeError> {
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
pub(crate) fn parse_timestamp(value: &str) -> Result<i64, ProtocolShapeError> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes
            .iter()
            .enumerate()
            .any(|(i, byte)| !matches!(i, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit())
    {
        return Err(ProtocolShapeError::InvalidTimestamp);
    }

    let number =
        |range: std::ops::Range<usize>| -> i64 { value[range].parse::<i64>().unwrap_or_default() };
    let year = number(0..4);
    let month = number(5..7);
    let day = number(8..10);
    let hour = number(11..13);
    let minute = number(14..16);
    let second = number(17..19);

    if year < 1
        || !(1..=12).contains(&month)
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

pub(crate) fn validate_lifetime(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge() -> SigningChallengeV1 {
        SigningChallengeV1 {
            schema_version: 1,
            challenge_id: "challenge-1".into(),
            nonce: "11".repeat(32),
            pending_signing_request_digest: "22".repeat(32),
            tenant_id: "tenant-1".into(),
            request_digest: "33".repeat(32),
            action_digest: "44".repeat(32),
            policy_digest: "55".repeat(32),
            context_digest: "66".repeat(32),
            issued_at: "2026-11-17T10:00:00Z".into(),
            expires_at: "2026-11-17T10:00:30Z".into(),
            signer_key_id: "permit-key-1".into(),
        }
    }

    #[test]
    fn accepts_well_formed_challenge_and_rejects_expired_order() {
        assert_eq!(challenge().validate(), Ok(()));
        let mut invalid = challenge();
        invalid.expires_at = invalid.issued_at.clone();
        assert_eq!(invalid.validate(), Err(ProtocolShapeError::InvalidLifetime));
    }

    #[test]
    fn rejects_challenge_lifetime_over_30_seconds() {
        let mut invalid = challenge();
        invalid.expires_at = "2026-11-17T10:00:31Z".into();
        assert_eq!(invalid.validate(), Err(ProtocolShapeError::InvalidLifetime));
    }

    #[test]
    fn rejects_impossible_calendar_timestamp() {
        let mut invalid = challenge();
        invalid.issued_at = "2026-02-30T10:00:00Z".into();
        assert_eq!(
            invalid.validate(),
            Err(ProtocolShapeError::InvalidTimestamp)
        );
    }

    #[test]
    fn rejects_non_lowercase_or_wrong_length_digest() {
        let mut invalid = challenge();
        invalid.nonce = "AA".repeat(32);
        assert_eq!(invalid.validate(), Err(ProtocolShapeError::InvalidDigest));
    }

    #[test]
    fn rejects_unknown_challenge_fields() {
        let json = serde_json::json!({
            "schema_version": 1,
            "challenge_id": "challenge-1",
            "nonce": "11".repeat(32),
            "pending_signing_request_digest": "22".repeat(32),
            "tenant_id": "tenant-1",
            "request_digest": "33".repeat(32),
            "action_digest": "44".repeat(32),
            "policy_digest": "55".repeat(32),
            "context_digest": "66".repeat(32),
            "issued_at": "2026-11-17T10:00:00Z",
            "expires_at": "2026-11-17T10:00:30Z",
            "signer_key_id": "permit-key-1",
            "unexpected": true
        });
        assert!(serde_json::from_value::<SigningChallengeV1>(json).is_err());
    }

    #[test]
    fn challenge_signature_verifies_exact_domain_separated_claims() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[17_u8; 32]);
        let claims = challenge();
        let canonical = canonical_json(&claims).unwrap();
        let mut message = b"AIVO-AGENTGUARD-SIGNING-CHALLENGE-V1\0".to_vec();
        message.extend_from_slice(&canonical);
        let signature = signing_key.sign(&message);
        let token = SignedSigningChallengeV1 {
            claims,
            signature: SignatureEnvelope {
                algorithm: SignatureAlgorithm::Ed25519,
                key_id: "permit-key-1".into(),
                signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            },
        };
        assert!(
            token
                .verify_signature(signing_key.verifying_key().as_bytes())
                .is_ok()
        );
    }
}
