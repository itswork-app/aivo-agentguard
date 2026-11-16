//! G1 permit claims and G3 `PermitEnvelopeV2` verification.
//!
//! This module verifies signed data only. Key lookup, purpose authorization,
//! revocation lookup, trusted clock acquisition, atomic consumption, and
//! side-effect execution remain responsibilities of higher-level boundaries.

use serde::{Deserialize, Serialize};

use crate::{
    CanonicalizationError, CryptoError, Decision, ProtocolShapeError, SignatureEnvelope,
    SignedAuthorizationAttestationV1, SignedSigningChallengeV1, canonical_json, hex_digest,
    protocol::{parse_timestamp, validate_hex_digest, validate_identifier, validate_lifetime},
    verify_ed25519,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationPermitV1 {
    pub permit_id: String,
    pub schema_version: u8,
    pub tenant_id: String,
    pub principal_id: String,
    pub agent_id: String,
    pub request_id: String,
    pub action_digest: String,
    pub policy_id: String,
    pub policy_version: String,
    pub policy_digest: String,
    pub context_digest: String,
    pub issued_at: String,
    pub expires_at: String,
    pub nonce: String,
    pub decision: Decision,
    pub signing_key_id: String,
}

impl AuthorizationPermitV1 {
    /// Validate the frozen G1 permit claim shape and its 60-second hard TTL.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schema versions, non-ALLOW decisions,
    /// malformed identifiers/digests, or invalid issue/expiry timestamps.
    pub fn validate(&self) -> Result<(), ProtocolShapeError> {
        if self.schema_version != 1 {
            return Err(ProtocolShapeError::UnsupportedSchemaVersion);
        }
        if self.decision != Decision::Allow {
            return Err(ProtocolShapeError::DecisionNotAllowed);
        }
        for value in [
            &self.permit_id,
            &self.tenant_id,
            &self.principal_id,
            &self.agent_id,
            &self.request_id,
            &self.policy_id,
            &self.policy_version,
            &self.signing_key_id,
        ] {
            validate_identifier(value)?;
        }
        for value in [
            &self.action_digest,
            &self.policy_digest,
            &self.context_digest,
            &self.nonce,
        ] {
            validate_hex_digest(value)?;
        }
        validate_lifetime(&self.issued_at, &self.expires_at, 60)
    }

    /// Build the exact G1 permit signature message using the frozen domain separator.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical JSON serialization fails.
    pub fn signing_message(&self) -> Result<Vec<u8>, CanonicalizationError> {
        let canonical = canonical_json(self)?;
        let mut message = b"AIVO-AGENTGUARD-PERMIT-V1\0".to_vec();
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    /// Verify the inner G1 permit signature against a caller-resolved permit key.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid claims, canonicalization failure, or an invalid signature.
    pub fn verify_signature(
        &self,
        signature: &SignatureEnvelope,
        public_key: &[u8; 32],
    ) -> Result<(), PermitEnvelopeError> {
        self.validate().map_err(PermitEnvelopeError::Protocol)?;
        signature
            .validate_shape()
            .map_err(|_| PermitEnvelopeError::KeyIdMismatch)?;
        if signature.key_id != self.signing_key_id
            || signature.algorithm != crate::SignatureAlgorithm::Ed25519
        {
            return Err(PermitEnvelopeError::KeyIdMismatch);
        }
        let message = self
            .signing_message()
            .map_err(|error| PermitEnvelopeError::Canonicalization(error.to_string()))?;
        verify_ed25519(public_key, signature, &message).map_err(PermitEnvelopeError::Crypto)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProvenanceV1 {
    pub policy_id: String,
    pub policy_version: String,
    pub policy_digest: String,
    pub policy_issuer_id: String,
    pub policy_signing_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationBindingV1 {
    pub issuer_id: String,
    pub issuer_key_id: String,
    pub attestation_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermitEnvelopeV2 {
    pub envelope_version: u8,
    pub permit_claims_v1: AuthorizationPermitV1,
    pub permit_signature_v1: SignatureEnvelope,
    pub signing_challenge_v1: SignedSigningChallengeV1,
    pub authorization_attestation_v1: SignedAuthorizationAttestationV1,
    pub policy_provenance: PolicyProvenanceV1,
    pub attestation_binding: AttestationBindingV1,
    pub permit_signer_key_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub envelope_signature: SignatureEnvelope,
}

#[derive(Serialize)]
struct PermitEnvelopeV2SigningPayload<'a> {
    envelope_version: u8,
    permit_claims_v1: &'a AuthorizationPermitV1,
    permit_signature_v1: &'a SignatureEnvelope,
    signing_challenge_v1: &'a SignedSigningChallengeV1,
    authorization_attestation_v1: &'a SignedAuthorizationAttestationV1,
    policy_provenance: &'a PolicyProvenanceV1,
    attestation_binding: &'a AttestationBindingV1,
    permit_signer_key_id: &'a str,
    issued_at: &'a str,
    expires_at: &'a str,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PermitEnvelopeError {
    #[error("unsupported permit envelope version; G3 requires v2")]
    UnsupportedEnvelopeVersion,
    #[error("permit or envelope signature key ID mismatch")]
    KeyIdMismatch,
    #[error("policy provenance does not match the permit and attestation")]
    PolicyBindingMismatch,
    #[error("attestation binding does not match the signed attestation")]
    AttestationBindingMismatch,
    #[error("challenge, attestation, permit, and envelope claims do not match")]
    CrossBindingMismatch,
    #[error("permit envelope timestamps are invalid or out of order")]
    InvalidTimestampOrder,
    #[error("permit envelope expiry exceeds an inner artifact expiry")]
    ExpiryEscalation,
    #[error("protocol validation failed: {0}")]
    Protocol(#[from] ProtocolShapeError),
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
    #[error("cryptographic verification failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("challenge signature verification failed: {0}")]
    ChallengeSignature(String),
    #[error("attestation signature verification failed: {0}")]
    AttestationSignature(String),
}

impl PermitEnvelopeV2 {
    /// Validate G3 envelope version, strict shape, exact bindings, and time ordering.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported versions, malformed claims, invalid
    /// signatures' key metadata, cross-artifact mismatch, or expiry escalation.
    pub fn validate_shape(&self) -> Result<(), PermitEnvelopeError> {
        if self.envelope_version != 2 {
            return Err(PermitEnvelopeError::UnsupportedEnvelopeVersion);
        }
        self.permit_claims_v1
            .validate()
            .map_err(PermitEnvelopeError::Protocol)?;
        self.signing_challenge_v1
            .validate_shape()
            .map_err(PermitEnvelopeError::Protocol)?;
        self.authorization_attestation_v1
            .validate_shape()
            .map_err(PermitEnvelopeError::Protocol)?;

        self.permit_signature_v1
            .validate_shape()
            .map_err(|_| PermitEnvelopeError::KeyIdMismatch)?;
        self.envelope_signature
            .validate_shape()
            .map_err(|_| PermitEnvelopeError::KeyIdMismatch)?;
        validate_identifier(&self.permit_signer_key_id)?;
        if self.permit_signature_v1.key_id != self.permit_claims_v1.signing_key_id
            || self.envelope_signature.key_id != self.permit_signer_key_id
        {
            return Err(PermitEnvelopeError::KeyIdMismatch);
        }

        let permit = &self.permit_claims_v1;
        let attestation = &self.authorization_attestation_v1.claims;
        let provenance = &self.policy_provenance;
        let binding = &self.attestation_binding;

        for value in [
            &provenance.policy_id,
            &provenance.policy_version,
            &provenance.policy_issuer_id,
            &provenance.policy_signing_key_id,
            &binding.issuer_id,
            &binding.issuer_key_id,
        ] {
            validate_identifier(value)?;
        }
        validate_hex_digest(&provenance.policy_digest)?;
        validate_hex_digest(&binding.attestation_digest)?;

        if provenance.policy_id != permit.policy_id
            || provenance.policy_version != permit.policy_version
            || provenance.policy_digest != permit.policy_digest
            || provenance.policy_id != attestation.policy_id
            || provenance.policy_version != attestation.policy_version
            || provenance.policy_digest != attestation.policy_digest
            || provenance.policy_issuer_id != attestation.policy_issuer_id
            || provenance.policy_signing_key_id != attestation.policy_signing_key_id
        {
            return Err(PermitEnvelopeError::PolicyBindingMismatch);
        }

        let computed_attestation_digest = self
            .authorization_attestation_v1
            .digest()
            .map_err(|error| PermitEnvelopeError::Canonicalization(error.to_string()))?;
        if binding.issuer_id != attestation.issuer_id
            || binding.issuer_key_id != attestation.issuer_key_id
            || binding.attestation_digest != hex_digest(&computed_attestation_digest)
        {
            return Err(PermitEnvelopeError::AttestationBindingMismatch);
        }

        self.authorization_attestation_v1
            .validate_challenge_binding(&self.signing_challenge_v1)
            .map_err(|_| PermitEnvelopeError::CrossBindingMismatch)?;

        if attestation.tenant_id != permit.tenant_id
            || attestation.principal_id != permit.principal_id
            || attestation.agent_id != permit.agent_id
            || attestation.request_id != permit.request_id
            || attestation.action_digest != permit.action_digest
            || attestation.context_digest != permit.context_digest
            || attestation.decision != Decision::Allow
        {
            return Err(PermitEnvelopeError::CrossBindingMismatch);
        }

        validate_lifetime(&self.issued_at, &self.expires_at, 60)?;
        let challenge = &self.signing_challenge_v1.claims;
        let challenge_issued = parse_timestamp(&challenge.issued_at)?;
        let challenge_expires = parse_timestamp(&challenge.expires_at)?;
        let attestation_issued = parse_timestamp(&attestation.issued_at)?;
        let permit_issued = parse_timestamp(&permit.issued_at)?;
        let permit_expires = parse_timestamp(&permit.expires_at)?;
        let envelope_issued = parse_timestamp(&self.issued_at)?;
        let envelope_expires = parse_timestamp(&self.expires_at)?;
        let attestation_expires = parse_timestamp(&attestation.expires_at)?;

        if challenge_issued > attestation_issued
            || attestation_issued > challenge_expires
            || attestation_issued > permit_issued
            || permit_issued > envelope_issued
        {
            return Err(PermitEnvelopeError::InvalidTimestampOrder);
        }
        if envelope_expires > permit_expires || envelope_expires > attestation_expires {
            return Err(PermitEnvelopeError::ExpiryEscalation);
        }
        if envelope_expires <= envelope_issued {
            return Err(PermitEnvelopeError::InvalidTimestampOrder);
        }
        Ok(())
    }

    /// Build the exact domain-separated message signed by the outer envelope signer.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical JSON serialization fails.
    pub fn signing_message(&self) -> Result<Vec<u8>, CanonicalizationError> {
        let payload = PermitEnvelopeV2SigningPayload {
            envelope_version: self.envelope_version,
            permit_claims_v1: &self.permit_claims_v1,
            permit_signature_v1: &self.permit_signature_v1,
            signing_challenge_v1: &self.signing_challenge_v1,
            authorization_attestation_v1: &self.authorization_attestation_v1,
            policy_provenance: &self.policy_provenance,
            attestation_binding: &self.attestation_binding,
            permit_signer_key_id: &self.permit_signer_key_id,
            issued_at: &self.issued_at,
            expires_at: &self.expires_at,
        };
        let canonical = canonical_json(&payload)?;
        let mut message = b"AIVO-AGENTGUARD-PERMIT-ENVELOPE-V2\0".to_vec();
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    /// Verify the outer envelope signature using a caller-resolved permit-purpose key.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid envelope shape, canonicalization failure,
    /// key ID mismatch, or invalid Ed25519 signature.
    pub fn verify_outer_signature(&self, public_key: &[u8; 32]) -> Result<(), PermitEnvelopeError> {
        self.validate_shape()?;
        let message = self
            .signing_message()
            .map_err(|error| PermitEnvelopeError::Canonicalization(error.to_string()))?;
        verify_ed25519(public_key, &self.envelope_signature, &message)
            .map_err(PermitEnvelopeError::Crypto)
    }

    /// Verify the frozen inner G1 permit signature independently of the outer signature.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid envelope shape, G1 claims, key ID mismatch,
    /// canonicalization failure, or invalid Ed25519 signature.
    pub fn verify_inner_permit_signature(
        &self,
        public_key: &[u8; 32],
    ) -> Result<(), PermitEnvelopeError> {
        self.validate_shape()?;
        self.permit_claims_v1
            .verify_signature(&self.permit_signature_v1, public_key)
    }

    /// Verify the challenge signature with the caller-resolved permit-purpose key.
    ///
    /// # Errors
    ///
    /// Returns an error when challenge shape or its Ed25519 signature is invalid.
    pub fn verify_challenge_signature(
        &self,
        public_key: &[u8; 32],
    ) -> Result<(), PermitEnvelopeError> {
        self.signing_challenge_v1
            .verify_signature(public_key)
            .map_err(|error| PermitEnvelopeError::ChallengeSignature(error.to_string()))
    }

    /// Verify the authorization attestation with the caller-resolved issuer-purpose key.
    ///
    /// # Errors
    ///
    /// Returns an error when attestation shape or its Ed25519 signature is invalid.
    pub fn verify_attestation_signature(
        &self,
        public_key: &[u8; 32],
    ) -> Result<(), PermitEnvelopeError> {
        self.authorization_attestation_v1
            .verify_signature(public_key)
            .map_err(|error| PermitEnvelopeError::AttestationSignature(error.to_string()))
    }

    /// Verify all four signatures independently after the caller resolves each purpose-scoped key.
    ///
    /// # Errors
    ///
    /// Returns an error if any claim binding or any inner permit, challenge,
    /// attestation, or outer envelope signature is invalid.
    pub fn verify_all_signatures(
        &self,
        inner_permit_key: &[u8; 32],
        challenge_key: &[u8; 32],
        attestation_key: &[u8; 32],
        envelope_key: &[u8; 32],
    ) -> Result<(), PermitEnvelopeError> {
        self.validate_shape()?;
        self.verify_inner_permit_signature(inner_permit_key)?;
        self.verify_challenge_signature(challenge_key)?;
        self.verify_attestation_signature(attestation_key)?;
        self.verify_outer_signature(envelope_key)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permit() -> AuthorizationPermitV1 {
        AuthorizationPermitV1 {
            permit_id: "permit-1".into(),
            schema_version: 1,
            tenant_id: "tenant-1".into(),
            principal_id: "principal-1".into(),
            agent_id: "agent-1".into(),
            request_id: "request-1".into(),
            action_digest: "11".repeat(32),
            policy_id: "policy-1".into(),
            policy_version: "1".into(),
            policy_digest: "22".repeat(32),
            context_digest: "33".repeat(32),
            issued_at: "2026-11-17T10:00:00Z".into(),
            expires_at: "2026-11-17T10:00:30Z".into(),
            nonce: "44".repeat(32),
            decision: Decision::Allow,
            signing_key_id: "permit-key-1".into(),
        }
    }

    #[test]
    fn accepts_g1_permit_claims_within_contract_lifetime() {
        assert_eq!(permit().validate(), Ok(()));
    }

    #[test]
    fn rejects_g1_non_allow_and_lifetime_escalation() {
        let mut invalid = permit();
        invalid.decision = Decision::Deny;
        assert_eq!(
            invalid.validate(),
            Err(ProtocolShapeError::DecisionNotAllowed)
        );

        let mut invalid = permit();
        invalid.expires_at = "2026-11-17T10:01:01Z".into();
        assert_eq!(invalid.validate(), Err(ProtocolShapeError::InvalidLifetime));
    }

    #[test]
    fn rejects_unknown_g1_permit_fields() {
        let mut value = serde_json::to_value(permit()).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<AuthorizationPermitV1>(value).is_err());
    }
}
