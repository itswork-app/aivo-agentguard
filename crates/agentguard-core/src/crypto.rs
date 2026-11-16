//! Ed25519 verification primitives. No private-key/signing API is exposed.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

use crate::SignatureEnvelope;

/// Errors raised while verifying an Ed25519 signature.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    #[error("signature is not valid unpadded base64url")]
    InvalidSignatureEncoding,
    #[error("signature must decode to exactly 64 bytes")]
    InvalidSignatureLength,
    #[error("signature envelope shape is invalid")]
    InvalidEnvelope,
    #[error("Ed25519 signature verification failed")]
    VerificationFailed,
}

/// Verify a fixed Ed25519 signature over the exact supplied message bytes.
///
/// The caller must resolve the public key from the correct purpose-scoped
/// trust store and check the key status before calling this function.
///
/// # Errors
///
/// Returns an error for malformed keys or envelopes, invalid signature
/// encoding or length, or a signature that does not verify.
pub fn verify_ed25519(
    public_key_bytes: &[u8; 32],
    envelope: &SignatureEnvelope,
    message: &[u8],
) -> Result<(), CryptoError> {
    envelope
        .validate_shape()
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let key =
        VerifyingKey::from_bytes(public_key_bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(envelope.signature.as_bytes())
        .map_err(|_| CryptoError::InvalidSignatureEncoding)?;
    if signature_bytes.len() != 64 {
        return Err(CryptoError::InvalidSignatureLength);
    }
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| CryptoError::InvalidSignatureLength)?;
    key.verify_strict(message, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::SignatureAlgorithm;

    #[test]
    fn verifies_ed25519_signature_and_rejects_tampering() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let message = b"agentguard protocol test";
        let signature = signing_key.sign(message);
        let envelope = SignatureEnvelope {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "test-permit-key".to_owned(),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        };

        assert_eq!(
            verify_ed25519(signing_key.verifying_key().as_bytes(), &envelope, message),
            Ok(())
        );
        assert_eq!(
            verify_ed25519(
                signing_key.verifying_key().as_bytes(),
                &envelope,
                b"altered"
            ),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn rejects_empty_key_identifier() {
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        let envelope = SignatureEnvelope {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: " ".to_owned(),
            signature: URL_SAFE_NO_PAD.encode([0_u8; 64]),
        };
        assert_eq!(
            verify_ed25519(signing_key.verifying_key().as_bytes(), &envelope, b"x"),
            Err(CryptoError::InvalidEnvelope)
        );
    }
}
