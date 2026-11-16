//! Ed25519 verification primitives. No private-key/signing API is exposed.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;
use crate::SignatureEnvelope;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    #[error("signature is not valid unpadded base64url")]
    InvalidSignatureEncoding,
    #[error("signature must decode to exactly 64 bytes")]
    InvalidSignatureLength,
    #[error("Ed25519 signature verification failed")]
    VerificationFailed,
}

/// Verify a fixed Ed25519 signature over the exact supplied message bytes.
///
/// The caller must first validate the envelope key purpose and resolve the
/// public key from the correct purpose-scoped trust store.
pub fn verify_ed25519(
    public_key_bytes: &[u8; 32],
    envelope: &SignatureEnvelope,
    message: &[u8],
) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(envelope.signature.as_bytes())
        .map_err(|_| CryptoError::InvalidSignatureEncoding)?;
    if signature_bytes.len() != 64 {
        return Err(CryptoError::InvalidSignatureLength);
    }
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| CryptoError::InvalidSignatureLength)?;
    key.verify_strict(message, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use super::*;
    use crate::SignatureAlgorithm;

    #[test]
    fn verifies_ed25519_signature() {
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
            verify_ed25519(signing_key.verifying_key().as_bytes(), &envelope, b"altered"),
            Err(CryptoError::VerificationFailed)
        );
    }
}
