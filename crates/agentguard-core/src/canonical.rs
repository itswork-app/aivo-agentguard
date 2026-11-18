//! Compatibility facade routing G3 protocol serialization through the
//! single strict `AgentGuard` canonicalization implementation.

use serde::Serialize;
use sha2::{Digest, Sha256};

pub type CanonicalizationError = agentguard_canonical::CanonicalError;

/// Serialize typed protocol claims and canonicalize them with the shared
/// `AgentGuard` v1 profile. Protocol structs must reject unknown fields.
///
/// # Errors
///
/// Returns an error when serialization fails or the strict canonical JSON
/// profile rejects the encoded protocol value.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalizationError> {
    let encoded =
        serde_json::to_vec(value).map_err(|_| CanonicalizationError::SerializationFailure)?;
    agentguard_canonical::canonicalize_json(&encoded)
}

/// Hash a domain separator and already-canonical payload bytes.
#[must_use]
pub fn domain_digest(domain: &[u8], canonical_payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical_payload);
    hasher.finalize().into()
}

/// Encode a 32-byte digest as lowercase hexadecimal.
#[must_use]
pub fn hex_digest(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
