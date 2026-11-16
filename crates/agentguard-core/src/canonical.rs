//! RFC 8785 canonical JSON and domain-separated SHA-256 digests.

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors raised while producing RFC 8785 canonical JSON.
#[derive(Debug, Error)]
pub enum CanonicalizationError {
    #[error("RFC 8785 canonicalization failed: {0}")]
    Jcs(#[from] serde_json::Error),
}

/// Serialize a validated protocol value using RFC 8785 JSON Canonicalization.
///
/// Security-critical structs must deny unknown fields and validate `AgentGuard`
/// numeric and string constraints before calling this function.
///
/// # Errors
///
/// Returns an error when the value cannot be serialized as canonical JSON.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalizationError> {
    serde_jcs::to_vec(value).map_err(CanonicalizationError::from)
}

/// SHA-256(domain separator || canonical payload).
///
/// Callers must pass the exact UTF-8 domain separator including its trailing
/// NUL byte, as defined by the versioned protocol specification.
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
