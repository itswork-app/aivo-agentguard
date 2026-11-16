//! RFC 8785 canonical JSON and domain-separated SHA-256 digests.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors raised while producing RFC 8785 canonical JSON.
#[derive(Debug, Error)]
pub enum CanonicalizationError {
    #[error("RFC 8785 canonicalization failed: {0}")]
    Jcs(#[from] serde_json::Error),
    #[error("security-relevant JSON numbers must be safe integers; floats are prohibited")]
    UnsupportedNumber,
}

/// Serialize a validated protocol value using RFC 8785 JSON Canonicalization.
///
/// Security-critical structs must deny unknown fields. Floating-point values
/// and integers outside the interoperable IEEE-754 safe integer range are
/// rejected before canonicalization.
///
/// # Errors
///
/// Returns an error when serialization fails or a number violates the
/// AgentGuard canonical numeric restrictions.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalizationError> {
    let value = serde_json::to_value(value)?;
    validate_numbers(&value)?;
    serde_jcs::to_vec(&value).map_err(CanonicalizationError::from)
}

fn validate_numbers(value: &Value) -> Result<(), CanonicalizationError> {
    const MAX_SAFE_INTEGER: i128 = 9_007_199_254_740_991;
    match value {
        Value::Number(number) => {
            if number.is_f64()
                || number
                    .as_i64()
                    .is_some_and(|integer| i128::from(integer).abs() > MAX_SAFE_INTEGER)
                || number
                    .as_u64()
                    .is_some_and(|integer| i128::from(integer) > MAX_SAFE_INTEGER)
            {
                return Err(CanonicalizationError::UnsupportedNumber);
            }
        }
        Value::Array(values) => {
            for item in values {
                validate_numbers(item)?;
            }
        }
        Value::Object(values) => {
            for item in values.values() {
                validate_numbers(item)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct ContainsFloat {
        value: f64,
    }

    #[derive(Serialize)]
    struct ContainsUnsafeInteger {
        value: u64,
    }

    #[test]
    fn rejects_floating_point_values() {
        assert!(matches!(
            canonical_json(&ContainsFloat { value: 1.5 }),
            Err(CanonicalizationError::UnsupportedNumber)
        ));
    }

    #[test]
    fn rejects_integers_outside_interoperable_safe_range() {
        assert!(matches!(
            canonical_json(&ContainsUnsafeInteger {
                value: 9_007_199_254_740_992
            }),
            Err(CanonicalizationError::UnsupportedNumber)
        ));
    }
}
