//! Strict `AgentGuard` canonical JSON and domain-separated SHA-256 primitives.
//!
//! The accepted JSON profile is intentionally narrower than general RFC 8785:
//! floating-point values are forbidden and integers must be IEEE-754 safe
//! integers. Large or exact numeric values belong in schema-defined strings.

use serde::de::{self, Deserialize, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

/// Maximum accepted raw JSON input size (1 MiB).
pub const MAX_CANONICAL_INPUT_BYTES: usize = 1_048_576;

/// Maximum absolute integer value accepted by the `AgentGuard` v1 profile.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_SAFE_INTEGER_DECIMAL: &[u8] = b"9007199254740991";

/// Stable, non-sensitive canonicalization failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalError {
    /// The raw input exceeds the configured byte limit.
    InputTooLarge,
    /// The input is not valid UTF-8 JSON or violates the JSON grammar.
    InvalidJson,
    /// An object contains a duplicate decoded member name.
    DuplicateKey,
    /// A floating-point or fractional numeric value was supplied.
    FloatNotAllowed,
    /// An integer is outside the interoperable safe integer range.
    UnsafeInteger,
    /// The parser's maximum nesting depth was exceeded.
    NestingLimitExceeded,
    /// Canonical serialization failed unexpectedly.
    SerializationFailure,
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InputTooLarge => "canonical JSON input exceeds the byte limit",
            Self::InvalidJson => "input is not valid JSON",
            Self::DuplicateKey => "JSON object contains a duplicate member name",
            Self::FloatNotAllowed => "floating-point values are not allowed",
            Self::UnsafeInteger => "integer is outside the safe integer range",
            Self::NestingLimitExceeded => "JSON nesting limit exceeded",
            Self::SerializationFailure => "canonical serialization failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CanonicalError {}

/// Closed set of `AgentGuard` v1 digest domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestDomain {
    /// Request identity and request content.
    Request,
    /// Action content.
    Action,
    /// Policy content.
    Policy,
    /// Permit content.
    Permit,
    /// Evidence event content.
    Event,
}

impl DigestDomain {
    /// Returns the exact domain-separation bytes, including the trailing NUL.
    #[must_use]
    pub const fn separator(self) -> &'static [u8] {
        match self {
            Self::Request => b"AIVO-AGENTGUARD-REQUEST-V1\0",
            Self::Action => b"AIVO-AGENTGUARD-ACTION-V1\0",
            Self::Policy => b"AIVO-AGENTGUARD-POLICY-V1\0",
            Self::Permit => b"AIVO-AGENTGUARD-PERMIT-V1\0",
            Self::Event => b"AIVO-AGENTGUARD-EVENT-V1\0",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StrictValue {
    Null,
    Bool(bool),
    Integer(i64),
    Unsigned(u64),
    String(String),
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an AgentGuard v1 JSON value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(E::custom("integer is outside the safe integer range"));
        }
        Ok(StrictValue::Integer(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value > MAX_SAFE_INTEGER {
            return Err(E::custom("integer is outside the safe integer range"));
        }
        Ok(StrictValue::Unsigned(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // RFC 8785 serializes every negative-zero representation as the
        // integer token "0". Preserve that rule as the sole numeric exception
        // to this profile's prohibition on floating-point values.
        if value == 0.0 && value.is_sign_negative() {
            return Ok(StrictValue::Integer(0));
        }
        Err(E::custom("floating-point values are not allowed"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictValue::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        let mut entries = Vec::new();
        while let Some(key) = object.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate object member"));
            }
            let value = object.next_value()?;
            entries.push((key, value));
        }
        Ok(StrictValue::Object(entries))
    }
}

fn classify_json_error(error: &serde_json::Error) -> CanonicalError {
    let message = error.to_string();
    if message.contains("duplicate object member") {
        CanonicalError::DuplicateKey
    } else if message.contains("floating-point values are not allowed") {
        CanonicalError::FloatNotAllowed
    } else if message.contains("integer is outside the safe integer range") {
        CanonicalError::UnsafeInteger
    } else if message.contains("recursion limit exceeded") {
        CanonicalError::NestingLimitExceeded
    } else {
        CanonicalError::InvalidJson
    }
}

// Called only after serde_json has validated the complete JSON grammar. This
// lexical pass preserves integer-token precision even when a token exceeds
// serde_json's native u64/i64 representation and would otherwise visit f64.
fn contains_unsafe_integer_token(input: &[u8]) -> bool {
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'"' => {
                index += 1;
                while index < input.len() {
                    match input[index] {
                        b'\\' => index = (index + 2).min(input.len()),
                        b'"' => {
                            index += 1;
                            break;
                        }
                        _ => index += 1,
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = index;
                while index < input.len()
                    && !matches!(
                        input[index],
                        b',' | b']' | b'}' | b' ' | b'\n' | b'\r' | b'\t'
                    )
                {
                    index += 1;
                }
                let token = &input[start..index];
                if !token.iter().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
                    let digits = token.strip_prefix(b"-").unwrap_or(token);
                    if digits.len() > MAX_SAFE_INTEGER_DECIMAL.len()
                        || (digits.len() == MAX_SAFE_INTEGER_DECIMAL.len()
                            && digits > MAX_SAFE_INTEGER_DECIMAL)
                    {
                        return true;
                    }
                }
            }
            _ => index += 1,
        }
    }
    false
}

/// Parses and canonicalizes raw JSON under the `AgentGuard` v1 numeric profile.
///
/// Raw bytes are required so duplicate keys can be detected before a generic
/// map representation can discard them. A syntax-only pass precedes the strict
/// visitor so oversized integer tokens can be classified without precision loss.
///
/// # Errors
///
/// Returns a stable `CanonicalError` for oversized input, malformed JSON,
/// duplicate keys, unsupported numeric values, or serialization failures.
pub fn canonicalize_json(input: &[u8]) -> Result<Vec<u8>, CanonicalError> {
    if input.len() > MAX_CANONICAL_INPUT_BYTES {
        return Err(CanonicalError::InputTooLarge);
    }

    let mut syntax = serde_json::Deserializer::from_slice(input);
    IgnoredAny::deserialize(&mut syntax)
        .and_then(|_| syntax.end())
        .map_err(|error| classify_json_error(&error))?;

    if contains_unsafe_integer_token(input) {
        return Err(CanonicalError::UnsafeInteger);
    }

    let value = serde_json::from_slice::<StrictValue>(input)
        .map_err(|error| classify_json_error(&error))?;

    let mut output = Vec::with_capacity(input.len());
    write_canonical(&value, &mut output)?;
    Ok(output)
}

/// Computes a raw 32-byte SHA-256 digest over domain separator + canonical JSON.
///
/// # Errors
///
/// Returns any canonicalization error produced while validating the input.
pub fn digest_json(domain: DigestDomain, input: &[u8]) -> Result<[u8; 32], CanonicalError> {
    let canonical = canonicalize_json(input)?;
    let mut hasher = Sha256::new();
    hasher.update(domain.separator());
    hasher.update(canonical);
    Ok(hasher.finalize().into())
}

/// Computes a lowercase 64-character hexadecimal domain-separated digest.
///
/// # Errors
///
/// Returns any canonicalization error produced while validating the input.
pub fn digest_hex(domain: DigestDomain, input: &[u8]) -> Result<String, CanonicalError> {
    let digest = digest_json(domain, input)?;
    let mut output = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        write!(&mut output, "{byte:02x}").map_err(|_| CanonicalError::SerializationFailure)?;
    }
    Ok(output)
}

#[cfg(test)]
fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn write_canonical(value: &StrictValue, output: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match value {
        StrictValue::Null => output.extend_from_slice(b"null"),
        StrictValue::Bool(true) => output.extend_from_slice(b"true"),
        StrictValue::Bool(false) => output.extend_from_slice(b"false"),
        StrictValue::Integer(number) => output.extend_from_slice(number.to_string().as_bytes()),
        StrictValue::Unsigned(number) => output.extend_from_slice(number.to_string().as_bytes()),
        StrictValue::String(value) => {
            let encoded =
                serde_json::to_string(value).map_err(|_| CanonicalError::SerializationFailure)?;
            output.extend_from_slice(encoded.as_bytes());
        }
        StrictValue::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical(item, output)?;
            }
            output.push(b']');
        }
        StrictValue::Object(entries) => {
            let mut sorted: Vec<_> = entries.iter().collect();
            sorted.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));

            output.push(b'{');
            for (index, (key, item)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                let encoded =
                    serde_json::to_string(key).map_err(|_| CanonicalError::SerializationFailure)?;
                output.extend_from_slice(encoded.as_bytes());
                output.push(b':');
                write_canonical(item, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_recursive_objects_and_preserves_array_order() {
        let input = br#" { "z": [ {"b":2,"a":1}, 3 ], "a": true } "#;
        assert_eq!(
            canonicalize_json(input).unwrap(),
            br#"{"a":true,"z":[{"a":1,"b":2},3]}"#
        );
    }

    #[test]
    fn canonical_string_escaping_matches_the_profile() {
        let input = br#"{"s":"quote:\" slash:/ backslash:\\ newline:\n tab:\t nul:\u0000"}"#;
        let expected = br#"{"s":"quote:\" slash:/ backslash:\\ newline:\n tab:\t nul:\u0000"}"#;
        assert_eq!(canonicalize_json(input).unwrap(), expected);
    }

    #[test]
    fn canonicalizes_negative_zero_as_zero() {
        for input in [b"-0".as_slice(), b"-0.0", b"-0e0"] {
            assert_eq!(canonicalize_json(input).unwrap(), b"0");
        }
        assert_eq!(
            canonicalize_json(b"0.0"),
            Err(CanonicalError::FloatNotAllowed)
        );
    }

    #[test]
    fn enforces_input_size_and_parser_nesting_limits() {
        let oversized = vec![b' '; MAX_CANONICAL_INPUT_BYTES + 1];
        assert_eq!(
            canonicalize_json(&oversized),
            Err(CanonicalError::InputTooLarge)
        );

        let deeply_nested = format!("{}null{}", "[".repeat(130), "]".repeat(130));
        assert_eq!(
            canonicalize_json(deeply_nested.as_bytes()),
            Err(CanonicalError::NestingLimitExceeded)
        );
    }

    #[test]
    fn sorts_object_keys_by_utf16_code_units() {
        let input = r#"{"\uE000":1,"\uD800\uDC00":2}"#.as_bytes();
        assert_eq!(
            canonicalize_json(input).unwrap(),
            "{\"𐀀\":2,\"\":1}".as_bytes()
        );
    }

    #[test]
    fn rejects_duplicate_keys_at_every_depth() {
        assert_eq!(
            canonicalize_json(br#"{"a":1,"a":2}"#),
            Err(CanonicalError::DuplicateKey)
        );
        assert_eq!(
            canonicalize_json(br#"{"outer":{"a":1,"a":2}}"#),
            Err(CanonicalError::DuplicateKey)
        );
        assert_eq!(
            canonicalize_json(br#"{"a":1,"\u0061":2}"#),
            Err(CanonicalError::DuplicateKey)
        );
    }

    #[test]
    fn rejects_floats_and_unsafe_integers() {
        assert_eq!(
            canonicalize_json(br#"{"amount":1.0}"#),
            Err(CanonicalError::FloatNotAllowed)
        );
        assert_eq!(
            canonicalize_json(br#"{"amount":9007199254740992}"#),
            Err(CanonicalError::UnsafeInteger)
        );
        assert_eq!(
            canonicalize_json(br#"{"amount":-9007199254740992}"#),
            Err(CanonicalError::UnsafeInteger)
        );
        assert_eq!(
            canonicalize_json(b"18446744073709551616"),
            Err(CanonicalError::UnsafeInteger)
        );
        assert_eq!(
            canonicalize_json(b"-18446744073709551616"),
            Err(CanonicalError::UnsafeInteger)
        );
        assert_eq!(
            canonicalize_json(br#"{"amount":9007199254740991}"#).unwrap(),
            br#"{"amount":9007199254740991}"#
        );
    }

    #[test]
    fn rejects_invalid_utf8_and_lone_surrogates() {
        assert_eq!(
            canonicalize_json(&[b'"', 0xff, b'"']),
            Err(CanonicalError::InvalidJson)
        );
        assert_eq!(
            canonicalize_json(br#""\ud800""#),
            Err(CanonicalError::InvalidJson)
        );
    }

    #[test]
    fn equivalent_json_inputs_have_identical_canonical_bytes() {
        let first = canonicalize_json(br#"{"b":2,"a":1}"#).unwrap();
        let second = canonicalize_json(br#" { "a" : 1, "b" : 2 } "#).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn domain_separated_golden_vectors_match() {
        let fixture = include_str!("../tests/vectors/domain-digests-v1.json");
        let corpus: serde_json::Value = serde_json::from_str(fixture).unwrap();
        let input = br#"{"a":1}"#;
        assert_eq!(
            canonicalize_json(input).unwrap(),
            corpus["canonical_json_utf8"].as_str().unwrap().as_bytes()
        );

        for vector in corpus["vectors"].as_array().unwrap() {
            let domain = match vector["domain"].as_str().unwrap() {
                "REQUEST" => DigestDomain::Request,
                "ACTION" => DigestDomain::Action,
                "POLICY" => DigestDomain::Policy,
                "PERMIT" => DigestDomain::Permit,
                "EVENT" => DigestDomain::Event,
                _ => panic!("unknown digest domain in golden vector"),
            };
            assert_eq!(
                digest_hex(domain, input).unwrap(),
                vector["sha256_hex"].as_str().unwrap(),
                "golden vector {}",
                vector["id"].as_str().unwrap()
            );
            assert_eq!(
                hex_encode(domain.separator()),
                vector["domain_separator_hex"].as_str().unwrap()
            );
            let mut preimage = domain.separator().to_vec();
            preimage.extend_from_slice(&canonicalize_json(input).unwrap());
            assert_eq!(
                hex_encode(&preimage),
                vector["preimage_hex"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn canonicalization_conformance_corpus_matches_exact_bytes_and_errors() {
        let fixture = include_str!("../tests/vectors/canonicalization-v1.json");
        let corpus: serde_json::Value = serde_json::from_str(fixture).unwrap();
        assert_eq!(
            corpus["schema_version"].as_str(),
            Some("agentguard.canonicalization-v1")
        );
        assert_eq!(
            corpus["profile"].as_str(),
            Some("agentguard-jcs-constrained-v1")
        );

        for vector in corpus["vectors"].as_array().unwrap() {
            let id = vector["id"].as_str().unwrap();
            let input = vector["input_json"].as_str().unwrap().as_bytes();
            if let Some(expected) = vector.get("expected_canonical_json_utf8") {
                assert_eq!(
                    canonicalize_json(input).unwrap(),
                    expected.as_str().unwrap().as_bytes(),
                    "canonical bytes for {id}"
                );
            } else {
                let expected_error = match vector["expected_error"].as_str().unwrap() {
                    "DuplicateKey" => CanonicalError::DuplicateKey,
                    "FloatNotAllowed" => CanonicalError::FloatNotAllowed,
                    "UnsafeInteger" => CanonicalError::UnsafeInteger,
                    "InvalidJson" => CanonicalError::InvalidJson,
                    other => panic!("unknown canonical error in vector {id}: {other}"),
                };
                assert_eq!(
                    canonicalize_json(input),
                    Err(expected_error),
                    "stable error for {id}"
                );
            }
        }
    }

    #[test]
    fn canonicalization_properties_hold_for_generated_inputs() {
        for left in 0_u64..32 {
            for right in 0_u64..32 {
                let forward = format!(r#"{{"left":{left},"right":{right}}}"#);
                let reverse = format!(r#"{{"right":{right},"left":{left}}}"#);
                let canonical = canonicalize_json(forward.as_bytes()).unwrap();
                let reordered = canonicalize_json(reverse.as_bytes()).unwrap();

                // Object insertion order is irrelevant and canonicalization is idempotent.
                assert_eq!(canonical, reordered);
                assert_eq!(canonicalize_json(&canonical).unwrap(), canonical);

                // Array order is significant and must not be sorted.
                let array_forward = format!("[{left},{right}]");
                let array_reverse = format!("[{right},{left}]");
                let canonical_array_forward = canonicalize_json(array_forward.as_bytes()).unwrap();
                let canonical_array_reverse = canonicalize_json(array_reverse.as_bytes()).unwrap();
                if left != right {
                    assert_ne!(canonical_array_forward, canonical_array_reverse);
                }
            }
        }
    }

    #[test]
    fn digest_is_bound_to_domain_and_nul_terminated_separator() {
        let request = digest_json(DigestDomain::Request, br#"{"a":1}"#).unwrap();
        let action = digest_json(DigestDomain::Action, br#"{"a":1}"#).unwrap();
        assert_ne!(request, action);
        assert_eq!(DigestDomain::Request.separator().last(), Some(&0));
    }
}
