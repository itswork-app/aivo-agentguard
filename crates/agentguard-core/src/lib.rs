//! Shared domain types and cryptographic protocol primitives for the AgentGuard product.
//!
//! This crate contains deterministic, side-effect-free primitives. It does not
//! hold signing keys, perform authorization orchestration, or execute actions.

mod canonical;
mod crypto;
mod protocol;
mod revocation;

pub use canonical::{CanonicalizationError, canonical_json, domain_digest, hex_digest};
pub use crypto::{CryptoError, verify_ed25519};
pub use protocol::{
    AttestationVerificationError, AuthorizationAttestationV1, ChallengeVerificationError, Decision,
    DecisionEventRef, EvidenceReceiptRef, KeyPurpose, ProtocolShapeError, SignatureAlgorithm,
    SignatureEnvelope, SignedAuthorizationAttestationV1, SignedSigningChallengeV1,
    SigningChallengeV1,
};
pub use revocation::{
    RevocationEntryV1, RevocationError, RevocationHighWaterMark, RevocationSnapshotV1,
    RevocationStatus, RevocationSubjectType, SignedRevocationSnapshotV1, validate_progression,
};

#[cfg(test)]
mod tests {
    use crate::{canonical_json, domain_digest, hex_digest};
    use serde::Serialize;

    #[derive(Serialize)]
    struct ReorderedA {
        z: u64,
        a: &'static str,
    }

    #[derive(Serialize)]
    struct ReorderedB {
        a: &'static str,
        z: u64,
    }

    #[test]
    fn canonical_json_is_independent_of_struct_field_order() {
        let a = canonical_json(&ReorderedA { z: 7, a: "agent" }).unwrap();
        let b = canonical_json(&ReorderedB { a: "agent", z: 7 }).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, br#"{"a":"agent","z":7}"#);
    }

    #[test]
    fn domain_digest_includes_exact_nul_terminated_domain() {
        let payload = br#"{"action":"transfer"}"#;
        let a = domain_digest(b"AIVO-AGENTGUARD-ACTION-V1\0", payload);
        let b = domain_digest(b"AIVO-AGENTGUARD-REQUEST-V1\0", payload);
        assert_ne!(a, b);
        assert_eq!(hex_digest(&a).len(), 64);
    }

    #[test]
    fn domain_separator_without_nul_is_not_equivalent() {
        let payload = b"payload";
        assert_ne!(
            domain_digest(b"AIVO-AGENTGUARD-ACTION-V1\0", payload),
            domain_digest(b"AIVO-AGENTGUARD-ACTION-V1", payload)
        );
    }
}
