//! Signed in-toto/SLSA evaluator provenance verification.
//!
//! Trust roots and owner-approved release manifests are supplied by the caller.
//! This module verifies the DSSE signature, exact build provenance bindings,
//! and observed artifact digest; it does not build or download artifacts.

use std::collections::BTreeMap;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    CanonicalizationError, CryptoError, SignatureAlgorithm, SignatureEnvelope,
    canonical_json, hex_digest, verify_ed25519,
};

const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
const SLSA_PROVENANCE_TYPE: &str = "https://slsa.dev/provenance/v1";

/// Owner-approved immutable evaluator release manifest.
///
/// The caller MUST load this record from an owner-controlled release allowlist,
/// not from the provenance envelope or runtime request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorReleaseManifestV1 {
    pub schema_version: u8,
    pub release_id: String,
    pub evaluator_semantic_version: String,
    pub artifact_name: String,
    pub artifact_sha256: String,
    pub source_repository: String,
    pub source_commit: String,
    pub cargo_lock_sha256: String,
    pub rust_toolchain: String,
    pub target_triple: String,
    pub builder_identity: String,
    pub workflow_identity: String,
    pub build_invocation: String,
    pub provenance_statement_sha256: String,
}

/// DSSE signature entry. DSSE uses standard base64 for signature bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseSignatureV1 {
    pub keyid: String,
    pub sig: String,
}

/// DSSE envelope carrying a signed in-toto statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseEnvelopeV1 {
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<DsseSignatureV1>,
}

/// in-toto Statement v1 payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InTotoStatementV1 {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<InTotoSubjectV1>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: SlsaProvenancePredicateV1,
}

/// Artifact subject in an in-toto statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InTotoSubjectV1 {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

/// SLSA Provenance v1 predicate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlsaProvenancePredicateV1 {
    #[serde(rename = "buildDefinition")]
    pub build_definition: SlsaBuildDefinitionV1,
    #[serde(rename = "runDetails")]
    pub run_details: SlsaRunDetailsV1,
}

/// SLSA build definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlsaBuildDefinitionV1 {
    #[serde(rename = "buildType")]
    pub build_type: String,
    #[serde(rename = "externalParameters")]
    pub external_parameters: Value,
    #[serde(rename = "internalParameters", default, skip_serializing_if = "Option::is_none")]
    pub internal_parameters: Option<Value>,
    #[serde(rename = "resolvedDependencies", default)]
    pub resolved_dependencies: Vec<SlsaResolvedDependencyV1>,
}

/// Resolved source or build dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlsaResolvedDependencyV1 {
    pub uri: String,
    pub digest: BTreeMap<String, String>,
}

/// SLSA run details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlsaRunDetailsV1 {
    pub builder: SlsaBuilderV1,
    pub metadata: SlsaRunMetadataV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byproducts: Option<Vec<Value>>,
}

/// Trusted builder identity in SLSA provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlsaBuilderV1 {
    pub id: String,
}

/// SLSA build invocation metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlsaRunMetadataV1 {
    #[serde(rename = "invocationId")]
    pub invocation_id: String,
    #[serde(rename = "startedOn", default, skip_serializing_if = "Option::is_none")]
    pub started_on: Option<String>,
    #[serde(rename = "finishedOn", default, skip_serializing_if = "Option::is_none")]
    pub finished_on: Option<String>,
}

/// Successfully verified evaluator release and its provenance binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvaluatorArtifactV1 {
    pub release_id: String,
    pub evaluator_semantic_version: String,
    pub artifact_sha256: String,
    pub provenance_statement_sha256: String,
    pub source_repository: String,
    pub source_commit: String,
    pub builder_identity: String,
    pub workflow_identity: String,
    pub build_invocation: String,
}

/// Provenance verification failures. Every failure is a hard deny.
#[derive(Debug, Error)]
pub enum ProvenanceError {
    #[error("invalid evaluator release manifest")]
    InvalidManifest,
    #[error("invalid DSSE envelope")]
    InvalidEnvelope,
    #[error("no trusted DSSE signature matched the configured provenance key")]
    MissingTrustedSignature,
    #[error("DSSE signature verification failed: {0}")]
    Signature(#[from] CryptoError),
    #[error("canonical provenance serialization failed: {0}")]
    Canonicalization(#[from] CanonicalizationError),
    #[error("in-toto/SLSA statement is invalid or unsupported")]
    InvalidStatement,
    #[error("provenance statement digest does not match the approved manifest")]
    StatementDigestMismatch,
    #[error("observed evaluator artifact digest does not match the approved manifest")]
    ArtifactDigestMismatch,
    #[error("provenance statement does not match the approved release manifest")]
    ManifestBindingMismatch,
}

/// Verify a signed DSSE in-toto/SLSA provenance statement against an
/// owner-approved release manifest and the digest of the actual evaluator bytes.
///
/// The public key MUST be resolved from a trusted provenance-issuer trust root;
/// it MUST NOT be selected from untrusted envelope metadata. The manifest MUST
/// come from an owner-controlled immutable allowlist.
///
/// # Errors
/// Returns an error for malformed claims, untrusted or invalid signatures,
/// unsupported provenance types, or any mismatch with the approved release.
pub fn verify_evaluator_provenance(
    envelope: &DsseEnvelopeV1,
    manifest: &EvaluatorReleaseManifestV1,
    observed_artifact_sha256: &str,
    provenance_public_key: &[u8; 32],
    expected_provenance_key_id: &str,
) -> Result<VerifiedEvaluatorArtifactV1, ProvenanceError> {
    validate_manifest(manifest)?;
    validate_digest(observed_artifact_sha256)?;
    if observed_artifact_sha256 != manifest.artifact_sha256 {
        return Err(ProvenanceError::ArtifactDigestMismatch);
    }
    let payload = verify_dsse(envelope, provenance_public_key, expected_provenance_key_id)?;
    let statement: InTotoStatementV1 =
        serde_json::from_slice(&payload).map_err(|_| ProvenanceError::InvalidStatement)?;
    let _canonical = canonical_json(&statement)?;
    validate_statement(&statement, manifest)?;

    let statement_digest = hex_digest(&Sha256::digest(&payload).into());
    if statement_digest != manifest.provenance_statement_sha256 {
        return Err(ProvenanceError::StatementDigestMismatch);
    }

    Ok(VerifiedEvaluatorArtifactV1 {
        release_id: manifest.release_id.clone(),
        evaluator_semantic_version: manifest.evaluator_semantic_version.clone(),
        artifact_sha256: manifest.artifact_sha256.clone(),
        provenance_statement_sha256: statement_digest,
        source_repository: manifest.source_repository.clone(),
        source_commit: manifest.source_commit.clone(),
        builder_identity: manifest.builder_identity.clone(),
        workflow_identity: manifest.workflow_identity.clone(),
        build_invocation: manifest.build_invocation.clone(),
    })
}

fn verify_dsse(
    envelope: &DsseEnvelopeV1,
    public_key: &[u8; 32],
    expected_key_id: &str,
) -> Result<Vec<u8>, ProvenanceError> {
    if envelope.payload_type != DSSE_PAYLOAD_TYPE
        || envelope.payload.is_empty()
        || envelope.signatures.is_empty()
        || envelope.signatures.len() > 8
        || expected_key_id.is_empty()
        || expected_key_id.len() > 256
    {
        return Err(ProvenanceError::InvalidEnvelope);
    }
    let payload = STANDARD
        .decode(envelope.payload.as_bytes())
        .map_err(|_| ProvenanceError::InvalidEnvelope)?;
    let pae = dsse_pae(&envelope.payload_type, &payload);
    let mut trusted_signature_found = false;
    let mut seen_key_ids = std::collections::BTreeSet::new();
    for entry in &envelope.signatures {
        if entry.keyid.is_empty()
            || entry.keyid.len() > 256
            || !seen_key_ids.insert(entry.keyid.as_str())
        {
            return Err(ProvenanceError::InvalidEnvelope);
        }
        if entry.keyid != expected_key_id {
            continue;
        }
        let signature_bytes = STANDARD
            .decode(entry.sig.as_bytes())
            .map_err(|_| ProvenanceError::InvalidEnvelope)?;
        if signature_bytes.len() != 64 {
            return Err(ProvenanceError::InvalidEnvelope);
        }
        let signature = SignatureEnvelope {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: entry.keyid.clone(),
            signature: URL_SAFE_NO_PAD.encode(signature_bytes),
        };
        verify_ed25519(public_key, &signature, &pae)?;
        trusted_signature_found = true;
    }
    if !trusted_signature_found {
        return Err(ProvenanceError::MissingTrustedSignature);
    }
    Ok(payload)
}

fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut result = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    result.extend_from_slice(payload);
    result
}

fn validate_manifest(manifest: &EvaluatorReleaseManifestV1) -> Result<(), ProvenanceError> {
    if manifest.schema_version != 1
        || manifest.release_id.is_empty()
        || manifest.evaluator_semantic_version.is_empty()
        || manifest.artifact_name.is_empty()
        || manifest.source_repository.is_empty()
        || manifest.rust_toolchain.is_empty()
        || manifest.target_triple.is_empty()
        || manifest.builder_identity.is_empty()
        || manifest.workflow_identity.is_empty()
        || manifest.build_invocation.is_empty()
    {
        return Err(ProvenanceError::InvalidManifest);
    }
    validate_digest(&manifest.artifact_sha256)?;
    validate_digest(&manifest.cargo_lock_sha256)?;
    validate_digest(&manifest.provenance_statement_sha256)?;
    if !manifest.source_commit.bytes().all(|b| b.is_ascii_hexdigit())
        || !matches!(manifest.source_commit.len(), 40 | 64)
    {
        return Err(ProvenanceError::InvalidManifest);
    }
    Ok(())
}

fn validate_statement(
    statement: &InTotoStatementV1,
    manifest: &EvaluatorReleaseManifestV1,
) -> Result<(), ProvenanceError> {
    if statement.statement_type != IN_TOTO_STATEMENT_TYPE
        || statement.predicate_type != SLSA_PROVENANCE_TYPE
        || statement.subject.is_empty()
    {
        return Err(ProvenanceError::InvalidStatement);
    }
    let artifact_subject_found = statement.subject.iter().any(|subject| {
        subject.name == manifest.artifact_name
            && subject.digest.get("sha256") == Some(&manifest.artifact_sha256)
    });
    if !artifact_subject_found {
        return Err(ProvenanceError::ManifestBindingMismatch);
    }

    let predicate = &statement.predicate;
    if predicate.run_details.builder.id != manifest.builder_identity
        || predicate.run_details.metadata.invocation_id != manifest.build_invocation
        || predicate.build_definition.build_type.is_empty()
    {
        return Err(ProvenanceError::ManifestBindingMismatch);
    }
    let external = predicate
        .build_definition
        .external_parameters
        .as_object()
        .ok_or(ProvenanceError::InvalidStatement)?;
    let exact_external = [
        ("sourceRepository", &manifest.source_repository),
        ("sourceCommit", &manifest.source_commit),
        ("cargoLockDigest", &manifest.cargo_lock_sha256),
        ("rustToolchain", &manifest.rust_toolchain),
        ("targetTriple", &manifest.target_triple),
        ("workflowIdentity", &manifest.workflow_identity),
    ];
    for (key, expected) in exact_external {
        if external.get(key).and_then(Value::as_str) != Some(expected.as_str()) {
            return Err(ProvenanceError::ManifestBindingMismatch);
        }
    }

    let source_found = predicate.build_definition.resolved_dependencies.iter().any(|dependency| {
        dependency.uri.starts_with("git+")
            && dependency.uri.contains(&manifest.source_repository)
            && dependency.digest.get("gitCommit") == Some(&manifest.source_commit)
    });
    let lock_found = predicate.build_definition.resolved_dependencies.iter().any(|dependency| {
        dependency.uri.contains("Cargo.lock")
            && dependency.digest.get("sha256") == Some(&manifest.cargo_lock_sha256)
    });
    if !source_found || !lock_found {
        return Err(ProvenanceError::ManifestBindingMismatch);
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), ProvenanceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProvenanceError::InvalidManifest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn fixture() -> (EvaluatorReleaseManifestV1, InTotoStatementV1, SigningKey) {
        let signing_key = SigningKey::from_bytes(&[42_u8; 32]);
        let artifact = "a".repeat(64);
        let source_commit = "b".repeat(40);
        let lock_digest = "c".repeat(64);
        let statement = InTotoStatementV1 {
            statement_type: IN_TOTO_STATEMENT_TYPE.into(),
            subject: vec![InTotoSubjectV1 {
                name: "agentguard-evaluator".into(),
                digest: BTreeMap::from([("sha256".into(), artifact.clone())]),
            }],
            predicate_type: SLSA_PROVENANCE_TYPE.into(),
            predicate: SlsaProvenancePredicateV1 {
                build_definition: SlsaBuildDefinitionV1 {
                    build_type: "https://github.com/actions/runner".into(),
                    external_parameters: json!({
                        "sourceRepository":"https://github.com/itswork-app/aivo-agentguard",
                        "sourceCommit":source_commit,
                        "cargoLockDigest":lock_digest,
                        "rustToolchain":"1.100.0",
                        "targetTriple":"x86_64-unknown-linux-gnu",
                        "workflowIdentity":"https://github.com/itswork-app/aivo-agentguard/.github/workflows/ci.yml"
                    }),
                    internal_parameters: None,
                    resolved_dependencies: vec![
                        SlsaResolvedDependencyV1 {
                            uri: "git+https://github.com/itswork-app/aivo-agentguard@refs/heads/main".into(),
                            digest: BTreeMap::from([("gitCommit".into(), source_commit.clone())]),
                        },
                        SlsaResolvedDependencyV1 {
                            uri: "file:Cargo.lock".into(),
                            digest: BTreeMap::from([("sha256".into(), lock_digest.clone())]),
                        },
                    ],
                },
                run_details: SlsaRunDetailsV1 {
                    builder: SlsaBuilderV1 { id: "https://github.com/actions/runner".into() },
                    metadata: SlsaRunMetadataV1 {
                        invocation_id: "run-123".into(),
                        started_on: None,
                        finished_on: None,
                    },
                    byproducts: None,
                },
            },
        };
        let payload = serde_json::to_vec(&statement).unwrap();
        let statement_digest = hex_digest(&Sha256::digest(&payload).into());
        let manifest = EvaluatorReleaseManifestV1 {
            schema_version: 1,
            release_id: "release-1".into(),
            evaluator_semantic_version: "0.1.0".into(),
            artifact_name: "agentguard-evaluator".into(),
            artifact_sha256: artifact,
            source_repository: "https://github.com/itswork-app/aivo-agentguard".into(),
            source_commit,
            cargo_lock_sha256: lock_digest,
            rust_toolchain: "1.100.0".into(),
            target_triple: "x86_64-unknown-linux-gnu".into(),
            builder_identity: "https://github.com/actions/runner".into(),
            workflow_identity: "https://github.com/itswork-app/aivo-agentguard/.github/workflows/ci.yml".into(),
            build_invocation: "run-123".into(),
            provenance_statement_sha256: statement_digest,
        };
        (manifest, statement, signing_key)
    }

    #[test]
    fn verifies_signed_provenance_against_approved_manifest() {
        let (manifest, statement, signing_key) = fixture();
        let payload = serde_json::to_vec(&statement).unwrap();
        let payload_type = DSSE_PAYLOAD_TYPE;
        let signature = signing_key.sign(&dsse_pae(payload_type, &payload));
        let envelope = DsseEnvelopeV1 {
            payload_type: payload_type.into(),
            payload: STANDARD.encode(payload),
            signatures: vec![DsseSignatureV1 {
                keyid: "build-provenance-key".into(),
                sig: STANDARD.encode(signature.to_bytes()),
            }],
        };
        let verified = verify_evaluator_provenance(
            &envelope,
            &manifest,
            &manifest.artifact_sha256,
            signing_key.verifying_key().as_bytes(),
            "build-provenance-key",
        ).unwrap();
        assert_eq!(verified.release_id, "release-1");
        assert_eq!(verified.source_commit, manifest.source_commit);
    }

    #[test]
    fn rejects_artifact_digest_mismatch_before_provenance_acceptance() {
        let (manifest, statement, signing_key) = fixture();
        let payload = serde_json::to_vec(&statement).unwrap();
        let signature = signing_key.sign(&dsse_pae(DSSE_PAYLOAD_TYPE, &payload));
        let envelope = DsseEnvelopeV1 {
            payload_type: DSSE_PAYLOAD_TYPE.into(),
            payload: STANDARD.encode(payload),
            signatures: vec![DsseSignatureV1 {
                keyid: "build-provenance-key".into(),
                sig: STANDARD.encode(signature.to_bytes()),
            }],
        };
        assert!(matches!(
            verify_evaluator_provenance(
                &envelope,
                &manifest,
                &"d".repeat(64),
                signing_key.verifying_key().as_bytes(),
                "build-provenance-key",
            ),
            Err(ProvenanceError::ArtifactDigestMismatch)
        ));
    }
}
