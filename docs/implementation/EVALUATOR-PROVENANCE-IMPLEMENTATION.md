# Evaluator Provenance Verification Implementation

**Status:** Implementation in progress — non-production
**Protocol baseline:** G3 v0.1.0
**Code:** `crates/agentguard-core/src/provenance.rs`

## Implemented

- Strict typed owner-approved evaluator release manifest.
- DSSE envelope parsing with the in-toto payload media type.
- DSSEv1 pre-authentication encoding and Ed25519 signature verification.
- Provenance verification key ID is pinned by caller configuration; untrusted envelope key IDs never select trust roots.
- Typed in-toto Statement v1 and SLSA Provenance v1 structures.
- Artifact subject SHA-256 must equal both the owner-approved manifest and the digest computed by the caller from the actual evaluator artifact bytes.
- Exact bindings for source repository, immutable commit, Cargo.lock SHA-256, Rust toolchain, target triple, builder identity, workflow identity, and build invocation.
- Resolved dependency entries must include the source commit and Cargo.lock digest.
- Provenance statement digest is SHA-256 of the exact DSSE payload bytes; the owner-approved manifest pins that digest.
- Any missing, malformed, untrusted, stale-by-policy, or mismatched field fails closed.

## Verification contract

1. Caller loads a release manifest from an owner-controlled immutable allowlist.
2. Caller computes SHA-256 over the exact evaluator artifact bytes.
3. Caller resolves the provenance verification public key from a trusted provenance-issuer trust root and checks its current status.
4. Verifier checks DSSE payload type and Ed25519 signature over DSSEv1 PAE bytes.
5. Verifier parses the in-toto Statement v1 / SLSA Provenance v1 payload.
6. Verifier checks statement digest, artifact subject, source repository/commit, Cargo.lock, toolchain, target triple, builder/workflow identity, and invocation against the approved manifest.
7. Only a successful result yields VerifiedEvaluatorArtifactV1.

## Explicit boundaries

- This module does not fetch or build artifacts, compute the artifact digest from a file itself, provision trust roots, or store the release allowlist.
- The caller must supply the observed digest from the exact evaluator artifact bytes and a key resolved from a trusted provenance-issuer configuration.
- The release manifest is trusted configuration and must be protected by owner approval and immutable/versioned release controls.
- The implementation does not claim any SLSA assurance level.
- The verifier does not yet run as a separately deployed process and is not yet integrated into the authorization-attestation issuer.
- Production key revocation, release-manifest governance, provenance generation workflow, artifact retention, and independent review remain release gates.

## Digest semantics

The manifest's provenance_statement_sha256 is SHA-256 over the exact decoded DSSE payload bytes. The DSSE signature is verified over the DSSEv1 pre-authentication encoding of payload type and exact payload bytes. The artifact_sha256 is computed by the caller over the exact evaluator artifact bytes, not inferred from the provenance statement.
