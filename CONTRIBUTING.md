# Contributing

Thank you for your interest in AIVO AgentGuard. The project is in its research and specification phase; interfaces and architecture may change before a stable release.

## Before contributing

1. Read the README and the governance and security documents in `docs/`.
2. Open an issue to discuss substantial changes before implementation.
3. Do not submit secrets, private keys, seed phrases, real user data, or live transaction credentials.
4. Do not claim production readiness or security guarantees that have not been independently validated.

## Engineering requirements

- Keep authorization decisions deterministic and reproducible.
- Keep LLM output advisory; it must never directly authorize execution.
- Fail closed on missing or invalid policy inputs.
- Add tests for positive, negative, boundary, and adversarial cases.
- Preserve evidence integrity and avoid mutable decision history.
- Document externally observable behavior and breaking changes.

## Local checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

## Pull requests

Use a focused branch and PR. Explain motivation, design, security impact, tests, and documentation changes. Do not combine unrelated refactors with security-sensitive behavior changes.

## License

The project license is pending an explicit maintainer decision. Until the license file and contribution terms are published, do not assume that contributions are accepted under a particular open-source license.
