# Contributing

Thank you for your interest in AIVO AgentGuard. The project is in its research and specification phase; interfaces may change before a stable release.

## Before contributing

1. Read the README and documents under `docs/`.
2. Open an issue before substantial changes.
3. Never submit secrets, private keys, seed phrases, real user data, or live transaction credentials.
4. Do not claim production readiness or unvalidated security guarantees.
5. Ensure you have the right to submit your contribution under Apache-2.0.

## Engineering requirements

- Keep authorization deterministic and reproducible.
- LLM output is advisory only and cannot authorize execution.
- Fail closed on missing or invalid policy inputs.
- Test positive, negative, boundary, and adversarial cases.
- Preserve evidence integrity; corrections use linked events, not destructive mutation.
- Document externally observable behavior and breaking changes.

## Local checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

## Pull requests

Use a focused branch and PR. Explain motivation, design, security impact, tests, and documentation changes. Do not combine unrelated refactors with security-sensitive changes.

## License and contributions

This project is licensed under the Apache License, Version 2.0. By intentionally submitting a contribution for inclusion, you agree that it is submitted under the terms of Apache-2.0, subject to that license. No separate CLA or DCO is currently required. You remain responsible for ensuring you have the rights needed to submit your contribution.
