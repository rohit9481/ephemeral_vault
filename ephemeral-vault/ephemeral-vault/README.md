# Ephemeral Vault

Scaffold repository for the Ephemeral Vault project.

Structure:
- programs/ephemeral-vault: Rust program scaffold for the on-chain logic (instructions, state, errors).
- backend: Rust backend service scaffold (API, services, DB schema).
- tests: placeholder test files.
- migrations: DB migration SQL.

How to build (Rust workspace):
- Install Rust and Cargo.
- From the repo root run `cargo build --workspace`.

Next steps:
- Implement program instruction logic and ABI.
- Wire up backend routes and select a web framework.
- Add CI and more complete tests.
