# algod-rust

Rust reimplementation of go-algorand. Phase 0 is a conformance harness.

## Shell Environment

- `cargo` and `go` are both in PATH.

## Bash Tool Constraints

- Do NOT chain test runs hoping for different results. If a test fails, diagnose the issue first.

## Common Commands

```bash
cargo build --workspace
cargo test --workspace
cargo test --test digest_test
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

## Project Structure

See `docs/DEV_WORKFLOW.md` for fixture generation, localnet, and testing workflows.

Workspace crates:
- `crates/core/algo-error` — error types
- `crates/core/algo-types` — Block, Transaction, etc.
- `crates/core/algo-codec` — msgpack encode/decode
- `crates/node/algo-rest-client` — REST client
- `crates/tools/algo-fixtures` — fixture capture
- `crates/tools/algo-conformance` — conformance comparison
- `bin/algod-rust` — CLI binary
