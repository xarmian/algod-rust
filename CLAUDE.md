# algod-rust

Rust reimplementation of go-algorand. Phase 0 is a conformance harness.

## Shell Environment

- `cargo` and `go` are both in PATH.

## Reference Implementation

- **go-algorand source** is at `../go-algorand`, pinned to `v4.5.1-stable` (detached HEAD)
- Use this as the authoritative reference for AVM opcodes, consensus params, field indices, and protocol semantics
- Key reference files:
  - `data/transactions/logic/opcodes.go` — opcode table, version gating
  - `data/transactions/logic/eval.go` — opcode implementations (opTxn, opGlobal, opAppLocalGet, etc.)
  - `data/transactions/logic/resources.go` — reference resolution, resource tracking
  - `config/consensus.go` — consensus params per version (LogicSigVersion, MinTxnFee, etc.)
  - `protocol/consensus.go` — consensus version constants (ConsensusCurrentVersion = V41)

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
