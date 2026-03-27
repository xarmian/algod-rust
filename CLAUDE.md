# algod-rust

Full Rust reimplementation of go-algorand — a production-grade Algorand node. Phases 0–5 are complete (conformance harness, block sync, AVM execution, ledger apply, validation, REST API). Currently in Phase 6 (consensus participation). See `docs/PROJECT_SCOPE.md` for full scope and `docs/PHASE6_PROPOSAL.md` for the current phase.

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
  - `ledger/simulation/simulator.go` — simulation engine (Simulator, check, evaluate)
  - `daemon/algod/api/server/v2/handlers.go` — REST API handlers

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
See `docs/CRATE_ARCHITECTURE.md` for detailed crate design and dependency rationale.

Workspace crates:

### Core (consensus-critical)
- `crates/core/algo-error` — error types
- `crates/core/algo-types` — Block, BlockHeader, Transaction, SignedTransaction, AccountData, etc.
- `crates/core/algo-codec` — canonical msgpack encode/decode
- `crates/core/algo-avm` — AVM (TEAL) interpreter, opcodes, logic evaluation
- `crates/core/algo-ledger` — ledger state, block apply, simulation engine, catchpoint sync
- `crates/core/algo-validate` — transaction validation, signature verification, block validation
- `crates/core/algo-agreement` — agreement protocol types and verification
- `crates/core/algo-consensus-crypto` — VRF, one-time signatures, Falcon post-quantum sigs
- `crates/core/algo-falcon` — Falcon-512 signature scheme
- `crates/core/algo-pool` — transaction pool

### Node
- `crates/node/algo-rest-api` — REST API v2 server (axum), handlers, models, NodeInterface trait
- `crates/node/algo-rest-client` — REST API client, parallel block fetching
- `crates/node/algo-network` — P2P networking

### Tools
- `crates/tools/algo-fixtures` — fixture capture from go-algorand
- `crates/tools/algo-conformance` — conformance comparison (Rust vs Go)
- `crates/tools/algo-bench` — benchmarks

### Binary
- `bin/algod-rust` — CLI binary (sync, serve, etc.)
