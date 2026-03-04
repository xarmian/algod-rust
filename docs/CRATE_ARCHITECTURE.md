# CRATE_ARCHITECTURE.md — Algod-Rust Crate Layout (Target Architecture)

_Last updated: 2026-03-04T02:01:04.209111Z_

This document proposes a scalable Rust **crate/workspace architecture** for a full Rust implementation of an Algorand node (“algod-rust”).

It is designed to support **Phase 0 → production** with strong boundaries:
- Consensus-critical logic isolated from IO and async concerns
- Clear layering (types/codec/crypto → execution/ledger → networking/node → APIs/tools)
- Testability (golden vectors, differential tests, fuzzing targets)
- Replaceability (swap storage engines, transport layers, API frontends)

---

## Guiding principles

1. **Pure core first**: `types`, `codec`, `crypto`, `protocol` crates should be deterministic, mostly `no_std`-friendly where possible, and never depend on async runtimes.
2. **One-way dependencies**: lower layers never import higher layers. Use traits to invert dependencies (e.g., storage, clock, network I/O).
3. **Consensus-critical isolation**: anything that can change consensus outcomes must be easy to audit and heavily tested.
4. **Feature gates by phase**: crates should compile in Phase 0 with minimal features; later phases enable more.
5. **Observability is orthogonal**: tracing/metrics wired at the edge, not throughout core logic.

---

## Workspace layout (top level)

```
algod-rust/
  Cargo.toml                # workspace
  crates/
    core/                   # pure, deterministic building blocks
    protocol/               # consensus & wire protocol logic
    execution/              # AVM, txn evaluation
    ledger/                 # state transition & storage abstractions
    network/                # gossip, peers, transport
    node/                   # orchestration runtime
    api/                    # REST (algod-compatible), admin, telemetry
    tools/                  # fixture capture, conformance, generators
    testing/                # fuzzers, differential harnesses
  bin/
    algod-rust/             # main node binary
    algod-rust-conform/     # conformance runner
    algod-rust-tools/       # multi-tool CLI
  docker/
  docs/
```

---

## Crate map (by layer)

### A) Core layer (deterministic, reusable)

These crates should have minimal dependencies and be safe to run in test harnesses, fuzzers, and offline validators.

**`core/algo-types`**
- Canonical Rust types for blocks, headers, txns, accounts, apps, assets, consensus params.
- Minimal derives (avoid serde in core if it risks changing behavior; keep debug features gated).

**`core/algo-codec`**
- Canonical msgpack encoding/decoding for blocks, txns, and network messages.
- Golden fixtures + property tests (encode/decode round-trip, canonicalization invariants).

**`core/algo-crypto`**
- Hashes (SHA512/256 etc.), Ed25519, VRF, signatures, key serialization.
- Exposes constant-time operations where applicable.
- Wrap audited libs; keep API stable.

**`core/algo-constants`**
- Protocol constants, limits, fee rules, min balances, etc. (versioned where needed).

**`core/algo-error`**
- Shared error types and diagnostic structures used across crates (no IO).

**`core/algo-time`**
- Deterministic time abstractions (traits: `Clock`, `MonotonicClock`) for testability.

---

### B) Protocol layer (consensus & wire, still mostly deterministic)

**`protocol/algo-protocol`**
- Protocol versioning, upgrade schedules (as data), consensus parameter resolution per round.
- Pure functions mapping (round, genesis) → params.

**`protocol/algo-msg`**
- Network message structures and codecs (gossip message types, envelopes).
- Should depend on `algo-codec` + `algo-types`, not on transport.

**`protocol/algo-consensus`**
- Core consensus state machine logic (BA*/sortition inputs/outputs), excluding timers/IO.
- Exposes “step” functions: feed inputs (messages, time ticks), produce outputs (actions).

**`protocol/algo-verify`**
- Stateless verification: header checks, signature checks, VRF checks, committee membership proofs.
- Used by both node and tooling.

---

### C) Execution layer (AVM & transaction evaluation)

**`execution/algo-avm`**
- TEAL interpreter/runtime, opcode implementations, cost accounting.
- Deterministic execution traces (optional) for differential testing.

**`execution/algo-txn-eval`**
- Transaction group evaluation rules that do not require persistent state (or abstract it).
- Bridges `algo-avm` with ledger state interface.

**`execution/algo-teal-stdlib`** (optional)
- Common precompiled templates/helpers for tests and fixtures.

---

### D) Ledger layer (state transition + storage abstractions)

**`ledger/algo-ledger-model`**
- The deterministic state transition engine:
  - `apply_block`, `apply_tx_group`, rewards, state updates
- Must be as pure as possible: takes an abstract `StateView/StateDelta` trait.

**`ledger/algo-state-traits`**
- Traits/interfaces:
  - `AccountStore`, `AppStore`, `AssetStore`, `BlockStore`, `CatchpointStore`
  - transactional semantics (`begin_tx`, `commit`, `rollback`)
- Defines the minimum storage contract required by `algo-ledger-model`.

**`ledger/algo-ledger-db`**
- Concrete storage implementation (choose RocksDB/ParityDB/SQLite—behind features).
- Implements `algo-state-traits`.

**`ledger/algo-catchup`**
- Catchpoint/snapshot logic, chunk download coordination (IO abstracted).
- Uses `algo-ledger-db` + `algo-state-traits` + `algo-verify`.

**`ledger/algo-index`** (optional)
- Optional indexing for API queries (balances/tx lookup), separate from consensus state.

---

### E) Network layer (peer management + transport)

**`network/algo-peer`**
- Peer identity, scoring/reputation, rate limiting, backpressure primitives.

**`network/algo-gossip`**
- Gossip logic: message routing, validation, fanout strategies (transport-agnostic).

**`network/algo-transport`**
- Transport trait(s) + implementations:
  - TCP (baseline), QUIC (optional)
- Handles framing, encryption/handshake if applicable.
- Only this crate depends on `tokio`/async IO directly.

---

### F) Node runtime layer (orchestration)

**`node/algo-runtime`**
- The orchestrator wiring together:
  - network ↔ consensus ↔ ledger ↔ catchup
- Actor/message-driven architecture recommended.
- Owns task supervision, shutdown, restart, and health checks.

**`node/algo-config`**
- Config loading/validation, defaults, env vars, file formats, feature flags.

**`node/algo-keys`**
- Participation keys, wallet/key storage, secure loading, key rotation hooks.

**`node/algo-observe`**
- Observer/follower mode (Phase 0/1): ingest blocks from REST or fixtures.
- Later can ingest from P2P without participating.

---

### G) API & ops layer

**`api/algo-rest`**
- Algod-compatible REST API:
  - endpoints for status, blocks, submit tx, pending tx, accounts, etc.
- Depends on ledger read interfaces + node runtime.

**`api/algo-admin`**
- Admin/debug endpoints, unsafe ops gated behind config.

**`api/algo-metrics`**
- Prometheus metrics, structured tracing integration.

**`api/algo-rpc`** (optional)
- If you want gRPC/WebSocket streaming.

---

### H) Tools & developer experience

**`tools/algo-fixtures`**
- Capture blocks/txns from Go localnet / testnet for golden tests.
- Normalize metadata, store expected digests.

**`tools/algo-conformance`**
- Differential test runner:
  - Go reference vs Rust decode/hash/ledger outcomes
- Produces JSON reports and mismatch artifacts.

**`tools/algo-genesis`**
- Genesis builders for localnet and deterministic testnets.

**`tools/algo-fuzz-targets`**
- libFuzzer/AFL targets for codec, avm, ledger-model, gossip message parsing.

---

## Phase mapping (what exists when)

### Phase 0 (Follower + decode + compare)
Required crates:
- core: `algo-types`, `algo-codec`, `algo-crypto` (partial), `algo-error`
- tools: `algo-conformance`, `algo-fixtures`
- node: `algo-observe` (REST ingest)
- api: optional (minimal metrics)

### Phase 1 (Full block stateless validation)
Add:
- protocol: `algo-protocol`, `algo-msg`, `algo-verify`
- execution: `algo-txn-eval` (partial)

### Phase 2 (Ledger apply, state equivalence)
Add:
- ledger: `algo-ledger-model`, `algo-state-traits`, `algo-ledger-db` (minimal)
- conformance: state checkpoints

### Phase 3 (AVM parity)
Add:
- `algo-avm` + traces + opcode parity suites

### Phase 4 (Catchup parity)
Add:
- `algo-catchup`, catchpoints, snapshots, pruning

### Phase 5 (P2P observer)
Add:
- `algo-peer`, `algo-gossip`, `algo-transport`, runtime wiring

### Phase 6 (Participation + block production)
Add:
- `algo-consensus` participation surfaces + `algo-keys` + proposer/voter integration

### Phase 7 (Hardening)
Add:
- extensive fuzzers, DOS sims, perf harnesses, API parity and docs

---

## Dependency rules (enforced with CI)

- `core/*` MUST NOT depend on `tokio`, networking, or storage engines.
- `protocol/*` MUST NOT depend on `api/*` or `node/*`.
- `execution/*` MAY depend on `core/*` and `protocol/*`, NOT on `network/*`.
- `ledger/*` MAY depend on `core/*`, `protocol/*`, `execution/*`; storage engines must be behind features.
- `network/*` depends on `core/*` and `protocol/*`.
- `node/*` depends on everything below; it is the integration layer.
- `api/*` depends on `node/*` and ledger read interfaces.
- `tools/*` may depend on any crate but should avoid circular deps.

Recommend CI checks:
- `cargo deny` for license/audit
- `cargo hack` to build feature matrices
- `cargo udeps` to keep deps clean

---

## Suggested binaries

**`bin/algod-rust`**
- Production node binary (eventually)
- Subcommands:
  - `run`, `init-localnet`, `status`, `catchup`, `keys`

**`bin/algod-rust-conform`**
- Conformance runner used in CI:
  - capture fixtures
  - validate rounds
  - produce mismatch artifacts

**`bin/algod-rust-tools`**
- Misc utilities (debug dumps, codec inspection, genesis builder)

---

## Recommended “actor-ish” runtime boundaries (node crate)

This is how to wire `node/algo-runtime` without shared mutable state:
- `NetActor`: manages peers, ingress/egress messages
- `ConsensusActor`: advances consensus steps, emits actions
- `LedgerActor`: applies blocks/tx groups, maintains state, emits events
- `CatchupActor`: orchestrates sync/catchpoints
- `ApiActor`: exposes read access / submits tx requests

Communication: bounded channels, typed messages, backpressure and shutdown signals.

---

## Appendix: Naming conventions

- Crate names: `algo-*` to keep workspace cohesive.
- Feature gates:
  - `storage-rocksdb`, `storage-paritydb`
  - `transport-quic`
  - `tracing`, `metrics`
  - `debug-dumps`
- Error types:
  - Use `thiserror` internally, map to stable public enums at boundaries.

---

## What “good” looks like

By the time the project is mature:
- Consensus-critical crates are small, audited, and heavily tested.
- Most changes land in `node/*`, `api/*`, or `network/*` without affecting core correctness.
- You can run the conformance suite against Go for any historical range and get actionable diffs.
- Multiple storage and transport backends can be swapped without touching consensus logic.
