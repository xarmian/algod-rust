# PROJECT_SCOPE.md — Algod-Rust Full Project Scope

_Last updated: 2026-05-22_

This document defines the **complete scope and definition of done** for the `algod-rust` project: a full Rust implementation of the Algorand **node and operator toolchain**, compatible with the existing network and interoperable with the existing go-algorand binary set.

---

# 1. Project Vision

The goal of **Algod-Rust** is to create a **fully compatible, production-grade implementation of the Algorand node** written in Rust that can:

- Join the Algorand network
- Participate in consensus
- Validate and produce blocks
- Execute the AVM
- Maintain ledger state
- Provide compatible APIs
- Interoperate seamlessly with existing nodes

Beyond the node itself, the project must also deliver a **Rust operator toolchain** that is at functional parity with the go-algorand binary set an operator/user actually invokes day-to-day (`kmd`, `goal`, `algokey`, `tealdbg`). The Rust toolchain must interoperate with go-algorand binaries (Rust `goal` ↔ Go `kmd`, Go `goal` ↔ Rust `algod`, etc.) so the ecosystem can mix-and-match implementations.

The Rust implementation should be:

- **Consensus compatible**
- **Protocol compatible**
- **Operationally equivalent**
- **CLI / toolchain compatible** — same subcommands, same flags, same output shapes for documented user-facing flows
- **Performance competitive or superior**

Ultimately, the deliverable is a **drop-in alternative to go-algorand** — both the daemon and the CLI ecosystem an operator uses to run it.

---

# 2. Definition of “Complete”

Algod-Rust is considered **complete** when the following conditions are met.

## Network Compatibility

A Rust node can:

- Connect to mainnet/testnet peers
- Participate in gossip protocol
- Validate incoming blocks
- Participate in consensus committees
- Produce blocks when selected

## Ledger Compatibility

Rust produces identical results to Go for:

- Block validation
- Transaction execution
- Ledger state transitions
- State roots
- Rewards calculations

## API Compatibility

Rust exposes equivalent APIs including:

- algod REST endpoints
- node health endpoints
- transaction submission endpoints
- block and account queries
- kmd REST endpoints (wallet, key, signing)

## CLI / Toolchain Compatibility

Rust ships drop-in equivalents of the user-facing go-algorand binaries:

- `goal-rust` — operator CLI (account, asset, app, clerk, node, wallet, network subcommands)
- `kmd-rust` — Key Management Daemon
- `algokey-rust` — offline key tool
- `tealdbg-rust` — TEAL debugger

These must accept the same subcommands and flags as their Go counterparts for documented flows, and must interoperate bidirectionally (Rust CLI → Go daemon and Go CLI → Rust daemon).

## Operational Readiness

The node supports:

- archival nodes
- participation nodes
- relay nodes
- catchpoint sync
- snapshots
- protocol upgrades

## Security and Reliability

The Rust node must:

- pass protocol conformance tests
- survive fuzz testing
- survive adversarial network conditions
- run long‑term without crashes or memory leaks

---

# 3. System Architecture Overview

The final system will consist of these primary subsystems:

- Networking Layer
- Consensus Engine
- Ledger Engine
- AVM Execution Engine
- Block Validation Engine
- Catchup / Sync Engine
- Storage Layer
- REST / RPC APIs

These components together form the full node runtime.

---

# 4. Major Subsystems

## Networking Layer

Handles peer-to-peer communication.

Responsibilities:

- peer discovery
- gossip message propagation
- block propagation
- transaction propagation
- peer reputation
- rate limiting
- DOS protection

---

## Consensus Engine

Implements the Algorand consensus protocol.

Responsibilities:

- committee selection (VRF)
- proposal validation
- vote aggregation
- fork resolution
- protocol upgrades

Consensus correctness is the **most critical property** of the system.

---

## Ledger Engine

Responsible for the state of the blockchain.

Responsibilities:

- account balances
- asset state
- application state
- rewards distribution
- participation state

Core operations include:

- apply_block
- validate_block
- apply_transaction_group
- update_state_root

Ledger results must match the reference implementation exactly.

---

## AVM Execution Engine

Implements the **Algorand Virtual Machine (TEAL)**.

Responsibilities:

- opcode execution
- contract state changes
- cost accounting
- deterministic evaluation

AVM behavior must remain **byte‑for‑byte compatible** with the reference implementation.

---

## Block Validation

Ensures blocks follow protocol rules.

Validation includes:

- transaction group correctness
- signature verification
- protocol rule enforcement
- AVM execution
- ledger updates

---

## Catchup and Fast Sync

Allows nodes to synchronize quickly.

Methods include:

- block-by-block sync
- catchpoints
- snapshot-based sync

Efficient catchup is critical for node usability.

---

## Storage Layer

Persistent blockchain state storage.

Data stored includes:

- blocks
- accounts
- assets
- applications
- participation state
- snapshots

Requirements:

- high write throughput
- efficient queries
- archival capability
- pruning support

---

## REST / RPC APIs

Expose node functionality externally.

Typical endpoints include:

- block queries
- account queries
- transaction submission
- transaction status
- node status
- metrics

API compatibility allows existing tooling to work with the Rust node.

---

## Operator Toolchain (CLI Ecosystem)

The Rust toolchain mirrors the user-facing surface of go-algorand. Binaries are tiered by how often a real operator/user invokes them.

### Tier 0 — Core daemons (drop-in mandatory)
- `algod-rust` — the node (this repo's existing binary; covered by Phases 0–7)
- `kmd-rust` — Key Management Daemon. Own REST API on its own port, SQLite-backed wallet store, mnemonic / Ed25519 / multisig / logicsig signing. Reference: `../go-algorand/daemon/kmd/`

### Tier 1 — Daily operator CLIs (drop-in mandatory)
- `goal-rust` — Primary operator CLI. Subcommand groups: `account`, `asset`, `app`, `clerk`, `node`, `wallet`, `network`, `kmd`, `protocol`. Talks to `algod` REST + `kmd` REST. Reference: `../go-algorand/cmd/goal/`
- `algokey-rust` — Offline key tool. Generate, sign (txn / arbitrary bytes), mnemonic ↔ key, multisig partial sigs. No daemon dependencies. Reference: `../go-algorand/cmd/algokey/`
- `tealdbg-rust` — TEAL debugger / DAP server for IDE integration. Drives the AVM interpreter step-by-step. Reference: `../go-algorand/cmd/tealdbg/`

### Tier 2 — Power-user / config / ops (best-effort)
- `algocfg`, `diagcfg`, `nodecfg` — config tooling
- `msgpacktool` — canonical msgpack inspect/encode
- `catchpointdump`, `catchupsrv` — catchpoint introspection / serving
- `algofix`, `algoh`, `carpenter` — config migration / host wrapper / log viewer

### Tier 3 — Internal release / test infra (not required for drop-in)
- `algons`, `algorelay`, `dispenser`, `dbgen`, `genesis`, `incorporate`, `loadgenerator`, `netdummy`, `netgoal`, `pingpong`, `updater`, `util`, `opdoc`, `buildtools`, `partitiontest_linter`

**Interop requirement.** Rust toolchain binaries must interoperate with their Go counterparts bidirectionally — Rust `goal` driving Go `kmd` + Go `algod`, Go `goal` driving Rust `kmd` + Rust `algod`, and all mixed permutations. This is what makes the toolchain drop-in rather than a parallel-but-isolated reimplementation.

---

# 5. Development Phases

## Phase 0 — Conformance Harness

Rust follower that consumes Go blocks and validates decoding and hashing.

Deliverables:

- block fixture capture
- canonical encoding
- conformance reporting

---

## Phase 1 — Stateless Block Validation

Add:

- transaction decoding
- signature verification
- protocol rule validation

---

## Phase 2 — Ledger Execution

Implement:

- account state transitions
- asset state updates
- reward calculations

Verify ledger roots against Go nodes.

---

## Phase 3 — AVM Execution

Implement:

- TEAL interpreter
- opcode execution
- contract state updates

---

## Phase 4 — Catchup and Sync

Add:

- fast synchronization
- catchpoints
- snapshots

Rust nodes can sync the entire chain.

---

## Phase 5 — Networking Integration

Replace REST ingestion with real P2P gossip.

Rust node becomes a **network observer node**.

---

## Phase 6 — Consensus Participation

Implement:

- VRF sortition
- vote generation
- proposal generation

Rust node becomes a **participation node**.

---

## Phase 7 — Production Hardening

Add:

- metrics
- observability
- fuzz testing
- performance optimization
- operational tooling

---

## Phase 8 — Operator Toolchain Parity

Deliver Rust equivalents of the user-facing go-algorand binaries (Tier 0 + Tier 1):

- `algokey-rust` — sequencing first (smallest surface, pure crypto, establishes the CLI crate pattern)
- `kmd-rust` — wallet daemon (REST API + SQLite key store)
- `goal-rust` — operator CLI (largest surface, decomposed by subcommand group; depends on algod REST + kmd REST)
- `tealdbg-rust` — TEAL debugger / DAP server

Acceptance:

- Each subcommand documented in `../go-algorand/cmd/<bin>/README.md` (or equivalent help text) has a Rust equivalent with the same flags + output shape.
- Cross-implementation interop tests pass: Rust CLI ↔ Go daemon and Go CLI ↔ Rust daemon for all documented flows.
- Tier 2 / Tier 3 binaries tracked as opportunistic follow-ups, not gating drop-in claim.

---

## Phase 9 — go-algorand Version-Upgrade Parity Sweeps

Ongoing maintenance phase, run whenever the pinned go-algorand reference version advances. Each sweep is its own epic (see `docs/epics/Epic-19-Go-Algorand-v4.6.0-Parity.md` for the first instance, `v4.5.1-stable` → `v4.6.0-stable`; `docs/epics/Epic-20-Go-Algorand-v4.7.0-Parity-And-P2P.md` for the second, `v4.6.0-stable` → `v4.7.0-stable`, also filed under its own `docs/PHASE10_PROPOSAL.md`; `docs/epics/Epic-21-Go-Algorand-v4.7.2-Parity.md` for the third, `v4.7.0-stable` → `v4.7.2-stable`, filed under `docs/PHASE11_PROPOSAL.md`): analyze every upstream change since the last pin, classify it (consensus-critical / api / avm / network / behavioral-other / not-applicable), open one issue per feature-level change, implement, and re-pin. See `docs/PHASE9_PROPOSAL.md`/`docs/PHASE10_PROPOSAL.md`/`docs/PHASE11_PROPOSAL.md` and the `algod-version-upgrade` skill for the full process. Does not gate on or block Phase 7/8 — orthogonal maintenance work, can interleave with either.

The `v4.6.0-stable → v4.7.0-stable` sweep additionally closes algod-rust's previously-deliberately-scoped-out libp2p P2P transport gap (see Phase 5's WS-gossip-only delivery above): a full `rust-libp2p`-based host, Kademlia DHT peer discovery, gossipsub block/vote/tx propagation, and capability advertisement, offered alongside the existing WS-gossip network in a configurable hybrid mode.

The `v4.7.0-stable → v4.7.2-stable` sweep is a small, security/bounds-check-focused patch release with no consensus version bump: a new group-level pre-signature-verification transaction screen, codec-level required-field decode enforcement, a defense-in-depth state-proof TreeDepth guard, and a msgpack decode nesting-depth cap.

---

# 6. Project Success Criteria

The project succeeds when:

### Consensus Compatibility

Rust nodes agree with Go nodes on:

- block validation
- ledger roots
- state transitions

### Network Participation

Rust nodes can:

- sync mainnet
- participate in consensus
- produce valid blocks

### Reliability

Nodes run continuously for long periods without failure.

### Performance

Performance is:

- comparable or better than Go implementation
- memory efficient
- stable under network load

---

# 7. Non‑Goals

The project does **not** attempt to:

- redesign the Algorand protocol
- modify consensus rules
- introduce incompatible APIs
- create a new blockchain

The goal is strict **protocol compatibility**.

---

# 8. Long‑Term Opportunities

After the Rust node is stable, additional improvements become possible:

- parallel transaction execution
- improved storage engines
- WASM execution engines
- more efficient catchup
- improved relay architecture

---

# 9. Project Risks

Major risks include:

- consensus incompatibility
- encoding mismatches
- AVM behavioral differences
- protocol edge cases

Mitigation strategies:

- strong conformance harness
- differential testing vs Go
- replay testing against historical blocks

---

# 10. Estimated Timeline

A realistic timeline for a small team:

Phase 0 — 2–3 months  
Phase 1 — 3–4 months  
Phase 2 — 4–6 months  
Phase 3 — 3–4 months  
Phase 4 — 2–3 months  
Phase 5 — 4–6 months  
Phase 6 — 3–4 months  
Phase 7 Hardening — 3–6 months  
Phase 8 Toolchain Parity — 4–6 months (some work parallelizable with Phase 7)

Estimated total:

**2.5–3.5 years**

---

# Final Definition of Done

Algod-Rust is complete when:

- Rust nodes run on **Algorand mainnet**
- They **participate in consensus**
- They **produce valid blocks**
- They **maintain identical ledger state**
- They run **reliably in production**
- The Rust **operator toolchain** (`goal-rust`, `kmd-rust`, `algokey-rust`, `tealdbg-rust`) is at functional parity with the Go equivalents and **interoperates bidirectionally** with go-algorand binaries

At that point the ecosystem benefits from **two independent end-to-end stacks** — node and operator toolchain — increasing decentralization, resilience, and operator choice.
