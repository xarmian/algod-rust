# PROJECT_SCOPE.md — Algod-Rust Full Project Scope

_Last updated: 2026-03-04T02:03:00.565172Z_

This document defines the **complete scope and definition of done** for the `algod-rust` project: a full Rust implementation of the Algorand node compatible with the existing network.

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

The Rust implementation should be:

- **Consensus compatible**
- **Protocol compatible**
- **Operationally equivalent**
- **Performance competitive or superior**

Ultimately, it should function as a **drop-in alternative to go-algorand**.

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
Hardening — 3–6 months

Estimated total:

**2–3 years**

---

# Final Definition of Done

Algod-Rust is complete when:

- Rust nodes run on **Algorand mainnet**
- They **participate in consensus**
- They **produce valid blocks**
- They **maintain identical ledger state**
- They run **reliably in production**

At that point the ecosystem benefits from **two independent node implementations**, increasing decentralization and resilience.
