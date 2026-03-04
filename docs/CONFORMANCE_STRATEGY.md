# CONFORMANCE_STRATEGY.md — Algod-Rust Protocol Conformance Strategy

_Last updated: 2026-03-04T02:04:22.827977Z_

This document describes the strategy for guaranteeing that **algod-rust remains fully compatible with go-algorand** at every stage of development.

Because consensus software is extremely sensitive to subtle differences in encoding, hashing, and execution behavior, the Rust node must be validated continuously against the Go implementation.

The conformance system acts as a **permanent differential testing harness** between the two implementations.

---

# 1. Core Philosophy

The conformance strategy follows three guiding principles:

1. **Differential Testing**
   - Every behavior of the Rust node should be compared against go-algorand.

2. **Deterministic Fixtures**
   - Historical blocks, transactions, and state transitions must be replayable deterministically.

3. **Incremental Validation**
   - Each subsystem must be validated independently before integration.

---

# 2. Layers of Conformance

Conformance testing is organized into layers from simplest to most complex.

```
Layer 1: Encoding / Decoding
Layer 2: Hashing and Canonicalization
Layer 3: Transaction Validation
Layer 4: Block Validation
Layer 5: Ledger State Transitions
Layer 6: AVM Execution
Layer 7: Catchup and Sync
Layer 8: Network Message Compatibility
Layer 9: Consensus Behavior
```

Each layer must pass before progressing to the next.

---

# 3. Layer 1 — Encoding / Decoding

Goal:

Ensure Rust decodes Algorand message formats exactly the same as Go.

Test strategy:

1. Capture raw msgpack blocks from go-algorand.
2. Decode using Rust codec.
3. Re-encode canonically.
4. Verify byte equivalence.

Test command example:

```
algod-rust-conform codec-test fixtures/block_100.msgpack
```

Failures here usually indicate:

- incorrect field ordering
- msgpack encoding differences
- integer size issues

---

# 4. Layer 2 — Hashing and Canonicalization

Goal:

Ensure all cryptographic digests match the Go implementation.

Tests include:

- transaction ID
- block hash
- payset hash
- state proof hashes

Validation process:

1. Compute hashes in Go.
2. Compute hashes in Rust.
3. Compare outputs.

Mismatch artifacts should include:

- canonical bytes
- decoded structure
- expected vs actual hash

---

# 5. Layer 3 — Transaction Validation

Goal:

Verify Rust correctly validates individual transactions.

Test scenarios:

- signature validation
- group size rules
- fee requirements
- asset rules
- application call constraints

Differential approach:

```
for each test_tx:
    go_result = go_algod.validate(tx)
    rust_result = rust_validator.validate(tx)

    assert(go_result == rust_result)
```

---

# 6. Layer 4 — Block Validation

Goal:

Ensure Rust accepts or rejects blocks exactly the same as Go.

Tests include:

- payset validation
- signature checks
- protocol rule enforcement
- timestamp validation

Replay strategy:

```
for block in historical_chain:
    go_valid = go_algod.validate_block(block)
    rust_valid = rust_algod.validate_block(block)

    assert(go_valid == rust_valid)
```

---

# 7. Layer 5 — Ledger State Transitions

Goal:

Ensure state updates are identical.

Procedure:

1. Start from the same genesis state.
2. Replay blocks sequentially.
3. Compare state roots after each block.

Validation points:

- account balances
- asset states
- application state
- participation state

Mismatch debugging should produce:

- full state diff
- transaction group responsible
- ledger snapshot

---

# 8. Layer 6 — AVM Execution

Goal:

Ensure TEAL execution produces identical results.

Tests include:

- opcode execution
- stack operations
- cost accounting
- state reads/writes

Testing methods:

1. Official TEAL test vectors.
2. Randomized contract execution.
3. Historical block replay.

Each execution should produce identical:

- return values
- state changes
- gas costs

---

# 9. Layer 7 — Catchup and Sync

Goal:

Ensure Rust node reconstructs the ledger identically.

Testing process:

1. Start with empty database.
2. Sync from peers or fixtures.
3. Compare resulting ledger root with Go node.

Key metrics:

- catchup speed
- state root equality
- snapshot correctness

---

# 10. Layer 8 — Network Message Compatibility

Goal:

Ensure Rust node understands all gossip messages.

Tests include:

- handshake messages
- block propagation
- vote messages
- proposal messages

Strategy:

Run mixed clusters of:

- Go nodes
- Rust nodes

Verify interoperability.

---

# 11. Layer 9 — Consensus Behavior

Goal:

Ensure Rust consensus decisions match Go nodes.

Testing environment:

Mixed testnet cluster.

```
Cluster:

3 Go nodes
3 Rust nodes
1 relay node
```

Validation checks:

- block proposals
- voting participation
- fork resolution
- final block agreement

---

# 12. Fixture Infrastructure

Fixtures are critical to reproducibility.

Fixtures should include:

- raw block bytes
- decoded JSON
- expected hashes
- expected ledger state root

Fixture storage example:

```
fixtures/
    blocks/
    txns/
    ledger/
    avm/
```

---

# 13. Automated Conformance Runner

Create a dedicated tool:

```
algod-rust-conform
```

Capabilities:

- capture fixtures from Go node
- replay historical blocks
- compare results
- generate mismatch reports

Report example:

```
reports/conformance.json
```

Includes:

- rounds tested
- mismatches found
- stack traces
- reproduction instructions

---

# 14. Continuous Integration

CI should automatically run:

- codec tests
- hash tests
- ledger replay tests
- AVM test vectors

Suggested CI steps:

```
cargo test
cargo fuzz run codec
algod-rust-conform validate --rounds 1..500
```

Failures should block merges.

---

# 15. Historical Replay Testing

The strongest validation is **replaying historical mainnet blocks**.

Procedure:

1. Export historical blocks from Go node.
2. Replay blocks through Rust ledger engine.
3. Compare resulting ledger state roots.

Testing ranges:

- first 10k blocks
- random mid-chain segments
- recent blocks

---

# 16. Fuzz Testing

Critical components should be fuzzed:

Targets:

- msgpack decoder
- transaction parser
- AVM opcode execution
- block validator

Example:

```
cargo fuzz run block_decode
```

---

# 17. Failure Debugging Tools

When mismatches occur, the system should generate:

- decoded object diff
- canonical byte diff
- hash comparison
- ledger state diff

These artifacts drastically reduce debugging time.

---

# 18. Long-Term Validation

Even after mainnet launch, conformance testing should continue.

Examples:

- replay last 1000 blocks daily
- cross-compare ledger roots
- fuzz new protocol features

---

# Final Principle

The Rust node should **never trust itself**.

Every behavior must be verified against the reference implementation until the Rust implementation becomes equally trusted.
