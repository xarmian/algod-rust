# Phase 1 Validation --- Stateless Block Validation

_Completed: 2026-03-04_

Phase 1 of algod-rust is **complete**. All five epics (plus one sub-epic) have been implemented, tested, and validated against both localnet fixtures and 101 mainnet blocks. The workspace contains 208 passing tests with zero failures. Rust can now decode every Algorand transaction type, verify cryptographic signatures, enforce stateless protocol rules, validate block-level commitments, and replay real mainnet blocks without false rejections.

---

## Epics Completed

| Epic | Title | Key Deliverables |
|------|-------|------------------|
| 8 | All Transaction Types | Flat "god struct" with ~40 fields covering pay, axfer, acfg, afrz, appl, keyreg, stpf. Supporting structs: AssetParams, StateSchema, BoxRef, MultisigSig, LogicSig. Diverse fixtures (blocks 1-9). Canonical encoder updated for all fields. |
| 9 | Signature Verification | `ed25519-dalek` v2, single-sig, multisig (threshold verification), logicsig (3 modes: delegated, contract account, delegated multisig), rekeyed account support, genesis field restoration before verification. |
| 10 | Stateless Protocol Rules | Min fee (1000 microAlgos), round window (MaxTxnLife = 1000), note/lease/group size limits, group ID validation (SHA512/256), fee pooling in atomic groups, 41 known protocol versions. |
| 11 | Block-Level Validation | Payset Merkle commitment (SHA512/256, `TL`/`MA`/`TX`/`STIB` domain prefixes), timestamp bounds, protocol version enforcement, aggregate block size (1 MiB for v7-v32, 5 MiB for v33+), genesis field consistency. `validate_block()` collects all errors without panicking. |
| 12 | Mainnet Block Replay | Replay CLI subcommand, Nodely public endpoint integration (mainnet/testnet), fee pooling support, vector commitments (SHA-256 txn256, SHA-512 txn512, bit-reversal permutation), `stpf` exemptions. 101 mainnet blocks (rounds 44000000-44000100), 4479 transactions, 0 failures. |
| 12a | Commitment Conformance | Raw-passthrough STIB encoding via `extract_raw_payset_blobs()`, hard commitment errors when raw blobs provided (warn-only without), `H("MB")` padding for empty VC positions, per-algorithm txid hashing (SHA-256/SHA-512). |

---

## Conformance Layers Covered

### Layer 3 --- Transaction Validation

Substantially covered. All stateless checks that can be performed without ledger state are implemented:

- **Signatures**: Ed25519 single-sig, multisig with threshold, logicsig (3 modes), rekeyed accounts via `auth_addr`.
- **Fees**: Per-transaction minimum fee enforcement; fee pooling across atomic groups (total group fee >= N x MinTxnFee).
- **Round window**: `last_valid - first_valid <= MaxTxnLife` (1000 rounds).
- **Size limits**: Note (<= 1024 bytes), lease (32 bytes), group (<= 16 transactions).
- **Group integrity**: Group ID matches SHA512/256 of concatenated canonical transaction hashes.
- **Protocol-injected exemptions**: `stpf` transactions exempt from fee and signature checks (by design).

**Deferred to later phases**: TEAL program evaluation (Phase 3), cross-block lease uniqueness (Phase 2), asset/application state rules (Phase 2).

### Layer 4 --- Block Validation

Substantially covered. All structural and cryptographic block-level checks are implemented:

- **Payset commitment** (`txn` field): SHA512/256 Merkle tree with `TL`/`MA` domain-separated nodes, `TX`/`STIB` leaf hashing.
- **Vector commitments** (`txn256`/`txn512`): SHA-256 and SHA-512 trees with bit-reversal permutation and `H("MB")` padding for empty positions.
- **Timestamp bounds**: Within acceptable range of previous block timestamp.
- **Protocol version**: Must be one of 41 known versions from go-algorand v4.5.1.
- **Aggregate block size**: Enforced per protocol (1 MiB or 5 MiB depending on version).
- **Genesis consistency**: Genesis ID and hash checked across all transactions in block.

**Deferred to later phases**: AVM-dependent validation (Phase 3).

---

## What Was Validated

### Transaction Decoding (Epic 8)

Every Algorand transaction type decodes with full type-specific fields:

- **pay**: Amount, receiver, close-remainder-to.
- **axfer**: Asset ID, asset amount, sender, receiver, close-to.
- **acfg**: Asset ID, asset params (total, decimals, unit name, asset name, URL, metadata hash, manager, reserve, freeze, clawback).
- **afrz**: Freeze asset ID, freeze address, freeze flag.
- **appl**: App ID, on-completion, approval/clear programs, app args, accounts, foreign apps/assets, box refs, global/local state schemas, extra pages.
- **keyreg**: Vote key, selection key, state proof key, vote first/last/key dilution, nonparticipation.
- **stpf**: State proof type, state proof body (opaque `rmpv::Value`).

Canonical encoding produces byte-identical output to Go for all types (verified via reference fixtures).

### Cryptographic Verification (Epics 9, 11, 12, 12a)

- **Ed25519 signatures**: Verified using `ed25519-dalek` v2 with RFC 8032 non-strict mode (matching Go behavior).
- **Multisig**: Threshold verification --- each subsig individually verified, threshold count confirmed.
- **LogicSig**: Contract account address derived from `SHA512/256("Program" || logic_bytes)`; delegated sigs verified against delegator key.
- **Rekeyed accounts**: Signatures verified against `auth_addr` (authorizing address) when present.
- **Genesis field restoration**: `genesis_id` (when `hgi=true`) and `genesis_hash` (always stripped) restored before signature verification.
- **Merkle commitment**: Recomputed from STIB-encoded paysets and compared to block header.
- **Vector commitments**: Recomputed with bit-reversal permutation and algorithm-specific hashing; matched against `txn256`/`txn512` header fields.
- **Raw-passthrough STIB**: Commitment verification uses raw msgpack bytes from the block response (not re-serialized), eliminating serde round-trip corruption of unknown fields.

### Protocol Rule Enforcement (Epic 10)

- Minimum fee: 1000 microAlgos per transaction (or covered by fee pooling in atomic groups).
- Round window: `last_valid - first_valid <= 1000`.
- Note size: <= 1024 bytes.
- Group size: <= 16 transactions.
- Lease size: exactly 0 or 32 bytes.
- Group ID integrity: SHA512/256 of canonical transaction hashes.
- Fee pooling: Total group fee >= N x MinTxnFee (allows individual fee=0).

### Mainnet Replay (Epic 12)

- 101 consecutive mainnet blocks: rounds 44,000,000 through 44,000,100.
- 4,479 transactions processed with 0 validation failures.
- All commitment types verified (Merkle + vector).
- Fee pooling, rekeyed accounts, and protocol-injected `stpf` transactions encountered and handled correctly.

---

## Known Gaps

| Gap | Notes |
|-----|-------|
| TEAL program evaluation | Deferred to Phase 3 (AVM Execution). LogicSig logic bytes are parsed but not executed. |
| Cross-block lease enforcement | Deferred to Phase 2 (Ledger Execution). Leases validated within groups only. |
| Asset/application state rules | Deferred to Phase 2. Requires ledger state (balances, ownership, app existence). |
| `EvalDelta` is opaque | Stored as `rmpv::Value`. Full modeling deferred to Phase 3. |
| Single-member groups skipped | Mainnet accommodation --- partial group views in blocks; not validated. |
| Fuzz testing | No fuzz targets defined yet. Recommended for Phase 2. |
| `stpf` fee/sig exemption | By design --- state proof transactions are protocol-injected and exempt from normal checks. |

---

## How to Reproduce

### Build and Test

```bash
# Build all crates
cargo build --workspace

# Run all 208 tests
cargo test --workspace

# Lint (must pass with zero warnings)
cargo clippy --workspace --all-targets -- -D warnings

# Format check
cargo fmt --all -- --check
```

### Localnet Conformance

```bash
# Start devnet and run conformance validation
make localnet-up
make validate
make localnet-down
```

### Mainnet Block Replay

```bash
# Replay 101 mainnet blocks (requires internet access to Nodely endpoint)
cargo run --bin algod-rust -- replay --network mainnet --start-round 44000000 --count 101
```

---

## Conclusion

Phase 1 proves that Rust can perform comprehensive stateless validation of Algorand blocks. Every transaction type decodes correctly, cryptographic signatures are verified, protocol rules are enforced, and block-level commitments (Merkle trees and vector commitments) are recomputed and matched. Validation against 101 real mainnet blocks with 4,479 transactions produced zero false rejections, demonstrating production-grade conformance with go-algorand.

The `algo-validate` crate provides a clean public API (`validate_block`, `validate_transaction`, `verify_signature`) that Phase 2 can build upon. The raw-passthrough STIB encoding ensures commitment verification is not corrupted by serde round-trips, a design that will carry forward as new fields are added.

Phase 1 feeds directly into:

- **Phase 2 (Ledger Execution)**: Stateless-valid blocks can now be applied to ledger state. Cross-block lease enforcement, balance checks, and asset/app state rules become possible.
- **Phase 3 (AVM Execution)**: LogicSig and application call TEAL evaluation. `EvalDelta` modeling.
- **Phase 5 (Networking)**: Stateless validation serves as the first filter for incoming blocks from peers --- reject invalid blocks before committing resources to stateful processing.
