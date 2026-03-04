# Phase 0 Validation — Conformance Harness

_Completed: 2026-03-04_

Phase 0 of algod-rust is **complete**. This document records what was built, what was validated, and what gaps remain.

---

## Epics Completed

| Epic | Title | Deliverables |
|------|-------|-------------|
| 0 | Project Bootstrap | Workspace structure, CI skeleton, Cargo workspace |
| 1 | Deterministic Localnet | Docker Compose devnet (algod-go + txn-generator sidecar) |
| 2 | Rust Follower Skeleton | REST client with retry/backoff, `BlockSource` trait |
| 3 | Codec Foundation | Msgpack decode/encode via rmp-serde, `Block`/`Transaction` types |
| 4 | Conformance v1 — Structural | Round-trip encode/decode, field-level comparison (13 header + 9 txn fields), JSON reports |
| 5a | Canonical Encoding | Byte-identical canonical msgpack encoding matching Go |
| 5b | Cryptographic Digests | Transaction IDs and block digests (SHA512/256) matching Go |
| 6 | One-Command Validation | `make validate` end-to-end pipeline, structured JSON reports |

---

## Conformance Layers Covered

Per [CONFORMANCE_STRATEGY.md](CONFORMANCE_STRATEGY.md):

- **Layer 1 — Encoding/Decoding**: Complete. Rust decodes Go msgpack blocks and re-encodes them with structural consistency.
- **Layer 2 — Hashing/Canonicalization**: Complete. Canonical encoding produces byte-identical output to Go. Transaction IDs and block digests match.

---

## What Was Validated

### Block Decoding
- Raw msgpack bytes from Go algod decoded into Rust `BlockResponse` structs
- All block header fields preserved across decode/re-encode round-trips

### Field-Level Comparison (13 header fields)
- `round`, `genesis_id`, `genesis_hash`, `timestamp`, `current_protocol`
- `fee_sink`, `rewards_pool`, `branch`, `seed`, `txn_commitment`
- `txn_counter`, `rewards_level`, `rewards_rate`, `proposer`

### Field-Level Comparison (9 transaction fields)
- `type`, `sender`, `fee`, `first_valid`, `last_valid`
- `amount`, `receiver`, `sig`, `note`

### Canonical Encoding
- Byte-level equivalence with Go's canonical msgpack encoding
- Verified against Go reference bytes extracted via `canonical-extract` tool
- Covers: `Transaction`, `SignedTransaction`, `SignedTxnInBlock`, `BlockHeader`

### Cryptographic Digests
- **Transaction IDs**: `SHA512/256("TX" || canonical_encode(txn))` — matches Go
- **Block digests**: `SHA512/256("BH" || canonical_encode(header))` — matches Go
- Block digest reference values extracted from next block's `prev` field

### Transaction Types Tested
- `pay` (payment) — fully modeled with all fields
- Other types (`axfer`, `acfg`, `afrz`, `appl`, `keyreg`, `stpf`) decode at the type-string level but type-specific fields are not yet modeled

---

## Known Gaps

| Gap | Notes |
|-----|-------|
| Only `pay` txn fields modeled | Other txn types decode but type-specific fields are ignored |
| No signature verification | Ed25519 signatures are stored as raw bytes but not verified |
| No protocol rule validation | Fee minimums, valid round windows, group constraints not checked |
| `msig`/`lsig` opaque | Multisig and logic sig stored as `rmpv::Value`, not parsed |
| `spt` opaque | State proof tracking stored as `rmpv::Value` |
| Devnet-only testing | No mainnet or testnet block replay |
| No CI pipeline | Validation is local-only via `make validate` |

---

## How to Reproduce

```bash
# Prerequisites: Docker, Rust toolchain, Go 1.21+

# One-command validation (starts localnet, generates txns, validates, reports)
make validate

# Output: ./reports/conformance.json
# Exit code: 0 = all pass, non-zero = failures

# Custom block count
make validate VALIDATE_BLOCKS=20

# Cleanup
make localnet-down
```

---

## Conclusion

Phase 0 proves the fundamental approach: Rust can faithfully decode, re-encode, and compute cryptographic digests for Algorand blocks with byte-level Go conformance. The framework (fixture capture, canonical encoding, differential comparison, structured reporting) is validated and extensible.

Extending to more transaction types, signature verification, and protocol rules is incremental work that builds on this foundation — not architectural change. See [PHASE1_PROPOSAL.md](PHASE1_PROPOSAL.md) for next steps.
