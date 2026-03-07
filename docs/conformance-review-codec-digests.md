# Conformance Review: Codec & Block Digests (Epics 0-7)

## Scope

Review of msgpack codec and block digest implementations in algod-rust against
go-algorand v4.5.1-stable. This covers canonical encoding correctness, block
digest computation, transaction ID computation, and group ID computation.

## Review Areas

1. **Canonical encoding** -- field ordering, omitempty semantics, serde_bytes usage
2. **Block digest computation** -- SHA512/256 with "BH" domain-separation prefix
3. **Transaction ID computation** -- SHA512/256 with "TX" domain-separation prefix
4. **Group ID computation** -- SHA512/256 with "TG" domain-separation prefix

---

## Findings

### Correct (NONE severity)

The following aspects were verified as conformant with go-algorand:

- Canonical encoding settings match Go: `Canonical=true`, `PositiveIntUnsigned=true`,
  `RecursiveEmptyCheck=true`.
- Key sorting is lexicographic byte-order, consistent with Go's `codec` library.
- `omitempty` semantics are correct for all field types: `u64` (zero), `bool` (false),
  `String` (empty), `ByteBuf` (empty), `Address` (zero), `Option` (None), `Vec` (empty).
- Integer packing uses compact encoding (fixint / uint8 / uint16 / uint32 / uint64),
  matching Go's positive-integer-unsigned behavior.
- SHA-512/256 implementation using the `sha2` crate produces correct output.
- Block digest: `SHA512/256("BH" || canonical_encode(header))` matches Go's
  `BlockHeader.Hash()`.
- Transaction ID: `SHA512/256("TX" || canonical_encode(txn))` matches Go's
  `Transaction.ID()`.
- Group ID: `SHA512/256("TG" || canonical_encode(TxGroup{txlist}))` matches Go's
  `TxGroup` hash.
- Nested struct encoding (AssetParams, StateSchema, BoxRef, MultisigSig, LogicSig)
  is correct.
- Flattened embedding for all transaction field groups (except HeartbeatTxnFields)
  is correct.

### Fixed in This Review

All items below were `omitempty` in Go and did not affect current devnet fixtures,
but would affect mainnet blocks containing the relevant transaction types or
protocol features.

#### BlockHeader (5 fields)

| Field | Codec Tag | Go Type | Severity | Impact |
|---|---|---|---|---|
| UpgradePropose | `upgradeprop` | string | MEDIUM | Block digests during upgrade voting |
| UpgradeDelay | `upgradedelay` | uint64 | MEDIUM | Block digests during upgrade voting |
| UpgradeApprove | `upgradeyes` | bool | MEDIUM | Block digests during upgrade voting |
| ExpiredParticipationAccounts | `partupdrmv` | []Address | MEDIUM | Block digests when accounts go offline |
| AbsentParticipationAccounts | `partupdabs` | []Address | MEDIUM | Block digests when accounts go offline |

#### Transaction (3 fields)

| Field | Codec Tag | Go Type | Severity | Impact |
|---|---|---|---|---|
| HeartbeatTxnFields | `hb` (nested sub-map) | struct pointer | HIGH | Txn IDs for heartbeat txns |
| StateProof Message | `spmsg` | struct | MEDIUM | Txn IDs for state proof txns |
| RejectVersion | `aprv` | uint64 | MEDIUM | Future app versioning |

#### LogicSig (1 field)

| Field | Codec Tag | Go Type | Severity | Impact |
|---|---|---|---|---|
| LMsig | `lmsig` | MultisigSig | LOW | Delegated multisig for lsigs |

### Remaining Low-Severity Items (not fixed)

| Item | Details | Impact |
|---|---|---|
| ExtraProgramPages type | Go: uint32, Rust: u64 | No practical impact (values 0-3) |
| AssetParams.Decimals type | Go: uint32, Rust: u64 | No practical impact (values 0-19) |
| 35 HashID constants not defined | Only TX, BH, TG implemented | Will be needed for Merkle proofs, state proofs, program hashing |
| StateProofTracking passthrough | Uses `rmpv::Value`, not typed | Safe when input from Go; fragile if Rust constructs natively |

---

## Test Coverage

- **18 existing digest conformance tests**: 8 block digests, 8 transaction IDs,
  1 mutation test, 1 display test.
- Coverage is limited to **devnet fixtures** (blocks 1-8).
- Transaction types tested: `pay`, `appl` (create/call), `keyreg`.
- **Not tested**: `axfer`, `acfg`, `afrz`, `stpf`, `heartbeat`.
- No mainnet block coverage (to be added in later phases).

---

## Methodology

- Field-by-field cross-reference of Go codec tags vs Rust serde annotations.
- Trace of digest computation paths in both Go and Rust.
- Review of `omitempty` predicate functions and their Rust equivalents.
- Review of integer packing thresholds.
- Analysis of existing test fixtures.

---

## References

- **Go source**: `../go-algorand` @ `v4.5.1-stable`
- **Key Go files**:
  - `protocol/codec.go` -- canonical encoding configuration
  - `protocol/hash.go` -- HashID constants and Hashable interface
  - `crypto/util.go` -- SHA512/256 helper
  - `data/bookkeeping/block.go` -- BlockHeader, Hash()
  - `data/transactions/transaction.go` -- Transaction, ID(), TxGroup
