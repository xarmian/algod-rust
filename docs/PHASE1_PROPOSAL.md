# Phase 1 Proposal — Stateless Block Validation

_Created: 2026-03-04_

## Goal

Validate Algorand blocks **without ledger state**. Given a block, can Rust confirm it is structurally and cryptographically valid — correct signatures, valid protocol rules, all transaction types decoded?

This covers Conformance Layers 3 (Transaction Validation) and 4 (Block Validation) from [CONFORMANCE_STRATEGY.md](CONFORMANCE_STRATEGY.md).

---

## What "Stateless" Means

Stateless validation checks everything that can be verified without knowing account balances, asset ownership, or application state:

- Are all signatures valid?
- Are fees above the protocol minimum?
- Are round windows valid?
- Are group IDs correct?
- Are all transaction fields well-formed?

It does **not** check:
- Does the sender have sufficient balance?
- Does the sender own the asset?
- Does the application exist?

Those are Phase 2 (Ledger Execution) concerns.

---

## Epic Breakdown

### Epic 8 — All Transaction Types

Model type-specific fields for every Algorand transaction type.

**Currently**: Only `pay` has modeled fields. Other types decode at the type-string level but their specific fields are stored in `rmpv::Value` overflow or silently ignored.

**Deliverables**:
- `axfer` (Asset Transfer): `xaid`, `aamt`, `asnd`, `arcv`, `aclose`
- `acfg` (Asset Config): `caid`, `apar` (total, decimals, unit name, asset name, url, metadata hash, manager, reserve, freeze, clawback)
- `afrz` (Asset Freeze): `faid`, `fadd`, `afrz`
- `appl` (Application Call): `apid`, `apan` (on-completion), `apap`, `apsu`, `apaa`, `apat`, `apfa`, `apas`, `apbx`, `apgs`, `apls`, `apep`
- `keyreg` (Key Registration): `votekey`, `selkey`, `sprfkey`, `votefst`, `votelst`, `votekd`, `nonpart`
- `stpf` (State Proof): `sptype`, `sp` (state proof body)
- Update canonical encoder for new fields
- Update conformance comparisons to check type-specific fields
- Generate diverse fixtures (requires `goal` commands for asset create, app call, keyreg, etc.)

### Epic 9 — Signature Verification

Verify cryptographic signatures on transactions.

**Deliverables**:
- Add `ed25519-dalek` dependency
- Verify single-sig (`sig` field) against sender address (which is the public key)
- Parse multisig structure: version, threshold, subsigs — verify each subsig, check threshold met
- LogicSig: parse structure (logic bytes, sig, msig, args) — defer TEAL evaluation to Phase 3
- Rekeyed accounts: verify against `auth_addr` when present
- Wire sig verification into conformance — verify all txns in captured blocks

### Epic 10 — Stateless Protocol Rules

Validate transactions against protocol rules that don't require state.

**Deliverables**:
- Minimum fee: 1000 microAlgos (or protocol-configured)
- Valid round window: `last_valid - first_valid <= MaxTxnLife` (1000 rounds)
- Note size: <= 1024 bytes
- Group size: <= 16 transactions
- Group ID: SHA512/256 of concatenated transaction hashes matches `group` field
- Lease constraints within a group
- Transaction size limit
- Genesis ID/hash consistency

### Epic 11 — Block-Level Validation

Validate entire blocks as a unit.

**Deliverables**:
- All transactions in payset pass stateless validation
- Timestamp bounds (within acceptable range of previous block)
- Protocol version is known/supported
- Payset commitment matches recomputed value
- Transaction size limit (`MaxTxnBytesPerBlock`) — deferred from Epic 10 as this is a block-level aggregate check
- Wire into `make validate` — report block-level validation results alongside existing conformance checks

### Epic 12 — Mainnet Block Replay

Test against real-world transaction diversity.

**Deliverables**:
- Capture mainnet/testnet block ranges (requires public algod endpoint or archival node)
- Replay through stateless validator
- Conformance report showing transaction type coverage
- Identify any decode failures or validation mismatches on production blocks

---

## New Infrastructure

### New Crate: `crates/core/algo-validate`

Stateless validation logic, separate from codec and conformance:

```
crates/core/algo-validate/
├── Cargo.toml
└── src/
    ├── lib.rs          # Public API: validate_transaction, validate_block
    ├── signature.rs    # Ed25519, multisig, logicsig verification
    ├── rules.rs        # Protocol rule checks (fees, rounds, sizes)
    └── block.rs        # Block-level validation
```

### New Dependency

- `ed25519-dalek` — Ed25519 signature verification (well-maintained, pure Rust)

---

## Success Criteria

1. All 7 transaction types decode with type-specific fields
2. Ed25519 signatures verified for all single-sig transactions in test blocks
3. Stateless protocol rules enforced (fee, rounds, note size, group size)
4. `make validate` reports block-level validation pass/fail
5. Mainnet block ranges pass stateless validation without false rejections

---

## Estimated Scope

Per PROJECT_SCOPE.md: Phase 1 estimated at 3-4 months for a small team.

| Epic | Estimated Effort | Dependencies |
|------|-----------------|--------------|
| 8 — All Transaction Types | Large | None |
| 9 — Signature Verification | Medium | Epic 8 (needs sender/auth_addr) |
| 10 — Stateless Protocol Rules | Medium | Epic 8 (needs all fields) |
| 11 — Block-Level Validation | Medium | Epics 9, 10 |
| 12 — Mainnet Block Replay | Medium | Epics 8-11 |

Epic 8 is the critical path — everything else depends on having all transaction types modeled.

---

## Known Limitations / Deferred Items

- **Full lease enforcement**: Epic 10 validates lease uniqueness within transaction groups only. Cross-block lease enforcement (no duplicate sender+lease within the validity window) requires ledger state and is deferred to Phase 2.
- **Transaction size limit**: Per-transaction byte size is not enforced individually. Go-algorand uses `MaxTxnBytesPerBlock` as a block-level aggregate limit, checked in Epic 11.

---

## Relationship to Later Phases

Phase 1 output feeds directly into:
- **Phase 2 (Ledger Execution)**: Stateless-valid blocks can be applied to ledger state
- **Phase 3 (AVM Execution)**: LogicSig and app call validation deferred to here
- **Phase 5 (Networking)**: Stateless validation is the first filter for incoming blocks from peers
