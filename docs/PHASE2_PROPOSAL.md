# Phase 2 Proposal — Ledger Execution

_Created: 2026-03-04_

## Goal

Implement account state transitions, asset state updates, and reward calculations. Verify ledger state against Go nodes after each block. This covers Conformance Layer 5 (Ledger State Transitions) from [CONFORMANCE_STRATEGY.md](CONFORMANCE_STRATEGY.md).

---

## What "Ledger Execution" Means

Ledger execution applies validated blocks to account state, producing the same balances and asset holdings as go-algorand:

- Do sender/receiver balances update correctly after payments?
- Do asset holdings track creates, transfers, opt-ins, freezes, destroys?
- Do rewards accrue and distribute correctly?
- Does participation state change correctly on keyreg?
- Are leases enforced across blocks?

It does **not** include:

- TEAL program execution (Phase 3 — AVM Execution)
- Independent EvalDelta computation (Phase 3 — app call results are taken from recorded block data)
- Catchpoint sync or snapshot loading (Phase 4)
- Block propagation or peer networking (Phase 5)

---

## What Exists (from Phase 1)

- 7 workspace crates: algo-error, algo-types, algo-codec, algo-validate, algo-rest-client, algo-fixtures, algo-conformance, plus bin/algod-rust CLI
- 208 tests passing, 101 mainnet blocks replayed with stateless validation
- BlockHeader already has rewards fields: `rewards_level` (earn), `rewards_rate` (rate), `rewards_residue` (frac), `rewards_recalculation_round` (rwcalr), `fee_sink`, `rewards_pool`
- SignedTransaction has ApplyData fields: `closing_amount` (ca), `asset_closing_amount` (aca), `sender_rewards` (rs), `receiver_rewards` (rr), `close_rewards` (rc), `eval_delta` (dt, opaque rmpv::Value), `apply_data_config_asset` (caid), `apply_data_application_id` (apid)
- Transaction has all type-specific fields for pay, axfer, acfg, afrz, appl, keyreg, stpf

## What's Missing

- No account/ledger state types (AccountData, AssetHolding, AppLocalState, AppParams)
- No storage layer
- No apply_transaction logic
- No reward calculation
- No genesis state loader
- No account REST API queries
- No cross-block lease enforcement
- No state root computation
- EvalDelta is opaque (rmpv::Value)

---

## Epic Breakdown

### Epic 13 — Genesis State & Account Model

Define the account data model and bootstrap from genesis.json.

**Deliverables**:
- New types in algo-types: `AccountData` (balance, rewards_base, status, vote/selection/stateproof keys, auth_addr, total_app_schema, total_extra_app_pages, min_balance tracking fields), `AssetHolding` (amount, frozen), `AssetParamsRecord` (full asset params + creator), `AppLocalState`, `AppParams` (programs + schemas + extra pages)
- Genesis JSON parser: read genesis.json, extract initial account allocations, fee sink, rewards pool, initial rewards state
- In-memory `LedgerState` struct: `HashMap<Address, AccountData>` with per-account asset holdings and app state
- New crate `crates/core/algo-ledger` with LedgerState, genesis loader
- Protocol-version-aware reward parameters (RewardsRateRefreshInterval, min-balance rules vary by version)
- Storage backend decision: SQLite (rusqlite) — matches go-algorand
- Unit tests: genesis load produces expected initial accounts and balances

**Affected crates/files**: New crate algo-ledger, modifications to algo-types (new types), algo-error (new Ledger variant)

### Epic 14 — Payment & Close-Remainder State Transitions

Apply pay transactions to ledger state and verify balances match Go.

**Deliverables**:
- `apply_transaction()` function in algo-ledger dispatching on txn_type
- Payment logic: debit sender (amount + fee), credit receiver, handle close-remainder-to (transfer remaining balance minus min balance)
- Account closure semantics: when close-remainder-to is set, transfer full balance, clear rewards_base, fail if account has remaining opted-in assets or apps
- Fee handling: credit fee_sink with transaction fees
- Reward distribution: compute and apply pending rewards to sender/receiver/close-to at time of transaction
- Rewards calculation: `rewards_earned = (rewards_level - account.rewards_base) * account.microalgos / rewards_units` (matching go-algorand's `basics.PendingRewards`)
- Rewards pool balance tracking: verify it decreases correctly as rewards are distributed
- Rekey state tracking: update account's auth_addr when rekey_to is set on any transaction type
- `apply_block()` function that processes all transactions in order, updates rewards state from block header
- Asset/app IDs taken from block's ApplyData (caid, apid) — not re-derived from counter
- Add `/v2/accounts/{addr}` to AlgodClient for conformance comparison
- Conformance test: replay localnet blocks, compare sender/receiver balances via REST

**Affected crates/files**: algo-ledger (new apply logic), algo-rest-client (account query), algo-types (AccountData extensions)

### Epic 15 — Asset State Transitions

Apply acfg, axfer, afrz transactions to ledger state.

**Deliverables**:
- Asset create (`acfg` with config_asset=0): allocate new asset ID from apply_data_config_asset, create AssetParamsRecord, credit full supply to creator's holding
- Asset reconfigure (`acfg` with config_asset!=0): update manager/reserve/freeze/clawback addresses (only if current manager matches sender)
- Asset destroy (`acfg` with config_asset!=0 and empty params): remove asset if creator holds full supply
- Asset opt-in (`axfer` to self with amount=0): create zero-balance holding
- Asset transfer (`axfer`): debit sender holding, credit receiver holding, handle clawback (asnd field), handle close-to (aclose field)
- Asset freeze (`afrz`): update frozen flag on target holding (only if freeze address matches sender)
- Min-balance tracking: each opted-in asset increases min balance by 100,000 microAlgos
- Fee/reward logic reused from Epic 14 shared infrastructure
- Minimal EvalDelta parsing: model global_delta, local_deltas, inner_txns from block ApplyData to apply app state changes without TEAL execution (needed for correct state on blocks with app calls)
- Conformance tests against localnet diverse fixtures

**Affected crates/files**: algo-ledger (asset apply logic, EvalDelta parsing), algo-types (AssetHolding, AssetParamsRecord, EvalDelta struct)

### Epic 16 — Participation & Key Registration State

Apply keyreg transactions and track participation state.

**Deliverables**:
- Online keyreg: store vote/selection/stateproof keys, vote first/last/key dilution on account
- Offline keyreg (nonpart=false, empty keys): mark account offline
- Nonparticipation keyreg (nonpart=true): mark account as non-participating (cannot earn rewards)
- Status transitions: Offline -> Online, Online -> Offline, * -> NotParticipating
- Participation state affects reward eligibility (non-participating accounts do not earn rewards)
- Cross-block lease enforcement: enforce lease uniqueness within the validity window (sender + lease must be unique across blocks within last_valid - first_valid rounds)

**Affected crates/files**: algo-ledger (keyreg apply, lease tracking), algo-types (account status enum)

### Epic 17a — Persistent Storage & Balance-Comparison Conformance

Add persistent storage and verify state against Go node via per-account balance comparison.

**Deliverables**:
- SQLite backend (rusqlite) for LedgerState so replay can handle thousands of blocks without OOM
- Conformance via per-account balance comparison using `/v2/accounts/{addr}` against local archival Go node (Docker)
- Replay CLI: extend replay subcommand with `--stateful` flag that applies blocks to ledger state and compares balances
- Makefile targets: `make replay-stateful`, Docker archival Go node for conformance
- Historical state access via local archival Go node with `?round=N` parameter support

**Affected crates/files**: algo-ledger (storage backend), algo-rest-client (account query with round param), CLI (replay subcommand), Makefile, docker/

### Epic 17b — Merkle Trie State Root (Stretch Goal)

Compute Merkle trie state root matching go-algorand.

**Deliverables**:
- Implement Algorand's account Merkle trie (go-algorand `merkletrie` package): domain-separated, sorted by address, produces a 32-byte state root
- Compare computed state root against Go node's reported value
- This is a stretch goal — if too complex for Phase 2, defer to Phase 2.5 or Phase 3

**Affected crates/files**: algo-ledger (Merkle trie implementation)

### Epic 18 — Phase 2 Closeout & Validation

End-to-end validation of ledger execution against Go reference.

**Deliverables**:
- Replay 1000+ mainnet blocks with stateful validation, comparing account state against Go node after each block
- Handle edge cases: rewards recalculation rounds, zero-balance accounts, account closure and re-creation
- Document known gaps (full app state re-execution — deferred to Phase 3 AVM)
- PHASE2_VALIDATION.md with epics completed, conformance results, known gaps
- Fuzz targets: add cargo-fuzz targets for apply_transaction and state serialization (at least 2)

**Affected crates/files**: Documentation, tests, fuzz targets

---

## New Infrastructure

### New Crate: `crates/core/algo-ledger`

Ledger state management, transaction application, reward computation, genesis loading, persistent storage:

```
crates/core/algo-ledger/
├── Cargo.toml
└── src/
    ├── lib.rs          # Public API: apply_block, apply_transaction, LedgerState
    ├── genesis.rs      # Genesis JSON parser and initial state loader
    ├── apply.rs        # Transaction application dispatch (pay, axfer, acfg, afrz, keyreg)
    ├── rewards.rs      # Reward calculation and distribution
    ├── lease.rs        # Cross-block lease enforcement
    └── storage.rs      # SQLite backend via rusqlite
```

### New Dependencies

| Dependency | Purpose |
|-----------|---------|
| rusqlite (~0.31) | Persistent account state storage (matches go-algorand) |
| serde_json (already available) | Genesis JSON parsing |

### New Makefile Targets

- `make replay-stateful` — stateful mainnet replay with conformance checks
- Docker archival Go node configuration for historical state queries

---

## Success Criteria

1. Account balances match Go after replaying blocks from genesis
2. Asset state matches (holdings, params, frozen status) for all accounts touched
3. Participation state matches after keyreg transactions
4. Reward calculations match for sampled accounts
5. Cross-block lease enforcement works
6. Stateful replay passes 1000+ mainnet blocks with zero state mismatches (app state via recorded EvalDelta)
7. Persistent storage works (survives restart, resumes replay)
8. At least 2 fuzz targets defined and run without crashes

---

## Estimated Scope

| Epic | Estimated Effort | Dependencies |
|------|-----------------|--------------|
| 13 — Genesis State & Account Model | Medium | None |
| 14 — Payment State Transitions | Medium | Epic 13 |
| 15 — Asset State Transitions | Medium | Epic 14 |
| 16 — Keyreg & Lease Enforcement | Small | Epic 14 |
| 17a — Persistent Storage & Conformance | Medium | Epics 14-16 |
| 17b — Merkle Trie State Root (stretch) | Large | Epic 17a |
| 18 — Phase 2 Closeout | Small | Epic 17a |

Epic 13 is the critical path — everything else depends on having the account model and genesis state in place.

---

## Known Limitations / Deferred Items

- **Full TEAL execution**: Phase 2 applies EvalDelta from recorded block data. Independent TEAL program execution and EvalDelta computation are deferred to Phase 3 (AVM Execution).
- **Inner transaction re-execution**: Inner transactions from app calls are applied from recorded ApplyData. Independent re-execution is Phase 3.
- **State root verification**: Epic 17b (Merkle trie state root) is a stretch goal. go-algorand's `merkletrie` is page-based and compressed. If too complex, defer to Phase 2.5 or Phase 3.
- **Box storage**: Full box storage accounting (min-balance impact, per-box costs) is modeled but deep box state verification may require Phase 3 AVM support.
- **Min-balance edge cases**: The min-balance formula depends on opted-in assets, apps, schema sizes, boxes, and extra pages. Formula must match exactly — edge cases may surface during mainnet replay.

---

## Risks

1. **Reward calculation complexity**: Edge cases around recalculation rounds, non-participating accounts, overflow handling, rewards_residue accumulation
2. **State root algorithm** (Epic 17b): go-algorand's merkletrie is page-based and compressed. May be deferred if too complex.
3. **EvalDelta boundary**: Minimal parsing in Phase 2; if inner transaction structures prove too complex, may need early Phase 3 work
4. **Historical state access**: Requires local archival Go node — adds Docker infrastructure complexity
5. **Min-balance computation**: Depends on opted-in assets, apps, schema sizes, boxes, extra pages — formula must match exactly

---

## Relationship to Later Phases

Phase 2 output feeds directly into:
- **Phase 3 (AVM Execution)**: Phase 2 applies EvalDelta from recorded block data. Phase 3 will re-execute TEAL programs to independently produce EvalDelta, enabling validation of app call results. Full EvalDelta modeling, inner transaction re-execution, and opcode-level conformance.
- **Phase 4 (Catchup and Sync)**: Persistent storage from Phase 2 provides the foundation for catchpoint sync and snapshot-based sync.
- **Phase 5 (Networking)**: Stateful validation serves as the second filter for incoming blocks — after stateless validation (Phase 1), blocks are applied to ledger state to verify correctness before acceptance.
