We are building algod-rust — a Rust reimplementation of go-algorand. Phase 1
(stateless block validation) is complete with 208 tests and 101 mainnet blocks
replayed. Phase 2 implements ledger execution — applying blocks to account state.

## Epic 13 — Genesis State & Account Model

This epic defines the account data model, creates the `algo-ledger` crate, and
bootstraps ledger state from genesis.json. Everything in Phase 2 depends on this.

### Background

Algorand's ledger tracks per-account state: balances, reward tracking, participation
keys, opted-in assets, opted-in applications, and authorization (rekey). The genesis
block initializes this state from a genesis.json file that defines initial account
allocations, the fee sink, the rewards pool, and protocol parameters.

go-algorand's account model lives in `data/basics/userBalance.go` (AccountData struct)
and genesis loading in `data/bookkeeping/genesis.go`. The Rust model must be compatible
but does not need to mirror Go's struct layout.

### Deliverables

1. **Account data types** in `algo-types`
   - `AccountData`: balance (microAlgos), rewards_base, status (Offline/Online/NotParticipating),
     vote_id, selection_id, state_proof_id, vote_first_valid, vote_last_valid, vote_key_dilution,
     auth_addr (for rekeyed accounts), total_assets_opted_in, total_created_assets,
     total_apps_opted_in, total_created_apps, total_extra_app_pages, total_box_bytes, total_boxes
   - `AssetHolding`: amount, frozen
   - `AssetParamsRecord`: full asset params (total, decimals, unit_name, asset_name, url,
     metadata_hash, manager, reserve, freeze, clawback) + creator address
   - `AppLocalState`: schema, key-value store
   - `AppParams`: approval_program, clear_state_program, global_state (key-value),
     local_state_schema, global_state_schema, extra_program_pages
   - `AccountStatus` enum: Offline, Online, NotParticipating

2. **New crate `crates/core/algo-ledger`**
   - `LedgerState` struct: in-memory state with `HashMap<Address, AccountData>`,
     per-account asset holdings `HashMap<(Address, u64), AssetHolding>`,
     per-account app local state, global asset params, global app params
   - Rewards tracking state: current rewards_level, rewards_rate, rewards_residue,
     rewards_recalculation_round, fee_sink address, rewards_pool address
   - Protocol-version-aware configuration: RewardsRateRefreshInterval, min-balance
     per asset (100,000 microAlgos), min-balance per app, etc.
   - Public API: `LedgerState::new()`, `LedgerState::from_genesis()`,
     `get_account()`, `get_asset_holding()`, `get_asset_params()`

3. **Genesis JSON parser** in `algo-ledger/src/genesis.rs`
   - Parse genesis.json format: network name, protocol version, initial allocations
   - Each allocation: address (base64 or base32), balance (microAlgos), status, participation keys
   - Identify fee sink and rewards pool from genesis allocations
   - Compute initial rewards state from genesis parameters
   - Mainnet genesis.json available from go-algorand repo

4. **Error variant**
   - Add `Ledger` variant to `AlgoError` in algo-error

5. **Unit tests**
   - Load testnet/devnet genesis.json, verify expected accounts exist with correct balances
   - Load mainnet genesis.json, verify fee sink and rewards pool addresses
   - Verify AccountData default values match go-algorand defaults
   - Test min-balance computation for various asset/app counts

### Key context
- BlockHeader already has rewards fields: earn, rate, frac, rwcalr, fee_sink, rewards_pool
- SignedTransaction has ApplyData fields: ca, aca, rs, rr, rc, dt, caid, apid
- Transaction has all type-specific fields for pay, axfer, acfg, afrz, appl, keyreg, stpf
- Storage backend: SQLite (rusqlite) — decided, but actual SQLite integration is Epic 17a.
  This epic uses in-memory HashMap for initial development.
- go-algorand uses `data/basics/userBalance.go` for AccountData
- go-algorand uses `data/bookkeeping/genesis.go` for genesis loading

### What success looks like
- `LedgerState::from_genesis("path/to/genesis.json")` produces correct initial state
- All account types are defined and serde-compatible
- Fee sink and rewards pool are identified from genesis
- Initial rewards state matches go-algorand's genesis initialization
- All existing 208 tests still pass, new genesis/account tests added

Read docs/ for architecture and conformance strategy.
Start by studying go-algorand's AccountData struct and genesis loading,
then define the Rust types and implement the genesis loader.
