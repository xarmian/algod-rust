We are building algod-rust — a Rust reimplementation of go-algorand. Phase 1
is complete. Epic 13 defines the account model, Epic 14 implements payment
state transitions with reward distribution.

## Epic 15 — Asset State Transitions

This epic applies asset transactions (acfg, axfer, afrz) to ledger state and
adds minimal EvalDelta parsing so that app state changes from recorded block
data can be applied without TEAL execution.

### Background

Algorand supports three asset transaction types:
- **acfg** (Asset Config): create, reconfigure, or destroy an asset
- **axfer** (Asset Transfer): opt-in, transfer, clawback, or close-out
- **afrz** (Asset Freeze): freeze or unfreeze an account's asset holding

Each operation has specific authorization rules and state effects. Asset creation
assigns a new asset ID (from the block's ApplyData `caid` field). Min-balance
increases by 100,000 microAlgos per opted-in asset.

Additionally, mainnet blocks contain application calls whose state effects are
recorded in EvalDelta (the `dt` field). To achieve correct ledger state during
replay, these recorded deltas must be applied even though we don't re-execute TEAL.

### Deliverables

1. **Asset create** (`acfg` with config_asset=0)
   - New asset ID from `apply_data_config_asset` (caid) in block's ApplyData
   - Create AssetParamsRecord with sender as creator
   - Credit full supply (total) to creator's asset holding
   - Increase creator's total_created_assets
   - Increase creator's min-balance by 100,000 microAlgos (asset holding)

2. **Asset reconfigure** (`acfg` with config_asset!=0)
   - Verify sender is current manager; if manager is zero (cleared), reject (asset is immutable)
   - Only update a role if it is currently non-zero in the ledger (cleared roles are permanently locked)
   - Zero address in txn = clear that role; absence from msgpack = zero address (equivalent)
   - Only the 4 address roles (manager, reserve, freeze, clawback) are mutable post-creation
   - Non-address fields (total, decimals, default_frozen, unit_name, etc.) are NOT updated on reconfig

3. **Asset destroy** (`acfg` with config_asset!=0, all-zero AssetParams)
   - Detection: `txn.asset_params == AssetParams::default()` (all fields zero/absent)
   - Verify creator holds full supply (all units returned)
   - Remove asset params from global state
   - Remove creator's holding
   - Decrease creator's total_created_assets and min-balance

4. **Asset opt-in** (`axfer` to self with amount=0)
   - Create zero-balance, unfrozen holding for receiver
   - Increase receiver's total_assets_opted_in and min-balance

5. **Asset transfer** (`axfer`)
   - Debit sender holding by asset_amount
   - Credit receiver holding by asset_amount
   - Clawback: if `asset_sender` (asnd) is set, sender is the clawback address,
     debit from asset_sender's holding instead
   - Close-to: if `asset_close_to` (aclose) is set, transfer remaining balance
     to close-to and remove sender's holding, decrease min-balance

6. **Asset freeze** (`afrz`)
   - Verify sender is the asset's freeze address
   - Set frozen flag on target account's holding

7. **Min-balance tracking**
   - 100,000 microAlgos per opted-in asset
   - 100,000 microAlgos per created asset
   - 100,000 microAlgos per opted-in app
   - 100,000 microAlgos per created app
   - 100,000 microAlgos per extra app page (= AppFlatParamsMinBalance)
   - Per schema entry (three-tier costing from go-algorand):
     - SchemaMinBalancePerEntry: 25,000 per slot (uint or byte-slice)
     - SchemaUintMinBalance: 3,500 additive per uint slot (total: 28,500/uint)
     - SchemaBytesMinBalance: 25,000 additive per byte-slice slot (total: 50,000/byte-slice)
   - Schema-aware `compute_min_balance(account, &LedgerState) -> u64` that looks up
     per-app global/local schemas to compute exact schema cost
   - `compute_min_balance(account) -> u64` simple version (no schema) retained for tests

8. **Minimal EvalDelta parsing**
   - Model `EvalDelta` struct (replacing opaque `rmpv::Value`):
     - `global_delta: Option<HashMap<Vec<u8>, ValueDelta>>` — app global state changes
     - `local_deltas: Option<HashMap<u64, HashMap<Vec<u8>, ValueDelta>>>` — per-account local state
     - `inner_txns: Option<Vec<SignedTransaction>>` — inner transactions with their own ApplyData
     - `logs: Option<Vec<Vec<u8>>>` — app call logs (stored but not validated)
   - `ValueDelta`: action (set_uint, set_bytes, delete), uint value, bytes value
   - Apply global_delta to app's global state
   - Apply local_deltas to accounts' app local state
   - Recursively apply inner_txns using the same apply_transaction logic
   - This enables correct state for blocks with app calls without TEAL execution

9. **Conformance tests**
   - Replay localnet diverse fixtures (blocks 1-9 cover acfg, axfer, afrz)
   - Verify asset holdings match Go node via REST after each block
   - Verify min-balance calculations match Go

### Key context
- Existing AssetParams struct in algo-types covers the protocol-level fields
- AssetHolding and AssetParamsRecord are new types from Epic 13
- Fee/reward logic from Epic 14 applies to all transaction types (shared infra)
- apply_data_config_asset (caid) and apply_data_application_id (apid) are already
  decoded on SignedTransaction
- eval_delta (dt) is currently `Option<rmpv::Value>` — will be replaced with typed struct
- go-algorand asset logic: `ledger/apply.go` (applyAssetConfigTx, applyAssetTransferTx,
  applyAssetFreezeTx)
- go-algorand EvalDelta: `data/transactions/eval.go`

### What success looks like
- All asset operations (create, reconfig, destroy, opt-in, transfer, clawback,
  close-out, freeze) produce correct state
- Min-balance tracks asset and app counts correctly
- EvalDelta from recorded blocks is applied (global/local state changes + inner txns)
- Asset conformance tests pass against localnet Go node
- Mainnet blocks with app calls don't cause state drift (via EvalDelta application)
- All existing tests still pass

Read docs/ for architecture and conformance strategy.
Start by studying go-algorand's asset apply functions, then implement
each operation. Add EvalDelta parsing after core asset logic is working.
