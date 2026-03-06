We are building algod-rust — a Rust reimplementation of go-algorand. Phase 1
is complete. Epics 13-16 implement the account model, payment/asset/keyreg state
transitions, reward distribution, and lease enforcement — all in-memory.

## Epic 17a — Persistent Storage & Balance-Comparison Conformance

This epic replaces the in-memory LedgerState with a SQLite-backed store and
builds the stateful replay conformance pipeline that compares Rust ledger state
against a Go archival node after each block.

### Background

In-memory state works for small block ranges but cannot scale to thousands of
mainnet blocks. go-algorand uses SQLite for ledger storage, so we adopt the same
backend for practical conformance debugging (can inspect both databases with
the same tools).

For conformance, we compare per-account balances after replaying blocks. This
requires a local archival Go node that supports the `/v2/accounts/{addr}?round=N`
parameter for historical state queries.

### Deliverables

1. **SQLite storage backend** in `algo-ledger/src/storage.rs`
   - Add `rusqlite` dependency to workspace
   - Schema: `accounts` table (address PRIMARY KEY, data BLOB as msgpack or JSON),
     `asset_holdings` table (address, asset_id, amount, frozen),
     `asset_params` table (asset_id PRIMARY KEY, creator, params BLOB),
     `app_params` table (app_id PRIMARY KEY, creator, params BLOB),
     `app_local_state` table (address, app_id, state BLOB),
     `leases` table (sender, lease, last_valid)
   - `SqliteLedger` struct implementing same API as in-memory LedgerState
   - Transaction batching: commit all state changes per block in a single SQLite transaction
   - Round tracking: `metadata` table with last committed round for resume capability

2. **LedgerState trait abstraction**
   - Extract trait from in-memory implementation: `get_account`, `set_account`,
     `get_asset_holding`, `set_asset_holding`, etc.
   - Both in-memory and SQLite backends implement the trait
   - apply_block/apply_transaction work against the trait (backend-agnostic)

3. **REST client extension for historical state**
   - Extend `get_account()` with optional `round` parameter: `/v2/accounts/{addr}?round=N`
   - This requires an archival Go node (non-archival nodes don't support historical queries)

4. **Docker archival Go node**
   - Add archival Go node configuration to `docker/docker-compose.yml`
   - Archival mode: set `Archival=true` in algod config
   - Port mapping: separate port from existing devnet node (e.g., 4002)
   - For mainnet replay: configure archival node pointed at mainnet
   - For localnet conformance: existing devnet node can serve as reference

5. **Stateful replay CLI**
   - Extend `replay` subcommand with `--stateful` flag
   - When stateful: load genesis, apply each block to LedgerState, optionally
     compare sampled accounts against Go node after each block
   - `--genesis` flag to specify genesis.json path
   - `--compare` flag to enable conformance comparison (requires Go node URL)
   - `--sample-rate N` to compare every Nth block (default: every block)
   - Resume capability: if SQLite DB exists at the expected path, resume from
     last committed round

6. **Makefile targets**
   - `make replay-stateful` — run stateful replay against localnet
   - `make replay-mainnet-stateful` — run against mainnet (with archival Go node)

7. **Conformance comparison logic**
   - After applying a block, query Go node for accounts touched in that block
   - Compare: balance, rewards_base, status, asset holdings count
   - Report mismatches with full context: round, address, expected vs actual
   - Sampling: compare a subset of accounts per block for performance

### Key context
- go-algorand uses SQLite with tables: accountbase, assetcreators, storedcatchpoints, etc.
- We don't need to match Go's exact schema — just need correct state
- rusqlite ~0.31 is the standard Rust SQLite binding
- Nodely public endpoints do NOT support historical account queries (?round=N)
- Local archival node required for conformance
- Current replay CLI: `cargo run --bin algod-rust -- replay --network mainnet --start-round N --count M`

### What success looks like
- LedgerState persists to SQLite, survives process restart
- Replay resumes from last committed round without re-processing
- Stateful replay of 1000+ localnet blocks with zero balance mismatches
- Docker archival Go node runs and serves historical account queries
- `make replay-stateful` passes end-to-end
- All existing tests still pass

### Known limitations
- **Inner transaction address coverage**: `collect_touched_addresses` extracts addresses from transaction fields and the `accounts` array, but does not walk EvalDelta inner transactions. Accounts mutated only by inner txns (e.g., app-to-app calls crediting a third-party address) are not included in `--compare` conformance checks. Full inner-txn address extraction deferred to Epic 18 or Phase 3.
- **`normalizedonlinebalance`**: Stored as raw `micro_algos` for Online accounts, not Go's sortition-weighted value. Acceptable for Phase 2; would need fixing for consensus participation.

Read docs/ for architecture and conformance strategy.
Start by defining the SQLite schema and implementing the storage trait,
then build the conformance comparison pipeline.
