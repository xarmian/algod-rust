use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use algo_agreement::{
    AccountSigningKeys, AsyncCryptoVerifier, BlockFactoryBridge, BlockValidatorBridge,
    EventsProcessingMonitor, NetworkAdvancer, Parameters, RandomSource, Service, SystemClock,
};
use algo_avm::group::GroupBudget;
use algo_codec::{canonical_encode_signed_txn_in_block, canonical_encode_transaction};
use algo_ledger::participation::ParticipationStore;
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::{
    AgreementKeyManagerBridge, AgreementLedgerBridge, BlockFetcher, CatchupService, FetchError,
    FetchedBlockCert, SqliteLedger,
};
use algo_network::local_tx_broadcast::{LocalTxBroadcaster, PoolIngestAdapter};
use algo_network::{
    AgreementNetworkBridge, GossipNode, Phonebook, WebsocketNetwork, WebsocketNetworkConfig,
    RELAY_ROLE,
};
use algo_pool::{PoolConfig, TransactionPool};
use algo_rest_api::node::BuildVersion;
use algo_rest_api::server::{ApiServer, ApiServerConfig};
use algo_rest_client::GossipBlockSource;
use algo_types::consensus::CONSENSUS_V41;
use algo_types::{AccountData, Address, BlockHeader, Digest, Round, TxnType};
use algo_validate::merkle::{compute_payset_merkle_root, compute_vector_commitment, HashAlgo};
use algo_validate::rules::{has_txn256, has_txn512};
use algo_validate::signature::verify_transaction_signature;
use rand::Rng;
use sha2::{Digest as _, Sha512_256};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::commands::network_common::genesis_id_for;
use crate::config::RestConfig;
use crate::node_interface_impl::{AlgodNodeInterface, NodeInterfaceConfig};

/// Upper bound on how long Ctrl-C is willing to wait for the REST
/// server's graceful shutdown to drain. The `wait_for_round` handler
/// already honours the shutdown token and should return promptly; this
/// cap is defence-in-depth for a hypothetical future handler that
/// forgets to. Short enough that operators aren't tempted to SIGKILL
/// the process, long enough that normal in-flight requests finish.
const REST_SHUTDOWN_HARD_CAP: Duration = Duration::from_secs(5);

/// A no-op `EventsProcessingMonitor` for production use.
///
/// Unlike `StubEventsProcessingMonitor` which stores all events in a Vec
/// (leaking memory), this implementation does nothing.
struct NoOpMonitor;

impl EventsProcessingMonitor for NoOpMonitor {
    fn update_events_queue(&self, _queue_name: &str, _queue_length: usize) {}
}

/// A `RandomSource` backed by the OS/thread-local CSPRNG.
///
/// Replaces `StubRandomSource::constant(42)` for production use.
struct RealRandomSource;

impl RandomSource for RealRandomSource {
    fn uint64(&self) -> u64 {
        rand::thread_rng().gen()
    }
}

/// A concrete [`NetworkAdvancer`] that wraps the gossip node.
///
/// When the agreement service makes progress (e.g. a certificate arrives or a
/// block is committed), it calls `on_network_advance()`. This adapter
/// delegates to the `GossipNode::on_network_advance()` method, which triggers
/// mesh maintenance (e.g. clique-resolution peer cycling).
///
/// Mirrors Go's `agreementLedger.n.OnNetworkAdvance()` in `node/impls.go`.
struct GossipNetworkAdvancer {
    node: Arc<dyn GossipNode>,
}

impl NetworkAdvancer for GossipNetworkAdvancer {
    fn on_network_advance(&self) {
        self.node.on_network_advance();
    }
}

/// A concrete [`BlockFetcher`] that fetches blocks from peers via the gossip
/// network's WebSocket unicast protocol.
///
/// The catchup service runs on a dedicated background thread and calls
/// `fetch_block` synchronously. This adapter bridges the async
/// `GossipBlockSource` to the sync trait by using `tokio::runtime::Handle::block_on`.
///
/// Mirrors Go's `universalFetcher` used in `catchup/service.go`.
struct GossipBlockFetcher {
    ws_network: Arc<WebsocketNetwork>,
    rt_handle: tokio::runtime::Handle,
}

impl BlockFetcher for GossipBlockFetcher {
    fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
        // SAFETY: This is called from the CatchupService's background std::thread,
        // NOT from a tokio worker thread. Calling block_on from within the tokio
        // runtime would panic.
        self.rt_handle.block_on(async {
            let peers = self.ws_network.get_unicast_peers().await;
            if peers.is_empty() {
                return Err(FetchError::NoPeersAvailable);
            }
            let source = GossipBlockSource::new(peers);
            let (response, raw_block_data) =
                source.get_block_with_raw_data(round).await.map_err(|e| {
                    FetchError::NetworkError(format!(
                        "block fetch failed for round {}: {}",
                        round, e
                    ))
                })?;

            // Extract raw payset blobs from the wire-format block bytes.
            // These are used for payset commitment verification, avoiding
            // re-encoding from typed structs which may lose unknown fields.
            let raw_payset_blobs =
                match algo_codec::extract_raw_payset_blobs_from_block(&raw_block_data) {
                    Ok(blobs) => Some(blobs),
                    Err(e) => {
                        tracing::warn!(
                            round = %round,
                            error = %e,
                            "could not extract raw payset blobs, falling back to typed re-encoding"
                        );
                        None
                    }
                };

            // Try to parse the gossip response's certificate data
            // (rmpv::Value) into a typed Certificate for fork detection.
            // If parsing fails, gracefully degrade to cert: None — the
            // catchup service already has the agreement cert and can
            // still commit blocks; fork detection just won't fire.
            //
            // The rmpv::Value preserves Go's codec tags ("rnd", "per",
            // "prop", etc.) as map keys. We re-encode to bytes and then
            // use the agreement codec's `decode_bundle` which understands
            // those tags, rather than rmp_serde which expects Rust field
            // names.
            let cert = response.cert.and_then(|val| {
                let mut bytes = Vec::new();
                rmpv::encode::write_value(&mut bytes, &val).ok()?;
                match algo_agreement::codec::decode_bundle(&bytes) {
                    Ok(bundle) => Some(algo_agreement::Certificate::from_bundle(&bundle)),
                    Err(e) => {
                        tracing::debug!(
                            round = %round,
                            error = %e,
                            "could not parse fetched certificate, fork detection unavailable for this block"
                        );
                        None
                    }
                }
            });
            Ok(FetchedBlockCert {
                block: response.block,
                cert,
                raw_payset_blobs,
            })
        })
    }
}

/// Domain separation prefix for transaction ID hashing (matches go-algorand).
const TX_PREFIX: &[u8] = b"TX";

/// Compute the transaction ID: SHA512/256("TX" || canonical_encode(txn)).
///
/// The transaction should have genesis fields restored before calling this,
/// since Go's `txn.ID()` is computed over the full transaction including
/// genesis_id and genesis_hash.
fn compute_txid(txn: &algo_types::Transaction) -> [u8; 32] {
    let canonical = canonical_encode_transaction(txn);
    let mut hasher = Sha512_256::new();
    hasher.update(TX_PREFIX);
    hasher.update(&canonical);
    hasher.finalize().into()
}

/// Compute the effective minimum balance for an account based on its
/// resource holdings and consensus parameters.
///
/// Mirrors Go's `MinBalance()` in `data/basics/userBalance.go`:
/// - Base min_balance
/// - Per asset opted-in: +min_balance each
/// - Per app created: +app_flat_params_min_balance each
/// - Per app opted-in: +app_flat_opt_in_min_balance each
/// - Per extra app page: +app_flat_params_min_balance each
/// - Schema entries: schema_min_balance_per_entry * num_entries
/// - Schema uints: schema_uint_min_balance * num_uint
/// - Schema bytes: schema_bytes_min_balance * num_byte_slice
/// - Per box: +box_flat_min_balance each
/// - Per box byte: +box_byte_min_balance each
fn effective_min_balance(account: &AccountData, params: &algo_types::ConsensusParams) -> u64 {
    let mut min: u64 = params.min_balance;

    // Per-asset holding cost
    min = min.saturating_add(
        params
            .min_balance
            .saturating_mul(account.total_assets_opted_in),
    );

    // Per-app created cost
    min = min.saturating_add(
        params
            .app_flat_params_min_balance
            .saturating_mul(account.total_created_apps),
    );

    // Per-app opted-in cost
    min = min.saturating_add(
        params
            .app_flat_opt_in_min_balance
            .saturating_mul(account.total_apps_opted_in),
    );

    // Schema cost: flat per entry + per-uint + per-bytes
    let schema = &account.total_app_schema;
    let num_entries = schema.num_uint.saturating_add(schema.num_byte_slice);
    min = min.saturating_add(
        params
            .schema_min_balance_per_entry
            .saturating_mul(num_entries),
    );
    min = min.saturating_add(
        params
            .schema_uint_min_balance
            .saturating_mul(schema.num_uint),
    );
    min = min.saturating_add(
        params
            .schema_bytes_min_balance
            .saturating_mul(schema.num_byte_slice),
    );

    // Per extra app page cost
    min = min.saturating_add(
        params
            .app_flat_params_min_balance
            .saturating_mul(account.total_extra_app_pages as u64),
    );

    // Per-box cost
    min = min.saturating_add(
        params
            .box_flat_min_balance
            .saturating_mul(account.total_boxes),
    );

    // Per box byte cost
    min = min.saturating_add(
        params
            .box_byte_min_balance
            .saturating_mul(account.total_box_bytes),
    );

    min
}

/// Apply a signed delta to an unsigned u64 value, clamping at 0.
/// Mirrors Go's `basics.AddSaturate` / `basics.SubSaturate` pattern.
fn apply_delta(base: u64, delta: i64) -> u64 {
    if delta >= 0 {
        base.saturating_add(delta as u64)
    } else {
        base.saturating_sub(delta.unsigned_abs())
    }
}

/// Apply a signed delta to an unsigned u32 value, clamping at 0.
fn apply_delta_u32(base: u32, delta: i64) -> u32 {
    if delta >= 0 {
        base.saturating_add(delta as u32)
    } else {
        base.saturating_sub(delta.unsigned_abs() as u32)
    }
}

/// Read-only snapshot of ledger state captured at evaluator creation.
///
/// Mirrors Go's `roundCowBase` pattern: snapshot the relevant state once at
/// the start of block evaluation, then release the ledger lock so agreement
/// and catchup can proceed concurrently.
///
/// Account reads use a dedicated read-only SQLite connection (via
/// [`algo_ledger::ReadSnapshot`]) that holds a deferred read transaction.
/// In WAL mode this provides true MVCC snapshot isolation — all account
/// reads see the database state as of snapshot creation, regardless of
/// concurrent writes by the main ledger connection (catchup, block commit).
/// The main ledger mutex is acquired only once during construction to
/// capture the lease table and open the snapshot connection; no further
/// locking is needed for individual account lookups.
///
/// For in-memory databases (tests), the `ReadSnapshot` is unavailable
/// because each in-memory connection is independent. In that case we fall
/// back to locking the ledger per account lookup with a round-consistency
/// guard that returns `None` if the ledger has advanced.
struct LedgerSnapshot {
    /// Cached account balances (sender address -> AccountData).
    /// Populated lazily on first access and cached for the block.
    accounts: HashMap<Address, Option<AccountData>>,
    /// Lease table snapshot from the ledger at evaluator creation time.
    lease_table: algo_ledger::LeaseTable,
    /// The round being evaluated.
    round: u64,
    /// The ledger's current round at snapshot creation time.
    /// Used to verify point-in-time consistency when falling back to the
    /// ledger mutex (in-memory DB path).
    snapshot_round: Round,
    /// Read-only snapshot connection for point-in-time account lookups.
    /// `Some` for file-backed databases (production), `None` for in-memory
    /// databases (tests) where a separate connection cannot share state.
    read_snapshot: Option<algo_ledger::ReadSnapshot>,
}

impl LedgerSnapshot {
    /// Create a new snapshot by briefly locking the ledger to capture lease
    /// state, open a read-only snapshot connection, and record the current
    /// round. The ledger lock is released before returning; subsequent
    /// account lookups go through the snapshot connection without locking.
    fn from_ledger(ledger: &Arc<Mutex<SqliteLedger>>, round: u64) -> Self {
        let l = ledger.lock().expect("ledger lock for snapshot");
        // Clone the lease table while holding the lock so the snapshot
        // reflects the actual lease state from prior committed blocks.
        let lease_table = l.lease_table().clone();
        // Capture the ledger's current round for consistency checks
        // (used only in the in-memory fallback path).
        let snapshot_round = l.current_round();
        // Open a read-only snapshot connection. In WAL mode this begins a
        // deferred read transaction that pins the reader to the current DB
        // state. For in-memory databases this returns None.
        let read_snapshot = l.open_read_snapshot();
        drop(l);
        LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table,
            round,
            snapshot_round,
            read_snapshot,
        }
    }

    /// Look up an account, checking the cache first, then the snapshot.
    ///
    /// When a `ReadSnapshot` is available (file-backed DB), account reads
    /// go directly through the snapshot connection — no mutex acquisition.
    /// For in-memory databases, falls back to locking the ledger with a
    /// round-consistency guard.
    fn get_account(
        &mut self,
        addr: &Address,
        ledger: &Arc<Mutex<SqliteLedger>>,
    ) -> Option<AccountData> {
        if let Some(cached) = self.accounts.get(addr) {
            return cached.clone();
        }
        let result = if let Some(ref snap) = self.read_snapshot {
            // Fast path: read from the snapshot connection (no mutex).
            snap.get_account(addr)
        } else {
            // Fallback for in-memory databases: acquire the ledger lock
            // and verify round consistency before reading.
            let l = ledger.lock().expect("ledger lock for account lookup");
            let current = l.current_round();
            if current != self.snapshot_round {
                warn!(
                    snapshot_round = self.snapshot_round.0,
                    current_round = current.0,
                    "ledger advanced during block evaluation; snapshot consistency violated"
                );
                return None;
            }
            l.get_account(addr)
        };
        self.accounts.insert(*addr, result.clone());
        result
    }

    /// Check whether a lease is active in the ledger snapshot.
    ///
    /// The snapshot's lease table was cloned from the ledger at evaluator
    /// creation time, so this is a pure read with no lock acquisition.
    fn check_lease(&self, sender: &Address, lease: &[u8; 32]) -> Result<(), algo_error::AlgoError> {
        self.lease_table.check(sender, lease, self.round)
    }
}

/// Per-address resource count deltas tracked in the COW overlay.
///
/// In Go, the cow layer stores modified `AccountData` records that include
/// updated `TotalAssets`, `TotalAppLocalStates`, `TotalAppParams`, etc.
/// We cannot store full `AccountData` because the block evaluator only
/// has snapshot access — so instead we track *deltas* that are merged with
/// snapshot data when computing effective min-balance.
///
/// Each field is a signed delta (i64) so it can represent both additions
/// (asset create, app opt-in) and removals (asset close-out, app delete).
#[derive(Debug, Clone, Default, PartialEq)]
struct ResourceCountDeltas {
    /// Delta for `total_assets_opted_in` (asset holdings).
    /// +1 on acfg create (creator auto-holds), +1 on axfer opt-in,
    /// -1 on axfer close-out.
    delta_total_assets_opted_in: i64,
    /// Delta for `total_created_assets` (asset params owned by creator).
    /// +1 on acfg create, -1 on acfg destroy.
    delta_total_created_assets: i64,
    /// Delta for `total_apps_opted_in` (app local states).
    /// +1 on appl opt-in, -1 on appl close-out / clear-state.
    delta_total_apps_opted_in: i64,
    /// Delta for `total_created_apps` (app params owned by creator).
    /// +1 on appl create, -1 on appl delete.
    delta_total_created_apps: i64,
    /// Delta for `total_extra_app_pages`.
    /// +extra_program_pages on appl create.
    delta_total_extra_app_pages: i64,
    /// Delta for `total_app_schema.num_uint`.
    delta_schema_num_uint: i64,
    /// Delta for `total_app_schema.num_byte_slice`.
    delta_schema_num_byte_slice: i64,
}

/// Copy-on-write overlay that accumulates mutations during block evaluation.
///
/// Mirrors Go's `roundCowState` pattern: reads check the overlay first, then
/// fall back to the snapshot/ledger. Writes go only to the overlay. The
/// overlay is discarded if the block is abandoned.
struct CowOverlay {
    /// Balance adjustments: maps address to remaining microAlgos.
    /// When a transaction is accepted, the sender's fee (and amount for
    /// payment txns) is deducted and the receiver's balance is credited.
    balance_deltas: HashMap<Address, u64>,
    /// Leases recorded within this block. Maps (sender, lease) to last_valid.
    leases: HashMap<(Address, [u8; 32]), u64>,
    /// Transaction IDs seen within this block, for duplicate detection.
    seen_txids: HashSet<[u8; 32]>,
    /// Auth-addr (rekey) overrides accumulated during block evaluation.
    /// Maps sender address to their new auth_addr after a RekeyTo transaction.
    /// `Some(addr)` means rekeyed to `addr`; `None` means rekeyed back to self
    /// (auth_addr cleared). Mirrors Go's `apply.Rekey()` which updates
    /// `acct.AuthAddr` in the cow state.
    auth_addr_deltas: HashMap<Address, Option<Address>>,
    /// Resource count deltas accumulated during block evaluation.
    /// Tracks changes to asset/app counts that affect min-balance computation.
    /// Mirrors Go's cow layer where modified AccountData includes updated
    /// TotalAssets, TotalAppLocalStates, TotalAppParams, etc.
    resource_deltas: HashMap<Address, ResourceCountDeltas>,
}

/// Lease key type used in the COW overlay: (sender, lease_bytes).
type LeaseKey = (Address, [u8; 32]);

/// An incremental checkpoint of `CowOverlay` state for tentative-apply rollback.
///
/// Instead of cloning all three collections (expensive near the 5000-txn limit),
/// we record only the keys that changed since the checkpoint was taken. On
/// rollback we iterate these small vecs and undo each change. On commit we
/// simply drop the checkpoint (clearing the tracking vecs).
///
/// This mirrors the conceptual pattern of Go's child-cow: only the delta
/// needs to be unwound, not the entire state.
struct CowCheckpoint {
    /// Balance keys modified since the checkpoint.
    /// Stores (address, Option<old_balance>). `None` means the key did not
    /// exist before the checkpoint — on rollback we remove it.
    balance_keys: Vec<(Address, Option<u64>)>,
    /// Lease keys added since the checkpoint.
    /// Stores (key, Option<old_last_valid>). `None` means the lease was new
    /// — on rollback we remove it.
    lease_keys: Vec<(LeaseKey, Option<u64>)>,
    /// Transaction IDs added since the checkpoint — on rollback we remove them.
    txid_keys: Vec<[u8; 32]>,
    /// Auth-addr keys modified since the checkpoint.
    /// Stores (address, Option<old_auth_addr>). The outer `Option` follows
    /// the same convention as balance_keys: `None` means the key did not
    /// exist before — on rollback we remove it.
    auth_addr_keys: Vec<(Address, Option<Option<Address>>)>,
    /// Resource delta keys modified since the checkpoint.
    /// Stores (address, Option<old_deltas>). `None` means the key did not
    /// exist before — on rollback we remove it.
    resource_delta_keys: Vec<(Address, Option<ResourceCountDeltas>)>,
}

impl CowOverlay {
    fn new() -> Self {
        CowOverlay {
            balance_deltas: HashMap::new(),
            leases: HashMap::new(),
            seen_txids: HashSet::new(),
            auth_addr_deltas: HashMap::new(),
            resource_deltas: HashMap::new(),
        }
    }

    /// Create an incremental checkpoint for rollback.
    ///
    /// This is O(1) — it just initialises empty tracking vecs. All
    /// subsequent mutations (via `set_balance_tracked`, `record_txid_tracked`,
    /// `record_lease_tracked`) will record the old value so we can undo them.
    fn checkpoint(&self) -> CowCheckpoint {
        CowCheckpoint {
            balance_keys: Vec::new(),
            lease_keys: Vec::new(),
            txid_keys: Vec::new(),
            auth_addr_keys: Vec::new(),
            resource_delta_keys: Vec::new(),
        }
    }

    /// Restore the overlay to a previous checkpoint by undoing only the
    /// mutations recorded since the checkpoint was taken.
    fn restore(&mut self, cp: CowCheckpoint) {
        // Undo balance changes.
        for (addr, old_val) in cp.balance_keys {
            match old_val {
                Some(v) => {
                    self.balance_deltas.insert(addr, v);
                }
                None => {
                    self.balance_deltas.remove(&addr);
                }
            }
        }
        // Undo lease changes.
        for (key, old_val) in cp.lease_keys {
            match old_val {
                Some(v) => {
                    self.leases.insert(key, v);
                }
                None => {
                    self.leases.remove(&key);
                }
            }
        }
        // Undo txid additions.
        for txid in cp.txid_keys {
            self.seen_txids.remove(&txid);
        }
        // Undo auth_addr changes.
        for (addr, old_val) in cp.auth_addr_keys {
            match old_val {
                Some(v) => {
                    self.auth_addr_deltas.insert(addr, v);
                }
                None => {
                    self.auth_addr_deltas.remove(&addr);
                }
            }
        }
        // Undo resource delta changes.
        for (addr, old_val) in cp.resource_delta_keys {
            match old_val {
                Some(v) => {
                    self.resource_deltas.insert(addr, v);
                }
                None => {
                    self.resource_deltas.remove(&addr);
                }
            }
        }
    }

    /// Set a balance in the overlay and record the old value in the checkpoint
    /// for potential rollback. If `cp` is `None`, behaves like `set_balance`.
    fn set_balance_tracked(&mut self, addr: &Address, balance: u64, cp: &mut CowCheckpoint) {
        let old = self.balance_deltas.insert(*addr, balance);
        cp.balance_keys.push((*addr, old));
    }

    /// Record a transaction ID and track it in the checkpoint for rollback.
    fn record_txid_tracked(&mut self, txid: [u8; 32], cp: &mut CowCheckpoint) {
        self.seen_txids.insert(txid);
        cp.txid_keys.push(txid);
    }

    /// Record a lease and track the old value in the checkpoint for rollback.
    fn record_lease_tracked(
        &mut self,
        sender: &Address,
        lease: &[u8; 32],
        last_valid: u64,
        cp: &mut CowCheckpoint,
    ) {
        if *lease == [0u8; 32] {
            return;
        }
        let key = (*sender, *lease);
        let old = self.leases.insert(key, last_valid);
        cp.lease_keys.push((key, old));
    }

    /// Record a rekey (auth_addr change) in the overlay with checkpoint tracking.
    ///
    /// Mirrors Go's `apply.Rekey()`: if `rekey_to == sender`, the auth_addr is
    /// cleared (set to `None`); otherwise it is set to the new address.
    fn set_auth_addr_tracked(
        &mut self,
        sender: &Address,
        rekey_to: &Address,
        cp: &mut CowCheckpoint,
    ) {
        let old = self.auth_addr_deltas.get(sender).cloned();
        // Special case: rekeying to self clears the auth_addr (Go sets it to Address{}).
        let new_auth = if rekey_to == sender {
            None
        } else {
            Some(*rekey_to)
        };
        self.auth_addr_deltas.insert(*sender, new_auth);
        cp.auth_addr_keys.push((*sender, old));
    }

    /// Apply a mutation to the resource count deltas for an address,
    /// recording the old value in the checkpoint for rollback.
    ///
    /// The `mutate` closure receives a mutable reference to the current
    /// `ResourceCountDeltas` for the address (initialised to the default
    /// zero-delta if no entry exists yet).
    fn mutate_resource_deltas_tracked(
        &mut self,
        addr: &Address,
        cp: &mut CowCheckpoint,
        mutate: impl FnOnce(&mut ResourceCountDeltas),
    ) {
        let old = self.resource_deltas.get(addr).cloned();
        let entry = self.resource_deltas.entry(*addr).or_default();
        mutate(entry);
        cp.resource_delta_keys.push((*addr, old));
    }

    /// Get the resource count deltas for an address from the overlay.
    /// Returns `None` if the overlay has no resource delta entry.
    fn get_resource_deltas(&self, addr: &Address) -> Option<&ResourceCountDeltas> {
        self.resource_deltas.get(addr)
    }

    /// Get the auth_addr override for an address from the overlay.
    /// Returns `Some(Some(addr))` if rekeyed to `addr`, `Some(None)` if
    /// rekeyed back to self (auth_addr cleared), `None` if the overlay has
    /// no entry (caller should fall back to the snapshot/ledger).
    fn get_auth_addr(&self, addr: &Address) -> Option<Option<Address>> {
        self.auth_addr_deltas.get(addr).cloned()
    }

    /// Check whether a lease conflicts with an already-included transaction
    /// in this block's overlay.
    fn check_lease_in_overlay(
        &self,
        sender: &Address,
        lease: &[u8; 32],
        round: u64,
    ) -> Result<(), algo_error::AlgoError> {
        // All-zero lease is always allowed.
        if *lease == [0u8; 32] {
            return Ok(());
        }
        if let Some(&last_valid) = self.leases.get(&(*sender, *lease)) {
            if last_valid >= round {
                return Err(algo_error::AlgoError::Ledger {
                    message: "duplicate lease in block".into(),
                });
            }
        }
        Ok(())
    }

    /// Record a lease in the overlay. No-op for zero leases.
    /// Used only in tests; production code uses `record_lease_tracked`.
    #[cfg(test)]
    fn record_lease(&mut self, sender: &Address, lease: &[u8; 32], last_valid: u64) {
        if *lease == [0u8; 32] {
            return;
        }
        self.leases.insert((*sender, *lease), last_valid);
    }

    /// Check whether a transaction ID has already been seen in this block.
    fn check_txid(&self, txid: &[u8; 32]) -> Result<(), algo_error::AlgoError> {
        if self.seen_txids.contains(txid) {
            return Err(algo_error::AlgoError::Ledger {
                message: "duplicate transaction ID in block".into(),
            });
        }
        Ok(())
    }

    /// Record a transaction ID in the overlay.
    /// Used only in tests; production code uses `record_txid_tracked`.
    #[cfg(test)]
    fn record_txid(&mut self, txid: [u8; 32]) {
        self.seen_txids.insert(txid);
    }

    /// Get the effective balance for an address from the overlay.
    /// Returns `None` if the overlay has no entry for this address (caller
    /// should fall back to the snapshot/ledger).
    fn get_balance(&self, addr: &Address) -> Option<u64> {
        self.balance_deltas.get(addr).copied()
    }

    /// Set the effective balance for an address in the overlay.
    /// Used only in tests; production code uses `set_balance_tracked`.
    #[cfg(test)]
    fn set_balance(&mut self, addr: &Address, balance: u64) {
        self.balance_deltas.insert(*addr, balance);
    }
}

/// A `BlockEvaluator` that validates transactions using stateless rules and
/// stateful checks (balance, lease, txid dedup) via a COW overlay.
///
/// Stateless validation covers: well-formedness (fees, round window, note/
/// lease/group size), group ID consistency, group fee pooling, and signature
/// verification. Stateful validation includes balance pre-checks, lease
/// uniqueness, and transaction ID duplicate detection using the COW overlay
/// on top of a ledger snapshot.
struct SimpleBlockEvaluator {
    hdr: algo_types::BlockHeader,
    /// Consensus parameters for the protocol version of this block.
    consensus_params: algo_types::ConsensusParams,
    /// Transactions included in the block so far.
    included_txns: Vec<algo_types::SignedTransaction>,
    /// Running total of serialized transaction bytes (for the per-block cap).
    txn_bytes: usize,
    /// Maximum transaction bytes allowed in this block. This is the minimum
    /// of the caller-provided limit and the consensus protocol limit.
    max_txn_bytes: usize,
    /// Handle to the shared ledger for snapshot reads.
    ledger: Arc<Mutex<SqliteLedger>>,
    /// Read-only snapshot of ledger state captured at evaluator creation.
    snapshot: LedgerSnapshot,
    /// COW overlay accumulating mutations from accepted transaction groups.
    overlay: CowOverlay,
    /// Running total of fees collected in this block.
    /// Mirrors Go's `eval.block.FeesCollected` used in v39+ headers.
    fees_collected: u64,
}

impl SimpleBlockEvaluator {
    /// Restore genesis fields on a signed transaction that may have had them
    /// stripped (STIB format). If `has_genesis_id` is set and genesis_id is
    /// empty, fill it from the block header. If genesis_hash is zero, fill
    /// it from the block header. This is needed for signature verification
    /// and txid computation.
    fn restore_genesis_fields(&self, stx: &mut algo_types::SignedTransaction) {
        if stx.has_genesis_id && stx.txn.genesis_id.is_empty() {
            stx.txn.genesis_id.clone_from(&self.hdr.genesis_id);
        }
        // Restore genesis_hash when the protocol requires it (modern protocols)
        // or when the STIB flag indicates the hash was stripped. On old protocols
        // where genesis_hash is optional, only restore if has_genesis_hash is set
        // to avoid mutating transactions that were legitimately signed without a
        // genesis hash. Mirrors Go's DecodeSignedTxn logic.
        if stx.txn.genesis_hash == [0u8; 32]
            && (self.consensus_params.require_genesis_hash || stx.has_genesis_hash)
        {
            stx.txn.genesis_hash.clone_from(&self.hdr.genesis_hash);
        }
    }

    /// Perform stateless validation only (well-formedness, group ID, fees,
    /// signatures). Returns the group with genesis fields restored so that
    /// `validate_group` can reuse it for txid computation without cloning
    /// the group a second time.
    ///
    /// Used by `test_transaction_group` (which takes `&self`) via
    /// a thin wrapper that discards the returned Vec.
    fn validate_group_stateless_inner(
        &self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<Vec<algo_types::SignedTransaction>, algo_error::AlgoError> {
        if txgroup.is_empty() {
            return Err(algo_error::AlgoError::Validation {
                message: "empty transaction group".into(),
            });
        }

        let params = &self.consensus_params;
        let round = self.hdr.round;

        // 1. Reject consensus-injected transaction types.
        // State proof (stpf) and heartbeat (hb) transactions are injected by
        // the consensus layer, not submitted by users through the pool.
        for stx in txgroup {
            if stx.txn.txn_type == TxnType::Stpf {
                return Err(algo_error::AlgoError::Validation {
                    message: "state proof transactions (stpf) cannot be submitted via the pool"
                        .into(),
                });
            }
            if stx.txn.txn_type == TxnType::Hb {
                return Err(algo_error::AlgoError::Validation {
                    message: "heartbeat transactions (hb) cannot be submitted via the pool".into(),
                });
            }
        }

        // 2. Per-transaction well-formedness.
        let in_group = txgroup.len() > 1;
        for stx in txgroup {
            algo_validate::validate_transaction_wellformed(
                &stx.txn,
                in_group && params.enable_fee_pooling,
                params,
                None, // SpecialAddresses not available without ledger lookup
            )?;

            // Check that the transaction's round window covers this block's round.
            if round < stx.txn.first_valid || round > stx.txn.last_valid {
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "transaction round window [{}, {}] does not cover block round {}",
                        stx.txn.first_valid.0, stx.txn.last_valid.0, round.0,
                    ),
                });
            }
        }

        // 3. Group ID consistency.
        algo_validate::validate_transaction_group(txgroup)?;

        // 4. Group fee pooling (for multi-txn groups with fee pooling enabled).
        if in_group && params.enable_fee_pooling {
            let refs: Vec<&algo_types::SignedTransaction> = txgroup.iter().collect();
            algo_validate::validate_group_fees_with_params(&refs, params).map_err(|e| {
                algo_error::AlgoError::Validation {
                    message: format!("group fee validation failed: {e}"),
                }
            })?;
        }

        // 5. Signature verification.
        // Restore genesis fields before verification — signatures are computed
        // over the ORIGINAL transaction (with genesis_id and genesis_hash), but
        // the pool receives transactions with these fields present. For pool
        // transactions the genesis fields should already be populated, but we
        // ensure they're set matching the block header, mirroring the pattern
        // from block.rs.
        let mut restored: Vec<algo_types::SignedTransaction> = txgroup.to_vec();
        for stx in &mut restored {
            self.restore_genesis_fields(stx);
        }

        // Create a per-group LogicSig budget for logicsig evaluation.
        let mut lsig_budget = GroupBudget::for_logicsig(restored.len());

        for (intra_group_idx, stx) in restored.iter().enumerate() {
            verify_transaction_signature(
                stx,
                &restored,
                intra_group_idx,
                &mut lsig_budget,
                params,
            )?;
        }

        Ok(restored)
    }

    /// Perform stateless validation only, discarding the restored group.
    /// Convenience wrapper for `test_transaction_group` which only needs
    /// the pass/fail result.
    fn validate_group_stateless(
        &self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        self.validate_group_stateless_inner(txgroup).map(|_| ())
    }

    /// Validate a transaction group using both stateless and stateful checks.
    ///
    /// Stateful checks (txid dedup, lease uniqueness, balance precheck) require
    /// `&mut self` because the snapshot cache is populated lazily.
    ///
    /// Checks performed (in addition to stateless):
    /// 6. Transaction ID duplicate detection (in-block overlay + ledger)
    /// 7. Lease uniqueness check (in-block overlay + ledger snapshot)
    /// 8. Rekey/auth-addr validation (authorizer matches ledger's auth_addr)
    /// 9. Sender balance precheck (fee + amount against overlay/snapshot)
    fn validate_group(
        &mut self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        // Run all stateless checks first; reuse the restored (genesis fields
        // populated) copies rather than cloning + restoring the group again.
        let restored = self.validate_group_stateless_inner(txgroup)?;

        let round = self.hdr.round;

        // 6. Transaction ID duplicate detection.
        // Compute txid for each transaction (with genesis fields restored)
        // and check for duplicates WITHIN the current group first, then
        // against the in-block overlay. Mirrors Go's cow.checkDup(txid)
        // which checks mods.Txids first.
        {
            let mut group_txids = HashSet::new();
            for stx in &restored {
                let txid = compute_txid(&stx.txn);
                if !group_txids.insert(txid) {
                    return Err(algo_error::AlgoError::Ledger {
                        message: "duplicate transaction ID within group".into(),
                    });
                }
                self.overlay.check_txid(&txid)?;
            }
        }

        // 7. Lease uniqueness check.
        // For each transaction with a non-zero lease, check:
        //   a. Duplicates WITHIN the current group (same sender + lease)
        //   b. The in-block overlay (already-included txns in this block)
        //   c. The ledger snapshot (existing leases from prior blocks)
        // Mirrors Go's cow.checkDup() which checks mods.Txleases then
        // delegates to roundCowBase.checkDup -> ledger.CheckDup.
        {
            let mut group_leases: HashSet<(Address, [u8; 32])> = HashSet::new();
            for stx in &restored {
                if stx.txn.lease != [0u8; 32] {
                    // Check within current group first
                    if !group_leases.insert((stx.txn.sender, stx.txn.lease)) {
                        return Err(algo_error::AlgoError::Ledger {
                            message: "duplicate lease within group".into(),
                        });
                    }
                    // Check overlay (leases from earlier groups in this block)
                    self.overlay.check_lease_in_overlay(
                        &stx.txn.sender,
                        &stx.txn.lease,
                        round.0,
                    )?;
                    // Check ledger snapshot (leases from prior committed blocks)
                    self.snapshot.check_lease(&stx.txn.sender, &stx.txn.lease)?;
                }
            }
        }

        // 8. Rekey/auth-addr validation.
        // Mirrors Go's `transaction()` (eval.go:1183-1195): verify that
        // the transaction's claimed authorizer matches the ledger's expected
        // authorizer for the sender. If the sender has been rekeyed, the
        // signature must be from the rekeyed-to address.
        //
        // The "authorizer" of a signed transaction is:
        //   - `stx.auth_addr` if set (non-None), else `stx.txn.sender`
        // The "correct authorizer" from the ledger is:
        //   - `acct.auth_addr` if set (non-zero), else `sender`
        //
        // We iterate `txgroup` (not `restored`) here because `auth_addr`
        // lives on SignedTransaction and is unaffected by genesis field
        // restoration.
        for stx in txgroup {
            let sender = &stx.txn.sender;
            let correct_authorizer = self.expected_authorizer(sender);

            // The transaction's claimed authorizer (Go's txn.Authorizer()).
            let txn_authorizer = match &stx.auth_addr {
                Some(addr) => *addr,
                None => stx.txn.sender,
            };

            if txn_authorizer != correct_authorizer {
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "transaction should have been authorized by {} but was actually authorized by {}",
                        correct_authorizer, txn_authorizer,
                    ),
                });
            }
        }

        // 9. Sender balance precheck.
        // Verify each sender has sufficient balance for fee + amount (for
        // payment transactions). This is a read-only precheck — actual
        // balance mutation is deferred to transaction_group() on acceptance.
        // Mirrors Go's approach of checking balances via cow.lookup() which
        // first checks the overlay, then falls back to the parent/ledger.
        //
        // We accumulate per-sender costs within this group to handle groups
        // where the same sender appears multiple times.
        //
        // Only payment transactions include the `amount` field in the Algo
        // cost. Other transaction types (axfer, acfg, afrz, appl, keyreg,
        // stpf, hb) only cost the fee in Algos.
        let mut group_costs: HashMap<Address, u64> = HashMap::new();
        for stx in txgroup {
            let sender = &stx.txn.sender;
            let cost = if stx.txn.txn_type == TxnType::Pay {
                stx.txn.fee.saturating_add(stx.txn.amount)
            } else {
                stx.txn.fee
            };
            let entry = group_costs.entry(*sender).or_insert(0);
            *entry = entry.saturating_add(cost);
        }

        for (sender, required) in &group_costs {
            // Check overlay first for cumulative effects of earlier groups,
            // then fall back to the ledger snapshot.
            let bal = self.effective_balance(sender);

            if bal < *required {
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "sender {} has insufficient balance: need {} microAlgos, have {}",
                        sender, required, bal,
                    ),
                });
            }
        }

        Ok(())
    }
}

impl SimpleBlockEvaluator {
    /// Compute the reward-adjusted balance for an account.
    ///
    /// Mirrors Go's `WithUpdatedRewards()` in `data/basics/userBalance.go`:
    /// before any debit/credit, the raw `MicroAlgos` is adjusted by pending
    /// rewards that have accrued since the account's `RewardsBase` was last
    /// updated. `NotParticipating` accounts are excluded from rewards.
    ///
    /// Formula:
    ///   reward_units = micro_algos / consensus.reward_unit
    ///   rewards_delta = block.rewards_level - account.rewards_base
    ///   pending = reward_units * rewards_delta
    ///   adjusted = micro_algos + pending
    fn balance_with_rewards(&self, acct: &AccountData) -> u64 {
        algo_ledger::compute_pending_rewards(acct, self.hdr.rewards_level)
            .checked_add(acct.micro_algos)
            .expect("reward overflow: account rewards exceeded u64 max")
    }

    /// Get the effective balance for an address, checking the overlay first
    /// then falling back to the snapshot/ledger.
    ///
    /// This is the single source of truth for balance lookups during
    /// evaluation, ensuring cross-group visibility of balance changes.
    ///
    /// When reading from the snapshot, the balance is adjusted for pending
    /// rewards using `balance_with_rewards()`, mirroring Go's
    /// `WithUpdatedRewards()` which is called in `Move()` and balance
    /// operations before any debit or credit.
    fn effective_balance(&mut self, addr: &Address) -> u64 {
        match self.overlay.get_balance(addr) {
            Some(bal) => bal,
            None => self
                .snapshot
                .get_account(addr, &self.ledger)
                .map(|acct| self.balance_with_rewards(&acct))
                .unwrap_or(0),
        }
    }

    /// Get the AccountData for an address, merging snapshot data with any
    /// overlay resource-count deltas.
    ///
    /// Mirrors Go's `cow.lookup(addr)` which returns modified account data
    /// from the cow layer. Resource count fields (total_assets_opted_in,
    /// total_created_assets, total_apps_opted_in, total_created_apps,
    /// total_extra_app_pages, total_app_schema) are adjusted by the
    /// overlay deltas so that effective_min_balance sees the up-to-date
    /// resource counts.
    fn get_account_data(&mut self, addr: &Address) -> Option<AccountData> {
        let mut acct = self.snapshot.get_account(addr, &self.ledger)?;
        if let Some(deltas) = self.overlay.get_resource_deltas(addr) {
            acct.total_assets_opted_in = apply_delta(
                acct.total_assets_opted_in,
                deltas.delta_total_assets_opted_in,
            );
            acct.total_created_assets =
                apply_delta(acct.total_created_assets, deltas.delta_total_created_assets);
            acct.total_apps_opted_in =
                apply_delta(acct.total_apps_opted_in, deltas.delta_total_apps_opted_in);
            acct.total_created_apps =
                apply_delta(acct.total_created_apps, deltas.delta_total_created_apps);
            acct.total_extra_app_pages = apply_delta_u32(
                acct.total_extra_app_pages,
                deltas.delta_total_extra_app_pages,
            );
            acct.total_app_schema.num_uint =
                apply_delta(acct.total_app_schema.num_uint, deltas.delta_schema_num_uint);
            acct.total_app_schema.num_byte_slice = apply_delta(
                acct.total_app_schema.num_byte_slice,
                deltas.delta_schema_num_byte_slice,
            );
        }
        Some(acct)
    }

    /// Determine the expected authorizer for a sender address.
    ///
    /// Mirrors Go's rekey check in `transaction()` (eval.go:1183-1195):
    /// 1. Check the COW overlay for a rekey delta from an earlier transaction
    ///    in this block.
    /// 2. Fall back to the ledger snapshot's `auth_addr` field.
    /// 3. If the account has no auth_addr set, the sender itself is the
    ///    expected authorizer.
    ///
    /// Returns the address that must match `txn.Authorizer()` (i.e.,
    /// `stx.auth_addr` if set, else `stx.txn.sender`).
    fn expected_authorizer(&mut self, sender: &Address) -> Address {
        // 1. Check overlay for rekey delta from earlier in this block.
        if let Some(overlay_auth) = self.overlay.get_auth_addr(sender) {
            return match overlay_auth {
                Some(addr) => addr,
                None => *sender, // rekeyed back to self
            };
        }
        // 2. Fall back to ledger snapshot.
        if let Some(acct) = self.snapshot.get_account(sender, &self.ledger) {
            if let Some(auth) = acct.auth_addr {
                if auth != Address::default() {
                    return auth;
                }
            }
        }
        // 3. Default: sender is its own authorizer.
        *sender
    }
}

impl algo_pool::traits::BlockEvaluator for SimpleBlockEvaluator {
    fn round(&self) -> Round {
        self.hdr.round
    }

    fn pay_set_size(&self) -> usize {
        self.included_txns.len()
    }

    fn test_transaction_group(
        &self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        // test_transaction_group performs stateless checks only (matching
        // Go's TestTransactionGroup which does well-formedness + group
        // consistency but doesn't mutate evaluator state). The full
        // stateful checks (txid dedup, lease, balance) run in
        // transaction_group() when the group is actually committed.
        self.validate_group_stateless(txgroup)
    }

    fn transaction_group(
        &mut self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        self.validate_group(txgroup)?;

        // Convert each transaction to STIB (SignedTxnInBlock) format:
        // strip genesis fields and set has_genesis_id / has_genesis_hash flags.
        // This mirrors go-algorand's BlockHeader.EncodeSignedTxn().
        //
        // Before stripping, validate that genesis fields match the block
        // header. Go returns an error on mismatch — we do the same.
        let mut stibs: Vec<algo_types::SignedTransaction> = Vec::with_capacity(txgroup.len());
        for stx in txgroup {
            let mut stib = stx.clone();

            // Reject transactions whose genesis_id doesn't match the block.
            if !stib.txn.genesis_id.is_empty() && stib.txn.genesis_id != self.hdr.genesis_id {
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "transaction genesis_id '{}' does not match block header '{}'",
                        stib.txn.genesis_id, self.hdr.genesis_id,
                    ),
                });
            }

            // Reject transactions whose genesis_hash doesn't match the block.
            if stib.txn.genesis_hash != [0u8; 32] && stib.txn.genesis_hash != self.hdr.genesis_hash
            {
                return Err(algo_error::AlgoError::Validation {
                    message: "transaction genesis_hash does not match block header".into(),
                });
            }

            // If the protocol requires genesis_hash, reject transactions with a zero hash.
            if self.consensus_params.require_genesis_hash && stib.txn.genesis_hash == [0u8; 32] {
                return Err(algo_error::AlgoError::Validation {
                    message: "transaction genesis_hash is required but missing".into(),
                });
            }

            // Strip genesis_id if present (it matched above).
            if !stib.txn.genesis_id.is_empty() {
                stib.txn.genesis_id = String::new();
                stib.has_genesis_id = true;
            }

            // Strip genesis_hash if present (it matched above).
            if stib.txn.genesis_hash != [0u8; 32] {
                stib.txn.genesis_hash = [0u8; 32];
                // Only set has_genesis_hash if the protocol doesn't
                // require it (matching go-algorand behavior).
                if !self.consensus_params.require_genesis_hash {
                    stib.has_genesis_hash = true;
                }
            }

            stibs.push(stib);
        }

        // Use exact byte counting via canonical STIB encoding.
        let max_bytes = self.max_txn_bytes;
        let exact_bytes: usize = stibs
            .iter()
            .map(|stib| canonical_encode_signed_txn_in_block(stib).len())
            .sum();

        if self.txn_bytes + exact_bytes > max_bytes {
            return Err(algo_error::AlgoError::Ledger {
                message: format!(
                    "transaction group would exceed block byte limit ({} + {} > {})",
                    self.txn_bytes, exact_bytes, max_bytes,
                ),
            });
        }

        // ── Tentative apply with rollback ────────────────────────────
        // Create an incremental checkpoint before making any mutations.
        // If the min-balance check (or any later check) fails, we restore
        // only the mutations tracked by the checkpoint, avoiding the cost
        // of cloning the entire overlay. This mirrors Go's child-cow
        // pattern where `cow.commitToParent()` is only called after all
        // checks pass.
        // Note: `included_txns` and `txn_bytes` do not need checkpointing —
        // they are only extended AFTER the min-balance check passes, so
        // rollback never needs to undo them.
        let mut checkpoint = self.overlay.checkpoint();
        let fees_collected_checkpoint = self.fees_collected;

        // The FeeSink address from the block header. Fees are credited
        // to this address in the overlay, mirroring Go's `takeFee()`
        // which calls `cow.Move(sender, FeeSink, fee)`.
        let fee_sink = self.hdr.fee_sink;

        // Record txids, leases, and balance deltas in the COW overlay.
        // This mirrors Go's cow.addTx() which records txids and leases,
        // and the balance mutations from applyTransaction().
        //
        // All mutations use the `_tracked` variants so the checkpoint
        // records what to undo on rollback.
        for stx in txgroup {
            // Restore genesis fields for txid computation.
            let mut restored = stx.clone();
            self.restore_genesis_fields(&mut restored);

            // Record transaction ID.
            let txid = compute_txid(&restored.txn);
            self.overlay.record_txid_tracked(txid, &mut checkpoint);

            // Record lease if non-zero.
            if stx.txn.lease != [0u8; 32] {
                self.overlay.record_lease_tracked(
                    &stx.txn.sender,
                    &stx.txn.lease,
                    stx.txn.last_valid.0,
                    &mut checkpoint,
                );
            }

            // Update balances in overlay following Go's apply.Payment() order:
            // 1. Debit fee from sender, credit fee to FeeSink (takeFee)
            // 2. Move amount from sender to receiver (cow.Move)
            // 3. If close_remainder_to is set, move remaining balance
            //    to close address and zero the sender (cow.CloseAccount)
            let sender = &stx.txn.sender;
            let sender_balance = self.effective_balance(sender);

            // Credit fee to FeeSink (mirrors Go's takeFee -> cow.Move).
            // Track fees_collected running total for the block header.
            //
            // Go's cow.Move(sender, FeeSink, fee) is a no-op when sender
            // IS the FeeSink (src == dst), so the fee neither leaves nor
            // arrives — the balance is unchanged. We mirror this by
            // skipping the fee debit/credit entirely when sender == fee_sink.
            //
            // When the sender IS the FeeSink, Go's takeFee does NOT add
            // the fee to feesCollected (eval.go:1253-1254) because there
            // are no net algos added to the Sink.
            let sender_after_fee = if sender == &fee_sink {
                // Self-transfer of fee: balance unchanged, no fees_collected bump.
                sender_balance
            } else {
                if stx.txn.fee > 0 {
                    let fee_sink_balance = self.effective_balance(&fee_sink);
                    self.overlay.set_balance_tracked(
                        &fee_sink,
                        fee_sink_balance.saturating_add(stx.txn.fee),
                        &mut checkpoint,
                    );
                    self.fees_collected = self.fees_collected.saturating_add(stx.txn.fee);
                }
                sender_balance.saturating_sub(stx.txn.fee)
            };

            // ── Transaction-type-specific balance mutations ────────
            // In Go, `applyTransaction()` (eval.go:1276) switches on the
            // transaction type after `takeFee()`. Only payment transactions
            // move Algos (amount + close_remainder_to). All other types
            // (keyreg, acfg, axfer, afrz, appl, stpf, hb) only pay the
            // fee — any type-specific side effects (asset units for axfer,
            // app state for appl, etc.) do not affect Algo balances.
            match stx.txn.txn_type {
                TxnType::Pay => {
                    // Credit receiver for payment transactions.
                    // This must happen BEFORE close-out so that when
                    // receiver == sender, the balance is correctly computed
                    // before zeroing. Mirrors Go's cow.Move(sender,
                    // receiver, amount).
                    if stx.txn.amount > 0 && !stx.txn.receiver.is_zero() {
                        let receiver = &stx.txn.receiver;
                        if receiver == sender {
                            // Self-payment: fee is debited but amount is a
                            // no-op (debit and credit cancel out). Just
                            // debit fee.
                            self.overlay.set_balance_tracked(
                                sender,
                                sender_after_fee,
                                &mut checkpoint,
                            );
                        } else {
                            let recv_balance = self.effective_balance(receiver);
                            self.overlay.set_balance_tracked(
                                receiver,
                                recv_balance.saturating_add(stx.txn.amount),
                                &mut checkpoint,
                            );
                            self.overlay.set_balance_tracked(
                                sender,
                                sender_after_fee.saturating_sub(stx.txn.amount),
                                &mut checkpoint,
                            );
                        }
                    } else {
                        self.overlay.set_balance_tracked(
                            sender,
                            sender_after_fee.saturating_sub(stx.txn.amount),
                            &mut checkpoint,
                        );
                    }

                    // Handle close_remainder_to: the sender's entire
                    // remaining balance (after fee + amount + receiver
                    // credit) goes to the close address and the sender's
                    // balance becomes 0. Closing an account to zero is
                    // valid (the account is deleted). Mirrors Go's
                    // apply.Payment() -> cow.CloseAccount().
                    if !stx.txn.close_remainder_to.is_zero() {
                        let close_addr = &stx.txn.close_remainder_to;
                        let remaining = self.effective_balance(sender);
                        if remaining > 0 && close_addr != sender {
                            let close_balance = self.effective_balance(close_addr);
                            self.overlay.set_balance_tracked(
                                close_addr,
                                close_balance.saturating_add(remaining),
                                &mut checkpoint,
                            );
                        }
                        // Sender balance goes to zero after close.
                        self.overlay.set_balance_tracked(sender, 0, &mut checkpoint);
                    }
                }
                // All non-payment transaction types: only the fee (already
                // deducted above) affects Algo balances. Asset transfers
                // move asset units (not Algos), and all other types have no
                // Algo balance side effects beyond the fee.
                _ => {
                    self.overlay
                        .set_balance_tracked(sender, sender_after_fee, &mut checkpoint);
                }
            }

            // Handle RekeyTo: update the sender's auth_addr in the overlay.
            // Mirrors Go's `apply.Rekey()` (apply.go:113-128) which is called
            // in `applyTransaction()` after `takeFee()`. If RekeyTo == sender,
            // the auth_addr is cleared (rekeyed back to self). Otherwise the
            // auth_addr is set to the RekeyTo address. This ensures subsequent
            // transactions from the same sender in this block see the updated
            // authorizer.
            if let Some(rekey_to) = &stx.txn.rekey_to {
                if *rekey_to != Address::default() {
                    self.overlay
                        .set_auth_addr_tracked(sender, rekey_to, &mut checkpoint);
                }
            }

            // ── Resource count delta tracking ────────────────────────
            // Track changes to resource counts that affect min-balance
            // computation. Mirrors Go's cow layer where apply.AssetConfig,
            // apply.AssetTransfer, and apply.ApplicationCall update
            // TotalAssets, TotalAppLocalStates, TotalAppParams, etc.
            match stx.txn.txn_type {
                TxnType::Acfg => {
                    if stx.txn.config_asset == 0 {
                        // Asset create: creator gets +1 total_created_assets
                        // and +1 total_assets_opted_in (auto-holding).
                        // Mirrors Go's asset.go:87-88.
                        self.overlay
                            .mutate_resource_deltas_tracked(sender, &mut checkpoint, |d| {
                                d.delta_total_created_assets += 1;
                                d.delta_total_assets_opted_in += 1;
                            });
                    } else if stx.txn.asset_params.is_none() {
                        // Asset destroy: creator gets -1 total_created_assets
                        // and -1 total_assets_opted_in (holding removed).
                        // Mirrors Go's asset.go:149-150.
                        self.overlay
                            .mutate_resource_deltas_tracked(sender, &mut checkpoint, |d| {
                                d.delta_total_created_assets -= 1;
                                d.delta_total_assets_opted_in -= 1;
                            });
                    }
                    // Reconfigure (config_asset != 0 && asset_params.is_some())
                    // does not change resource counts.
                }
                TxnType::Axfer => {
                    // Opt-in: sender == asset_receiver, amount == 0, no
                    // close-to. The sender is opting into the asset.
                    // Mirrors Go's asset.go:305 (TotalAssets += 1).
                    let asset_receiver = stx.txn.asset_receiver.unwrap_or_default();
                    if asset_receiver == *sender
                        && stx.txn.asset_amount == 0
                        && stx.txn.asset_close_to.is_none()
                    {
                        self.overlay
                            .mutate_resource_deltas_tracked(sender, &mut checkpoint, |d| {
                                d.delta_total_assets_opted_in += 1;
                            });
                    }
                    // Close-out: asset_close_to is set.
                    // Mirrors Go's asset.go:419 (TotalAssets -= 1).
                    if let Some(close_to) = &stx.txn.asset_close_to {
                        if !close_to.is_zero() {
                            // The source of the close-out is the sender
                            // (or asset_sender for clawback, but clawback
                            // close is rejected by Go).
                            self.overlay.mutate_resource_deltas_tracked(
                                sender,
                                &mut checkpoint,
                                |d| {
                                    d.delta_total_assets_opted_in -= 1;
                                },
                            );
                        }
                    }
                }
                TxnType::Appl => {
                    if stx.txn.application_id == 0 {
                        // App create: creator gets +1 total_created_apps,
                        // plus schema and extra pages.
                        // Mirrors Go's application.go:106-115.
                        let global_schema = stx
                            .txn
                            .global_state_schema
                            .as_ref()
                            .cloned()
                            .unwrap_or_default();
                        let extra_pages = stx.txn.extra_program_pages;
                        self.overlay
                            .mutate_resource_deltas_tracked(sender, &mut checkpoint, |d| {
                                d.delta_total_created_apps += 1;
                                d.delta_total_extra_app_pages += extra_pages as i64;
                                d.delta_schema_num_uint += global_schema.num_uint as i64;
                                d.delta_schema_num_byte_slice +=
                                    global_schema.num_byte_slice as i64;
                            });
                    } else {
                        match stx.txn.on_completion {
                            1 => {
                                // OptIn: sender gets +1 total_apps_opted_in
                                // plus local schema added to total_app_schema.
                                // Mirrors Go's application.go:301-306.
                                //
                                // NOTE: We don't have access to the app's
                                // local schema from the txn fields alone
                                // (it's stored in app params). For now we
                                // track the opt-in count; the local schema
                                // contribution would require looking up the
                                // app params which the block evaluator doesn't
                                // currently do.
                                self.overlay.mutate_resource_deltas_tracked(
                                    sender,
                                    &mut checkpoint,
                                    |d| {
                                        d.delta_total_apps_opted_in += 1;
                                    },
                                );
                            }
                            2 | 3 => {
                                // CloseOut (2) or ClearState (3): sender gets
                                // -1 total_apps_opted_in.
                                // Mirrors Go's application.go:354.
                                self.overlay.mutate_resource_deltas_tracked(
                                    sender,
                                    &mut checkpoint,
                                    |d| {
                                        d.delta_total_apps_opted_in -= 1;
                                    },
                                );
                            }
                            5 => {
                                // DeleteApplication: creator gets -1
                                // total_created_apps.
                                // Mirrors Go's application.go:150.
                                //
                                // NOTE: The schema and extra pages removal
                                // would require looking up the app params.
                                // For now we track the app count.
                                self.overlay.mutate_resource_deltas_tracked(
                                    sender,
                                    &mut checkpoint,
                                    |d| {
                                        d.delta_total_created_apps -= 1;
                                    },
                                );
                            }
                            _ => {
                                // NoOp (0), UpdateApplication (4): no
                                // resource count changes.
                            }
                        }
                    }
                }
                _ => {
                    // Pay, KeyReg, AssetFreeze, StateProof, Heartbeat:
                    // no resource count changes.
                }
            }
        }

        // ── Min-balance check after apply ────────────────────────────
        // After tentatively applying all balance mutations for this
        // group, verify that no affected account has dropped below the
        // effective minimum balance. Mirrors Go's `checkMinBalance(cow)`
        // which calls `dataNew.MinBalance(&eval.proto)` accounting for
        // assets, apps, schema, boxes, and extra app pages.
        //
        // Accounts at exactly zero are allowed — this represents a
        // closed/deleted account, matching Go's `data.IsZero()` check.

        // Collect addresses modified in this group for the check.
        let mut modified_addrs: HashSet<Address> = HashSet::new();
        for stx in txgroup {
            modified_addrs.insert(stx.txn.sender);
            // Only payment transactions modify receiver/close-to balances.
            if stx.txn.txn_type == TxnType::Pay {
                if !stx.txn.receiver.is_zero() {
                    modified_addrs.insert(stx.txn.receiver);
                }
                if !stx.txn.close_remainder_to.is_zero() {
                    modified_addrs.insert(stx.txn.close_remainder_to);
                }
            }
        }

        for addr in &modified_addrs {
            // Skip FeeSink, RewardsPool, and StateProofSender from
            // min-balance checks, matching Go's checkMinBalance
            // (eval.go:1113-1119).
            if *addr == self.hdr.fee_sink
                || *addr == self.hdr.rewards_pool
                || *addr == Address::STATE_PROOF_SENDER
            {
                continue;
            }

            let balance = self.effective_balance(addr);
            // A zero balance is valid (account closed/deleted), matching
            // Go's `if data.IsZero() { continue }` in checkMinBalance.
            if balance == 0 {
                continue;
            }
            // Compute the effective min balance from the account's
            // resource counts (assets, apps, schema, boxes).
            let acct_data = self.get_account_data(addr);
            let min_bal = match &acct_data {
                Some(acct) => effective_min_balance(acct, &self.consensus_params),
                // Unknown account with non-zero balance: use base min.
                None => self.consensus_params.min_balance,
            };
            if balance < min_bal {
                // Min-balance violation — rollback overlay and fees.
                self.overlay.restore(checkpoint);
                self.fees_collected = fees_collected_checkpoint;
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "account {} balance {} below minimum {} after transaction group",
                        addr, balance, min_bal,
                    ),
                });
            }
            // Check MaximumMinimumBalance: if the effective min exceeds
            // this threshold, the transaction is rejected. Mirrors Go's
            // checkMinBalance (eval.go:1146-1149). The field is 0 (no
            // limit) from v32+, but earlier versions enforce it.
            let max_min = self.consensus_params.maximum_minimum_balance;
            if max_min > 0 && min_bal > max_min {
                self.overlay.restore(checkpoint);
                self.fees_collected = fees_collected_checkpoint;
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "account {} would use too much space after this transaction. \
                         Minimum balance requirements would be {} (greater than max {})",
                        addr, min_bal, max_min,
                    ),
                });
            }
        }

        // All checks passed — commit the STIB data and byte counts.
        self.txn_bytes += exact_bytes;
        self.included_txns.extend(stibs);

        Ok(())
    }

    fn generate_block(
        &mut self,
        _voting_accounts: &[algo_types::Address],
    ) -> Result<algo_types::Block, algo_error::AlgoError> {
        let txn_count = self.included_txns.len() as u64;

        // Take ownership of included transactions for payset assembly.
        let payset = std::mem::take(&mut self.included_txns);

        // Build the block by propagating ALL header fields from self.hdr,
        // then overriding the computed fields (txn_counter, commitments,
        // payset). This ensures fee_sink, rewards_pool, rewards_level,
        // rewards_rate, rewards_residue, rewards_recalculation_round,
        // proposer, and all other header fields are preserved.
        let hdr = &self.hdr;
        let mut block = algo_types::Block {
            round: hdr.round,
            branch: hdr.branch,
            seed: hdr.seed,
            timestamp: hdr.timestamp,
            genesis_id: hdr.genesis_id.clone(),
            genesis_hash: hdr.genesis_hash,
            proposer: hdr.proposer,
            fee_sink: hdr.fee_sink,
            rewards_pool: hdr.rewards_pool,
            rewards_level: hdr.rewards_level,
            rewards_rate: hdr.rewards_rate,
            rewards_residue: hdr.rewards_residue,
            rewards_recalculation_round: hdr.rewards_recalculation_round,
            current_protocol: hdr.current_protocol.clone(),
            next_protocol: hdr.next_protocol.clone(),
            next_protocol_approvals: hdr.next_protocol_approvals,
            next_protocol_switch_on: hdr.next_protocol_switch_on,
            next_protocol_vote_before: hdr.next_protocol_vote_before,
            txn_counter: hdr.txn_counter.saturating_add(txn_count),
            fees_collected: self.fees_collected,
            bonus: hdr.bonus,
            proposer_payout: hdr.proposer_payout,
            prev512: hdr.prev512,
            state_proof_tracking: hdr.state_proof_tracking.clone(),
            upgrade_propose: hdr.upgrade_propose.clone(),
            upgrade_delay: hdr.upgrade_delay,
            upgrade_approve: hdr.upgrade_approve,
            expired_participation_accounts: hdr.expired_participation_accounts.clone(),
            absent_participation_accounts: hdr.absent_participation_accounts.clone(),
            payset,
            // Commitment fields are computed below.
            txn_commitment: [0u8; 32],
            txn256: [0u8; 32],
            txn512: [0u8; 64],
        };

        // Compute the SHA-512/256 Merkle root (the primary `txn` commitment).
        // This matches go-algorand's PaysetCommit() → paysetCommit(PaysetCommitMerkle).
        block.txn_commitment = compute_payset_merkle_root(&block);

        // Protocol-gated vector commitments.
        let proto = &self.hdr.current_protocol;

        // SHA-256 vector commitment (txn256 field, v34+).
        if has_txn256(proto) {
            let vc256 = compute_vector_commitment(&block, HashAlgo::Sha256);
            block.txn256.copy_from_slice(&vc256);
        }

        // SHA-512 vector commitment (txn512 field, v41+).
        if has_txn512(proto) {
            let vc512 = compute_vector_commitment(&block, HashAlgo::Sha512);
            block.txn512.copy_from_slice(&vc512);
        }

        Ok(block)
    }

    fn reset_txn_bytes(&mut self) {
        self.txn_bytes = 0;
    }
}

/// A minimal `PoolLedger` that wraps `SqliteLedger` behind a `Mutex`.
///
/// The `TransactionPool` requires an `Arc<dyn PoolLedger>`, so we provide
/// this thin adapter that delegates to the same SQLite ledger used by the
/// agreement bridges.
struct PoolLedgerAdapter {
    ledger: Arc<Mutex<SqliteLedger>>,
}

impl algo_pool::traits::PoolLedger for PoolLedgerAdapter {
    fn latest(&self) -> Round {
        self.ledger
            .lock()
            .map(|l| l.current_round())
            .unwrap_or(Round(0))
    }

    fn block_hdr(&self, round: Round) -> Result<algo_types::BlockHeader, algo_error::AlgoError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|e| algo_error::AlgoError::Ledger {
                message: format!("ledger lock poisoned: {e}"),
            })?;
        let hdr_data = ledger
            .get_block_header_data(round.0)
            .map_err(|e| algo_error::AlgoError::Ledger {
                message: format!("block_hdr({}) read error: {e}", round.0),
            })?
            .ok_or_else(|| algo_error::AlgoError::Ledger {
                message: format!("no block header data for round {}", round.0),
            })?;
        BlockHeader::decode_from_bytes(&hdr_data).map_err(|e| algo_error::AlgoError::Ledger {
            message: format!("block_hdr({}) decode error: {e}", round.0),
        })
    }

    fn consensus_params(
        &self,
        round: Round,
    ) -> Result<algo_types::ConsensusParams, algo_error::AlgoError> {
        let hdr = self.block_hdr(round)?;
        algo_types::consensus::consensus_params_for_version(&hdr.current_protocol).ok_or_else(
            || algo_error::AlgoError::Ledger {
                message: format!(
                    "unknown protocol version '{}' in block header for round {}",
                    hdr.current_protocol, round.0
                ),
            },
        )
    }

    fn start_evaluator(
        &self,
        hdr: algo_types::BlockHeader,
        _payset_hint: usize,
        max_txn_bytes_per_block: usize,
    ) -> Result<Box<dyn algo_pool::traits::BlockEvaluator>, algo_error::AlgoError> {
        let consensus_params = algo_types::consensus::consensus_params_for_version(
            &hdr.current_protocol,
        )
        .ok_or_else(|| {
            // Go returns protocol.Error(hdr.CurrentProtocol) for unknown
            // versions — do the same instead of silently falling back.
            algo_error::AlgoError::Ledger {
                message: format!(
                    "unknown protocol version '{}' in block header",
                    hdr.current_protocol
                ),
            }
        })?;

        // Snapshot the ledger state at evaluator creation time.
        // This briefly acquires the mutex, captures lease state, then releases.
        let snapshot = LedgerSnapshot::from_ledger(&self.ledger, hdr.round.0);

        // Use the caller-provided byte limit, or the consensus protocol
        // default if the caller passed 0. Take the minimum of the two when
        // both are non-zero, matching Go's behavior.
        let consensus_max = consensus_params.max_txn_bytes_per_block as usize;
        let max_txn_bytes = if max_txn_bytes_per_block == 0 {
            consensus_max
        } else {
            max_txn_bytes_per_block.min(consensus_max)
        };

        Ok(Box::new(SimpleBlockEvaluator {
            hdr,
            consensus_params,
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes,
            ledger: self.ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        }))
    }
}

/// Parse a hex-encoded genesis hash into a 32-byte array.
fn parse_genesis_hash(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let hex_str = hex_str.trim();
    if hex_str.len() != 64 {
        anyhow::bail!(
            "genesis hash must be 64 hex characters (32 bytes), got {} chars",
            hex_str.len()
        );
    }
    let mut arr = [0u8; 32];
    for i in 0..32 {
        arr[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow::anyhow!("invalid hex in genesis hash at byte {}: {}", i, e))?;
    }
    Ok(arr)
}

/// Load the VRF + one-time-signature signing secrets for the participation
/// key(s) the pseudonode will vote with at `round`, keyed by account address,
/// for the agreement `Parameters.signing_keys` map.
///
/// Without these secrets the `AsyncPseudonode` emits placeholder (zero-filled)
/// VRF proofs and OTS signatures, which the crypto verifier rejects — so the
/// node can never produce a valid proposal or vote and rounds never advance.
/// This is the node-side analogue of Go's wiring, where `account.Participation`
/// carries the `*crypto.VRFSecrets` + `*crypto.OneTimeSignatureSecrets` into the
/// agreement service. Here the secrets live in the [`ParticipationStore`]; we
/// reconstruct them per key via `get_for_round` (VRF from its 32-byte seed, OTS
/// from its msgpack blob).
///
/// Key selection mirrors the public-record key manager exactly: we enumerate
/// the keys via `get_for_voting_round` (which applies the
/// `effectiveFirst/effectiveLast` window in addition to raw validity), then load
/// each one's secrets by its participation ID. This is critical for
/// consistency — `get_for_round` alone filters only on raw `firstValid/lastValid`,
/// so for an account holding a not-yet-effective or deactivated key alongside
/// the active one it could load the wrong secret and overwrite the active entry,
/// leaving the pseudonode signing the active public record with a mismatched
/// secret (invalid proposals/votes). Driving off the effective records means the
/// secret loaded for an account always matches the record the agreement uses.
///
/// Keys with no loadable secret valid at `round` (a legacy record with no voting
/// blob) are skipped; a load error for one key is logged and skipped rather than
/// failing the whole node.
///
/// This is a **startup snapshot** for the imminent round, handed to the agreement
/// service once; it does not refresh as rounds advance, so it does not survive
/// participation-key validity-window boundaries (a key that becomes effective
/// only later, or a mid-run rotation). Per-round secret refresh in the pseudonode
/// is tracked in TASK-272.
fn load_signing_keys_for_round(
    part_store: &ParticipationStore,
    round: Round,
) -> HashMap<Address, AccountSigningKeys> {
    let mut signing_keys = HashMap::new();
    // Select keys with the same effective-window semantics the pseudonode's
    // key manager uses (`AgreementKeyManagerBridge::voting_keys` →
    // `get_for_voting_round`), so the secret we load for an account matches the
    // public participation record the agreement will sign under. `keys_round`
    // is the same round for this startup snapshot.
    let records = match part_store.get_for_voting_round(round, round) {
        Ok(records) => records,
        Err(e) => {
            warn!(error = %e, "failed to enumerate participation keys; node will not sign consensus messages");
            return signing_keys;
        }
    };
    for record in &records {
        match part_store.get_for_round(&record.participation_id, round) {
            Ok(Some(part)) => {
                // `part.parent` is the root account the key votes for; the
                // pseudonode looks up signing keys by that address. The map
                // holds one secret per address, so if an account has more than
                // one simultaneously-effective key (e.g. multiple unregistered
                // keys with NULL/0 effective rounds), only one secret can be
                // represented. Keep the first deterministically and warn rather
                // than silently overwriting — disambiguating per public record
                // needs per-record signing in the pseudonode (TASK-272).
                match signing_keys.entry(part.parent) {
                    std::collections::hash_map::Entry::Occupied(_) => {
                        warn!(
                            account = %record.account,
                            participation_id = %record.participation_id,
                            "multiple effective participation keys for this account; keeping the first loaded secret and ignoring this one (TASK-272)",
                        );
                    }
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(AccountSigningKeys {
                            vrf: part.vrf,
                            ots: part.voting,
                        });
                    }
                }
            }
            Ok(None) => {
                // Effective record with no loadable voting secret (legacy
                // record / empty blob) — it simply won't contribute signatures.
            }
            Err(e) => {
                warn!(
                    account = %record.account,
                    participation_id = %record.participation_id,
                    error = %e,
                    "failed to load participation secrets; this key will not sign",
                );
            }
        }
    }
    signing_keys
}

/// Open (or create) the agreement crash recovery database.
///
/// Mirrors go-algorand v4.5.1-stable `node/node.go:305-323`, which opens
/// `crash.sqlite` (`config.CrashFilename`) inside the genesis directory next
/// to the ledger and threads the resulting accessor into `agreement.Parameters`.
///
/// Without this connection, `Parameters.crash_db` is `None`, the agreement
/// service skips persistence entirely, and a node crash mid-round can lead to
/// equivocation (double-vote) on restart. See [[DOC-21]] §3.7.
fn open_crash_db(ledger_path: &Path) -> anyhow::Result<rusqlite::Connection> {
    let crash_db_path = ledger_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("crash.sqlite");
    let conn = rusqlite::Connection::open(&crash_db_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to open agreement crash db at {}: {}",
            crash_db_path.display(),
            e
        )
    })?;
    info!(
        path = %crash_db_path.display(),
        "opened agreement crash recovery database"
    );
    Ok(conn)
}

/// CLI + TOML inputs for the REST API server. CLI fields already
/// shadow the TOML fields at parse time; this struct keeps them
/// together so the resolver sees a single consistent bundle.
#[derive(Debug, Default, Clone)]
pub struct RestOptions {
    /// `--rest-listen` flag value. When `None`, the `[rest].listen`
    /// field from the loaded config file is consulted.
    pub listen: Option<String>,
    /// `--data-dir` flag value. Applied as the API server's data
    /// directory (where `algod.token`, `algod.admin.token`, and
    /// `algod.net` are read/written). Defaults to the `[rest].data_dir`
    /// field when unset.
    pub data_dir: Option<PathBuf>,
    /// `--genesis-path` flag value. Used to read `genesis.json`
    /// verbatim for the REST API's `/genesis` endpoint. Defaults to
    /// `[rest].genesis_path`, then `<data_dir>/genesis.json`.
    pub genesis_path: Option<PathBuf>,
    /// The parsed `[rest]` table, if any. Provides defaults for every
    /// CLI flag above; CLI flags always win when both are set.
    pub file_rest: Option<RestConfig>,
}

/// Fully-resolved REST configuration, ready to hand to [`ApiServer`].
#[derive(Debug, Clone)]
struct ResolvedRest {
    listen: SocketAddr,
    data_dir: Option<PathBuf>,
    api_token: Option<String>,
    admin_token: Option<String>,
    genesis_path: Option<PathBuf>,
    async_backlog_size: Option<usize>,
}

impl RestOptions {
    /// Merge CLI flags, `[rest]` TOML fields, and a sensible
    /// `data_dir` default so the caller gets a concrete socket
    /// address + auxiliary paths. Returns `Ok(None)` when REST is
    /// disabled (no `--rest-listen`, no `[rest].listen`).
    fn resolve(&self, default_data_dir: Option<&Path>) -> anyhow::Result<Option<ResolvedRest>> {
        let listen_str = self
            .listen
            .clone()
            .or_else(|| self.file_rest.as_ref().and_then(|r| r.listen.clone()));
        let Some(listen_str) = listen_str else {
            return Ok(None);
        };
        let listen: SocketAddr = listen_str
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --rest-listen address {:?}: {e}", listen_str))?;

        let data_dir = self
            .data_dir
            .clone()
            .or_else(|| self.file_rest.as_ref().and_then(|r| r.data_dir.clone()))
            .or_else(|| default_data_dir.map(Path::to_path_buf));

        // Token overrides come only from the config file — we avoid a
        // CLI flag so operators aren't tempted to paste secrets on the
        // command line (process-listing leak). The API server defaults
        // to reading `algod.token` / `algod.admin.token` from
        // `data_dir`, so CLI-only setups work without any overrides.
        let (api_token, admin_token) = match self.file_rest.as_ref() {
            Some(rest) => (rest.api_token.clone(), rest.admin_token.clone()),
            None => (None, None),
        };

        let genesis_path = self
            .genesis_path
            .clone()
            .or_else(|| self.file_rest.as_ref().and_then(|r| r.genesis_path.clone()));

        let async_backlog_size = self.file_rest.as_ref().and_then(|r| r.async_backlog_size);

        Ok(Some(ResolvedRest {
            listen,
            data_dir,
            api_token,
            admin_token,
            genesis_path,
            async_backlog_size,
        }))
    }
}

/// Best-effort load of `genesis.json`. Tries the explicit
/// `genesis_path` first and, on `NotFound`, falls back to
/// `<data_dir>/genesis.json`. Returns `Ok(None)` only when *both*
/// candidates are absent (or neither candidate was provided); returns
/// `Err` on real I/O errors (permission denied, partial read, etc.)
/// so a missing file never blocks startup while a misconfigured one
/// does.
///
/// The fallback chain matters when an operator passes
/// `--genesis-path` pointing at a stale location: the documented
/// behaviour is "use the explicit path if present, otherwise try the
/// data-dir default". The prior short-circuit on explicit-NotFound
/// silently synthesized a stub, which could make `/genesis` serve
/// incorrect bytes when a real file was available under `data_dir`.
fn load_genesis_json(
    explicit: Option<&Path>,
    data_dir: Option<&Path>,
) -> anyhow::Result<Option<String>> {
    // Walk the candidate list in priority order. Each entry is
    // (path, origin-label); the label appears in log lines so
    // operators can see which candidate served the response.
    let mut candidates: Vec<(std::path::PathBuf, &'static str)> = Vec::new();
    if let Some(p) = explicit {
        candidates.push((p.to_path_buf(), "--genesis-path"));
    }
    if let Some(dir) = data_dir {
        let derived = dir.join("genesis.json");
        // Deduplicate — if `--genesis-path` already pointed at the
        // same file, we don't want a noisy second read attempt.
        if !candidates.iter().any(|(p, _)| p == &derived) {
            candidates.push((derived, "<data_dir>/genesis.json"));
        }
    }

    for (path, origin) in &candidates {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                info!(
                    path = %path.display(),
                    origin = origin,
                    bytes = contents.len(),
                    "loaded genesis.json"
                );
                return Ok(Some(contents));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Try the next candidate. Missing files are soft
                // failures so the synthesized stub remains available
                // as a last resort.
                continue;
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to read genesis.json at {} ({}): {e}",
                    path.display(),
                    origin
                ));
            }
        }
    }
    Ok(None)
}

/// Build a stub genesis.json body for the REST `/genesis` endpoint
/// when no real file is available. Matches go-algorand's minimal
/// `bookkeeping.Genesis` JSON shape (network + id + proto + empty
/// alloc) so downstream clients that only read `network` / `id` work.
fn synthesize_genesis_json(genesis_id: &str, network: &str, proto: &str) -> String {
    // Strip the `network-` prefix from genesis_id to get the suffix
    // go-algorand stores in `id` (e.g. "mainnet-v1.0" → "v1.0").
    let id_suffix = genesis_id
        .strip_prefix(&format!("{network}-"))
        .unwrap_or(genesis_id);
    let value = serde_json::json!({
        "network": network,
        "id": id_suffix,
        "proto": proto,
        "alloc": [],
        "fees": "",
        "rwd": "",
    });
    serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string())
}

/// Run the participate command: start the agreement protocol and participate
/// in consensus using the provided participation keys.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    ledger_path: &Path,
    genesis_id: Option<&str>,
    network: &str,
    peers: &[String],
    partkey_path: &Path,
    listen_address: Option<&str>,
    relay_messages: bool,
    genesis_hash_hex: Option<&str>,
    rest_opts: RestOptions,
) -> anyhow::Result<()> {
    // Resolve genesis ID: use the provided value, or look it up by network name.
    let resolved_genesis_id = match genesis_id {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => genesis_id_for(network)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown network '{}': use --genesis-id to specify the genesis ID",
                    network
                )
            })?
            .to_string(),
    };

    // Parse genesis hash (default to zeros if not provided).
    let genesis_hash = match genesis_hash_hex {
        Some(hex_str) => parse_genesis_hash(hex_str)?,
        None => [0u8; 32],
    };

    info!(
        ledger = %ledger_path.display(),
        genesis_id = %resolved_genesis_id,
        network = network,
        peers = peers.len(),
        partkey = %partkey_path.display(),
        listen = listen_address.unwrap_or("none"),
        "starting consensus participation"
    );

    // -----------------------------------------------------------------------
    // 1. Open the SQLite ledger (shared between agreement and pool bridges).
    // -----------------------------------------------------------------------
    let sqlite_ledger = SqliteLedger::open(ledger_path).map_err(|e| {
        anyhow::anyhow!("failed to open ledger at {}: {}", ledger_path.display(), e)
    })?;

    // Reject anything but a fully populated block archive before
    // booting agreement. Participating with a missing tail block — or
    // with the catchpoint-only "blockdb empty" shape — would risk
    // producing votes against state that the block archive can't
    // reproduce on the next restart.
    match sqlite_ledger.reconcile_cross_file().map_err(|e| {
        anyhow::anyhow!("reconcile cross-file consistency for participate ledger: {e}")
    })? {
        algo_ledger::CrossFileState::Empty | algo_ledger::CrossFileState::Consistent { .. } => {}
        algo_ledger::CrossFileState::CatchpointOnly { tracker_round } => {
            anyhow::bail!(
                "participate requires blocks on disk; the ledger is catchpoint-only at round \
                 {tracker_round}. Run `algod-rust sync` first to populate the block archive."
            );
        }
        algo_ledger::CrossFileState::BlockBehind {
            tracker_round,
            block_max_round,
        } => {
            anyhow::bail!(
                "ledger inconsistency: tracker at round {tracker_round} but blockdb.blocks max \
                 is {block_max_round}. Recover from a catchpoint or delete the DB."
            );
        }
    }

    let latest = sqlite_ledger.current_round().0;
    info!(path = %ledger_path.display(), latest_round = latest, "opened ledger database");

    let ledger = Arc::new(Mutex::new(sqlite_ledger));

    // Open the agreement crash recovery database alongside the ledger.
    // Without this, agreement state is never persisted before votes are
    // broadcast, so a crash-restart could cause equivocation. Mirrors Go's
    // `node/node.go:305-323`. See [[DOC-21]] §3.7.
    let crash_db = open_crash_db(ledger_path)?;

    // -----------------------------------------------------------------------
    // 2. Open the participation key store.
    // -----------------------------------------------------------------------
    let part_store = ParticipationStore::open(partkey_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to open participation key store at {}: {}",
            partkey_path.display(),
            e
        )
    })?;
    let key_count = part_store.get_all().map(|v| v.len()).unwrap_or(0);
    info!(
        path = %partkey_path.display(),
        keys = key_count,
        "opened participation key store"
    );

    if key_count == 0 {
        warn!("No participation keys found — node will not produce valid proposals or votes");
    } else {
        // Check whether loaded keys have the required VRF/vote secrets.
        // Records missing vote_id or vrf_public_key will be filtered out by
        // the key manager and won't contribute to consensus.
        if let Ok(records) = part_store.get_all() {
            let missing: Vec<_> = records
                .iter()
                .filter(|r| r.vote_id.is_none() || r.vrf_public_key.is_none())
                .collect();
            for rec in &missing {
                warn!(
                    account = %rec.account,
                    participation_id = %rec.participation_id,
                    vote_id_present = rec.vote_id.is_some(),
                    vrf_key_present = rec.vrf_public_key.is_some(),
                    "participation key is missing vote_id or VRF key — it will not produce valid consensus messages"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // 3. Build the gossip network node.
    // -----------------------------------------------------------------------
    let phonebook = Arc::new(Phonebook::new(60, Duration::from_secs(60)));
    if !peers.is_empty() {
        phonebook.replace_peer_list(peers, "cli", RELAY_ROLE);
        info!(count = peers.len(), "added initial peer addresses");
    }

    let net_config = WebsocketNetworkConfig {
        genesis_id: resolved_genesis_id.clone(),
        network_id: network.to_string(),
        net_address: listen_address.map(|s| s.to_string()),
        // Default participation nodes to "peer" (non-relay) mode;
        // `--relay-messages` lets callers opt this node into a relay
        // role when another peer needs to dial it for gossip (e.g.
        // the two-binary tx-propagation E2E in PLAN-74 / TASK-80).
        // `WebsocketNetwork` gates the inbound listener on both
        // `net_address.is_some()` and `relay_messages`, so setting
        // this flag without `--listen-address` only enables outbound
        // broadcast forwarding — typically useful only when both are
        // set together.
        relay_messages,
        gossip_fanout: peers.len().max(algo_network::DEFAULT_GOSSIP_FANOUT),
        ..Default::default()
    };

    let gossip_node = Arc::new(WebsocketNetwork::new(net_config, phonebook));

    // -------------------------------------------------------------------
    // Construct the transaction pool early and register the inbound TX
    // handler on the multiplexer **before** starting the listener. If
    // we start the gossip node first and register after, inbound TX
    // frames that arrive during the startup window fall through to
    // `Multiplexer::handle`'s Ignore fallback and are silently dropped
    // (PLAN-33 / TASK-69, gap G1 in DOC-23).
    //
    // The `SeenTxCache` is created here so it can be shared with the
    // TxSyncer when TASK-70 lands.
    // -------------------------------------------------------------------
    let pool_ledger_adapter = Arc::new(PoolLedgerAdapter {
        ledger: ledger.clone(),
    });
    let pool = Arc::new(TransactionPool::new(
        PoolConfig::default(),
        pool_ledger_adapter as Arc<dyn algo_pool::traits::PoolLedger>,
    ));
    let tx_seen_cache = Arc::new(algo_network::SeenTxCache::new(
        algo_network::TxSyncerConfig::default().seen_cache_size,
    ));
    gossip_node.multiplexer().register_handlers(vec![
        algo_network::handler::TaggedMessageHandler {
            tag: algo_network::Tag::Transaction,
            handler: Arc::new(algo_network::TxTagHandler::new(
                pool.clone(),
                tx_seen_cache.clone(),
            )),
        },
    ]);

    // -------------------------------------------------------------------
    // Bootstrap the pool's block evaluator from the current ledger tip
    // BEFORE starting the gossip network.
    //
    // Without this, submissions routed through `LocalTxBroadcaster`
    // (either in-process or via the REST `POST /v2/transactions` path)
    // fail with `PoolError::NoPendingBlockEvaluator` until agreement
    // commits its first block. The pool's `recompute_block_evaluator`
    // reads `ledger.latest()` + `block_hdr(latest)` to build the
    // evaluator, so the `Block` passed here is purely a trigger — its
    // fields are ignored. Mirrors go-algorand's `node.go:startNode`,
    // which calls `pool.OnNewBlock` during node initialization to
    // prime the pool.
    //
    // Bootstrapping before `start_arc()` closes the second startup
    // race noted in PLAN-33 / TASK-69 (gap G1 in DOC-23): inbound TX
    // frames that arrive immediately after the listener binds would
    // otherwise call `pool.remember()` on a pool with no evaluator
    // and surface as `NoPendingBlockEvaluator` errors.
    //
    // On a freshly-initialized ledger that lacks a tip block,
    // `recompute_block_evaluator` returns early and leaves the pool
    // without an evaluator, which is the pre-bootstrap behavior —
    // this call is strictly additive.
    // -------------------------------------------------------------------
    pool.on_new_block(&algo_types::Block::default(), &HashSet::new());

    // Start the network (listener + mesh). TX-tag handler is already
    // wired AND the pool has its evaluator, so inbound transactions
    // cannot slip past during the startup window.
    gossip_node
        .start_arc()
        .await
        .map_err(|e| anyhow::anyhow!("failed to start gossip network: {}", e))?;

    let (addr, listening) = gossip_node.address();
    if listening {
        info!(address = %addr, "gossip network listening");
    } else {
        info!("gossip network started (no listener)");
    }

    // -----------------------------------------------------------------------
    // 3b. Construct the local tx broadcaster.
    //
    // Shares `tx_seen_cache` with the inbound TX handler so peer echoes
    // of our local submissions are deduplicated before reaching the
    // pool. Needed by the `AlgodNodeInterface::broadcast_signed_tx_group`
    // path (PLAN-74 TASK-77) — cheap to construct even when the REST
    // server is disabled so the adapter's shape stays stable.
    // -----------------------------------------------------------------------
    let broadcaster = Arc::new(LocalTxBroadcaster::new(
        Arc::new(PoolIngestAdapter::new(pool.clone())),
        gossip_node.clone() as Arc<dyn GossipNode>,
        tx_seen_cache.clone(),
    ));

    // -----------------------------------------------------------------------
    // 3c. Optional: start the REST API server.
    //
    // When the operator passes `--rest-listen` (or sets `[rest].listen`
    // in `algod-rust.toml`), we build an `AlgodNodeInterface` adapter
    // around the ledger + pool + broadcaster and hand it to
    // `ApiServer::serve`. Shutdown is coordinated through a shared
    // `CancellationToken` that the Ctrl-C handler cancels (see step 7
    // below).
    // -----------------------------------------------------------------------
    let shutdown_token = CancellationToken::new();
    let default_data_dir = ledger_path.parent().map(Path::to_path_buf);
    let rest_cfg = rest_opts.resolve(default_data_dir.as_deref())?;
    let rest_server_handle = if let Some(cfg) = rest_cfg {
        let genesis_json = load_genesis_json(cfg.genesis_path.as_deref(), cfg.data_dir.as_deref())?
            .unwrap_or_else(|| {
                warn!(
                    "no genesis.json found; synthesizing a minimal stub for the /genesis endpoint"
                );
                synthesize_genesis_json(&resolved_genesis_id, network, CONSENSUS_V41)
            });

        let node_config = NodeInterfaceConfig {
            genesis_id: resolved_genesis_id.clone(),
            genesis_hash: Digest(genesis_hash),
            genesis_json,
            build_version: BuildVersion::from_build_env(),
            default_protocol: CONSENSUS_V41.into(),
        };

        let mut adapter = AlgodNodeInterface::new(ledger.clone(), node_config)
            .with_pool(pool.clone())
            .with_broadcaster(broadcaster.clone())
            .with_shutdown_token(shutdown_token.clone());
        if let Some(capacity) = cfg.async_backlog_size {
            adapter = adapter.with_async_backlog_capacity(capacity);
        }
        let node = Arc::new(adapter);

        let api_config = ApiServerConfig {
            listen_addr: cfg.listen,
            data_dir: cfg.data_dir.clone(),
            api_token: cfg.api_token.clone(),
            admin_token: cfg.admin_token.clone(),
        };

        info!(
            listen = %cfg.listen,
            data_dir = ?cfg.data_dir,
            "starting REST API server"
        );

        let shutdown_future = {
            let token = shutdown_token.clone();
            async move { token.cancelled().await }
        };
        let api_server = ApiServer::new(api_config);
        let (bound_addr, join_handle) = api_server
            .serve(node, shutdown_future)
            .await
            .map_err(|e| anyhow::anyhow!("failed to bind REST API listener: {e}"))?;
        info!(address = %bound_addr, "REST API server bound");
        Some(join_handle)
    } else {
        None
    };

    // -----------------------------------------------------------------------
    // 4. Build agreement bridges.
    // -----------------------------------------------------------------------

    // Network bridge: wraps GossipNode for agreement message passing.
    let rt_handle = tokio::runtime::Handle::current();
    let agreement_network = AgreementNetworkBridge::with_defaults(
        gossip_node.clone() as Arc<dyn GossipNode>,
        rt_handle.clone(),
    );

    // Network advancer: wraps the gossip node so the ledger bridge can
    // signal network progress when certificates arrive.
    let network_advancer: Arc<dyn NetworkAdvancer> = Arc::new(GossipNetworkAdvancer {
        node: gossip_node.clone() as Arc<dyn GossipNode>,
    });

    // Ledger bridge: wraps SqliteLedger for agreement read/write access.
    // Uses `new_with_catchup` to enable the certificate-driven catchup path.
    // The returned `cert_rx` is consumed by the CatchupService below.
    let (agreement_ledger, cert_rx) =
        AgreementLedgerBridge::new_with_catchup(ledger.clone(), network_advancer.clone());

    // Load the actual signing secrets (VRF + OTS) before the store is moved
    // into the key-manager bridge. The bridge only exposes public voting
    // records; the pseudonode needs the secrets to sign proposals/votes. Load
    // for the next round to produce (latest + 1), which selects the keyset
    // valid for the rounds this node will participate in.
    let signing_keys = load_signing_keys_for_round(&part_store, Round(latest + 1));
    if signing_keys.is_empty() {
        warn!(
            round = latest + 1,
            "no participation signing secrets loaded — node will not produce valid proposals or votes"
        );
    } else {
        info!(
            accounts = signing_keys.len(),
            round = latest + 1,
            "loaded participation signing secrets for consensus"
        );
    }

    // Key manager bridge: wraps ParticipationStore for voting key lookups.
    let key_manager = AgreementKeyManagerBridge::new(part_store);

    // Block factory bridge: wraps TransactionPool for block assembly.
    let block_factory = BlockFactoryBridge::new(pool.clone());

    // Block validator bridge: wraps algo-validate for incoming block checks.
    // Extract the timestamp from the latest committed block header so the
    // validator can enforce the MaxTimestampIncrement constraint.
    let prev_timestamp: Option<i64> = {
        let l = ledger.lock().expect("ledger lock");
        let current = l.current_round().0;
        if current > 0 {
            match l.get_block_header_data(current) {
                Ok(Some(hdr_bytes)) => match BlockHeader::decode_from_bytes(&hdr_bytes) {
                    Ok(hdr) => {
                        info!(
                            round = current,
                            timestamp = hdr.timestamp,
                            "extracted previous block timestamp"
                        );
                        Some(hdr.timestamp)
                    }
                    Err(e) => {
                        warn!(round = current, error = %e, "failed to decode block header for timestamp; skipping timestamp validation");
                        None
                    }
                },
                Ok(None) => {
                    warn!(
                        round = current,
                        "no block header data found; skipping timestamp validation"
                    );
                    None
                }
                Err(e) => {
                    warn!(round = current, error = %e, "failed to read block header data; skipping timestamp validation");
                    None
                }
            }
        } else {
            // Round 0 (genesis) — no previous timestamp needed.
            None
        }
    };
    // A single shared BlockValidatorBridge is used by both the Parameters
    // (demux loop / ensure action) and the AsyncCryptoVerifier (proposal
    // verification). This mirrors Go where the same BlockValidator is passed
    // to both. Sharing ensures that `set_prev_timestamp` updates made in
    // `do_ensure_action` are visible to the crypto verifier's proposal
    // validation, keeping timestamp validation accurate.
    let block_validator: Arc<BlockValidatorBridge> = Arc::new(BlockValidatorBridge::new(
        resolved_genesis_id.clone(),
        genesis_hash,
        prev_timestamp,
    ));

    // Real random source backed by the OS CSPRNG; no-op monitor.
    let random_source = RealRandomSource;
    let monitor = NoOpMonitor;

    // Real crypto verifier backed by the agreement ledger bridge.
    // This verifies VRF credentials and OTS signatures on incoming votes
    // and bundles, rather than blindly accepting them.
    //
    // The block validator is also threaded into the crypto verifier so that
    // proposal verification validates the block eagerly and caches the
    // `ValidatedBlock` — mirroring Go's `makeCryptoVerifier(l, v, ...)`.
    let crypto_ledger = Arc::new(AgreementLedgerBridge::new(ledger.clone()));
    let crypto =
        AsyncCryptoVerifier::new_with_validator(crypto_ledger, Arc::clone(&block_validator));

    // -----------------------------------------------------------------------
    // 5. Build and start the catchup service.
    // -----------------------------------------------------------------------
    // The catchup service runs a background thread that receives certificates
    // from the agreement service (via `cert_rx`) and fetches the corresponding
    // blocks from peers when the ledger doesn't have them yet.
    //
    // The catchup bridge is a separate `AgreementLedgerBridge` wrapping the
    // same underlying `SqliteLedger`. It only needs `ensure_block` to commit
    // fetched blocks, and shares the same ledger mutex so commits are visible
    // to the agreement service immediately.
    let catchup_bridge = Arc::new(AgreementLedgerBridge::new_with_advancer_and_condvar(
        ledger.clone(),
        network_advancer,
        agreement_ledger.round_advanced_condvar(),
    ));

    let block_fetcher: Arc<dyn BlockFetcher> = Arc::new(GossipBlockFetcher {
        ws_network: gossip_node.clone(),
        rt_handle,
    });

    let catchup_ledger: Arc<dyn algo_ledger::CatchupLedger> = catchup_bridge;

    let mut catchup_service = CatchupService::start(cert_rx, catchup_ledger, block_fetcher);
    info!("catchup service started");

    // -----------------------------------------------------------------------
    // 6. Build and start the agreement Service.
    // -----------------------------------------------------------------------
    let params = Parameters {
        network: agreement_network,
        ledger: agreement_ledger,
        key_manager,
        block_factory,
        block_validator,
        random_source,
        monitor,
        crypto,
        clock: SystemClock::new(),
        crash_db: Some(crash_db),
        signing_keys,
    };

    let service = Service::new(params);
    let handle = service.start();

    info!(
        genesis_id = %resolved_genesis_id,
        latest_round = latest,
        "consensus participation active -- press Ctrl+C to stop"
    );

    // -----------------------------------------------------------------------
    // 7. Wait for shutdown signal (Ctrl+C).
    // -----------------------------------------------------------------------
    tokio::signal::ctrl_c().await?;

    info!("shutting down consensus participation...");

    // Cancel the shared token first so the REST server's graceful
    // shutdown begins unblocking in-flight requests while we tear
    // down agreement + gossip. The server's own draining uses axum's
    // `with_graceful_shutdown`, so connections finish their current
    // request before the listener closes.
    shutdown_token.cancel();

    // Stop the agreement service first, then the catchup service (mirrors
    // Go's shutdown order where the agreement service is stopped before the
    // catchup service, ensuring no new certificates are sent after the
    // catchup service shuts down).
    handle.shutdown();
    catchup_service.stop();
    gossip_node.stop().await;

    // Await the REST server last — its graceful shutdown depends on
    // axum finishing any in-flight requests, and by now gossip has
    // stopped serving fresh data so the responses are stable. The
    // adapter's `wait_for_round` honours `shutdown_token` so
    // long-poll `wait-for-block-after` handlers return 408 promptly
    // instead of hanging out their full 60s deadline; a hard-cap
    // timeout is still applied as a defence-in-depth safety net in
    // case a future handler forgets to honour the token.
    if let Some(join_handle) = rest_server_handle {
        match tokio::time::timeout(REST_SHUTDOWN_HARD_CAP, join_handle).await {
            Ok(Ok(())) => info!("REST API server stopped"),
            Ok(Err(e)) => warn!(err = %e, "REST API server task terminated unexpectedly"),
            Err(_) => warn!(
                cap = ?REST_SHUTDOWN_HARD_CAP,
                "REST API server did not drain within the shutdown cap; abandoning the join handle"
            ),
        }
    }
    info!("consensus participation stopped");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_pool::traits::BlockEvaluator;
    use algo_types::{
        consensus::consensus_params_for_version, Address, ConsensusParams, Round,
        SignedTransaction, Transaction, TxnType,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde_bytes::ByteBuf;
    use std::sync::{Arc, Mutex};

    // ── Helper: create an in-memory ledger ──────────────────────────
    fn test_ledger() -> Arc<Mutex<SqliteLedger>> {
        Arc::new(Mutex::new(
            SqliteLedger::open_in_memory().expect("in-memory ledger"),
        ))
    }

    // ── load_signing_keys_for_round ─────────────────────────────────

    #[test]
    fn load_signing_keys_returns_secrets_for_valid_round() {
        use algo_ledger::participation::Participation;

        let store = ParticipationStore::open_in_memory().expect("in-memory part store");
        let account = Address([7u8; 32]);
        // Generate a key valid for rounds [0, 1000]. key_lifetime=0 skips
        // state-proof key generation — irrelevant to VRF/OTS signing.
        let part = Participation::generate(account, Round(0), Round(1000), 10_000, 0)
            .expect("generate participation");
        let want_vrf_pk = part.vrf_pubkey().0;
        store.insert(&part).expect("insert participation");

        // A round inside the validity window loads the secrets, keyed by the
        // parent account, with the VRF keypair reconstructed from its seed.
        let keys = load_signing_keys_for_round(&store, Round(1));
        assert_eq!(keys.len(), 1, "exactly one account's secrets loaded");
        let signing = keys.get(&account).expect("secrets for the account");
        assert_eq!(
            signing.vrf.pk.0, want_vrf_pk,
            "loaded VRF keypair must match the inserted key",
        );

        // A round outside the validity window loads nothing.
        let none = load_signing_keys_for_round(&store, Round(2_000));
        assert!(none.is_empty(), "no secrets outside the validity window");
    }

    #[test]
    fn load_signing_keys_empty_store_returns_empty() {
        let store = ParticipationStore::open_in_memory().expect("in-memory part store");
        assert!(load_signing_keys_for_round(&store, Round(1)).is_empty());
    }

    #[test]
    fn load_signing_keys_uses_effective_window_not_raw_validity() {
        // Regression: the loader must select keys with the same effective-window
        // semantics the pseudonode's key manager uses (`get_for_voting_round`),
        // not raw firstValid/lastValid (`get_for_round` alone). Otherwise an
        // account holding a deactivated key (still raw-valid) could overwrite the
        // active key's secret in the address-keyed map, leaving the node signing
        // the active public record with the wrong secret.
        use algo_ledger::participation::Participation;

        let store = ParticipationStore::open_in_memory().expect("in-memory part store");
        let account = Address([9u8; 32]);

        // Two keys for the same account, both raw-valid over [0, 1000] but with
        // distinct VRF keypairs so we can tell which secret got loaded.
        let key_a = Participation::generate(account, Round(0), Round(1000), 10_000, 0)
            .expect("generate key A");
        let key_b = Participation::generate(account, Round(0), Round(1000), 10_000, 0)
            .expect("generate key B");
        let vrf_a = key_a.vrf_pubkey().0;
        let vrf_b = key_b.vrf_pubkey().0;
        assert_ne!(vrf_a, vrf_b, "test keys must differ");
        let id_a = store.insert(&key_a).expect("insert key A");
        let id_b = store.insert(&key_b).expect("insert key B");

        // Activate A at round 1, then B at round 500 — registering B deactivates
        // A (sets A.effectiveLast = 499). At round 600 only B is effective.
        store.register(&id_a, Round(1)).expect("register A");
        store.register(&id_b, Round(500)).expect("register B");

        let keys = load_signing_keys_for_round(&store, Round(600));
        let signing = keys.get(&account).expect("the effective key's secrets");
        assert_eq!(
            signing.vrf.pk.0, vrf_b,
            "must load the EFFECTIVE key (B), not the deactivated-but-raw-valid key (A)",
        );
    }

    #[test]
    fn load_signing_keys_collapses_multiple_effective_keys_deterministically() {
        // The signing map holds one secret per address. If an account has two
        // simultaneously-effective keys (both unregistered → NULL/0 effective
        // rounds, so both pass `get_for_voting_round`), the loader must collapse
        // to a single, deterministically-chosen entry (keep-first + warn) rather
        // than panic or produce duplicates. Full per-record disambiguation is
        // tracked in TASK-272.
        use algo_ledger::participation::Participation;

        let store = ParticipationStore::open_in_memory().expect("in-memory part store");
        let account = Address([3u8; 32]);
        let key_a = Participation::generate(account, Round(0), Round(1000), 10_000, 0)
            .expect("generate key A");
        let key_b = Participation::generate(account, Round(0), Round(1000), 10_000, 0)
            .expect("generate key B");
        let vrf_a = key_a.vrf_pubkey().0;
        let vrf_b = key_b.vrf_pubkey().0;
        store.insert(&key_a).expect("insert key A");
        store.insert(&key_b).expect("insert key B");

        let keys = load_signing_keys_for_round(&store, Round(1));
        assert_eq!(keys.len(), 1, "one secret per address — collapsed");
        let loaded = keys
            .get(&account)
            .expect("a secret for the account")
            .vrf
            .pk
            .0;
        assert!(
            loaded == vrf_a || loaded == vrf_b,
            "loaded secret must be one of the inserted keys",
        );
    }

    // ── Helpers: RestOptions / load_genesis_json ────────────────────
    //
    // These tests cover the CLI/TOML merge and genesis-file fallback
    // added in PLAN-74 TASK-79; they don't touch the agreement
    // protocol so no mock ledger / evaluator is needed.

    #[test]
    fn rest_options_disabled_when_no_listen_anywhere() {
        let opts = RestOptions::default();
        let resolved = opts.resolve(None).expect("resolve ok");
        assert!(resolved.is_none());
    }

    #[test]
    fn rest_options_cli_listen_overrides_toml_listen() {
        let opts = RestOptions {
            listen: Some("127.0.0.1:9999".to_string()),
            data_dir: None,
            genesis_path: None,
            file_rest: Some(RestConfig {
                listen: Some("127.0.0.1:1111".to_string()),
                ..RestConfig::default()
            }),
        };
        let resolved = opts
            .resolve(None)
            .expect("resolve ok")
            .expect("rest enabled");
        assert_eq!(resolved.listen.to_string(), "127.0.0.1:9999");
    }

    #[test]
    fn rest_options_falls_back_to_toml_listen() {
        let opts = RestOptions {
            file_rest: Some(RestConfig {
                listen: Some("0.0.0.0:8080".into()),
                ..RestConfig::default()
            }),
            ..RestOptions::default()
        };
        let resolved = opts.resolve(None).unwrap().expect("rest enabled");
        assert_eq!(resolved.listen.to_string(), "0.0.0.0:8080");
    }

    #[test]
    fn rest_options_invalid_listen_reports_error() {
        let opts = RestOptions {
            listen: Some("not-a-socket-addr".into()),
            ..RestOptions::default()
        };
        let err = opts.resolve(None).unwrap_err();
        assert!(
            err.to_string().contains("invalid --rest-listen"),
            "expected parse-error message, got {err}"
        );
    }

    #[test]
    fn rest_options_data_dir_defaults_to_ledger_parent() {
        let opts = RestOptions {
            listen: Some("127.0.0.1:4001".into()),
            data_dir: None,
            genesis_path: None,
            file_rest: None,
        };
        let ledger_parent = std::path::Path::new("/srv/algod");
        let resolved = opts.resolve(Some(ledger_parent)).unwrap().unwrap();
        assert_eq!(
            resolved.data_dir.as_deref(),
            Some(ledger_parent),
            "missing data_dir should default to the ledger's parent directory"
        );
    }

    #[test]
    fn rest_options_cli_data_dir_overrides_default() {
        let opts = RestOptions {
            listen: Some("127.0.0.1:4001".into()),
            data_dir: Some(PathBuf::from("/var/lib/algod")),
            genesis_path: None,
            file_rest: None,
        };
        let resolved = opts
            .resolve(Some(std::path::Path::new("/srv/algod")))
            .unwrap()
            .unwrap();
        assert_eq!(
            resolved.data_dir.as_deref(),
            Some(std::path::Path::new("/var/lib/algod"))
        );
    }

    #[test]
    fn rest_options_token_overrides_come_only_from_toml() {
        let opts = RestOptions {
            listen: Some("127.0.0.1:4001".into()),
            file_rest: Some(RestConfig {
                api_token: Some("from-toml-api".into()),
                admin_token: Some("from-toml-admin".into()),
                ..RestConfig::default()
            }),
            ..RestOptions::default()
        };
        let resolved = opts.resolve(None).unwrap().unwrap();
        assert_eq!(resolved.api_token.as_deref(), Some("from-toml-api"));
        assert_eq!(resolved.admin_token.as_deref(), Some("from-toml-admin"));
    }

    #[test]
    fn rest_options_async_backlog_plumbed_from_toml() {
        let opts = RestOptions {
            listen: Some("127.0.0.1:4001".into()),
            file_rest: Some(RestConfig {
                async_backlog_size: Some(42),
                ..RestConfig::default()
            }),
            ..RestOptions::default()
        };
        let resolved = opts.resolve(None).unwrap().unwrap();
        assert_eq!(resolved.async_backlog_size, Some(42));
    }

    #[test]
    fn load_genesis_json_returns_none_when_paths_absent() {
        let got = load_genesis_json(None, None).expect("ok with no paths");
        assert!(got.is_none());
    }

    #[test]
    fn load_genesis_json_prefers_explicit_path_then_data_dir() {
        let tmp = std::env::temp_dir().join(format!(
            "algod-rust-test-genesis-{}.json",
            std::process::id()
        ));
        std::fs::write(&tmp, r#"{"network":"unit-test"}"#).unwrap();
        let got = load_genesis_json(Some(&tmp), None)
            .expect("ok")
            .expect("file present");
        assert_eq!(got, r#"{"network":"unit-test"}"#);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_genesis_json_missing_explicit_falls_back_to_data_dir() {
        // When `--genesis-path` points at a missing file but
        // `<data_dir>/genesis.json` exists, the real file wins — we
        // must not silently synthesize a stub when a real file is
        // available under the data directory.
        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-test-dd-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let data_dir_genesis = tmp_dir.join("genesis.json");
        std::fs::write(&data_dir_genesis, r#"{"network":"fallback"}"#).unwrap();

        let got = load_genesis_json(
            Some(std::path::Path::new("/no/such/genesis.json")),
            Some(&tmp_dir),
        )
        .expect("ok — fallback succeeds")
        .expect("data_dir/genesis.json should serve the response");
        assert_eq!(got, r#"{"network":"fallback"}"#);

        let _ = std::fs::remove_file(&data_dir_genesis);
        let _ = std::fs::remove_dir(&tmp_dir);
    }

    #[test]
    fn load_genesis_json_all_candidates_absent_returns_none() {
        // When both the explicit path and the data_dir default are
        // missing, the function returns `Ok(None)` so startup can
        // synthesize a stub. This is the "no real genesis file
        // anywhere on disk" path, distinct from the fallback test
        // above.
        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-test-absent-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        // Intentionally do NOT create `genesis.json` in `tmp_dir`.

        let got = load_genesis_json(
            Some(std::path::Path::new("/no/such/genesis.json")),
            Some(&tmp_dir),
        )
        .expect("ok when both absent");
        assert!(got.is_none());

        let _ = std::fs::remove_dir(&tmp_dir);
    }

    #[test]
    fn load_genesis_json_deduplicates_when_explicit_equals_data_dir_derived() {
        // If `--genesis-path` resolves to the same file as
        // `<data_dir>/genesis.json`, the function must not attempt
        // two reads. The test exercises the dedup branch by pointing
        // both candidates at the same path.
        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-test-dedup-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let shared = tmp_dir.join("genesis.json");
        std::fs::write(&shared, r#"{"network":"shared"}"#).unwrap();

        let got = load_genesis_json(Some(&shared), Some(&tmp_dir))
            .expect("ok")
            .expect("shared file serves");
        assert_eq!(got, r#"{"network":"shared"}"#);

        let _ = std::fs::remove_file(&shared);
        let _ = std::fs::remove_dir(&tmp_dir);
    }

    #[test]
    fn synthesize_genesis_json_produces_minimal_valid_body() {
        let json = synthesize_genesis_json("mainnet-v1.0", "mainnet", "https://example.com/v41");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["network"], "mainnet");
        assert_eq!(parsed["id"], "v1.0");
        assert_eq!(parsed["proto"], "https://example.com/v41");
        assert!(parsed["alloc"].is_array());
    }

    #[test]
    fn synthesize_genesis_json_passes_through_when_prefix_missing() {
        let json = synthesize_genesis_json("foo-bar-baz", "mainnet", "proto");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "foo-bar-baz");
    }

    // ── Helper: V41 consensus params ────────────────────────────────
    fn v41_params() -> ConsensusParams {
        consensus_params_for_version(CONSENSUS_V41).unwrap()
    }

    // ── Helper: build an evaluator with pre-seeded account balances ─
    fn make_evaluator(
        ledger: &Arc<Mutex<SqliteLedger>>,
        params: &ConsensusParams,
        round: u64,
        accounts: &[(Address, u64)],
    ) -> SimpleBlockEvaluator {
        make_evaluator_with_accounts(ledger, params, round, accounts, &[])
    }

    /// Build an evaluator with full AccountData entries (for min-balance tests).
    fn make_evaluator_with_accounts(
        ledger: &Arc<Mutex<SqliteLedger>>,
        params: &ConsensusParams,
        round: u64,
        simple_accounts: &[(Address, u64)],
        full_accounts: &[(Address, AccountData)],
    ) -> SimpleBlockEvaluator {
        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        // Pre-populate the snapshot cache so tests don't need the ledger
        // to actually contain accounts.
        for (addr, balance) in simple_accounts {
            snapshot.accounts.insert(
                *addr,
                Some(algo_types::AccountData {
                    micro_algos: *balance,
                    ..Default::default()
                }),
            );
        }
        for (addr, acct) in full_accounts {
            snapshot.accounts.insert(*addr, Some(acct.clone()));
        }
        SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(round),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        }
    }

    // ── Helper: ed25519 keypair → (Address, SigningKey) ─────────────
    fn test_keypair(seed: u8) -> (Address, SigningKey) {
        let secret = [seed; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let pk = signing_key.verifying_key().to_bytes();
        (Address(pk), signing_key)
    }

    // ── Helper: sign a transaction with ed25519 ─────────────────────
    fn sign_txn(txn: &Transaction, key: &SigningKey) -> [u8; 64] {
        let canonical = algo_codec::canonical_encode_transaction(txn);
        let mut msg = Vec::with_capacity(2 + canonical.len());
        msg.extend_from_slice(b"TX");
        msg.extend_from_slice(&canonical);
        let sig = key.sign(&msg);
        sig.to_bytes()
    }

    // ── Helper: build a signed payment txn for a given round ────────
    fn make_signed_pay(
        sender_key: &SigningKey,
        sender: &Address,
        receiver: &Address,
        amount: u64,
        fee: u64,
        round: u64,
    ) -> SignedTransaction {
        let txn = Transaction {
            txn_type: TxnType::Pay,
            sender: *sender,
            receiver: *receiver,
            amount,
            fee,
            first_valid: Round(round),
            last_valid: Round(round + 1000),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            ..Default::default()
        };
        let sig = sign_txn(&txn, sender_key);
        SignedTransaction {
            txn,
            sig,
            ..Default::default()
        }
    }

    // ====================================================================
    // 1. CowOverlay unit tests
    // ====================================================================

    #[test]
    fn cow_overlay_txid_dedup() {
        let mut overlay = CowOverlay::new();
        let txid = [0x42; 32];
        assert!(overlay.check_txid(&txid).is_ok());
        overlay.record_txid(txid);
        let err = overlay.check_txid(&txid).unwrap_err();
        assert!(err.to_string().contains("duplicate transaction ID"));
    }

    #[test]
    fn cow_overlay_lease_dedup() {
        let mut overlay = CowOverlay::new();
        let sender = Address([1; 32]);
        let lease = [0xBB; 32];
        let round = 100;
        assert!(overlay
            .check_lease_in_overlay(&sender, &lease, round)
            .is_ok());
        overlay.record_lease(&sender, &lease, round + 500);
        let err = overlay
            .check_lease_in_overlay(&sender, &lease, round)
            .unwrap_err();
        assert!(err.to_string().contains("duplicate lease"));
    }

    #[test]
    fn cow_overlay_zero_lease_always_allowed() {
        let mut overlay = CowOverlay::new();
        let sender = Address([1; 32]);
        let zero_lease = [0u8; 32];
        overlay.record_lease(&sender, &zero_lease, 999);
        assert!(overlay
            .check_lease_in_overlay(&sender, &zero_lease, 100)
            .is_ok());
    }

    #[test]
    fn cow_overlay_balance_tracking() {
        let mut overlay = CowOverlay::new();
        let addr = Address([5; 32]);
        assert!(overlay.get_balance(&addr).is_none());
        overlay.set_balance(&addr, 1_000_000);
        assert_eq!(overlay.get_balance(&addr), Some(1_000_000));
    }

    #[test]
    fn cow_checkpoint_and_rollback() {
        let mut overlay = CowOverlay::new();
        let addr = Address([7; 32]);
        overlay.set_balance(&addr, 500_000);
        let txid1 = [0x01; 32];
        overlay.record_txid(txid1);

        // Checkpoint (incremental — records nothing initially)
        let mut cp = overlay.checkpoint();

        // Mutate using tracked variants so changes are recorded in the
        // checkpoint for rollback.
        overlay.set_balance_tracked(&addr, 100, &mut cp);
        let txid2 = [0x02; 32];
        overlay.record_txid_tracked(txid2, &mut cp);
        assert_eq!(overlay.get_balance(&addr), Some(100));
        assert!(overlay.check_txid(&txid2).is_err());

        // Rollback — only the tracked mutations are undone.
        overlay.restore(cp);
        assert_eq!(overlay.get_balance(&addr), Some(500_000));
        // txid2 should no longer be seen
        assert!(overlay.check_txid(&txid2).is_ok());
        // txid1 should still be seen
        assert!(overlay.check_txid(&txid1).is_err());
    }

    // ====================================================================
    // 2. stpf / heartbeat rejection tests
    // ====================================================================

    #[test]
    fn reject_stpf_from_pool() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(1);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let mut stx = make_signed_pay(&key, &sender, &Address([2; 32]), 0, 1000, 100);
        stx.txn.txn_type = TxnType::Stpf;
        // Re-sign after mutation
        stx.sig = sign_txn(&stx.txn, &key);

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("stpf"),
            "expected stpf rejection, got: {err}"
        );
    }

    #[test]
    fn reject_heartbeat_from_pool() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(1);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let mut stx = make_signed_pay(&key, &sender, &Address([2; 32]), 0, 1000, 100);
        stx.txn.txn_type = TxnType::Hb;
        // Re-sign after mutation
        stx.sig = sign_txn(&stx.txn, &key);

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("hb") || err.to_string().contains("heartbeat"),
            "expected heartbeat rejection, got: {err}"
        );
    }

    // ====================================================================
    // 3. Signature verification tests
    // ====================================================================

    #[test]
    fn valid_single_sig_accepted() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(10);
        let (receiver, _) = test_keypair(11);
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[(sender, 10_000_000), (receiver, 100_000)],
        );

        let stx = make_signed_pay(&key, &sender, &receiver, 1000, 1000, 100);
        assert!(eval.transaction_group(&[stx]).is_ok());
    }

    #[test]
    fn invalid_signature_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(20);
        let (receiver, _) = test_keypair(21);
        let eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let mut stx = make_signed_pay(&key, &sender, &receiver, 1000, 1000, 100);
        // Corrupt signature
        stx.sig[0] ^= 0xFF;

        let err = eval.test_transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("signature"),
            "expected signature error, got: {err}"
        );
    }

    #[test]
    fn missing_signature_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, _key) = test_keypair(30);
        let (receiver, _) = test_keypair(31);
        let eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let stx = SignedTransaction {
            txn: Transaction {
                txn_type: TxnType::Pay,
                sender,
                receiver,
                amount: 1000,
                fee: 1000,
                first_valid: Round(100),
                last_valid: Round(1100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                ..Default::default()
            },
            sig: [0u8; 64], // no signature
            ..Default::default()
        };

        let err = eval.test_transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("no signature"),
            "expected no-signature error, got: {err}"
        );
    }

    // ====================================================================
    // 4. Lease uniqueness tests
    // ====================================================================

    #[test]
    fn duplicate_lease_in_block_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(40);
        let (receiver, _) = test_keypair(41);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let lease = [0xCC; 32];

        // First txn with lease (amount=0 to avoid receiver min-balance issues)
        let mut stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        stx1.txn.lease = lease;
        stx1.sig = sign_txn(&stx1.txn, &key);
        assert!(eval.transaction_group(&[stx1]).is_ok());

        // Second txn with same lease but different note (so txid differs) — should be rejected
        let txn2 = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 0,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            lease,
            note: ByteBuf::from(vec![0x01]), // different note -> different txid
            ..Default::default()
        };
        let sig2 = sign_txn(&txn2, &key);
        let stx2 = SignedTransaction {
            txn: txn2,
            sig: sig2,
            ..Default::default()
        };
        let err = eval.transaction_group(&[stx2]).unwrap_err();
        assert!(
            err.to_string().contains("lease"),
            "expected lease error, got: {err}"
        );
    }

    #[test]
    fn different_leases_accepted() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(42);
        let (receiver, _) = test_keypair(43);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let mut stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        stx1.txn.lease = [0xDD; 32];
        stx1.sig = sign_txn(&stx1.txn, &key);
        assert!(eval.transaction_group(&[stx1]).is_ok());

        let mut stx2 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        stx2.txn.lease = [0xEE; 32];
        stx2.sig = sign_txn(&stx2.txn, &key);
        assert!(eval.transaction_group(&[stx2]).is_ok());
    }

    // ====================================================================
    // 5. TxID dedup tests
    // ====================================================================

    #[test]
    fn duplicate_txid_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(50);
        let (receiver, _) = test_keypair(51);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);

        // First submission succeeds
        assert!(eval.transaction_group(std::slice::from_ref(&stx)).is_ok());

        // Same exact transaction again — should be rejected as duplicate txid
        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("duplicate transaction ID"),
            "expected duplicate txid error, got: {err}"
        );
    }

    #[test]
    fn duplicate_txid_within_group_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(52);
        let (receiver, _) = test_keypair(53);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // Build a single transaction and submit it twice in the same group.
        // Both copies are identical so they have the same txid.
        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        let err = eval.transaction_group(&[stx.clone(), stx]).unwrap_err();
        assert!(
            err.to_string()
                .contains("duplicate transaction ID within group"),
            "expected intra-group duplicate txid error, got: {err}"
        );
    }

    #[test]
    fn duplicate_lease_within_group_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(54);
        let (receiver, _) = test_keypair(55);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let lease = [0xFF; 32];

        // Two transactions from the same sender with the same lease but
        // different notes (so they have different txids).
        let mut stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        stx1.txn.lease = lease;
        stx1.txn.note = ByteBuf::from(vec![0x01]);
        stx1.sig = sign_txn(&stx1.txn, &key);

        let mut stx2 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        stx2.txn.lease = lease;
        stx2.txn.note = ByteBuf::from(vec![0x02]);
        stx2.sig = sign_txn(&stx2.txn, &key);

        let err = eval.transaction_group(&[stx1, stx2]).unwrap_err();
        assert!(
            err.to_string().contains("duplicate lease within group"),
            "expected intra-group duplicate lease error, got: {err}"
        );
    }

    // ====================================================================
    // 6. Balance / min-balance tests
    // ====================================================================

    #[test]
    fn insufficient_balance_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(60);
        let (receiver, _) = test_keypair(61);
        // Sender only has 500 microAlgos — not enough for fee(1000) + amount(100)
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 500)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 100, 1000, 100);
        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("insufficient balance"),
            "expected insufficient balance, got: {err}"
        );
    }

    #[test]
    fn sender_below_min_balance_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(62);
        let (receiver, _) = test_keypair(63);
        // Sender has exactly min_balance + fee + amount — after deduction they'd
        // have amount=0 left. Let's set them up so they'd have a few uAlgos left
        // but below min_balance.
        // fee=1000, amount=0 -> sender_after = balance - 1000
        // We want: 0 < sender_after < min_balance
        // So balance = 1000 + 50_000 = 51_000, sender_after = 50_000 < 100_000
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 51_000)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("below minimum") || err.to_string().contains("min"),
            "expected min-balance error, got: {err}"
        );
    }

    #[test]
    fn close_remainder_zeros_sender_and_credits_close_addr() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(64);
        let (receiver, _) = test_keypair(65);
        let (close_addr, _) = test_keypair(66);
        // Sender: 1_000_000, fee=1000, amount=200_000
        // After cost: 1_000_000 - 1000 - 200_000 = 799_000
        // Close: sender -> 0, close_addr gets 799_000
        let initial_close_balance = 500_000u64;
        let initial_receiver_balance = 100_000u64;
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[
                (sender, 1_000_000),
                (receiver, initial_receiver_balance),
                (close_addr, initial_close_balance),
            ],
        );

        let mut stx = make_signed_pay(&key, &sender, &receiver, 200_000, 1000, 100);
        stx.txn.close_remainder_to = close_addr;
        stx.sig = sign_txn(&stx.txn, &key);

        assert!(eval.transaction_group(&[stx]).is_ok());

        // Verify sender is zero (closed)
        assert_eq!(eval.effective_balance(&sender), 0);
        // Verify close_addr got the remainder
        // sender_after_cost = 1_000_000 - 1000 - 200_000 = 799_000
        // close_addr = 500_000 + 799_000 = 1_299_000
        assert_eq!(
            eval.effective_balance(&close_addr),
            initial_close_balance + (1_000_000 - 1000 - 200_000)
        );
        // Verify receiver got the amount
        assert_eq!(
            eval.effective_balance(&receiver),
            initial_receiver_balance + 200_000
        );
    }

    #[test]
    fn cross_group_receiver_can_spend() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender_a, key_a) = test_keypair(70);
        let (sender_b, key_b) = test_keypair(71);
        let (receiver, _) = test_keypair(72);
        // sender_a has 1M, sender_b has 0
        // Group 1: A sends 500_000 to B
        // Group 2: B sends 100_000 to receiver (needs balance from group 1)
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[
                (sender_a, 1_000_000),
                (sender_b, 200_000), // needs min balance + fee
            ],
        );

        // Group 1: A -> B for 500_000
        let stx1 = make_signed_pay(&key_a, &sender_a, &sender_b, 500_000, 1000, 100);
        assert!(eval.transaction_group(&[stx1]).is_ok());

        // Group 2: B -> receiver for 100_000 (B should have 200_000 + 500_000 = 700_000 now)
        let stx2 = make_signed_pay(&key_b, &sender_b, &receiver, 100_000, 1000, 100);
        assert!(
            eval.transaction_group(&[stx2]).is_ok(),
            "receiver from group 1 should be able to spend in group 2"
        );

        // B's balance: 700_000 - 100_000 - 1000 = 599_000
        assert_eq!(eval.effective_balance(&sender_b), 599_000);
    }

    // ====================================================================
    // 7. COW rollback test (rejected group doesn't corrupt overlay)
    // ====================================================================

    #[test]
    fn rejected_group_does_not_corrupt_overlay() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(80);
        let (receiver, _) = test_keypair(81);
        // Give sender enough for one group but the second would drop below min balance
        // after the first. The second group should fail min-balance check and
        // the overlay should be rolled back.
        //
        // Balance: 200_000. min_balance = 100_000.
        // Group 1: fee=1000, amount=0 -> sender=199_000 (ok, above min_balance)
        // Group 2 (will fail): fee=1000, amount=99_000 -> sender=99_000 (below min_balance!)
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 200_000)]);

        // Group 1 succeeds
        let stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        assert!(eval.transaction_group(&[stx1]).is_ok());
        assert_eq!(eval.effective_balance(&sender), 199_000);

        // Group 2 should fail (would put sender at 99_000 < 100_000)
        // Use a different note to avoid duplicate txid
        let stx2_txn = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 99_000,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x01]),
            ..Default::default()
        };
        let sig2 = sign_txn(&stx2_txn, &key);
        let stx2 = SignedTransaction {
            txn: stx2_txn,
            sig: sig2,
            ..Default::default()
        };
        let err = eval.transaction_group(&[stx2]).unwrap_err();
        assert!(
            err.to_string().contains("below minimum"),
            "expected min-balance error, got: {err}"
        );

        // After rollback, sender balance should still be 199_000 (from group 1)
        assert_eq!(
            eval.effective_balance(&sender),
            199_000,
            "overlay should be rolled back after rejected group"
        );

        // And we should be able to do a valid group 3
        let stx3_txn = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 0,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x02]),
            ..Default::default()
        };
        let sig3 = sign_txn(&stx3_txn, &key);
        let stx3 = SignedTransaction {
            txn: stx3_txn,
            sig: sig3,
            ..Default::default()
        };
        assert!(eval.transaction_group(&[stx3]).is_ok());
        assert_eq!(eval.effective_balance(&sender), 198_000);
    }

    // ====================================================================
    // 8. Exact byte counting / block size limit tests
    // ====================================================================

    #[test]
    fn block_byte_limit_enforced() {
        let ledger = test_ledger();
        let mut params = v41_params();
        // Set a very small block byte limit to force rejection
        params.max_txn_bytes_per_block = 50;
        let (sender, key) = test_keypair(90);
        let (receiver, _) = test_keypair(91);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // A normal pay txn will be >50 bytes in STIB encoding
        let stx = make_signed_pay(&key, &sender, &receiver, 100, 1000, 100);
        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("block byte limit") || err.to_string().contains("exceed"),
            "expected block byte limit error, got: {err}"
        );
    }

    #[test]
    fn second_group_exceeds_byte_limit() {
        let ledger = test_ledger();
        let mut params = v41_params();
        let (sender, key) = test_keypair(92);
        let (receiver, _) = test_keypair(93);

        // First, figure out how big a single STIB is (amount=0 avoids receiver min-balance)
        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        let stib_size = algo_codec::canonical_encode_signed_txn_in_block(&stx).len();

        // Set limit so first txn fits but second doesn't
        params.max_txn_bytes_per_block = (stib_size + 10) as u64;
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // First group fits
        let stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        assert!(eval.transaction_group(&[stx1]).is_ok());

        // Second group should exceed
        let stx2_txn = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 0,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x01]),
            ..Default::default()
        };
        let sig2 = sign_txn(&stx2_txn, &key);
        let stx2 = SignedTransaction {
            txn: stx2_txn,
            sig: sig2,
            ..Default::default()
        };
        let err = eval.transaction_group(&[stx2]).unwrap_err();
        assert!(
            err.to_string().contains("exceed") || err.to_string().contains("block byte limit"),
            "expected byte limit error, got: {err}"
        );
    }

    // ====================================================================
    // 9. Merkle commitment tests
    // ====================================================================

    #[test]
    fn generate_block_with_payset_computes_txn_commitment() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(100);
        let (receiver, _) = test_keypair(101);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        eval.transaction_group(&[stx]).unwrap();

        let block = eval.generate_block(&[]).unwrap();

        // Payset should be non-empty
        assert_eq!(block.payset.len(), 1);

        // txn_commitment should be non-zero (Merkle root of non-empty payset)
        assert_ne!(
            block.txn_commitment, [0u8; 32],
            "txn_commitment should be non-zero for non-empty payset"
        );

        // Verify it matches the independently computed Merkle root
        let expected = algo_validate::merkle::compute_payset_merkle_root(&block);
        assert_eq!(block.txn_commitment, expected);
    }

    #[test]
    fn generate_block_empty_payset_has_zero_commitment() {
        let ledger = test_ledger();
        let params = v41_params();
        let eval = make_evaluator(&ledger, &params, 100, &[]);

        // Cast to mutable for generate_block
        let mut eval = eval;
        let block = eval.generate_block(&[]).unwrap();

        assert!(block.payset.is_empty());
        assert_eq!(
            block.txn_commitment, [0u8; 32],
            "empty payset should have zero txn_commitment"
        );
    }

    #[test]
    fn generate_block_v41_computes_vector_commitments() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(102);
        let (receiver, _) = test_keypair(103);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        eval.transaction_group(&[stx]).unwrap();

        let block = eval.generate_block(&[]).unwrap();

        // V41 has both txn256 (v34+) and txn512 (v41+)
        assert!(
            algo_validate::rules::has_txn256(CONSENSUS_V41),
            "V41 should support txn256"
        );
        assert!(
            algo_validate::rules::has_txn512(CONSENSUS_V41),
            "V41 should support txn512"
        );

        assert_ne!(
            block.txn256, [0u8; 32],
            "txn256 should be non-zero for V41 with non-empty payset"
        );
        assert_ne!(
            block.txn512, [0u8; 64],
            "txn512 should be non-zero for V41 with non-empty payset"
        );

        // Verify they match independently computed values
        let expected_256 = algo_validate::merkle::compute_vector_commitment(
            &block,
            algo_validate::merkle::HashAlgo::Sha256,
        );
        assert_eq!(block.txn256.as_slice(), expected_256.as_slice());

        let expected_512 = algo_validate::merkle::compute_vector_commitment(
            &block,
            algo_validate::merkle::HashAlgo::Sha512,
        );
        assert_eq!(block.txn512.as_slice(), expected_512.as_slice());
    }

    #[test]
    fn generate_block_old_protocol_skips_vector_commitments() {
        let ledger = test_ledger();
        // Use v30 params — no vector commitments
        let v30_proto = algo_types::consensus::CONSENSUS_V30;
        let params = consensus_params_for_version(v30_proto).unwrap();
        let (sender, key) = test_keypair(104);
        let (receiver, _) = test_keypair(105);

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: v30_proto.to_string(),
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot: LedgerSnapshot {
                accounts: {
                    let mut m = HashMap::new();
                    m.insert(
                        sender,
                        Some(algo_types::AccountData {
                            micro_algos: 10_000_000,
                            ..Default::default()
                        }),
                    );
                    m
                },
                lease_table: algo_ledger::LeaseTable::new(),
                round: 100,
                snapshot_round: Round(0),
                read_snapshot: None,
            },
            overlay: CowOverlay::new(),
            fees_collected: 0,
        };

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        eval.transaction_group(&[stx]).unwrap();

        let block = eval.generate_block(&[]).unwrap();

        assert!(!algo_validate::rules::has_txn256(v30_proto));
        assert!(!algo_validate::rules::has_txn512(v30_proto));
        assert_eq!(block.txn256, [0u8; 32], "v30 should not compute txn256");
        assert_eq!(block.txn512, [0u8; 64], "v30 should not compute txn512");
    }

    // ====================================================================
    // 10. Evaluator round and pay_set_size
    // ====================================================================

    #[test]
    fn evaluator_round_and_pay_set_size() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(110);
        let (receiver, _) = test_keypair(111);
        let mut eval = make_evaluator(&ledger, &params, 42, &[(sender, 10_000_000)]);

        assert_eq!(eval.round(), Round(42));
        assert_eq!(eval.pay_set_size(), 0);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 42);
        eval.transaction_group(&[stx]).unwrap();

        assert_eq!(eval.pay_set_size(), 1);
    }

    // ====================================================================
    // 11. STIB genesis field stripping
    // ====================================================================

    #[test]
    fn transaction_group_strips_genesis_fields() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(120);
        let (receiver, _) = test_keypair(121);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        // Pre-check: the txn has genesis fields set
        assert_eq!(stx.txn.genesis_id, "test-v1");
        assert_eq!(stx.txn.genesis_hash, [0xAA; 32]);

        eval.transaction_group(&[stx]).unwrap();

        // After inclusion, the included_txns should have genesis fields stripped
        // (STIB format). Generate the block to access them.
        let block = eval.generate_block(&[]).unwrap();
        let stib = &block.payset[0];
        assert!(
            stib.txn.genesis_id.is_empty(),
            "STIB should have genesis_id stripped"
        );
        assert_eq!(
            stib.txn.genesis_hash, [0u8; 32],
            "STIB should have genesis_hash zeroed"
        );
        assert!(stib.has_genesis_id, "STIB should set has_genesis_id flag");
    }

    // ====================================================================
    // 12. Multi-transaction group test (T1)
    // ====================================================================

    #[test]
    fn multi_txn_group_accepted_and_included() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender_a, key_a) = test_keypair(130);
        let (sender_b, key_b) = test_keypair(131);
        let (receiver, _) = test_keypair(132);
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[
                (sender_a, 10_000_000),
                (sender_b, 10_000_000),
                (receiver, 100_000),
            ],
        );

        // Build two transactions that will form a group.
        let mut txn_a = Transaction {
            txn_type: TxnType::Pay,
            sender: sender_a,
            receiver,
            amount: 1_000,
            fee: 1_000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            ..Default::default()
        };
        let mut txn_b = Transaction {
            txn_type: TxnType::Pay,
            sender: sender_b,
            receiver,
            amount: 2_000,
            fee: 1_000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            ..Default::default()
        };

        // Compute group ID (compute_group_id zeroes the group field internally).
        let group_id = algo_validate::rules::compute_group_id(&[txn_a.clone(), txn_b.clone()]);
        txn_a.group = *group_id.as_bytes();
        txn_b.group = *group_id.as_bytes();

        // Sign both transactions (with group field set).
        let sig_a = sign_txn(&txn_a, &key_a);
        let sig_b = sign_txn(&txn_b, &key_b);
        let stx_a = SignedTransaction {
            txn: txn_a,
            sig: sig_a,
            ..Default::default()
        };
        let stx_b = SignedTransaction {
            txn: txn_b,
            sig: sig_b,
            ..Default::default()
        };

        // Submit as a single group of 2 transactions.
        assert!(
            eval.transaction_group(&[stx_a, stx_b]).is_ok(),
            "multi-txn group should be accepted"
        );

        // Both should appear in the block payset.
        let block = eval.generate_block(&[]).unwrap();
        assert_eq!(
            block.payset.len(),
            2,
            "block should contain both transactions from the group"
        );
    }

    // ====================================================================
    // 13. Header field propagation test (T3)
    // ====================================================================

    #[test]
    fn generate_block_propagates_all_header_fields() {
        let ledger = test_ledger();
        let params = v41_params();

        // Set distinctive values on the header fields that H2 was dropping.
        let fee_sink = Address([0x11; 32]);
        let rewards_pool = Address([0x22; 32]);
        let proposer = Address([0x33; 32]);

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(500),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                fee_sink,
                rewards_pool,
                proposer,
                rewards_level: 42,
                rewards_rate: 100,
                rewards_residue: 7,
                rewards_recalculation_round: Round(1000),
                bonus: 99,
                proposer_payout: 6789,
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot: LedgerSnapshot {
                accounts: HashMap::new(),
                lease_table: algo_ledger::LeaseTable::new(),
                round: 500,
                snapshot_round: Round(0),
                read_snapshot: None,
            },
            overlay: CowOverlay::new(),
            fees_collected: 12345,
        };

        let block = eval.generate_block(&[]).unwrap();

        // Verify all header fields were propagated to the generated block.
        assert_eq!(block.fee_sink, fee_sink, "fee_sink should be propagated");
        assert_eq!(
            block.rewards_pool, rewards_pool,
            "rewards_pool should be propagated"
        );
        assert_eq!(block.proposer, proposer, "proposer should be propagated");
        assert_eq!(
            block.rewards_level, 42,
            "rewards_level should be propagated"
        );
        assert_eq!(block.rewards_rate, 100, "rewards_rate should be propagated");
        assert_eq!(
            block.rewards_residue, 7,
            "rewards_residue should be propagated"
        );
        assert_eq!(
            block.rewards_recalculation_round,
            Round(1000),
            "rewards_recalculation_round should be propagated"
        );
        assert_eq!(block.bonus, 99, "bonus should be propagated");
        assert_eq!(
            block.fees_collected, 12345,
            "fees_collected should be propagated"
        );
        assert_eq!(
            block.proposer_payout, 6789,
            "proposer_payout should be propagated"
        );
    }

    // ====================================================================
    // 14. Effective min-balance tests
    // ====================================================================

    #[test]
    fn effective_min_balance_base_account() {
        let params = v41_params();
        let acct = AccountData::default();
        // Base account with no assets/apps should have just the base min_balance.
        assert_eq!(effective_min_balance(&acct, &params), params.min_balance);
    }

    #[test]
    fn effective_min_balance_with_assets() {
        let params = v41_params();
        let acct = AccountData {
            micro_algos: 1_000_000,
            total_assets_opted_in: 3,
            ..Default::default()
        };
        // base + 3 * min_balance for assets
        let expected = params.min_balance + 3 * params.min_balance;
        assert_eq!(effective_min_balance(&acct, &params), expected);
    }

    #[test]
    fn effective_min_balance_with_apps_and_schema() {
        let params = v41_params();
        let acct = AccountData {
            micro_algos: 10_000_000,
            total_created_apps: 2,
            total_apps_opted_in: 1,
            total_extra_app_pages: 3,
            total_app_schema: algo_types::StateSchema {
                num_uint: 4,
                num_byte_slice: 2,
            },
            ..Default::default()
        };
        // base
        let mut expected = params.min_balance;
        // created apps: 2 * app_flat_params_min_balance
        expected += 2 * params.app_flat_params_min_balance;
        // opted-in apps: 1 * app_flat_opt_in_min_balance
        expected += params.app_flat_opt_in_min_balance;
        // schema entries: (4+2) * schema_min_balance_per_entry
        expected += 6 * params.schema_min_balance_per_entry;
        // schema uints: 4 * schema_uint_min_balance
        expected += 4 * params.schema_uint_min_balance;
        // schema bytes: 2 * schema_bytes_min_balance
        expected += 2 * params.schema_bytes_min_balance;
        // extra pages: 3 * app_flat_params_min_balance
        expected += 3 * params.app_flat_params_min_balance;
        assert_eq!(effective_min_balance(&acct, &params), expected);
    }

    #[test]
    fn effective_min_balance_with_boxes() {
        let params = v41_params();
        let acct = AccountData {
            micro_algos: 10_000_000,
            total_boxes: 5,
            total_box_bytes: 1000,
            ..Default::default()
        };
        let expected = params.min_balance
            + 5 * params.box_flat_min_balance
            + 1000 * params.box_byte_min_balance;
        assert_eq!(effective_min_balance(&acct, &params), expected);
    }

    #[test]
    fn min_balance_check_uses_effective_min_balance() {
        // An account with 3 asset opt-ins has an effective min balance of
        // 100_000 + 3 * 100_000 = 400_000. A transaction that would leave
        // the account with 300_000 should be rejected even though 300_000
        // exceeds the base min_balance of 100_000.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(140);
        let (receiver, _) = test_keypair(141);

        let sender_acct = AccountData {
            micro_algos: 500_000,
            total_assets_opted_in: 3,
            ..Default::default()
        };

        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        // fee=1000, amount=199_000 -> sender after = 500_000 - 200_000 = 300_000
        // effective min balance = 100_000 + 3*100_000 = 400_000
        // 300_000 < 400_000 -> should be rejected
        let stx = make_signed_pay(&key, &sender, &receiver, 199_000, 1000, 100);
        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("below minimum"),
            "expected min-balance error for account with assets, got: {err}"
        );
    }

    #[test]
    fn account_with_assets_above_effective_min_accepted() {
        // Same as above but leaving enough balance above effective min.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(142);
        let (receiver, _) = test_keypair(143);

        let sender_acct = AccountData {
            micro_algos: 1_000_000,
            total_assets_opted_in: 3,
            ..Default::default()
        };

        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        // fee=1000, amount=0 -> sender after = 999_000
        // effective min balance = 100_000 + 3*100_000 = 400_000
        // 999_000 >= 400_000 -> should be accepted
        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "account with assets above effective min balance should be accepted"
        );
    }

    // ====================================================================
    // 15. FeeSink balance tracking tests
    // ====================================================================

    #[test]
    fn fee_sink_credited_after_transaction() {
        let ledger = test_ledger();
        let params = v41_params();
        let fee_sink = Address([0xFE; 32]);
        let (sender, key) = test_keypair(150);
        let (receiver, _) = test_keypair(151);

        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round: 100,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        snapshot.accounts.insert(
            sender,
            Some(AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            }),
        );
        // FeeSink starts with 1_000_000
        snapshot.accounts.insert(
            fee_sink,
            Some(AccountData {
                micro_algos: 1_000_000,
                ..Default::default()
            }),
        );

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                fee_sink,
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        };

        // Submit a transaction with fee=2000
        let stx = make_signed_pay(&key, &sender, &receiver, 0, 2000, 100);
        eval.transaction_group(&[stx]).unwrap();

        // FeeSink should have been credited: 1_000_000 + 2000 = 1_002_000
        assert_eq!(
            eval.effective_balance(&fee_sink),
            1_002_000,
            "FeeSink should be credited with the transaction fee"
        );
        assert_eq!(
            eval.fees_collected, 2000,
            "fees_collected should track the running total"
        );
    }

    #[test]
    fn fee_sink_accumulates_across_groups() {
        let ledger = test_ledger();
        let params = v41_params();
        let fee_sink = Address([0xFE; 32]);
        let (sender, key) = test_keypair(152);
        let (receiver, _) = test_keypair(153);

        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round: 100,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        snapshot.accounts.insert(
            sender,
            Some(AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            }),
        );
        snapshot.accounts.insert(
            fee_sink,
            Some(AccountData {
                micro_algos: 0,
                ..Default::default()
            }),
        );

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                fee_sink,
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        };

        // Group 1: fee=1000
        let stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        eval.transaction_group(&[stx1]).unwrap();

        // Group 2: fee=3000 (different note to get different txid)
        let txn2 = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 0,
            fee: 3000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x01]),
            ..Default::default()
        };
        let sig2 = sign_txn(&txn2, &key);
        let stx2 = SignedTransaction {
            txn: txn2,
            sig: sig2,
            ..Default::default()
        };
        eval.transaction_group(&[stx2]).unwrap();

        // FeeSink should have accumulated: 0 + 1000 + 3000 = 4000
        assert_eq!(
            eval.effective_balance(&fee_sink),
            4000,
            "FeeSink should accumulate fees across groups"
        );
        assert_eq!(
            eval.fees_collected, 4000,
            "fees_collected should accumulate across groups"
        );
    }

    #[test]
    fn fees_collected_in_generated_block() {
        let ledger = test_ledger();
        let params = v41_params();
        let fee_sink = Address([0xFE; 32]);
        let (sender, key) = test_keypair(154);
        let (receiver, _) = test_keypair(155);

        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round: 100,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        snapshot.accounts.insert(
            sender,
            Some(AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            }),
        );
        snapshot.accounts.insert(
            fee_sink,
            Some(AccountData {
                micro_algos: 0,
                ..Default::default()
            }),
        );

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                fee_sink,
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        };

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 5000, 100);
        eval.transaction_group(&[stx]).unwrap();

        let block = eval.generate_block(&[]).unwrap();
        assert_eq!(
            block.fees_collected, 5000,
            "generated block should contain accumulated fees_collected"
        );
    }

    #[test]
    fn fee_sink_rollback_on_min_balance_violation() {
        // When a group is rejected due to min-balance violation,
        // the fees_collected should be rolled back too.
        let ledger = test_ledger();
        let params = v41_params();
        let fee_sink = Address([0xFE; 32]);
        let (sender, key) = test_keypair(156);
        let (receiver, _) = test_keypair(157);

        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round: 100,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        // Sender has 200_000, min_balance = 100_000
        snapshot.accounts.insert(
            sender,
            Some(AccountData {
                micro_algos: 200_000,
                ..Default::default()
            }),
        );
        snapshot.accounts.insert(
            fee_sink,
            Some(AccountData {
                micro_algos: 0,
                ..Default::default()
            }),
        );

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                fee_sink,
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        };

        // First: a valid group with fee=1000
        let stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        eval.transaction_group(&[stx1]).unwrap();
        assert_eq!(eval.fees_collected, 1000);

        // Second: a group that will fail min-balance (would leave 99_000 < 100_000)
        let txn2 = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 99_000,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x01]),
            ..Default::default()
        };
        let sig2 = sign_txn(&txn2, &key);
        let stx2 = SignedTransaction {
            txn: txn2,
            sig: sig2,
            ..Default::default()
        };
        assert!(eval.transaction_group(&[stx2]).is_err());

        // fees_collected should be rolled back to 1000 (from the first group only)
        assert_eq!(
            eval.fees_collected, 1000,
            "fees_collected should be rolled back on rejection"
        );
        // FeeSink balance should also be rolled back
        assert_eq!(
            eval.effective_balance(&fee_sink),
            1000,
            "FeeSink balance should be rolled back on rejection"
        );
    }

    // ====================================================================
    // F6. sender == close_remainder_to test
    // ====================================================================

    #[test]
    fn close_remainder_to_self_zeros_sender() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(200);
        let (receiver, _) = test_keypair(201);
        // Sender: 1_000_000, fee=1000, amount=100_000
        // close_remainder_to = sender (self-close)
        // After fee + amount: 1_000_000 - 1000 - 100_000 = 899_000
        // Close to self: remaining goes to sender... but sender is set to 0.
        // Net result: sender ends at 0, receiver gets 100_000.
        // The close-to-self should NOT double-credit because the code
        // skips the credit when close_addr == sender.
        let initial_receiver_balance = 100_000u64;
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[(sender, 1_000_000), (receiver, initial_receiver_balance)],
        );

        let mut stx = make_signed_pay(&key, &sender, &receiver, 100_000, 1000, 100);
        stx.txn.close_remainder_to = sender; // close to self
        stx.sig = sign_txn(&stx.txn, &key);

        assert!(eval.transaction_group(&[stx]).is_ok());

        // Sender should be zero (closed)
        assert_eq!(
            eval.effective_balance(&sender),
            0,
            "sender should be zero after self-close"
        );
        // Receiver should get the amount
        assert_eq!(
            eval.effective_balance(&receiver),
            initial_receiver_balance + 100_000,
            "receiver should get the payment amount"
        );
    }

    // ====================================================================
    // F7. sender == fee_sink: fees_collected NOT incremented
    // ====================================================================

    #[test]
    fn sender_is_fee_sink_no_fees_collected_increment() {
        let ledger = test_ledger();
        let params = v41_params();
        // Use a deterministic address as FeeSink. We need the sender to
        // BE the fee_sink address.
        let (fee_sink_addr, fee_sink_key) = test_keypair(210);
        let (receiver, _) = test_keypair(211);

        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round: 100,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        snapshot.accounts.insert(
            fee_sink_addr,
            Some(algo_types::AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            }),
        );
        snapshot.accounts.insert(
            receiver,
            Some(algo_types::AccountData {
                micro_algos: 100_000,
                ..Default::default()
            }),
        );

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                fee_sink: fee_sink_addr, // FeeSink IS the sender
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        };

        // Send a transaction FROM the FeeSink address
        let stx = make_signed_pay(&fee_sink_key, &fee_sink_addr, &receiver, 1000, 1000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "transaction from FeeSink should succeed"
        );

        // fees_collected should NOT be incremented when sender == FeeSink
        assert_eq!(
            eval.fees_collected, 0,
            "fees_collected should not be incremented when sender is the FeeSink"
        );

        // The fee_sink balance should reflect only the amount debit (1000),
        // NOT the fee debit, because the fee is a self-transfer (no-op).
        // Original: 10_000_000, amount sent: 1000 => expected: 9_999_000
        assert_eq!(
            eval.effective_balance(&fee_sink_addr),
            10_000_000 - 1000, // amount only, fee is self-transfer
            "fee_sink balance should only be debited by the payment amount, not the fee"
        );
    }

    // ====================================================================
    // 16. Rekey / auth-addr validation tests
    // ====================================================================

    /// Helper: build a signed payment txn with a custom auth_addr field.
    /// The transaction is signed by `signer_key` and the `auth_addr` on
    /// the SignedTransaction is set to `auth_addr_opt`.
    fn make_signed_pay_with_auth(
        signer_key: &SigningKey,
        sender: &Address,
        receiver: &Address,
        amount: u64,
        fee: u64,
        round: u64,
        auth_addr_opt: Option<Address>,
    ) -> SignedTransaction {
        let txn = Transaction {
            txn_type: TxnType::Pay,
            sender: *sender,
            receiver: *receiver,
            amount,
            fee,
            first_valid: Round(round),
            last_valid: Round(round + 1000),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            ..Default::default()
        };
        let sig = sign_txn(&txn, signer_key);
        SignedTransaction {
            txn,
            sig,
            auth_addr: auth_addr_opt,
            ..Default::default()
        }
    }

    /// Helper: build a signed payment txn with rekey_to set.
    #[allow(clippy::too_many_arguments)]
    fn make_signed_pay_with_rekey(
        signer_key: &SigningKey,
        sender: &Address,
        receiver: &Address,
        amount: u64,
        fee: u64,
        round: u64,
        auth_addr_opt: Option<Address>,
        rekey_to: Address,
    ) -> SignedTransaction {
        let txn = Transaction {
            txn_type: TxnType::Pay,
            sender: *sender,
            receiver: *receiver,
            amount,
            fee,
            first_valid: Round(round),
            last_valid: Round(round + 1000),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            rekey_to: Some(rekey_to),
            ..Default::default()
        };
        let sig = sign_txn(&txn, signer_key);
        SignedTransaction {
            txn,
            sig,
            auth_addr: auth_addr_opt,
            ..Default::default()
        }
    }

    #[test]
    fn rekey_correct_auth_addr_passes() {
        // Account has been rekeyed in the ledger. Transaction with the
        // correct auth_addr should pass validation.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, _sender_key) = test_keypair(160);
        let (receiver, _) = test_keypair(161);
        let (auth, auth_key) = test_keypair(162);

        // Set up the sender's account with auth_addr pointing to the
        // auth key (simulating a prior rekey).
        let sender_acct = AccountData {
            micro_algos: 10_000_000,
            auth_addr: Some(auth),
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        // Transaction is signed by auth_key, auth_addr=Some(auth).
        let stx =
            make_signed_pay_with_auth(&auth_key, &sender, &receiver, 0, 1000, 100, Some(auth));

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "rekeyed account with correct auth_addr should be accepted"
        );
    }

    #[test]
    fn rekey_wrong_auth_addr_rejected() {
        // Account has been rekeyed in the ledger. Transaction with the
        // wrong auth_addr (signed by original sender key) should fail.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, sender_key) = test_keypair(163);
        let (receiver, _) = test_keypair(164);
        let (auth, _auth_key) = test_keypair(165);

        // Sender has auth_addr = auth (rekeyed).
        let sender_acct = AccountData {
            micro_algos: 10_000_000,
            auth_addr: Some(auth),
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        // Transaction is signed by sender_key (wrong!) with no auth_addr.
        // The authorizer is sender, but the ledger expects auth.
        let stx = make_signed_pay_with_auth(&sender_key, &sender, &receiver, 0, 1000, 100, None);

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("should have been authorized by"),
            "expected auth-addr mismatch error, got: {err}"
        );
    }

    #[test]
    fn rekey_missing_auth_addr_rejected() {
        // Account has been rekeyed but the transaction doesn't set
        // auth_addr at all (authorizer = sender, expected = auth).
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, sender_key) = test_keypair(166);
        let (receiver, _) = test_keypair(167);
        let (auth, _) = test_keypair(168);

        let sender_acct = AccountData {
            micro_algos: 10_000_000,
            auth_addr: Some(auth),
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        // No auth_addr on the transaction — authorizer defaults to sender.
        let stx = make_signed_pay_with_auth(&sender_key, &sender, &receiver, 0, 1000, 100, None);

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("should have been authorized by"),
            "expected auth-addr mismatch error, got: {err}"
        );
    }

    #[test]
    fn non_rekeyed_account_with_auth_addr_rejected() {
        // Account has NOT been rekeyed (auth_addr is None/zero in ledger).
        // Transaction sets auth_addr to some other address — this should fail
        // because the expected authorizer is the sender itself.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, _sender_key) = test_keypair(169);
        let (receiver, _) = test_keypair(170);
        let (other, other_key) = test_keypair(171);

        // Sender has no auth_addr — not rekeyed.
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // Transaction claims auth_addr = other (wrong!).
        let stx =
            make_signed_pay_with_auth(&other_key, &sender, &receiver, 0, 1000, 100, Some(other));

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("should have been authorized by"),
            "expected auth-addr mismatch error, got: {err}"
        );
    }

    #[test]
    fn rekey_to_within_block_affects_subsequent_txn() {
        // Transaction 1: sender rekeys to auth via rekey_to.
        // Transaction 2: sender must now use auth as authorizer.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, sender_key) = test_keypair(172);
        let (receiver, _) = test_keypair(173);
        let (auth, auth_key) = test_keypair(174);

        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // Txn 1: sender sends a payment and rekeys to auth.
        // Signed by sender_key (no auth_addr set), rekey_to = auth.
        let stx1 =
            make_signed_pay_with_rekey(&sender_key, &sender, &receiver, 0, 1000, 100, None, auth);
        assert!(
            eval.transaction_group(&[stx1]).is_ok(),
            "rekey transaction should succeed"
        );

        // Txn 2: sender sends another payment, now signed by auth_key
        // with auth_addr = auth. This should succeed because the overlay
        // tracks the rekey from txn 1.
        let stx2 =
            make_signed_pay_with_auth(&auth_key, &sender, &receiver, 0, 1000, 100, Some(auth));
        assert!(
            eval.transaction_group(&[stx2]).is_ok(),
            "post-rekey transaction with correct auth should succeed"
        );
    }

    #[test]
    fn rekey_to_within_block_old_key_rejected() {
        // Transaction 1: sender rekeys to auth.
        // Transaction 2: sender tries to use the old key — should fail.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, sender_key) = test_keypair(175);
        let (receiver, _) = test_keypair(176);
        let (auth, _auth_key) = test_keypair(177);

        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // Txn 1: rekey to auth.
        let stx1 =
            make_signed_pay_with_rekey(&sender_key, &sender, &receiver, 0, 1000, 100, None, auth);
        assert!(
            eval.transaction_group(&[stx1]).is_ok(),
            "rekey transaction should succeed"
        );

        // Txn 2: try to use sender_key (old key, no auth_addr).
        let stx2 = make_signed_pay_with_auth(&sender_key, &sender, &receiver, 0, 1000, 100, None);
        let err = eval.transaction_group(&[stx2]).unwrap_err();
        assert!(
            err.to_string().contains("should have been authorized by"),
            "old key after rekey should be rejected, got: {err}"
        );
    }

    #[test]
    fn rekey_back_to_self_restores_original_key() {
        // Transaction 1: sender rekeys to auth.
        // Transaction 2: sender (signed by auth) rekeys back to self.
        // Transaction 3: sender uses original key — should succeed.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, sender_key) = test_keypair(178);
        let (receiver, _) = test_keypair(179);
        let (auth, auth_key) = test_keypair(180);

        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // Txn 1: rekey sender -> auth.
        let stx1 =
            make_signed_pay_with_rekey(&sender_key, &sender, &receiver, 0, 1000, 100, None, auth);
        assert!(
            eval.transaction_group(&[stx1]).is_ok(),
            "rekey to auth should succeed"
        );

        // Txn 2: rekey sender -> sender (rekey back to self), signed by auth.
        let stx2 = make_signed_pay_with_rekey(
            &auth_key,
            &sender,
            &receiver,
            0,
            1000,
            100,
            Some(auth),
            sender,
        );
        assert!(
            eval.transaction_group(&[stx2]).is_ok(),
            "rekey back to self should succeed"
        );

        // Txn 3: sender uses original key (no auth_addr).
        let stx3 = make_signed_pay_with_auth(&sender_key, &sender, &receiver, 0, 1000, 100, None);
        assert!(
            eval.transaction_group(&[stx3]).is_ok(),
            "after rekeying back to self, original key should work"
        );
    }

    // ====================================================================
    // Reward-adjusted balance tests
    // ====================================================================

    /// Helper: build an evaluator with a non-zero rewards_level in the block
    /// header, allowing tests to exercise reward-adjusted balance logic.
    fn make_evaluator_with_rewards(
        ledger: &Arc<Mutex<SqliteLedger>>,
        params: &ConsensusParams,
        round: u64,
        rewards_level: u64,
        full_accounts: &[(Address, AccountData)],
    ) -> SimpleBlockEvaluator {
        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        for (addr, acct) in full_accounts {
            snapshot.accounts.insert(*addr, Some(acct.clone()));
        }
        SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(round),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                rewards_level,
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        }
    }

    #[test]
    fn reward_adjusted_effective_balance() {
        // An account with 2_000_000 microAlgos (2 reward units) and
        // rewards_base=10, with block rewards_level=20, should have
        // pending rewards = (20-10) * (2_000_000 / 1_000_000) = 20.
        // Effective balance = 2_000_000 + 20 = 2_000_020.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, _key) = test_keypair(1);
        let acct = AccountData {
            micro_algos: 2_000_000,
            rewards_base: 10,
            status: algo_types::AccountStatus::Online,
            ..Default::default()
        };
        let mut eval = make_evaluator_with_rewards(&ledger, &params, 100, 20, &[(sender, acct)]);

        assert_eq!(eval.effective_balance(&sender), 2_000_020);
    }

    #[test]
    fn reward_adjusted_balance_allows_transfer_above_raw() {
        // Sender has 1_000_000 raw microAlgos + pending rewards of 500_000.
        // This means the sender can afford a transfer of up to ~1_500_000.
        // Without reward adjustment, a 1_200_000 (amount + fee) transfer
        // would be rejected because raw balance is only 1_000_000.
        //
        // Setup: 1_000_000 microAlgos, rewards_base=0, rewards_level=500_000.
        // reward_units = 1_000_000 / 1_000_000 = 1
        // pending = (500_000 - 0) * 1 = 500_000
        // effective = 1_000_000 + 500_000 = 1_500_000
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(1);
        let (receiver, _) = test_keypair(2);
        let fee_sink = Address([0xFE; 32]);
        let acct = AccountData {
            micro_algos: 1_000_000,
            rewards_base: 0,
            status: algo_types::AccountStatus::Online,
            ..Default::default()
        };
        // Also seed the fee_sink so it exists.
        let fee_sink_acct = AccountData {
            micro_algos: 10_000_000,
            ..Default::default()
        };
        let mut eval = make_evaluator_with_rewards(
            &ledger,
            &params,
            100,
            500_000,
            &[(sender, acct), (fee_sink, fee_sink_acct)],
        );
        eval.hdr.fee_sink = fee_sink;

        // Send 1_199_000 + 1_000 fee = 1_200_000 total cost.
        // Raw balance = 1_000_000 would fail, but reward-adjusted = 1_500_000 passes.
        let stx = make_signed_pay(&key, &sender, &receiver, 1_199_000, 1_000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "transfer should succeed with reward-adjusted balance"
        );
    }

    #[test]
    fn not_participating_gets_no_reward_adjustment() {
        // NotParticipating accounts do not receive rewards, so the
        // effective balance should equal the raw micro_algos.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, _key) = test_keypair(1);
        let acct = AccountData {
            micro_algos: 5_000_000,
            rewards_base: 0,
            status: algo_types::AccountStatus::NotParticipating,
            ..Default::default()
        };
        let mut eval = make_evaluator_with_rewards(&ledger, &params, 100, 100, &[(sender, acct)]);

        // Without reward adjustment, would be 5_000_000.
        // With reward adjustment for Online, would be 5_000_000 + (100 * 5) = 5_000_500.
        // But NotParticipating → no rewards → 5_000_000.
        assert_eq!(eval.effective_balance(&sender), 5_000_000);
    }

    #[test]
    fn reward_adjusted_balance_raw_below_threshold_but_adjusted_above() {
        // Sender's raw balance is below the amount needed, but after
        // reward adjustment the effective balance is sufficient.
        // raw = 900_000, reward units = 0 (below 1 Algo), so no adjustment.
        // This verifies sub-unit balances correctly get no reward boost.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, _key) = test_keypair(1);
        let acct = AccountData {
            micro_algos: 900_000,
            rewards_base: 0,
            status: algo_types::AccountStatus::Online,
            ..Default::default()
        };
        let mut eval = make_evaluator_with_rewards(&ledger, &params, 100, 1_000, &[(sender, acct)]);

        // reward_units = 900_000 / 1_000_000 = 0 (integer division)
        // pending = 1000 * 0 = 0
        // effective = 900_000
        assert_eq!(eval.effective_balance(&sender), 900_000);
    }

    #[test]
    fn reward_adjusted_balance_offline_still_gets_rewards() {
        // Offline accounts (not NotParticipating) still receive rewards,
        // matching Go's behavior where only NotParticipating is excluded.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, _key) = test_keypair(1);
        let acct = AccountData {
            micro_algos: 3_000_000,
            rewards_base: 5,
            status: algo_types::AccountStatus::Offline,
            ..Default::default()
        };
        let mut eval = make_evaluator_with_rewards(&ledger, &params, 100, 15, &[(sender, acct)]);

        // reward_units = 3_000_000 / 1_000_000 = 3
        // pending = (15 - 5) * 3 = 30
        // effective = 3_000_000 + 30 = 3_000_030
        assert_eq!(eval.effective_balance(&sender), 3_000_030);
    }

    // ====================================================================
    // 16. Non-payment transaction type balance handling tests
    // ====================================================================

    /// Helper: build a signed non-payment transaction (only fee deducted).
    fn make_signed_txn(
        sender_key: &SigningKey,
        sender: &Address,
        txn_type: TxnType,
        fee: u64,
        round: u64,
    ) -> SignedTransaction {
        let txn = Transaction {
            txn_type,
            sender: *sender,
            fee,
            first_valid: Round(round),
            last_valid: Round(round + 1000),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            ..Default::default()
        };
        let sig = sign_txn(&txn, sender_key);
        SignedTransaction {
            txn,
            sig,
            ..Default::default()
        }
    }

    #[test]
    fn keyreg_only_deducts_fee() {
        // Key registration transactions should only deduct the fee from the
        // sender's Algo balance — no amount or close-remainder-to handling.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(110);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 1_000_000)]);

        let stx = make_signed_txn(&key, &sender, TxnType::Keyreg, 1000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "keyreg transaction should be accepted"
        );
        // Only fee deducted: 1_000_000 - 1000 = 999_000
        assert_eq!(eval.effective_balance(&sender), 999_000);
    }

    #[test]
    fn acfg_only_deducts_fee() {
        // Asset config transactions should only deduct the fee.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(111);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 1_000_000)]);

        let stx = make_signed_txn(&key, &sender, TxnType::Acfg, 1000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "acfg transaction should be accepted"
        );
        assert_eq!(eval.effective_balance(&sender), 999_000);
    }

    #[test]
    fn afrz_only_deducts_fee() {
        // Asset freeze transactions should only deduct the fee.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(112);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 1_000_000)]);

        let stx = make_signed_txn(&key, &sender, TxnType::Afrz, 1000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "afrz transaction should be accepted"
        );
        assert_eq!(eval.effective_balance(&sender), 999_000);
    }

    #[test]
    fn appl_only_deducts_fee() {
        // Application call transactions should only deduct the fee from Algo
        // balance (inner transactions are handled separately).
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(113);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 1_000_000)]);

        let stx = make_signed_txn(&key, &sender, TxnType::Appl, 1000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "appl transaction should be accepted"
        );
        assert_eq!(eval.effective_balance(&sender), 999_000);
    }

    #[test]
    fn axfer_does_not_deduct_algo_amount() {
        // Asset transfer transactions move asset units (not Algos).
        // The `amount` field on Transaction is the payment-specific `amt`
        // field. For axfer, the asset amount is in `asset_amount` (`aamt`).
        // Only the fee should be deducted from the sender's Algo balance.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(114);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 1_000_000)]);

        let stx = make_signed_txn(&key, &sender, TxnType::Axfer, 1000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "axfer transaction should be accepted"
        );
        // Only fee deducted, asset_amount does not affect Algo balance.
        assert_eq!(eval.effective_balance(&sender), 999_000);
    }

    #[test]
    fn axfer_with_receiver_does_not_credit_algo_balance() {
        // Even when an axfer has receiver and amount fields set (which they
        // could be due to the flat Transaction struct), the Algo balance of
        // the receiver should NOT be credited. Only payment transactions
        // move Algos via the receiver/amount fields.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(115);
        let (receiver, _) = test_keypair(116);
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[(sender, 1_000_000), (receiver, 500_000)],
        );

        // Build an axfer that happens to have payment fields set (should be
        // ignored for balance purposes).
        let txn = Transaction {
            txn_type: TxnType::Axfer,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            // These are payment fields — should be ignored for axfer:
            receiver,
            amount: 100_000,
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "axfer should be accepted even with payment fields set"
        );
        // Sender: only fee deducted (amount is payment-specific, ignored for axfer)
        assert_eq!(eval.effective_balance(&sender), 999_000);
        // Receiver: unchanged (amount is not credited for non-payment txns)
        assert_eq!(eval.effective_balance(&receiver), 500_000);
    }

    #[test]
    fn non_payment_close_remainder_to_ignored() {
        // The close_remainder_to field is a payment-specific field. If a
        // non-payment transaction somehow has it set, it should NOT cause
        // the sender's balance to be closed out.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(117);
        let (close_addr, _) = test_keypair(118);
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[(sender, 1_000_000), (close_addr, 500_000)],
        );

        // Build a keyreg with close_remainder_to set (should be ignored).
        let txn = Transaction {
            txn_type: TxnType::Keyreg,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            close_remainder_to: close_addr,
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "keyreg with close_remainder_to should be accepted (field ignored)"
        );
        // Sender: only fee deducted, NOT closed out
        assert_eq!(eval.effective_balance(&sender), 999_000);
        // Close address: unchanged
        assert_eq!(eval.effective_balance(&close_addr), 500_000);
    }

    #[test]
    fn non_payment_precheck_only_requires_fee() {
        // The balance precheck should only require fee (not fee+amount) for
        // non-payment transactions. A sender with just enough for the fee
        // plus min-balance should pass.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(119);
        // Sender has min_balance (100_000) + fee (1000) = 101_000.
        // For a payment with amount=50_000, this would fail the precheck.
        // For a keyreg (fee-only), this should succeed.
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 101_000)]);

        let stx = make_signed_txn(&key, &sender, TxnType::Keyreg, 1000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "keyreg with exact fee + min_balance should be accepted"
        );
        assert_eq!(eval.effective_balance(&sender), 100_000);
    }

    #[test]
    fn multiple_non_payment_txn_types_in_sequence() {
        // Multiple non-payment transactions from the same sender should
        // each only deduct their fee, not any amount field.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(120);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 1_000_000)]);

        // Three different non-payment transaction types in sequence.
        // All use round=100 (the block round) but different fees/types
        // to produce unique txids.
        let stx1 = make_signed_txn(&key, &sender, TxnType::Keyreg, 1000, 100);
        let stx2 = make_signed_txn(&key, &sender, TxnType::Acfg, 2000, 100);
        let stx3 = make_signed_txn(&key, &sender, TxnType::Afrz, 1500, 100);

        eval.transaction_group(&[stx1])
            .expect("stx1 keyreg should succeed");
        eval.transaction_group(&[stx2])
            .expect("stx2 acfg should succeed");
        eval.transaction_group(&[stx3])
            .expect("stx3 afrz should succeed");

        // Total fees: 1000 + 2000 + 1500 = 4500
        assert_eq!(eval.effective_balance(&sender), 1_000_000 - 4500);
    }

    #[test]
    fn payment_still_deducts_amount_and_handles_close() {
        // Regression test: ensure payment transactions still correctly
        // deduct amount, credit receiver, and handle close_remainder_to
        // after the transaction-type gating was added.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(121);
        let (receiver, _) = test_keypair(122);
        let (close_addr, _) = test_keypair(123);
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[
                (sender, 2_000_000),
                (receiver, 100_000),
                (close_addr, 300_000),
            ],
        );

        let mut stx = make_signed_pay(&key, &sender, &receiver, 500_000, 1000, 100);
        stx.txn.close_remainder_to = close_addr;
        stx.sig = sign_txn(&stx.txn, &key);

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "payment with close_remainder_to should be accepted"
        );
        // Sender: closed to 0
        assert_eq!(eval.effective_balance(&sender), 0);
        // Receiver: 100_000 + 500_000 = 600_000
        assert_eq!(eval.effective_balance(&receiver), 600_000);
        // Close addr: 300_000 + remainder (2_000_000 - 1000 - 500_000 = 1_499_000)
        assert_eq!(eval.effective_balance(&close_addr), 300_000 + 1_499_000);
    }

    // ====================================================================
    // Resource count delta tracking tests
    // ====================================================================

    #[test]
    fn acfg_create_raises_sender_min_balance() {
        // Creating an asset (acfg with config_asset=0) should raise the
        // sender's effective min-balance by 2 * min_balance: one for the
        // created asset (total_created_assets) counted via
        // total_assets_opted_in, plus a second for the auto-holding.
        // Go reference: asset.go:87-88 sets TotalAssets += 1 and
        // TotalAssetParams += 1. Our effective_min_balance uses
        // total_assets_opted_in (asset holdings) which maps to TotalAssets.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(200);

        // Sender has exactly enough for fee + base min_balance. After the
        // acfg create, the overlay should reflect +1 total_created_assets
        // and +1 total_assets_opted_in, raising effective min to:
        //   base (100_000) + 1*min_balance (assets) = 200_000
        // But we also need the created-asset cost. Total effective min:
        //   100_000 + 1*100_000 (opted-in asset) + 0 (created assets not
        //   counted separately by effective_min_balance) ... wait, let me
        //   check: effective_min_balance counts total_assets_opted_in and
        //   total_created_apps, not total_created_assets directly.
        //
        // Actually, checking the Go code: `MinBalance` uses `TotalAssets`
        // (which includes both holdings and created) for asset cost.
        // Our effective_min_balance uses `total_assets_opted_in` for asset
        // cost. On asset create, Go increments TotalAssets by 1 (for the
        // auto-holding). We do the same with delta_total_assets_opted_in.
        //
        // So effective min after create: base + 1*min_balance = 200_000.
        // Give sender 201_000 (fee=1000, so after fee = 200_000 = min_bal).
        let sender_acct = AccountData {
            micro_algos: 201_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        // Build acfg create transaction (config_asset=0 means create).
        let txn = Transaction {
            txn_type: TxnType::Acfg,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            config_asset: 0,
            asset_params: Some(algo_types::AssetParams::default()),
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        // After create: balance = 200_000, effective min = 200_000.
        // This should just barely pass.
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "acfg create with exact min balance should be accepted"
        );

        // Verify resource deltas were applied.
        let acct_data = eval.get_account_data(&sender).unwrap();
        assert_eq!(
            acct_data.total_assets_opted_in, 1,
            "total_assets_opted_in should be 1 after asset create"
        );
        assert_eq!(
            acct_data.total_created_assets, 1,
            "total_created_assets should be 1 after asset create"
        );
    }

    #[test]
    fn acfg_create_rejected_when_min_balance_too_low() {
        // Creating an asset raises min-balance. If the sender doesn't have
        // enough balance to cover the new min-balance, the txn is rejected.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(201);

        // Sender has 150_000. After fee (1000): 149_000.
        // After acfg create: effective min = 100_000 + 1*100_000 = 200_000.
        // 149_000 < 200_000 -> should be rejected.
        let sender_acct = AccountData {
            micro_algos: 150_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        let txn = Transaction {
            txn_type: TxnType::Acfg,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            config_asset: 0,
            asset_params: Some(algo_types::AssetParams::default()),
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("below minimum"),
            "acfg create should be rejected when balance < new min: {err}"
        );
    }

    #[test]
    fn appl_optin_raises_sender_min_balance() {
        // Opting into an app (on_completion=1 with existing app_id) should
        // raise the sender's effective min-balance by app_flat_opt_in_min_balance.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(202);

        // After opt-in: effective min = base + 1*app_flat_opt_in_min_balance
        // = 100_000 + 100_000 = 200_000.
        // Give sender 201_000 (fee=1000, after fee=200_000).
        let sender_acct = AccountData {
            micro_algos: 201_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        let txn = Transaction {
            txn_type: TxnType::Appl,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            application_id: 42, // existing app
            on_completion: 1,   // OptIn
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "appl opt-in with exact min balance should be accepted"
        );

        let acct_data = eval.get_account_data(&sender).unwrap();
        assert_eq!(
            acct_data.total_apps_opted_in, 1,
            "total_apps_opted_in should be 1 after app opt-in"
        );
    }

    #[test]
    fn appl_optin_rejected_when_min_balance_too_low() {
        // Opting into an app raises min-balance. If the sender doesn't have
        // enough to cover it, the txn is rejected.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(203);

        // After fee (1000): 149_000. Effective min after opt-in: 200_000.
        // 149_000 < 200_000 -> rejected.
        let sender_acct = AccountData {
            micro_algos: 150_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        let txn = Transaction {
            txn_type: TxnType::Appl,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            application_id: 42,
            on_completion: 1, // OptIn
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("below minimum"),
            "appl opt-in should be rejected when balance < new min: {err}"
        );
    }

    #[test]
    fn resource_deltas_rolled_back_on_min_balance_violation() {
        // When a min-balance check fails, the resource count deltas
        // should be rolled back along with balance changes.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(204);

        // Sender has 150_000. After fee: 149_000.
        // acfg create raises min to 200_000 -> violation -> rollback.
        let sender_acct = AccountData {
            micro_algos: 150_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        let txn = Transaction {
            txn_type: TxnType::Acfg,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            config_asset: 0,
            asset_params: Some(algo_types::AssetParams::default()),
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        assert!(eval.transaction_group(&[stx]).is_err());

        // After rollback, resource deltas should be empty and
        // account data should show no changes.
        let acct_data = eval.get_account_data(&sender).unwrap();
        assert_eq!(
            acct_data.total_assets_opted_in, 0,
            "total_assets_opted_in should be 0 after rollback"
        );
        assert_eq!(
            acct_data.total_created_assets, 0,
            "total_created_assets should be 0 after rollback"
        );
        // Balance should also be unchanged (rollback).
        assert_eq!(
            eval.effective_balance(&sender),
            150_000,
            "balance should be restored after rollback"
        );
    }

    #[test]
    fn axfer_optin_raises_sender_min_balance() {
        // Asset opt-in via axfer (sender == asset_receiver, amount == 0)
        // should raise the sender's effective min-balance.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(205);

        // After opt-in: effective min = base + 1*min_balance = 200_000.
        // Give sender 201_000 (fee=1000, after fee=200_000).
        let sender_acct = AccountData {
            micro_algos: 201_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        let txn = Transaction {
            txn_type: TxnType::Axfer,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            xaid: 99,                     // existing asset
            asset_amount: 0,              // opt-in amount
            asset_receiver: Some(sender), // self-transfer = opt-in
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "axfer opt-in with exact min balance should be accepted"
        );

        let acct_data = eval.get_account_data(&sender).unwrap();
        assert_eq!(
            acct_data.total_assets_opted_in, 1,
            "total_assets_opted_in should be 1 after axfer opt-in"
        );
    }

    #[test]
    fn appl_create_raises_sender_min_balance() {
        // Creating an app (application_id=0) should raise the sender's
        // effective min-balance by app_flat_params_min_balance plus
        // schema costs and extra page costs.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(206);

        // App create with global schema: 2 uints, 1 byte-slice, 1 extra page.
        // Effective min after create:
        //   base: 100_000
        //   + 1 * app_flat_params_min_balance (created app): 100_000
        //   + 1 * app_flat_params_min_balance (extra page): 100_000
        //   + 3 * schema_min_balance_per_entry (2 uint + 1 byte): 75_000
        //   + 2 * schema_uint_min_balance: 7_000
        //   + 1 * schema_bytes_min_balance: 25_000
        //   = 407_000
        // Give sender 408_000 (fee=1000, after fee=407_000).
        let sender_acct = AccountData {
            micro_algos: 408_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        let txn = Transaction {
            txn_type: TxnType::Appl,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            application_id: 0, // create
            on_completion: 0,  // NoOp
            global_state_schema: Some(algo_types::StateSchema {
                num_uint: 2,
                num_byte_slice: 1,
            }),
            extra_program_pages: 1,
            approval_program: Some(serde_bytes::ByteBuf::from(vec![0x06, 0x81, 0x01])),
            clear_state_program: Some(serde_bytes::ByteBuf::from(vec![0x06, 0x81, 0x01])),
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "appl create with exact min balance should be accepted"
        );

        let acct_data = eval.get_account_data(&sender).unwrap();
        assert_eq!(
            acct_data.total_created_apps, 1,
            "total_created_apps should be 1 after app create"
        );
        assert_eq!(
            acct_data.total_extra_app_pages, 1,
            "total_extra_app_pages should be 1 after app create"
        );
        assert_eq!(
            acct_data.total_app_schema.num_uint, 2,
            "schema num_uint should be 2 after app create"
        );
        assert_eq!(
            acct_data.total_app_schema.num_byte_slice, 1,
            "schema num_byte_slice should be 1 after app create"
        );
    }

    #[test]
    fn multiple_acfg_creates_accumulate_resource_deltas() {
        // Two asset creates in sequence should accumulate resource deltas.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(207);

        // After 2 creates: effective min = base + 2*min_balance = 300_000.
        // Give sender enough for 2 fees + 300_000.
        let sender_acct = AccountData {
            micro_algos: 302_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        for i in 0..2u64 {
            let txn = Transaction {
                txn_type: TxnType::Acfg,
                sender,
                fee: 1000,
                first_valid: Round(100),
                last_valid: Round(1100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                config_asset: 0,
                asset_params: Some(algo_types::AssetParams::default()),
                // Use note field to make txids unique.
                note: serde_bytes::ByteBuf::from(vec![i as u8]),
                ..Default::default()
            };
            let sig = sign_txn(&txn, &key);
            let stx = SignedTransaction {
                txn,
                sig,
                ..Default::default()
            };
            eval.transaction_group(&[stx])
                .unwrap_or_else(|e| panic!("acfg create {i} should succeed: {e}"));
        }

        let acct_data = eval.get_account_data(&sender).unwrap();
        assert_eq!(
            acct_data.total_assets_opted_in, 2,
            "total_assets_opted_in should be 2 after two asset creates"
        );
        assert_eq!(
            acct_data.total_created_assets, 2,
            "total_created_assets should be 2 after two asset creates"
        );
    }

    // ====================================================================
    // F9. receiver == close_remainder_to: credits accumulate
    // ====================================================================

    #[test]
    fn receiver_equals_close_remainder_to_accumulates_credits() {
        // When receiver and close_remainder_to are the SAME address, the
        // receiver should get both the payment amount AND the remaining
        // close-out balance. The sender should end at 0 (closed).
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(220);
        let (receiver, _) = test_keypair(221);

        let initial_receiver_balance = 100_000u64;
        let sender_balance = 1_000_000u64;
        let amount = 200_000u64;
        let fee = 1_000u64;

        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[
                (sender, sender_balance),
                (receiver, initial_receiver_balance),
            ],
        );

        // Build payment where receiver == close_remainder_to
        let mut stx = make_signed_pay(&key, &sender, &receiver, amount, fee, 100);
        stx.txn.close_remainder_to = receiver; // same as receiver
        stx.sig = sign_txn(&stx.txn, &key);

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "payment with receiver == close_remainder_to should be accepted"
        );

        // Sender should be zero (closed out)
        assert_eq!(
            eval.effective_balance(&sender),
            0,
            "sender should be zero after close"
        );

        // Receiver gets: amount + remainder
        // remainder = sender_balance - fee - amount = 1_000_000 - 1_000 - 200_000 = 799_000
        // total credit to receiver = amount + remainder = 200_000 + 799_000 = 999_000
        let remainder = sender_balance - fee - amount;
        assert_eq!(
            eval.effective_balance(&receiver),
            initial_receiver_balance + amount + remainder,
            "receiver should get both payment amount and close remainder"
        );
    }

    // ====================================================================
    // F10. Empty group rejection
    // ====================================================================

    #[test]
    fn empty_group_rejected() {
        // Calling transaction_group with an empty slice should return an
        // error mentioning the empty group.
        let ledger = test_ledger();
        let params = v41_params();
        let mut eval = make_evaluator(&ledger, &params, 100, &[]);

        let err = eval
            .transaction_group(&[])
            .expect_err("empty group should be rejected");
        assert!(
            err.to_string().contains("empty"),
            "expected error mentioning 'empty', got: {err}"
        );
    }

    // ====================================================================
    // F11. generate_block txn_counter increment
    // ====================================================================

    #[test]
    fn generate_block_txn_counter_incremented() {
        // After processing N transactions, generate_block() should produce
        // a block header whose txn_counter equals the original txn_counter + N.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(230);
        let (receiver, _) = test_keypair(231);

        let starting_txn_counter = 42_000u64;

        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round: 100,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        snapshot.accounts.insert(
            sender,
            Some(AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            }),
        );

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                txn_counter: starting_txn_counter,
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        };

        // Submit 3 individual transaction groups (1 txn each)
        let stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        eval.transaction_group(&[stx1]).unwrap();

        let txn2 = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 0,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x01]),
            ..Default::default()
        };
        let sig2 = sign_txn(&txn2, &key);
        let stx2 = SignedTransaction {
            txn: txn2,
            sig: sig2,
            ..Default::default()
        };
        eval.transaction_group(&[stx2]).unwrap();

        let txn3 = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 0,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x02]),
            ..Default::default()
        };
        let sig3 = sign_txn(&txn3, &key);
        let stx3 = SignedTransaction {
            txn: txn3,
            sig: sig3,
            ..Default::default()
        };
        eval.transaction_group(&[stx3]).unwrap();

        let block = eval.generate_block(&[]).unwrap();

        assert_eq!(
            block.txn_counter,
            starting_txn_counter + 3,
            "txn_counter should equal starting value + number of transactions"
        );
    }

    /// `open_crash_db` must create `crash.sqlite` next to the ledger and the
    /// resulting connection must round-trip persisted state through close +
    /// reopen — exercising the same restore path the agreement service uses
    /// on restart. Covers TASK-61 / [[DOC-21]] §3.7.
    #[test]
    fn test_open_crash_db_roundtrip() {
        use algo_agreement::persistence::{persist, restore};
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        // Use a unique tmp dir so parallel test runs don't collide.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-crashdb-test-{}-{}",
            std::process::id(),
            nonce,
        ));
        fs::create_dir_all(&tmp_dir).expect("create tmp dir");
        let ledger_path = tmp_dir.join("ledger.sqlite");
        let crash_db_path = tmp_dir.join("crash.sqlite");

        let payload: Vec<u8> = b"persisted-agreement-state".to_vec();

        // Open the crash db, write a payload, then drop the connection to
        // simulate a node shutdown / crash.
        {
            let conn = super::open_crash_db(&ledger_path).expect("open crash db");
            persist(&conn, &payload).expect("persist payload");
        }

        // The file must exist next to the ledger using the Go-compatible name.
        assert!(
            crash_db_path.exists(),
            "crash.sqlite was not created at {}",
            crash_db_path.display(),
        );

        // Reopen and restore — must return the exact bytes we wrote.
        let conn = super::open_crash_db(&ledger_path).expect("reopen crash db");
        let restored = restore(&conn)
            .expect("restore must succeed")
            .expect("restored payload must be present");
        assert_eq!(
            restored, payload,
            "restored bytes do not match persisted bytes",
        );

        // Cleanup. Drop conn first so SQLite releases its file handles.
        drop(conn);
        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
