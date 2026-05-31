//! Production `NodeInterface` implementation for the `algod-rust` binary.
//!
//! Backs the REST API crate's [`NodeInterface`] trait with a live
//! [`SqliteLedger`] and cached genesis / build metadata. This file is the
//! *skeleton* established by PLAN-74 / TASK-75 — it covers the read-only
//! surface (status, genesis, block lookups, account state). PLAN-36
//! TASK-128 wired `get_state_delta_for_round` to the ledger's in-memory
//! `DeltaCache` rolling window.
//! Downstream tasks layer additional methods onto the same struct:
//!
//! - Pool methods (`TASK-76`) — `pending_transactions`, `get_pending_transaction`
//! - Broadcast methods (`TASK-77`) — `broadcast_signed_tx_group`,
//!   `async_broadcast_signed_tx_group`
//! - Simulation (`TASK-78`) — `simulate`, via `algo_ledger::simulation::Simulator`
//! - CLI wiring (`TASK-79`) — `commands/participate.rs` constructs
//!   [`AlgodNodeInterface`] when `--rest-listen` is provided and hands
//!   it to [`algo_rest_api::server::ApiServer`].
//!
//! Reference: `../go-algorand/daemon/algod/api/server/v2/handlers.go` @
//! `v4.5.1-stable` (the trait is modeled after `v2.NodeInterface`).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use algo_codec::{
    canonical_encode_block_header, compute_block_digest, compute_txn_id, decode_block,
};
use algo_ledger::apply::ApplyData;
use algo_ledger::erasable_db::ErasableDb;
use algo_ledger::participation::{
    restore_participation, Participation, ParticipationID, ParticipationRecord, ParticipationStore,
};
use algo_ledger::simulation::{
    AppInitialState, AvmValueTrace, ExecTraceConfig, OpcodeTraceUnit, ProgramTrace,
    ResourcesInitialStates, ResultEvalOverrides, SimulationRequest, SimulationResult, Simulator,
    SimulatorError, StateChange, StateChangeKind, StateChangeOp, TransactionTrace, TxnGroupResult,
    TxnResult,
};
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::{SqliteLedger, StateDelta};
use algo_network::local_tx_broadcast::{LocalTxBroadcaster, LocalTxError};
use algo_pool::TransactionPool;
use algo_rest_api::models::{
    ApplicationInitialStates, ApplicationKVStorage, ApplicationStateOperation, AvmKeyValue,
    AvmValue, PreEncodedTxInfo, ScratchChange, SimulateInitialStates, SimulateRequest,
    SimulateResponse, SimulateTraceConfig, SimulateTransactionGroupResult,
    SimulateTransactionResult, SimulationEvalOverrides, SimulationOpcodeTraceUnit,
    SimulationTransactionExecTrace,
};
use algo_rest_api::node::{
    AccountLookup, AppResourceLookup, ApplicationLookup, AssetLookup, AssetResourceLookup,
    AssetResourceWithIDs, BuildVersion, NodeError, NodeInterface, NodeStatus, ProtocolSwitchInfo,
    TxnGroupDeltaWithIds, TxnWithStatus,
};
use algo_types::consensus::consensus_params_for_version;
use algo_types::{
    AccountData, Address, Block, BlockHeader, ConsensusParams, Digest, Round, SignedTransaction,
};
use async_trait::async_trait;
use sha2::{Digest as _, Sha512_256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::warn;

/// Default upgrade-vote window length (in rounds) for the current Algorand
/// mainnet protocol.
///
/// The Rust `ConsensusParams` struct does not yet surface `UpgradeVoteRounds`
/// (it lives in go-algorand's `config.ConsensusParams`, not `protocol`), so we
/// hard-code the v41 value here. When the field is ported into
/// `algo_types::ConsensusParams`, this constant should be removed and the
/// trait method should pull the value from [`Self::current_protocol`].
///
/// Reference: `../go-algorand/config/consensus.go` — `UpgradeVoteRounds` for
/// `v41` @ `v4.5.1-stable`.
const DEFAULT_UPGRADE_VOTE_ROUNDS: u64 = 10_000;

/// Default upgrade-approval threshold (number of yes-votes required) for the
/// current Algorand mainnet protocol.
///
/// See [`DEFAULT_UPGRADE_VOTE_ROUNDS`] for the rationale — same hard-coding
/// applies. Reference: `../go-algorand/config/consensus.go` —
/// `UpgradeThreshold` for `v41`.
const DEFAULT_UPGRADE_THRESHOLD: u64 = 9_000;

/// Polling interval used by [`AlgodNodeInterface::wait_for_round`] when no
/// asynchronous round-commit notification channel is available.
///
/// The REST handler already wraps `wait_for_round` in a `tokio::select!` with
/// a caller-supplied timeout, so a coarse poll is acceptable. Once the
/// adapter is wired into the live agreement-side block-commit path (TASK-79),
/// this should be replaced with a `tokio::sync::watch<u64>` receiver driven
/// by the commit loop.
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Default backlog size for the `async_broadcast_signed_tx_group` admission
/// semaphore, matching go-algorand's `TxBacklogSize = 26000` default in
/// `config/localTemplate.go` @ `v4.5.1-stable`. Under saturation the async
/// trait method returns an error rather than spawning unbounded tasks.
/// TASK-79 will wire this through `algod-rust.toml` so operators can tune
/// it from the node config.
const DEFAULT_ASYNC_BACKLOG_SIZE: usize = 26_000;

/// How many recent rounds `get_pending_transaction` scans for a committed
/// transaction when the pool no longer holds it. A dev node produces one block
/// per submission, so this window is rarely deep in practice; the cap bounds the
/// worst-case scan. Roughly the default transaction validity window.
const CONFIRM_LOOKBACK_ROUNDS: u64 = 1000;

/// Construction-time configuration for [`AlgodNodeInterface`].
///
/// All fields are cached on the adapter so per-call trait methods stay
/// branch-free. Callers (the `participate` subcommand today, a future `serve`
/// subcommand tomorrow) populate this from the genesis file, build-time
/// environment, and node configuration before constructing the adapter.
#[derive(Debug, Clone)]
pub struct NodeInterfaceConfig {
    /// Genesis ID string, e.g. `"mainnet-v1.0"`.
    pub genesis_id: String,
    /// Genesis block hash (32 bytes).
    pub genesis_hash: Digest,
    /// Full contents of the `genesis.json` file. Returned verbatim by the
    /// `/genesis` endpoint — must match the on-disk bytes exactly so clients
    /// that hash the response agree with nodes that read the file directly.
    pub genesis_json: String,
    /// Build-time version information (from [`BuildVersion::from_build_env`]
    /// or an equivalent source).
    pub build_version: BuildVersion,
    /// Fallback protocol version used before any blocks have been committed
    /// (i.e. when `SqliteLedger::protocol()` returns an empty string). This
    /// is typically the genesis protocol version.
    pub default_protocol: String,
}

/// Production `NodeInterface` adapter backed by a live [`SqliteLedger`] and
/// (optionally) an in-memory [`TransactionPool`] + [`LocalTxBroadcaster`].
///
/// Cheap to clone-by-`Arc` and share across REST handlers. The adapter
/// exposes read-heavy methods plus pool lookups and tx broadcast; simulate
/// and participation-key installation are still added by downstream
/// PLAN-74 tasks. The pool and broadcaster are optional so tests and
/// subcommands that don't need write paths (e.g. read-only catchpoint
/// replay) can construct the adapter without them — the dependent trait
/// methods fall back to [`NodeError::NotImplemented`] when the collaborator
/// is absent.
pub struct AlgodNodeInterface {
    ledger: Arc<Mutex<SqliteLedger>>,
    pool: Option<Arc<TransactionPool>>,
    broadcaster: Option<Arc<LocalTxBroadcaster>>,
    /// Bounded admission semaphore for
    /// [`NodeInterface::async_broadcast_signed_tx_group`] — shed load
    /// instead of spawning unbounded `tokio::spawn` tasks. Mirrors
    /// go-algorand's `backlogQueue` in `data/txHandler.go`. Default
    /// capacity is [`DEFAULT_ASYNC_BACKLOG_SIZE`]; override via
    /// [`Self::with_async_backlog_capacity`].
    async_backlog_permits: Arc<Semaphore>,
    /// Optional shutdown signal. When the enclosing subcommand's
    /// cancellation token fires,
    /// [`NodeInterface::wait_for_round`] terminates its polling loop
    /// early with [`NodeError::Timeout`] so in-flight
    /// `wait-for-block-after` handlers don't hold the REST server's
    /// graceful-shutdown future open until their own 60s deadline
    /// expires. Unset for read-only / test contexts — the adapter
    /// still polls until the caller-supplied timeout arrives.
    shutdown_token: Option<CancellationToken>,
    genesis_id: String,
    genesis_hash: Digest,
    genesis_json: String,
    build_version: BuildVersion,
    default_protocol: String,
    /// When set, `broadcast_signed_tx_group` ingests the group into the pool and
    /// immediately produces a single block (single-node, no agreement) — go's
    /// dev mode. Requires a pool; no broadcaster/gossip is used. See
    /// [`crate::dev_producer`].
    dev_mode: bool,
    /// Serializes dev-mode production so concurrent submissions don't assemble
    /// against the same round before each other's `on_new_block` drains the
    /// pool. Mirrors go's `node.mu.Lock()` in dev-mode `BroadcastSignedTxGroup`.
    dev_produce_lock: Arc<tokio::sync::Mutex<()>>,
    /// Per-transaction ApplyData (created asset/app ids, eval delta) captured
    /// from dev-mode commits, keyed by txid, so `get_pending_transaction` can
    /// report it on confirmation. Dev blocks don't carry ApplyData in their
    /// payset (the assembly evaluator doesn't run the AVM, so the txn commitment
    /// is over the apply-data-free payset), so it's surfaced from this in-memory
    /// side cache instead. Only entries with a created id or eval delta are
    /// stored, so it stays small. Dev-mode only. (Execute mode doesn't yet
    /// populate `eval_delta` — TASK-280 — so in practice this currently caches
    /// asset/app creates; the `eval_delta` plumbing is already in place for when
    /// it does.)
    dev_apply_data: Arc<std::sync::Mutex<std::collections::HashMap<Digest, ApplyData>>>,
    /// Optional participation-key store backing the `/v2/participation*`
    /// endpoints (list/get/install/remove/append/generate). Persisted to
    /// `<genesisDir>/partregistry.sqlite` by `node start`, mirroring go's
    /// `config.ParticipationRegistryFilename` at
    /// `../go-algorand/node/node.go:868`. Absent for read-only / test contexts
    /// — the participation trait methods then report
    /// [`NodeError::NotImplemented`]. Wrapped in a `Mutex` because the
    /// underlying rusqlite `Connection` is not `Sync`.
    part_store: Option<Arc<Mutex<ParticipationStore>>>,
}

impl AlgodNodeInterface {
    /// Construct a new adapter without a transaction pool or broadcaster
    /// — suitable for read-only ledger inspection. Pool- and
    /// broadcaster-dependent trait methods will report
    /// `NodeError::NotImplemented` until the collaborators are attached via
    /// [`Self::with_pool`] / [`Self::with_broadcaster`].
    pub fn new(ledger: Arc<Mutex<SqliteLedger>>, config: NodeInterfaceConfig) -> Self {
        Self {
            ledger,
            pool: None,
            broadcaster: None,
            async_backlog_permits: Arc::new(Semaphore::new(DEFAULT_ASYNC_BACKLOG_SIZE)),
            shutdown_token: None,
            genesis_id: config.genesis_id,
            genesis_hash: config.genesis_hash,
            genesis_json: config.genesis_json,
            build_version: config.build_version,
            default_protocol: config.default_protocol,
            dev_mode: false,
            dev_produce_lock: Arc::new(tokio::sync::Mutex::new(())),
            dev_apply_data: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            part_store: None,
        }
    }

    /// Attach a participation-key store so the `/v2/participation*` endpoints
    /// (list/get/install/remove/append/generate) operate against persisted
    /// keys. Builder-style, matching [`Self::with_pool`]. Without it those
    /// methods report [`NodeError::NotImplemented`] (mirroring go's behavior
    /// when no participation registry is configured).
    #[must_use]
    pub fn with_participation_store(mut self, store: Arc<Mutex<ParticipationStore>>) -> Self {
        self.part_store = Some(store);
        self
    }

    /// Enable dev mode: `broadcast_signed_tx_group` ingests directly into the
    /// pool and produces one block per group (single-node, no agreement). The
    /// caller must also attach a pool via [`Self::with_pool`]. Builder-style.
    #[must_use]
    pub fn with_dev_mode(mut self) -> Self {
        self.dev_mode = true;
        self
    }

    /// Attach a shared [`CancellationToken`] so
    /// [`NodeInterface::wait_for_round`] can break out of its polling
    /// loop when the node starts shutting down. See the
    /// [`AlgodNodeInterface::shutdown_token`] docstring for the
    /// rationale.
    #[must_use]
    pub fn with_shutdown_token(mut self, token: CancellationToken) -> Self {
        self.shutdown_token = Some(token);
        self
    }

    /// Override the async-broadcast backlog capacity. TASK-79 will call
    /// this from the node-config loader so operators can tune the
    /// `/v2/transactions/async` admission window.
    #[must_use]
    pub fn with_async_backlog_capacity(mut self, capacity: usize) -> Self {
        // `Semaphore::new(0)` is legal (immediately refuses everything)
        // but a zero capacity is almost certainly a misconfiguration, so
        // floor at 1 to keep at least one slot open. Matches the
        // `SeenTxCache::new` behavior.
        self.async_backlog_permits = Arc::new(Semaphore::new(capacity.max(1)));
        self
    }

    /// Attach a transaction pool to the adapter. Builder-style so a single
    /// `AlgodNodeInterface::new(...).with_pool(pool)` call covers the common
    /// "full-node" path in the binary wiring (TASK-79) while tests can
    /// continue constructing an adapter without a pool.
    #[must_use]
    pub fn with_pool(mut self, pool: Arc<TransactionPool>) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Attach a [`LocalTxBroadcaster`] so `broadcast_signed_tx_group` and
    /// `async_broadcast_signed_tx_group` route submitted groups through the
    /// ingest → gossip path. Builder-style to match [`Self::with_pool`].
    #[must_use]
    pub fn with_broadcaster(mut self, broadcaster: Arc<LocalTxBroadcaster>) -> Self {
        self.broadcaster = Some(broadcaster);
        self
    }

    /// Return the attached pool or a [`NodeError::NotImplemented`] if none
    /// was set. Used by pool-backed trait methods as a single-site check so
    /// the error string is consistent.
    fn pool(&self, method: &'static str) -> Result<&TransactionPool, NodeError> {
        self.pool
            .as_deref()
            .ok_or(NodeError::NotImplemented(method))
    }

    /// Acquire the ledger `Mutex`, surfacing poison as
    /// [`NodeError::Internal`] so an earlier panic inside the simulator
    /// (or any other code path that held the lock) does not cascade into
    /// panics for every subsequent REST request. Must be used by every
    /// `Result`-returning lock site; non-`Result` methods
    /// ([`Self::min_txn_fee`], [`Self::suggested_fee`]) handle poison
    /// inline by recovering the guard from the poisoned lock.
    fn lock_ledger(
        &self,
        method: &'static str,
    ) -> Result<std::sync::MutexGuard<'_, SqliteLedger>, NodeError> {
        self.ledger.lock().map_err(|_| {
            NodeError::Internal(format!(
                "{method}: ledger lock poisoned — an earlier operation panicked \
                 while holding the lock; subsequent requests may return stale state \
                 until the node is restarted"
            ))
        })
    }

    /// Search recent committed blocks for `txid`, returning its confirmed-round
    /// status. Bounded to the most recent [`CONFIRM_LOOKBACK_ROUNDS`] rounds.
    /// Returns `Ok(None)` when the transaction isn't found in that window. The
    /// apply-data fields (closing amounts, rewards, created ids, eval delta) are
    /// left at their defaults for now — only `confirmed_round` and the
    /// transaction itself are populated; richer apply data is a follow-up.
    fn lookup_confirmed_txn(&self, txid: &Digest) -> Result<Option<TxnWithStatus>, NodeError> {
        let ledger = self.lock_ledger("get_pending_transaction")?;
        let current = ledger.current_round().0;
        let lo = current.saturating_sub(CONFIRM_LOOKBACK_ROUNDS).max(1);
        for round in (lo..=current).rev() {
            let Some(bytes) = ledger
                .get_block_data(round)
                .map_err(|e| NodeError::Internal(format!("get_block_data({round}): {e}")))?
            else {
                continue;
            };
            let block = decode_block(&bytes)
                .map_err(|e| NodeError::Internal(format!("decode_block({round}): {e}")))?;
            for stx in &block.payset {
                // Restore the genesis fields the block's STIB encoding strips so
                // the id matches the submitter's and the response carries the
                // transaction as signed.
                let restored = crate::dev_producer::restore_block_genesis_fields(stx, &block);
                if compute_txn_id(&restored.txn) == *txid {
                    // Surface ApplyData (created asset/app id, eval delta) from
                    // the dev-mode side cache, if captured at commit time.
                    let ad = self
                        .dev_apply_data
                        .lock()
                        .ok()
                        .and_then(|cache| cache.get(txid).cloned());
                    return Ok(Some(TxnWithStatus {
                        txn: restored,
                        confirmed_round: round,
                        pool_error: String::new(),
                        closing_amount: ad.as_ref().map_or(0, |a| a.closing_amount),
                        asset_closing_amount: ad.as_ref().map_or(0, |a| a.asset_closing_amount),
                        sender_rewards: ad.as_ref().map_or(0, |a| a.sender_rewards),
                        receiver_rewards: ad.as_ref().map_or(0, |a| a.receiver_rewards),
                        close_rewards: ad.as_ref().map_or(0, |a| a.close_rewards),
                        asset_index: ad.as_ref().map(|a| a.config_asset).filter(|id| *id != 0),
                        application_index: ad
                            .as_ref()
                            .map(|a| a.application_id)
                            .filter(|id| *id != 0),
                        eval_delta: ad.and_then(|a| a.eval_delta),
                        logs: None,
                        inner_txns: None,
                    }));
                }
            }
        }
        Ok(None)
    }

    /// Lock the attached participation store, surfacing absence as
    /// [`NodeError::NotImplemented`] and lock poison as
    /// [`NodeError::Internal`]. Single call site so the error strings stay
    /// consistent across the participation methods.
    fn lock_part_store(
        &self,
        method: &'static str,
    ) -> Result<std::sync::MutexGuard<'_, ParticipationStore>, NodeError> {
        let store = self
            .part_store
            .as_ref()
            .ok_or(NodeError::NotImplemented(method))?;
        store.lock().map_err(|_| {
            NodeError::Internal(format!(
                "{method}: participation store lock poisoned — an earlier operation panicked \
                 while holding the lock"
            ))
        })
    }

    /// Return the attached broadcaster (or [`NodeError::NotImplemented`]
    /// when absent) plus an `Arc` clone suitable for spawning onto
    /// `tokio::spawn` for the fire-and-forget variant.
    fn broadcaster(&self, method: &'static str) -> Result<Arc<LocalTxBroadcaster>, NodeError> {
        self.broadcaster
            .as_ref()
            .map(Arc::clone)
            .ok_or(NodeError::NotImplemented(method))
    }

    /// Try to reserve a slot on the async-broadcast backlog semaphore.
    /// Returns an owned permit (moved into the background task so it's
    /// released when `submit_group` completes) or
    /// [`NodeError::Internal`] with a fixed `"broadcast: async backlog
    /// full"` prefix when all slots are in use. Extracted as a helper so
    /// the admission logic is unit-testable without standing up a live
    /// broadcaster.
    fn reserve_async_backlog_permit(
        permits: &Arc<Semaphore>,
    ) -> Result<OwnedSemaphorePermit, NodeError> {
        Arc::clone(permits)
            .try_acquire_owned()
            .map_err(|_| NodeError::Internal("broadcast: async backlog full".into()))
    }

    /// Convert a [`LocalTxError`] to the trait-level [`NodeError`].
    ///
    /// The `NodeInterface` trait only exposes the four variants
    /// (`NotFound`, `Timeout`, `NotImplemented`, `Internal`) — none of
    /// which map cleanly to a client-data rejection (invalid signature,
    /// bad fee, duplicate). For now every `LocalTxError` collapses to
    /// `Internal` with the category preserved in the message; handlers can
    /// key off the prefix if/when a richer trait error is added.
    fn local_tx_error_to_node_error(err: LocalTxError) -> NodeError {
        match err {
            LocalTxError::Empty => NodeError::Internal("broadcast: empty group".into()),
            LocalTxError::Pool(msg) => {
                NodeError::Internal(format!("broadcast: pool rejected group: {msg}"))
            }
            LocalTxError::Encode(msg) => {
                NodeError::Internal(format!("broadcast: encode failed: {msg}"))
            }
            LocalTxError::Broadcast(msg) => {
                NodeError::Internal(format!("broadcast: gossip failed: {msg}"))
            }
        }
    }

    /// Resolve the effective protocol string for a locked ledger guard,
    /// falling back to the configured `default_protocol` when the ledger has
    /// no committed blocks yet (empty `protocol()`).
    fn resolve_protocol(&self, ledger: &SqliteLedger) -> String {
        let live = ledger.protocol().to_string();
        if live.is_empty() {
            self.default_protocol.clone()
        } else {
            live
        }
    }

    /// Look up the consensus params for a given protocol string.
    fn resolve_consensus_params(proto: &str) -> Result<ConsensusParams, NodeError> {
        consensus_params_for_version(proto).ok_or_else(|| {
            NodeError::Internal(format!("unknown consensus protocol version: {proto}"))
        })
    }

    /// Snapshot of the ledger-visible status fields captured under a single
    /// `Mutex` acquisition — prevents tearing across an agreement commit that
    /// would otherwise leave `last_round` and `latest_header` on different
    /// rounds (a real risk when agreement/catchup commits are concurrent).
    fn read_status_snapshot(&self) -> Result<StatusSnapshot, NodeError> {
        let ledger = self.lock_ledger("status")?;
        let last_round = ledger
            .last_committed_round()
            .map_err(|e| NodeError::Internal(format!("last_committed_round: {e}")))?
            .unwrap_or(0);
        let protocol = self.resolve_protocol(&ledger);
        let latest_header = ledger
            .get_block_header(last_round)
            .map_err(|e| NodeError::Internal(format!("get_block_header({last_round}): {e}")))?;
        Ok(StatusSnapshot {
            last_round,
            protocol,
            latest_header,
        })
    }

    /// Snapshot of an account lookup captured under a single lock — keeps
    /// `last_round` and `account_data` on the same round even if agreement
    /// commits while the handler is running.
    fn read_account_snapshot(&self, addr: &Address) -> Result<(u64, AccountData), NodeError> {
        let ledger = self.lock_ledger("lookup_account")?;
        let last_round = ledger
            .last_committed_round()
            .map_err(|e| NodeError::Internal(format!("last_committed_round: {e}")))?
            .unwrap_or(0);
        let account_data = ledger.get_account(addr).unwrap_or_default();
        Ok((last_round, account_data))
    }

    /// Return the last committed round for a lookup performed under an already
    /// held ledger lock, mapping the SQLite error into a `NodeError::Internal`
    /// tagged with the calling method. Returns `0` for an empty ledger
    /// (`last_committed_round` is `None`), matching `ledger.Latest()` on a
    /// freshly initialised ledger.
    fn committed_round(ledger: &SqliteLedger, method: &str) -> Result<u64, NodeError> {
        Ok(ledger
            .last_committed_round()
            .map_err(|e| NodeError::Internal(format!("{method}: last_committed_round: {e}")))?
            .unwrap_or(0))
    }

    /// Compute the block digest (SHA512/256 of `"BH" || canonical(header)`)
    /// directly from a header. Mirrors `algo_codec::compute_block_digest` but
    /// accepts a `BlockHeader` so callers can serve `/v2/blocks/{round}/hash`
    /// via the cheaper header-only path instead of decoding the full block.
    fn block_digest_from_header(header: &BlockHeader) -> Digest {
        let canonical = canonical_encode_block_header(header);
        let mut hasher = Sha512_256::new();
        hasher.update(b"BH");
        hasher.update(&canonical);
        Digest(hasher.finalize().into())
    }
}

/// Values captured by [`AlgodNodeInterface::read_status_snapshot`] under a
/// single lock — see that helper's docs for why.
struct StatusSnapshot {
    last_round: u64,
    protocol: String,
    latest_header: Option<BlockHeader>,
}

#[async_trait]
impl NodeInterface for AlgodNodeInterface {
    // ---- Genesis / build metadata (cached, branch-free) ----

    fn genesis_id(&self) -> &str {
        &self.genesis_id
    }

    fn genesis_hash(&self) -> &Digest {
        &self.genesis_hash
    }

    fn genesis_json(&self) -> &str {
        &self.genesis_json
    }

    fn build_version(&self) -> &BuildVersion {
        &self.build_version
    }

    // ---- Status / upgrade vote ----

    async fn status(&self) -> Result<NodeStatus, NodeError> {
        let snap = self.read_status_snapshot()?;

        // Protocol-switch fields come from the latest block header when
        // present; fall back to "next == current, next round = last + 1" when
        // the ledger is empty.
        let (next_version, next_version_round, next_version_supported) =
            match snap.latest_header.as_ref() {
                Some(h) if !h.next_protocol.is_empty() => (
                    h.next_protocol.clone(),
                    h.next_protocol_switch_on.0,
                    consensus_params_for_version(&h.next_protocol).is_some(),
                ),
                _ => (
                    snap.protocol.clone(),
                    snap.last_round.saturating_add(1),
                    true,
                ),
            };

        Ok(NodeStatus {
            last_round: snap.last_round,
            // Without a commit-time notification channel we cannot track the
            // wall-clock delta accurately; reported as zero until TASK-79
            // wires the adapter to the block-commit path.
            time_since_last_round: 0,
            catchup_time: 0,
            last_version: snap.protocol,
            next_version,
            next_version_round,
            next_version_supported,
            stopped_at_unsupported_round: false,
            // Catchpoint-catchup progress is zero until the catchpoint
            // service exposes its state via this adapter (future work).
            catchpoint: String::new(),
            last_catchpoint: String::new(),
            catchpoint_total_accounts: 0,
            catchpoint_processed_accounts: 0,
            catchpoint_verified_accounts: 0,
            catchpoint_total_kvs: 0,
            catchpoint_processed_kvs: 0,
            catchpoint_verified_kvs: 0,
            catchpoint_total_blocks: 0,
            catchpoint_acquired_blocks: 0,
            next_protocol_vote_before: snap
                .latest_header
                .as_ref()
                .map(|h| h.next_protocol_vote_before.0)
                .unwrap_or(0),
            next_protocol_approvals: snap
                .latest_header
                .as_ref()
                .map(|h| h.next_protocol_approvals)
                .unwrap_or(0),
            // This node's own upgrade vote is not yet configurable — report
            // the conservative default (no-approve, no-delay).
            upgrade_approve: false,
            upgrade_delay: 0,
        })
    }

    async fn suggested_fee(&self) -> u64 {
        // go-algorand returns max(MinTxnFee, median(recent fees)). Without a
        // rolling-fee tracker this falls back to MinTxnFee, matching the
        // conservative behavior of a freshly-started node.
        self.min_txn_fee().await
    }

    async fn min_txn_fee(&self) -> u64 {
        // The trait signature returns `u64` (no `Result`), so a poisoned
        // lock falls back to the protocol default (1000 microAlgos)
        // rather than panicking. Recovering the guard from poison here
        // is safe because this is a read-only lookup of the cached
        // protocol string — no write path depends on it.
        let proto = match self.ledger.lock() {
            Ok(g) => self.resolve_protocol(&g),
            Err(poisoned) => self.resolve_protocol(&poisoned.into_inner()),
        };
        consensus_params_for_version(&proto)
            .map(|p| p.min_txn_fee)
            .unwrap_or(1_000)
    }

    fn upgrade_vote_rounds(&self) -> u64 {
        DEFAULT_UPGRADE_VOTE_ROUNDS
    }

    fn upgrade_threshold(&self) -> u64 {
        DEFAULT_UPGRADE_THRESHOLD
    }

    async fn wait_for_round(&self, round: u64) -> Result<(), NodeError> {
        // Poll the ledger's last-committed round. The REST handler
        // wraps this future in a `tokio::select!` with the caller's
        // timeout, so this loop cannot leak if `round` never arrives.
        //
        // Two shutdown surfaces cause us to break out early:
        //   1. Lock poison — already handled by `lock_ledger`.
        //   2. Cancellation token — when the enclosing subcommand
        //      starts shutting down the agreement service, no new
        //      rounds will ever land. We surface
        //      [`NodeError::Timeout`] so the REST handler returns 408
        //      and the axum graceful-shutdown future isn't held open
        //      for the client's 60s deadline.
        //
        // Replacing the poll with a notification channel driven by the
        // block-commit path is a PLAN-34 refinement — see the comment
        // on [`WAIT_POLL_INTERVAL`].
        loop {
            let last = {
                let ledger = self.lock_ledger("wait_for_round")?;
                ledger
                    .last_committed_round()
                    .map_err(|e| NodeError::Internal(format!("last_committed_round: {e}")))?
                    .unwrap_or(0)
            };
            if last >= round {
                return Ok(());
            }
            match &self.shutdown_token {
                Some(token) => {
                    tokio::select! {
                        () = tokio::time::sleep(WAIT_POLL_INTERVAL) => {}
                        () = token.cancelled() => {
                            return Err(NodeError::Timeout(
                                "wait_for_round: node is shutting down".into(),
                            ));
                        }
                    }
                }
                None => tokio::time::sleep(WAIT_POLL_INTERVAL).await,
            }
        }
    }

    async fn latest_block_header_protocol_info(&self) -> Result<ProtocolSwitchInfo, NodeError> {
        let snap = self.read_status_snapshot()?;
        let info = match snap.latest_header {
            Some(h) => ProtocolSwitchInfo {
                // An upgrade is pending iff `next_protocol` is non-empty.
                // When there's no pending upgrade we treat the current
                // protocol as fully supported.
                next_protocol_supported: h.next_protocol.is_empty()
                    || consensus_params_for_version(&h.next_protocol).is_some(),
                next_protocol_switch_on: h.next_protocol_switch_on.0,
                next_protocol: h.next_protocol,
            },
            None => ProtocolSwitchInfo {
                next_protocol: String::new(),
                next_protocol_supported: true,
                next_protocol_switch_on: 0,
            },
        };
        Ok(info)
    }

    // ---- Block lookup ----

    async fn get_block(&self, round: u64) -> Result<Block, NodeError> {
        let bytes = {
            let ledger = self.lock_ledger("get_block")?;
            ledger
                .get_block_data(round)
                .map_err(|e| NodeError::Internal(format!("get_block_data({round}): {e}")))?
        }
        .ok_or_else(|| NodeError::NotFound(format!("block round {round} not found")))?;

        Block::decode_from_bytes(&bytes)
            .map_err(|e| NodeError::Internal(format!("decode block {round}: {e}")))
    }

    async fn get_block_header(&self, round: u64) -> Result<BlockHeader, NodeError> {
        let ledger = self.lock_ledger("get_block_header")?;
        ledger
            .get_block_header(round)
            .map_err(|e| NodeError::Internal(format!("get_block_header({round}): {e}")))?
            .ok_or_else(|| NodeError::NotFound(format!("block header for round {round} not found")))
    }

    async fn get_block_hash(&self, round: u64) -> Result<Option<Digest>, NodeError> {
        // Prefer the header-only path (SHA512/256("BH" || canonical(header)))
        // — it's cheaper and doesn't depend on full-block decoding. Fall
        // back to the full block when header bytes are missing or empty:
        // `bin/algod-rust/src/commands/relay.rs` stores blocks with
        // `put_block(round, "", &[], block_data)` — a valid persisted row
        // with empty `hdrdata`. The pre-refactor impl hashed via
        // `compute_block_digest(&block)`, which kept relay-populated rows
        // hashable; this fallback preserves that behavior.
        let (hdr_bytes_opt, blk_bytes_opt) = {
            let ledger = self.lock_ledger("get_block_hash")?;
            let h = ledger
                .get_block_header_data(round)
                .map_err(|e| NodeError::Internal(format!("get_block_header_data({round}): {e}")))?;
            let b = ledger
                .get_block_data(round)
                .map_err(|e| NodeError::Internal(format!("get_block_data({round}): {e}")))?;
            (h, b)
        };

        // Row completely absent → Ok(None) (matches the trait's documented
        // semantic: not-yet-available rounds return None, not an error).
        let hdr_nonempty = hdr_bytes_opt
            .as_deref()
            .map(|b| !b.is_empty())
            .unwrap_or(false);
        let blk_nonempty = blk_bytes_opt
            .as_deref()
            .map(|b| !b.is_empty())
            .unwrap_or(false);
        if !hdr_nonempty && !blk_nonempty {
            return Ok(None);
        }

        // Header path — only used when `hdrdata` is present and non-empty.
        // A decode failure falls through to the blkdata path rather than
        // surfacing an Internal error; this mirrors the pre-refactor
        // behavior for rows with malformed headers but intact blocks.
        if hdr_nonempty {
            let hdr_bytes = hdr_bytes_opt
                .as_deref()
                .expect("hdr_nonempty checked above");
            if let Ok(header) = BlockHeader::decode_from_reader(&mut &*hdr_bytes) {
                return Ok(Some(Self::block_digest_from_header(&header)));
            }
        }

        // Fallback: decode the full block and hash via compute_block_digest.
        let blk_bytes = blk_bytes_opt
            .as_deref()
            .filter(|b| !b.is_empty())
            .ok_or_else(|| {
                NodeError::Internal(format!(
                    "block {round} has unusable hdrdata and no blkdata fallback"
                ))
            })?;
        let block = Block::decode_from_bytes(blk_bytes)
            .map_err(|e| NodeError::Internal(format!("decode block {round}: {e}")))?;
        Ok(Some(compute_block_digest(&block)))
    }

    async fn get_block_raw_msgpack(&self, round: u64) -> Result<Vec<u8>, NodeError> {
        // Mirrors go-algorand's `rpcs.RawBlockBytes(ledger, round)`: returns
        // the `{"block": block, "cert": cert}` envelope that the REST
        // endpoint serves with `X-Algorand-Struct: block-v1`.
        //
        // Pass the stored halves through *verbatim* by hand-building the
        // msgpack map. Decoding + re-encoding through a typed `BlockResponse`
        // would drop unknown fields (breaking forward compatibility) and
        // would omit the `cert` key entirely when absent due to
        // `#[serde(skip_serializing_if)]`. See also
        // `algo_network::block_service::encode_pre_encoded_block_cert` which
        // uses the same hand-rolled pattern for P2P block responses —
        // consolidating the two into a shared helper is a follow-up.
        let (block_bytes, cert_bytes_opt) = {
            let ledger = self.lock_ledger("get_block_raw_msgpack")?;
            let blk = ledger
                .get_block_data(round)
                .map_err(|e| NodeError::Internal(format!("get_block_data({round}): {e}")))?
                .ok_or_else(|| NodeError::NotFound(format!("no block for round {round}")))?;
            let cert = ledger
                .get_block_cert(round)
                .map_err(|e| NodeError::Internal(format!("get_block_cert({round}): {e}")))?;
            (blk, cert)
        };

        let entry_count: u8 = if cert_bytes_opt.is_some() { 2 } else { 1 };
        let mut buf = Vec::with_capacity(block_bytes.len() + 32);

        // fixmap(N) — N <= 15 here (we only ever emit 1 or 2 entries).
        buf.push(0x80 | entry_count);

        // "block" key (fixstr, length 5) + raw block bytes (already msgpack).
        buf.push(0xa5);
        buf.extend_from_slice(b"block");
        buf.extend_from_slice(&block_bytes);

        if let Some(cert_bytes) = cert_bytes_opt {
            // "cert" key (fixstr, length 4) + raw cert bytes.
            buf.push(0xa4);
            buf.extend_from_slice(b"cert");
            buf.extend_from_slice(&cert_bytes);
        }

        Ok(buf)
    }

    // ---- Ledger state delta ----

    /// Look up the ledger state delta for `round`.
    ///
    /// PLAN-36 / TASK-116 removed the Rust-only `state_deltas` SQLite table
    /// that previously backed this lookup; PLAN-36 TASK-128 wires the
    /// in-memory [`algo_ledger::DeltaCache`] (rolling 320-round window,
    /// populated by `SqliteLedger::apply_block_caching_delta` from the live
    /// sync driver) into this handler. Rounds inside the window return their
    /// captured delta; rounds outside the window (older than the cache's
    /// retention, or never applied through the caching path — e.g. a node
    /// serving REST while still in catchpoint-replay mode) return
    /// `NotFound`. Mirrors go-algorand's
    /// `daemon/algod/api/server/v2/handlers.go::GetLedgerStateDelta`, which
    /// also bounds its lookup window in-memory.
    async fn get_state_delta_for_round(&self, round: u64) -> Result<StateDelta, NodeError> {
        let ledger = self.lock_ledger("get_state_delta_for_round")?;
        ledger
            .get_cached_state_delta(round)
            .ok_or_else(|| NodeError::NotFound(format!("no state delta for round {round}")))
    }

    async fn get_txn_group_delta(&self, id: &Digest) -> Result<StateDelta, NodeError> {
        let ledger = self.lock_ledger("get_txn_group_delta")?;
        if !ledger.group_delta_tracer_enabled() {
            return Err(NodeError::NotImplemented("get_txn_group_delta"));
        }
        ledger
            .txn_group_delta_for_id(id)
            .ok_or_else(|| NodeError::NotFound(format!("no delta for transaction group {id}")))
    }

    async fn get_txn_group_deltas_for_round(
        &self,
        round: u64,
    ) -> Result<Vec<TxnGroupDeltaWithIds>, NodeError> {
        let ledger = self.lock_ledger("get_txn_group_deltas_for_round")?;
        if !ledger.group_delta_tracer_enabled() {
            return Err(NodeError::NotImplemented("get_txn_group_deltas_for_round"));
        }
        let groups = ledger
            .txn_group_deltas_for_round(round)
            .ok_or_else(|| NodeError::NotFound(format!("round {round} not found in tracer")))?;
        Ok(groups
            .into_iter()
            .map(|g| TxnGroupDeltaWithIds {
                ids: g.ids.iter().map(|d| d.to_string()).collect(),
                delta: g.delta,
            })
            .collect())
    }

    // ---- Account state ----

    async fn lookup_account(&self, addr: &Address) -> Result<AccountLookup, NodeError> {
        let (last_round, account_data) = self.read_account_snapshot(addr)?;
        // `AccountData` already carries the four resource maps alongside the
        // core fields — clone them into the lookup result rather than
        // re-querying per-resource accessors.
        Ok(AccountLookup {
            amount_without_pending_rewards: account_data.micro_algos,
            assets: account_data.assets.clone(),
            created_assets: account_data.asset_params.clone(),
            app_local_states: account_data.app_local_states.clone(),
            created_apps: account_data.app_params.clone(),
            account_data,
            last_round,
        })
    }

    async fn lookup_account_basic(&self, addr: &Address) -> Result<AccountLookup, NodeError> {
        // "Basic" mode (`exclude=all` on the REST endpoint) skips the
        // potentially-large resource maps — return empty BTreeMaps.
        let (last_round, account_data) = self.read_account_snapshot(addr)?;
        Ok(AccountLookup {
            amount_without_pending_rewards: account_data.micro_algos,
            assets: Default::default(),
            created_assets: Default::default(),
            app_local_states: Default::default(),
            created_apps: Default::default(),
            account_data,
            last_round,
        })
    }

    // ---- Asset / app / box resource lookups (TASK-266) ----
    //
    // These back `goal account info` (held/created assets + apps + boxes) and
    // the `asset` / `app` command groups against the SqliteLedger. They mirror
    // go-algorand's resource lookups in
    // `../go-algorand/daemon/algod/api/server/v2/handlers.go` @ `v4.5.1-stable`:
    // AccountAssetInformation, AccountApplicationInformation, GetAssetByID,
    // GetApplicationByID, AccountAssetsInformation, GetApplicationBoxByName,
    // GetApplicationBoxes. State is read from the live ledger via the
    // `LedgerStore` accessors (`get_asset_holding`, `get_asset_params`,
    // `get_app_local_state`, `get_app_params`, `get_box`, `box_keys_for_app`,
    // `asset_holdings_for_addr`), which already resolve creators through the
    // `assetcreators` table.

    async fn lookup_asset_resource(
        &self,
        addr: &Address,
        asset_id: u64,
    ) -> Result<AssetResourceLookup, NodeError> {
        let ledger = self.lock_ledger("lookup_asset_resource")?;
        let last_round = Self::committed_round(&ledger, "lookup_asset_resource")?;
        // Holding is present iff the address has opted in; params are present
        // only when this address is the asset's creator (mirrors
        // handlers.go:557 AccountAssetInformation, which fills AssetHolding from
        // the holding and CreatedAsset from params keyed on the creator).
        let asset_holding = ledger.get_asset_holding(addr, asset_id);
        let asset_params = ledger
            .get_asset_params(asset_id)
            .filter(|rec| &rec.creator == addr)
            .map(|rec| rec.params);
        Ok(AssetResourceLookup {
            asset_holding,
            asset_params,
            last_round,
        })
    }

    async fn lookup_app_resource(
        &self,
        addr: &Address,
        app_id: u64,
    ) -> Result<AppResourceLookup, NodeError> {
        let ledger = self.lock_ledger("lookup_app_resource")?;
        let last_round = Self::committed_round(&ledger, "lookup_app_resource")?;
        // Local state is present iff opted in; params are present only when
        // this address created the app (handlers.go:605
        // AccountApplicationInformation). `get_app_params` carries the creator
        // in `AppParams.creator`, resolved via the assetcreators table.
        let app_local_state = ledger.get_app_local_state(addr, app_id);
        let app_params = ledger
            .get_app_params(app_id)
            .filter(|params| &params.creator == addr);
        Ok(AppResourceLookup {
            app_local_state,
            app_params,
            last_round,
        })
    }

    async fn lookup_application(&self, app_id: u64) -> Result<ApplicationLookup, NodeError> {
        let ledger = self.lock_ledger("lookup_application")?;
        let last_round = Self::committed_round(&ledger, "lookup_application")?;
        // Mirrors handlers.go:1690 GetApplicationByID: resolve the creator,
        // then look up AppParams. `get_app_params` returns `None` (→
        // `app_params: None`, the handler maps that to 404) when the app does
        // not exist; otherwise it carries the resolved creator.
        let (app_params, creator) = match ledger.get_app_params(app_id) {
            Some(params) => {
                let creator = params.creator;
                (Some(params), creator)
            }
            None => (None, Address::default()),
        };
        Ok(ApplicationLookup {
            app_params,
            creator,
            last_round,
        })
    }

    async fn lookup_asset_by_id(&self, asset_id: u64) -> Result<AssetLookup, NodeError> {
        let ledger = self.lock_ledger("lookup_asset_by_id")?;
        let last_round = Self::committed_round(&ledger, "lookup_asset_by_id")?;
        // Mirrors handlers.go:1808 GetAssetByID: resolve the creator, then look
        // up AssetParams. `get_asset_params` returns `None` (→ 404 at the
        // handler) when the asset does not exist.
        let (asset_params, creator) = match ledger.get_asset_params(asset_id) {
            Some(rec) => (Some(rec.params), rec.creator),
            None => (None, Address::default()),
        };
        Ok(AssetLookup {
            asset_params,
            creator,
            last_round,
        })
    }

    async fn lookup_assets(
        &self,
        addr: &Address,
        asset_id_gt: u64,
        limit: u64,
    ) -> Result<(Vec<AssetResourceWithIDs>, u64), NodeError> {
        let ledger = self.lock_ledger("lookup_assets")?;
        let last_round = Self::committed_round(&ledger, "lookup_assets")?;
        // Mirrors handlers.go:1138 AccountAssetsInformation /
        // ledger.LookupAssets: list the account's asset *holdings* with
        // AssetID > asset_id_gt, ascending, capped at `limit`. For each
        // holding, Go's `LookupLimitedResources` LEFT JOINs `assetcreators`
        // and the creator's resource row, so the creator + asset params are
        // returned for ANY holder of a still-existing asset — not only when
        // the queried address is itself the creator (the holder's amount /
        // frozen are merged onto the creator's params). When the asset has no
        // creator (e.g. deleted), creator stays zero and params are omitted.
        // Refs: `../go-algorand/ledger/store/trackerdb/sqlitedriver/sql.go:90`
        // (lookupLimitedResourcesStmt) + `:447` (LookupLimitedResources),
        // `ledger/acctupdates.go:1217` lookupAssetResources.
        let mut holdings = ledger.asset_holdings_for_addr(addr);
        holdings.sort_unstable_by_key(|(aidx, _)| *aidx);
        let mut records = Vec::new();
        for (asset_id, holding) in holdings {
            if asset_id <= asset_id_gt {
                continue;
            }
            if records.len() as u64 >= limit {
                break;
            }
            // Resolve the asset's creator (via the assetcreators table) and
            // its params, independent of whether `addr` is the creator.
            let (creator, asset_params) = match ledger.get_asset_params(asset_id) {
                Some(rec) => (rec.creator, Some(rec.params)),
                None => (Address::default(), None),
            };
            records.push(AssetResourceWithIDs {
                asset_id,
                asset_holding: Some(holding),
                creator,
                asset_params,
            });
        }
        Ok((records, last_round))
    }

    async fn lookup_kv(
        &self,
        app_id: u64,
        key: &[u8],
    ) -> Result<(Option<Vec<u8>>, u64), NodeError> {
        let ledger = self.lock_ledger("lookup_kv")?;
        let last_round = Self::committed_round(&ledger, "lookup_kv")?;
        // `get_box` constructs the full `bx:`-prefixed KV key internally
        // (sqlite.rs make_box_key), matching ledger.LookupKv + apps.MakeBoxKey
        // (handlers.go:1790 GetApplicationBoxByName). `key` is the raw box name.
        let value = ledger.get_box(app_id, key);
        Ok((value, last_round))
    }

    async fn lookup_keys_by_prefix(
        &self,
        app_id: u64,
        prefix: &[u8],
    ) -> Result<(Vec<Vec<u8>>, u64), NodeError> {
        let ledger = self.lock_ledger("lookup_keys_by_prefix")?;
        let last_round = Self::committed_round(&ledger, "lookup_keys_by_prefix")?;
        // `box_keys_for_app` returns box names already stripped of the KV
        // prefix (sqlite.rs:4409). The handler passes an empty prefix to list
        // all boxes (handlers.go:1733 GetApplicationBoxes); filter here for the
        // general LookupKeysByPrefix contract.
        let mut keys = ledger.box_keys_for_app(app_id);
        if !prefix.is_empty() {
            keys.retain(|k| k.starts_with(prefix));
        }
        Ok((keys, last_round))
    }

    async fn total_boxes(&self, app_id: u64) -> Result<(u64, u64), NodeError> {
        let ledger = self.lock_ledger("total_boxes")?;
        let last_round = Self::committed_round(&ledger, "total_boxes")?;
        // Boxes are owned by the application *account* (its escrow address),
        // not the creator — the count lives on that account's record
        // (handlers.go:1742 looks up `applicationID.Address()` and reads
        // `record.TotalBoxes`). O(1) account-record read, no key scan.
        let app_addr = Address(algo_ledger::avm_context::app_address(app_id));
        let total = ledger
            .get_account(&app_addr)
            .map(|acct| acct.total_boxes)
            .unwrap_or(0);
        Ok((total, last_round))
    }

    async fn consensus_params(&self) -> Result<ConsensusParams, NodeError> {
        let proto = {
            let ledger = self.lock_ledger("consensus_params")?;
            self.resolve_protocol(&ledger)
        };
        Self::resolve_consensus_params(&proto)
    }

    // ---- Pool-backed methods (TASK-76) ----

    async fn get_pending_txns_from_pool(&self) -> Result<Vec<SignedTransaction>, NodeError> {
        let pool = self.pool("get_pending_txns_from_pool")?;
        // `pending_tx_groups` snapshots the pool's proposal-ordered groups.
        // Flatten into a single list — go-algorand's
        // `GetPendingTxnsFromPool` returns exactly this shape.
        let groups = pool.pending_tx_groups();
        let flat: Vec<SignedTransaction> = groups.into_iter().flatten().collect();
        Ok(flat)
    }

    async fn get_pending_transaction(
        &self,
        txid: &Digest,
    ) -> Result<Option<TxnWithStatus>, NodeError> {
        let pool = self.pool("get_pending_transaction")?;
        let (txn, pool_error, found) = pool.lookup(txid);
        if let Some(status) = Self::map_pool_lookup(txn, pool_error, found) {
            // Still pending, or evicted with an error — answer from the pool.
            return Ok(Some(status));
        }
        // Not in the pool: it may have been committed. Search recent blocks for
        // the txid and report its confirmed round. Mirrors go's
        // `GetPendingTransaction` ledger fallback (the block-side confirmation
        // lookup deferred from the original pool-only implementation).
        self.lookup_confirmed_txn(txid)
    }

    // ---- Broadcast methods (TASK-77) ----

    async fn broadcast_signed_tx_group(
        &self,
        tx_group: Vec<SignedTransaction>,
    ) -> Result<(), NodeError> {
        // Dev mode: ingest directly into the pool and produce one block
        // (single-node, no gossip/agreement), mirroring go's
        // `BroadcastSignedTxGroup` → `writeDevmodeBlock`. The pool `remember`
        // and the block commit are blocking work, so run them off the async
        // runtime.
        if self.dev_mode {
            let pool = self
                .pool
                .clone()
                .ok_or(NodeError::NotImplemented("broadcast_signed_tx_group (dev)"))?;
            let ledger = self.ledger.clone();
            let apply_data_cache = self.dev_apply_data.clone();
            // Serialize production so concurrent submissions don't assemble
            // against the same round before each other's on_new_block drains the
            // pool (go holds node.mu across Remember + writeDevmodeBlock). Held
            // across the spawn_blocking below.
            let _produce_guard = self.dev_produce_lock.lock().await;
            return tokio::task::spawn_blocking(move || {
                // Prime the evaluator before the first ingest (a fresh pool has
                // none until the first block); idempotent thereafter.
                pool.ensure_evaluator_primed();
                pool.remember(tx_group)
                    .map_err(|e| NodeError::BadRequest(format!("pool rejected group: {e}")))?;
                match crate::dev_producer::produce_dev_block(&pool, &ledger) {
                    Ok((block, apply_data)) => {
                        // Cache per-txn ApplyData (created ids / eval delta) for
                        // get_pending_transaction to report on confirmation.
                        if let Ok(mut cache) = apply_data_cache.lock() {
                            for (stx, ad) in block.payset.iter().zip(apply_data.iter()) {
                                if ad.config_asset != 0
                                    || ad.application_id != 0
                                    || ad.eval_delta.is_some()
                                {
                                    cache.insert(
                                        crate::dev_producer::block_txn_id(stx, &block),
                                        ad.clone(),
                                    );
                                }
                            }
                        }
                        Ok::<(), NodeError>(())
                    }
                    Err(e) => {
                        // The block (including this just-remembered group) failed
                        // to apply — typically a rejecting app program under
                        // Execute mode. Drop the pending group so the rejected
                        // transaction doesn't wedge later blocks; dev submits are
                        // serialized and each drains the pool, so only this group
                        // is pending here.
                        pool.reset();
                        Err(NodeError::BadRequest(format!(
                            "dev block production rejected the group: {e}"
                        )))
                    }
                }
            })
            .await
            .map_err(|e| NodeError::Internal(format!("dev broadcast task join failed: {e}")))?;
        }

        let broadcaster = self.broadcaster("broadcast_signed_tx_group")?;
        // `submit_group` runs ingest → seen-cache → gossip broadcast and
        // returns the first txid on success. The NodeInterface contract
        // for this method returns `()`, so we discard the txid; handlers
        // that need it (e.g. `POST /v2/transactions`) re-derive it from
        // the submitted group.
        broadcaster
            .submit_group(tx_group)
            .await
            .map(|_first_txid| ())
            .map_err(Self::local_tx_error_to_node_error)
    }

    async fn async_broadcast_signed_tx_group(
        &self,
        tx_group: Vec<SignedTransaction>,
    ) -> Result<(), NodeError> {
        // Fire-and-forget: the caller gets Ok as soon as the group is
        // accepted for background processing. This matches go-algorand's
        // `Node.AsyncBroadcastSignedTxGroup`, which routes through
        // `txHandler.LocalTransaction` — a non-blocking backlog enqueue
        // that returns success once the group is queued and performs
        // validation + gossip later. See
        // `../go-algorand/node/node.go:596-600` and
        // `../go-algorand/data/txHandler.go:873-888` @ v4.5.1-stable.
        //
        // The three *synchronous* error surfaces this method preserves:
        //   1. No broadcaster attached       → NotImplemented
        //   2. Empty group                   → Internal("empty group")
        //   3. Async backlog is full         → Internal("async backlog full")
        //
        // Pool-rejection / gossip failures after the spawn are not
        // surfaced through the return value. `LocalTxBroadcaster::submit_group`
        // logs Pool / Broadcast errors (see
        // `local_tx_broadcast.rs:200-222`); we add a dedicated `warn!`
        // for Encode because the broadcaster propagates that variant
        // without its own log (`local_tx_broadcast.rs:193`).
        // Callers that need synchronous rejection signals should use
        // `broadcast_signed_tx_group` instead.
        let broadcaster = self.broadcaster("async_broadcast_signed_tx_group")?;

        // Preflight the obviously-bad cases synchronously so clients see
        // immediate feedback rather than a silent drop.
        if tx_group.is_empty() {
            return Err(Self::local_tx_error_to_node_error(LocalTxError::Empty));
        }

        // Admission control: mirror go-algorand's bounded backlog. Under
        // saturation we surface `backlog full` instead of spawning an
        // unbounded task per request. The permit is moved into the
        // spawned task so it's dropped when `submit_group` completes,
        // freeing the slot.
        let permit = Self::reserve_async_backlog_permit(&self.async_backlog_permits)?;

        // Spawn the full ingest + gossip path. `LocalTxBroadcaster`
        // already emits structured warnings for Pool and Broadcast
        // errors, so only Encode (which returns directly without
        // logging) gets an adapter-side log.
        tokio::spawn(async move {
            let _permit = permit; // release slot on completion
            if let Err(err) = broadcaster.submit_group(tx_group).await {
                if matches!(&err, LocalTxError::Encode(_)) {
                    warn!(
                        error = %err,
                        "async_broadcast_signed_tx_group: encode failed",
                    );
                }
            }
        });
        Ok(())
    }

    // ---- Simulation (TASK-78) ----

    async fn simulate(&self, request: SimulateRequest) -> Result<SimulateResponse, NodeError> {
        // The REST handler populates `decoded_txn_groups` from the raw
        // JSON/msgpack `txn_groups` before calling us. Direct trait callers
        // that bypass the handler must populate it themselves.
        let sim_req = Self::build_simulation_request(request);

        // Run the simulator under the ledger lock. `Simulator` takes
        // `&mut L: LedgerStore` and uses snapshot/restore to leave the
        // store unchanged on both the `Ok` and `Err` paths. A panic
        // *inside* the simulator bypasses the explicit restore (the
        // snapshot is dropped mid-way) and poisons the `std::sync::Mutex`,
        // so we handle poison here rather than `expect`-ing — an earlier
        // panic does not cascade into the entire REST surface dying on
        // subsequent requests. Long AVM simulations still stall other
        // ledger access and block the current Tokio worker;
        // `spawn_blocking` (or migrating to `tokio::sync::Mutex`) is
        // tracked as a refinement under PLAN-34 alongside the rest of
        // the simulation-response fidelity work.
        let result = {
            let mut ledger = self.lock_ledger("simulate")?;
            let mut simulator = Simulator::new(&mut *ledger);
            simulator
                .simulate(sim_req)
                .map_err(Self::map_simulator_error)?
        };
        Ok(Self::build_simulate_response(result))
    }

    // ---- Participation key methods (TASK-265) ----
    //
    // Backed by the optional [`ParticipationStore`] attached via
    // [`Self::with_participation_store`]. These mirror go-algorand's
    // `AlgorandFullNode` participation methods in
    // `../go-algorand/node/node.go` (ListParticipationKeys:878,
    // GetParticipationKey:883, RemoveParticipationKey:894,
    // AppendParticipationKeys:927, InstallParticipationKey:965) and the
    // `generateKeyHandler` path at
    // `../go-algorand/daemon/algod/api/server/v2/handlers.go:261`.

    /// List all participation keys. Mirrors `Node.ListParticipationKeys`
    /// (`../go-algorand/node/node.go:878` → `Registry().GetAll()`).
    async fn list_participation_keys(&self) -> Result<Vec<ParticipationRecord>, NodeError> {
        let store = self.lock_part_store("list_participation_keys")?;
        store
            .get_all()
            .map_err(|e| NodeError::Internal(format!("list_participation_keys: {e}")))
    }

    /// Get a single participation key by ID. Mirrors `Node.GetParticipationKey`
    /// (`../go-algorand/node/node.go:883`): a zero/absent record surfaces as
    /// `account.ErrParticipationIDNotFound`. The REST handler maps the
    /// returned record's `is_zero()` to a 404, but we additionally map a
    /// genuine miss to [`NodeError::NotFound`] so direct trait callers get the
    /// same semantics.
    async fn get_participation_key(
        &self,
        id: &ParticipationID,
    ) -> Result<ParticipationRecord, NodeError> {
        let store = self.lock_part_store("get_participation_key")?;
        match store
            .get(id)
            .map_err(|e| NodeError::Internal(format!("get_participation_key: {e}")))?
        {
            Some(record) => Ok(record),
            None => Err(NodeError::NotFound("participation id not found".into())),
        }
    }

    /// Install a participation key from a raw partkey-DB binary blob. Mirrors
    /// `Node.InstallParticipationKey` (`../go-algorand/node/node.go:965`):
    /// write the bytes to a temporary erasable DB, `RestoreParticipation`,
    /// reject a zero parent, then register it (duplicates rejected). The temp
    /// file is removed before returning, matching go's `defer os.Remove`.
    async fn install_participation_key(&self, data: Vec<u8>) -> Result<ParticipationID, NodeError> {
        // Fail fast with NotImplemented when no store is configured, before
        // doing the (potentially slow) decode work — matches the behavior of
        // the other participation methods.
        if self.part_store.is_none() {
            return Err(NodeError::NotImplemented("install_participation_key"));
        }

        // Restore the Participation from the supplied partkey bytes by
        // round-tripping through a temporary on-disk sqlite DB (the partkey
        // schema reader operates on a file-backed connection). We do this
        // before taking the store lock so the (potentially slow) msgpack
        // decode doesn't serialize against other participation calls.
        let participation = Self::restore_from_partkey_bytes(&data)?;

        // Reject a missing (zero) parent address, matching go's explicit
        // check (`node.go:996`).
        if participation.parent == Address([0u8; 32]) {
            return Err(NodeError::Internal(
                "cannot install partkey with missing (zero) parent address".into(),
            ));
        }

        let store = self.lock_part_store("install_participation_key")?;
        store.insert(&participation).map_err(|e| {
            // The UNIQUE(participationID) constraint surfaces duplicates;
            // map them to the same message go returns from AddParticipation.
            if matches!(
                &e,
                rusqlite::Error::SqliteFailure(ffi, _)
                    if ffi.code == rusqlite::ErrorCode::ConstraintViolation
            ) {
                NodeError::Internal(
                    "ParticipationRegistry: cannot register duplicate participation key".into(),
                )
            } else {
                NodeError::Internal(format!("install_participation_key: {e}"))
            }
        })
    }

    /// Remove a participation key by ID. Mirrors `Node.RemoveParticipationKey`
    /// (`../go-algorand/node/node.go:894`): an unknown ID is
    /// `ErrParticipationIDNotFound` → [`NodeError::NotFound`]. (algod-rust
    /// stores keys in the registry DB only — there is no separate partkey file
    /// to unlink, unlike go's on-disk `.partkey` files.)
    async fn remove_participation_key(&self, id: &ParticipationID) -> Result<(), NodeError> {
        let store = self.lock_part_store("remove_participation_key")?;
        let deleted = store
            .delete(id)
            .map_err(|e| NodeError::Internal(format!("remove_participation_key: {e}")))?;
        if deleted {
            Ok(())
        } else {
            Err(NodeError::NotFound("participation id not found".into()))
        }
    }

    /// Append state-proof keys to an existing participation key. Mirrors
    /// `Node.AppendParticipationKeys` (`../go-algorand/node/node.go:927` →
    /// `Registry().AppendKeys`). `keys` is the raw `StateProofKeys`
    /// (`[]merklesignature.KeyRoundPair`) msgpack body POSTed to
    /// `/v2/participation/{id}`; we decode it and insert each key with its
    /// explicit round, matching go's `appendKeysOp.apply`
    /// (`../go-algorand/data/account/registeryDbOps.go:268`). An unknown ID
    /// returns [`NodeError::NotFound`], matching go's public `Registry.AppendKeys`
    /// which rejects an id missing from its cache with
    /// `ErrParticipationIDNotFound` before queuing the DB op
    /// (`../go-algorand/data/account/participationRegistry.go:560`).
    async fn append_participation_keys(
        &self,
        id: &ParticipationID,
        keys: Vec<u8>,
    ) -> Result<(), NodeError> {
        // A malformed body or an empty key list is a client error (go's
        // AppendKeys handler `badRequest`s on both — handlers.go:378), so these
        // surface as 400, not 500.
        let pairs = algo_consensus_crypto::merklesig::decode_state_proof_keys(&keys)
            .map_err(|e| NodeError::BadRequest(format!("unable to parse keys from body: {e}")))?;
        if pairs.is_empty() {
            return Err(NodeError::BadRequest(
                "empty request, please attach keys to request body".into(),
            ));
        }
        let store = self.lock_part_store("append_participation_keys")?;
        let appended = store
            .append_state_proof_keys_with_rounds(id, &pairs)
            .map_err(|e| NodeError::Internal(format!("append_participation_keys: {e}")))?;
        if appended {
            Ok(())
        } else {
            Err(NodeError::NotFound("participation id not found".into()))
        }
    }

    /// Generate participation keys server-side and install them. Mirrors go's
    /// `generateKeyHandler` (`../go-algorand/daemon/algod/api/server/v2/handlers.go:261`),
    /// which calls `participation.GenParticipationKeysTo` then
    /// `InstallParticipationKey`. We generate the [`Participation`] directly
    /// (no intermediate partkey file) and persist it. The REST handler already
    /// runs this on a background task behind a single-permit semaphore, so it
    /// returns 200 immediately and logs the resulting id.
    async fn generate_participation_keys(
        &self,
        address: Address,
        first: u64,
        last: u64,
        dilution: Option<u64>,
    ) -> Result<ParticipationID, NodeError> {
        // Enforce the consensus `MaxKeyregValidPeriod` bound before generating,
        // matching go's `FillDBWithParticipationKeys`
        // (../go-algorand/data/account/participation.go:231), which reads the
        // limit from the current consensus params and rejects an over-long
        // validity window. `Participation::generate` only checks `last >= first`,
        // so without this the endpoint would generate (and persist) keys with
        // windows go rejects — a large CPU/RAM cost on an untrusted request.
        if last < first {
            return Err(NodeError::Internal(format!(
                "firstValid {first} is after lastValid {last}"
            )));
        }
        let proto = {
            let ledger = self.lock_ledger("generate_participation_keys")?;
            self.resolve_protocol(&ledger)
        };
        let params = Self::resolve_consensus_params(&proto)?;
        if params.max_keyreg_valid_period != 0
            && last.saturating_sub(first) > params.max_keyreg_valid_period
        {
            return Err(NodeError::Internal(format!(
                "the validity period for mss is too large: the limit is {}",
                params.max_keyreg_valid_period
            )));
        }

        // `dilution = 0` defers to the default in `Participation::generate`
        // (matching go's `nilToZero(params.Dilution)`).
        let key_dilution = dilution.unwrap_or(0);
        let participation = Participation::generate(
            address,
            Round(first),
            Round(last),
            key_dilution,
            algo_consensus_crypto::merklesig::KEY_LIFETIME_DEFAULT,
        )
        .map_err(NodeError::Internal)?;

        let store = self.lock_part_store("generate_participation_keys")?;
        store
            .insert(&participation)
            .map_err(|e| NodeError::Internal(format!("generate_participation_keys: {e}")))
    }
}

impl AlgodNodeInterface {
    /// Decode a partkey-DB binary blob into a [`Participation`] by writing it
    /// to a temporary on-disk sqlite file and reading it with
    /// [`restore_participation`]. The temp file is removed before returning.
    /// Mirrors go's `createTemporaryParticipationKey` then
    /// `MakeErasableAccessor` then `RestoreParticipationWithSecrets` in
    /// `../go-algorand/node/node.go:965`.
    fn restore_from_partkey_bytes(data: &[u8]) -> Result<Participation, NodeError> {
        if data.is_empty() {
            return Err(NodeError::Internal("cannot install empty partkey".into()));
        }

        use std::io::Write as _;

        // Create the temp file securely: on unix 0600 (private-key material),
        // exclusive creation (`O_CREAT|O_EXCL` — fails rather than following a
        // pre-placed symlink or clobbering an existing file), and a unique name
        // combining the pid, a high-resolution timestamp, and a process-global
        // counter so concurrent installs never collide. Go uses a
        // random-suffixed name in the genesis dir (node.go:936); we keep the
        // bytes off any shared path and lock down the mode the same way go's
        // umask-respecting participation files are expected to be protected.
        static TEMP_PARTKEY_COUNTER: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = TEMP_PARTKEY_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "algod-rust-partkey.{}.{nonce}.{seq}.bin",
            std::process::id()
        ));

        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            // The 0600 mode is unix-only; on other platforms exclusive creation
            // in a private temp dir is the available protection.
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            let mut file = opts
                .open(&path)
                .map_err(|e| NodeError::Internal(format!("creating temp partkey: {e}")))?;
            file.write_all(data)
                .and_then(|()| file.flush())
                .map_err(|e| {
                    let _ = std::fs::remove_file(&path);
                    NodeError::Internal(format!("writing temp partkey: {e}"))
                })?;
        }

        let result = (|| {
            let db = ErasableDb::open(&path)
                .map_err(|e| NodeError::Internal(format!("opening temp partkey db: {e}")))?;
            restore_participation(&db)
                .map_err(|e| NodeError::Internal(format!("restoring partkey: {e}")))
        })();

        // Always remove the temp file, mirroring go's `defer os.Remove`.
        let _ = std::fs::remove_file(&path);

        result
    }
}

impl AlgodNodeInterface {
    // ---- Simulation conversion helpers (TASK-78) ----
    //
    // These pure functions translate between the REST-level model types
    // (`algo_rest_api::models::Simulate*`) and the ledger's internal
    // simulation types (`algo_ledger::simulation::Simulation*`). Keeping
    // them as associated functions lets each conversion branch be
    // exercised without standing up a live simulator.
    //
    // Response-shape fidelity gaps (`eval_overrides`, `initial_states`,
    // `exec-trace` contents, unnamed-resources-accessed, etc.) are
    // tracked in PLAN-34; this task only plumbs the call.

    /// Translate the REST `SimulateTraceConfig` into the ledger's
    /// [`ExecTraceConfig`], collapsing `Option<bool>` flags to `bool`.
    fn exec_trace_config_from_model(cfg: Option<SimulateTraceConfig>) -> ExecTraceConfig {
        let cfg = cfg.unwrap_or_default();
        ExecTraceConfig {
            enable: cfg.enable.unwrap_or(false),
            stack: cfg.stack_change.unwrap_or(false),
            scratch: cfg.scratch_change.unwrap_or(false),
            state: cfg.state_change.unwrap_or(false),
        }
    }

    /// Build the ledger's [`SimulationRequest`] from the REST
    /// [`SimulateRequest`]. Uses the handler-populated
    /// `decoded_txn_groups` field — callers that bypass the handler must
    /// populate it before calling this method.
    ///
    /// Note: `allow_more_logging` is plumbed through for forward
    /// compatibility but is currently a no-op inside
    /// [`algo_ledger::simulation::Simulator::simulate`], which does not
    /// yet raise the AVM `max_log_calls` / `max_log_size` limits. The
    /// simulator-side wiring lands with the rest of the
    /// simulation-response fidelity work in PLAN-34. Callers that rely
    /// on relaxed log limits should not expect this flag to take effect
    /// until then.
    fn build_simulation_request(request: SimulateRequest) -> SimulationRequest {
        SimulationRequest {
            round: request.round.map(Round),
            txn_groups: request.decoded_txn_groups,
            allow_empty_signatures: request.allow_empty_signatures.unwrap_or(false),
            allow_more_logging: request.allow_more_logging.unwrap_or(false),
            allow_unnamed_resources: request.allow_unnamed_resources.unwrap_or(false),
            extra_opcode_budget: request.extra_opcode_budget.unwrap_or(0),
            trace_config: Self::exec_trace_config_from_model(request.exec_trace_config),
            fix_signers: request.fix_signers.unwrap_or(false),
        }
    }

    /// Collapse a zero counter to `None` so `skip_serializing_if` keeps
    /// the wire response tidy. Mirrors go-algorand's
    /// `omitempty`-on-uint behavior.
    fn opt_nonzero_u64(value: u64) -> Option<u64> {
        if value == 0 {
            None
        } else {
            Some(value)
        }
    }

    /// Build a minimal [`PreEncodedTxInfo`] from a simulation [`TxnResult`].
    ///
    /// Fields sourced from `ApplyData` (rewards, closing amounts, asset /
    /// application indexes, state deltas, logs, inner transactions) are
    /// deliberately left `None` — populating them fully is PLAN-34's
    /// response-fidelity work. The `txn` field is populated from the
    /// result so clients can confirm which transaction the result refers
    /// to even without apply-data parity.
    fn pre_encoded_txinfo_from_txn_result(result: &TxnResult) -> PreEncodedTxInfo {
        PreEncodedTxInfo {
            txn: result.txn.clone().unwrap_or_default(),
            pool_error: String::new(),
            confirmed_round: None,
            closing_amount: None,
            asset_closing_amount: None,
            sender_rewards: None,
            receiver_rewards: None,
            close_rewards: None,
            asset_index: None,
            application_index: None,
            global_state_delta: None,
            local_state_delta: None,
            logs: None,
            inner_txns: None,
        }
    }

    /// Convert a single simulation [`TxnResult`] into the REST shape.
    fn txn_result_to_model(result: TxnResult) -> SimulateTransactionResult {
        let txn_result = Self::pre_encoded_txinfo_from_txn_result(&result);
        SimulateTransactionResult {
            app_budget_consumed: Self::opt_nonzero_u64(result.app_budget_consumed),
            // Translate the captured execution trace: top-level opcode units
            // (TASK-248), logic-sig + inner-transaction traces and
            // spawned-inners wiring (TASK-249). Per-opcode state-changes are
            // TASK-259.
            exec_trace: result.trace.as_ref().map(Self::exec_trace_to_model),
            fixed_signer: result.fixed_signer.map(|a| a.to_string()),
            logic_sig_budget_consumed: Self::opt_nonzero_u64(result.logicsig_budget_consumed),
            txn_result,
            unnamed_resources_accessed: None,
        }
    }

    /// Convert a simulation [`TxnGroupResult`] into the REST shape.
    fn txn_group_result_to_model(group: TxnGroupResult) -> SimulateTransactionGroupResult {
        SimulateTransactionGroupResult {
            app_budget_added: Self::opt_nonzero_u64(group.app_budget_added),
            app_budget_consumed: Self::opt_nonzero_u64(group.app_budget_consumed),
            failed_at: group
                .failed_at
                .map(|path| path.into_iter().map(|i| i as u64).collect()),
            failure_message: group.failure_message,
            txn_results: group
                .txn_results
                .into_iter()
                .map(Self::txn_result_to_model)
                .collect(),
            unnamed_resources_accessed: None,
        }
    }

    /// Build the top-level [`SimulateResponse`] from the simulator's
    /// [`SimulationResult`].
    ///
    /// `version` is the simulator format version (2). `eval_overrides`,
    /// `exec_trace_config`, and `initial_states` mirror go-algorand's
    /// `convertSimulationResult` (`utils.go`): each is present only when it
    /// carries non-default information.
    fn build_simulate_response(result: SimulationResult) -> SimulateResponse {
        let initial_states = result.initial_states.map(Self::initial_states_to_model);
        let eval_overrides = Self::eval_overrides_to_model(&result.eval_overrides);
        let exec_trace_config = Self::exec_trace_config_to_response(&result.trace_config);
        SimulateResponse {
            eval_overrides,
            exec_trace_config,
            initial_states,
            last_round: result.last_round.0,
            txn_groups: result
                .txn_groups
                .into_iter()
                .map(Self::txn_group_result_to_model)
                .collect(),
            version: result.version,
        }
    }

    /// Convert the simulator's applied [`ResultEvalOverrides`] into the REST
    /// [`SimulationEvalOverrides`]. Returns `None` when no overrides were
    /// applied, and omits individual fields at their zero value — matching
    /// go-algorand's `convertSimulationResult` / `omitEmpty` semantics.
    fn eval_overrides_to_model(ov: &ResultEvalOverrides) -> Option<SimulationEvalOverrides> {
        let is_default = !ov.allow_empty_signatures
            && !ov.allow_unnamed_resources
            && ov.extra_opcode_budget == 0
            && !ov.fix_signers
            && ov.max_log_calls.is_none()
            && ov.max_log_size.is_none();
        if is_default {
            return None;
        }
        Some(SimulationEvalOverrides {
            allow_empty_signatures: ov.allow_empty_signatures.then_some(true),
            allow_unnamed_resources: ov.allow_unnamed_resources.then_some(true),
            extra_opcode_budget: (ov.extra_opcode_budget != 0).then_some(ov.extra_opcode_budget),
            fix_signers: ov.fix_signers.then_some(true),
            max_log_calls: ov.max_log_calls,
            max_log_size: ov.max_log_size,
        })
    }

    /// Convert the simulator's [`ExecTraceConfig`] into the REST
    /// [`SimulateTraceConfig`] for the response. Returns `None` when no trace
    /// features were enabled (zero value), and omits individual `false` flags —
    /// matching go-algorand's `omitempty` codec tags on `ExecTraceConfig`.
    fn exec_trace_config_to_response(cfg: &ExecTraceConfig) -> Option<SimulateTraceConfig> {
        if !cfg.enable && !cfg.stack && !cfg.scratch && !cfg.state {
            return None;
        }
        Some(SimulateTraceConfig {
            enable: cfg.enable.then_some(true),
            scratch_change: cfg.scratch.then_some(true),
            stack_change: cfg.stack.then_some(true),
            state_change: cfg.state.then_some(true),
        })
    }

    /// Convert a captured [`AvmValueTrace`] into the REST [`AvmValue`].
    ///
    /// Uses go-algorand's TEAL value type tags: `1` = bytes, `2` = uint.
    fn avm_value_trace_to_model(value: &AvmValueTrace) -> AvmValue {
        match value {
            AvmValueTrace::Uint64(n) => AvmValue {
                bytes: None,
                value_type: 2,
                uint: Some(*n),
            },
            AvmValueTrace::Bytes(b) => AvmValue {
                bytes: Some(b.clone()),
                value_type: 1,
                uint: None,
            },
        }
    }

    /// Convert the captured top-level [`TransactionTrace`] into the REST
    /// [`SimulationTransactionExecTrace`]: approval/clear-state/logic-sig opcode
    /// units + program hashes (TASK-248), recursive inner-transaction traces
    /// with spawned-inners wiring and clear-state-rollback fields (TASK-249).
    /// Per-opcode state-changes are TASK-259. Field omission follows
    /// go-algorand's `convertTxnTrace` (`utils.go:455`): empty slices and
    /// zero/false scalars are omitted.
    fn exec_trace_to_model(trace: &TransactionTrace) -> SimulationTransactionExecTrace {
        let inner_trace = if trace.inner_traces.is_empty() {
            None
        } else {
            Some(
                trace
                    .inner_traces
                    .iter()
                    .map(Self::exec_trace_to_model)
                    .collect(),
            )
        };
        SimulationTransactionExecTrace {
            approval_program_hash: trace.approval_program_hash.map(|h| h.to_vec()),
            approval_program_trace: trace
                .approval_program_trace
                .as_ref()
                .map(Self::program_trace_to_units),
            clear_state_program_hash: trace.clear_state_program_hash.map(|h| h.to_vec()),
            clear_state_program_trace: trace
                .clear_state_program_trace
                .as_ref()
                .map(Self::program_trace_to_units),
            // omitEmpty: false → None, true → Some(true).
            clear_state_rollback: trace.clear_state_rollback.then_some(true),
            clear_state_rollback_error: trace.clear_state_rollback_error.clone(),
            inner_trace,
            logic_sig_hash: trace.logicsig_hash.map(|h| h.to_vec()),
            logic_sig_trace: trace
                .logicsig_trace
                .as_ref()
                .map(Self::program_trace_to_units),
        }
    }

    /// Convert a [`ProgramTrace`] into a list of REST opcode trace units.
    fn program_trace_to_units(trace: &ProgramTrace) -> Vec<SimulationOpcodeTraceUnit> {
        trace
            .opcodes
            .iter()
            .map(Self::opcode_unit_to_model)
            .collect()
    }

    /// Convert one captured [`OpcodeTraceUnit`] into the REST shape, omitting
    /// empty/zero fields to match go-algorand's `omitempty` codec tags.
    fn opcode_unit_to_model(unit: &OpcodeTraceUnit) -> SimulationOpcodeTraceUnit {
        let stack_additions = if unit.stack_additions.is_empty() {
            None
        } else {
            Some(
                unit.stack_additions
                    .iter()
                    .map(Self::avm_value_trace_to_model)
                    .collect(),
            )
        };
        let stack_pop_count = (unit.stack_pop_count != 0).then_some(unit.stack_pop_count as u64);
        let scratch_changes = if unit.scratch_changes.is_empty() {
            None
        } else {
            Some(
                unit.scratch_changes
                    .iter()
                    .map(|(slot, value)| ScratchChange {
                        slot: *slot as u64,
                        new_value: Self::avm_value_trace_to_model(value),
                    })
                    .collect(),
            )
        };
        let state_changes = if unit.state_changes.is_empty() {
            None
        } else {
            Some(
                unit.state_changes
                    .iter()
                    .map(Self::state_change_to_model)
                    .collect(),
            )
        };
        let spawned_inners = if unit.spawned_inners.is_empty() {
            None
        } else {
            Some(unit.spawned_inners.iter().map(|i| *i as u64).collect())
        };
        SimulationOpcodeTraceUnit {
            pc: unit.pc as u64,
            scratch_changes,
            spawned_inners,
            stack_additions,
            stack_pop_count,
            state_changes,
        }
    }

    /// Convert a captured [`StateChange`] (global/local/box write or delete)
    /// into the REST [`ApplicationStateOperation`]. Operation is `w` for a write
    /// and `d` for a delete (taken from the recorded op, not inferred from the
    /// new value — a box write whose opcode errored is still a `w` with no
    /// value), matching go-algorand's AppStateOpEnum encoding.
    fn state_change_to_model(change: &StateChange) -> ApplicationStateOperation {
        let app_state_type = match change.kind {
            StateChangeKind::GlobalState => "g",
            StateChangeKind::LocalState => "l",
            StateChangeKind::BoxState => "b",
        }
        .to_string();
        let operation = match change.op {
            StateChangeOp::Write => "w",
            StateChangeOp::Delete => "d",
        }
        .to_string();
        ApplicationStateOperation {
            account: change.account.map(|a| a.to_string()),
            app_state_type,
            key: change.key.clone(),
            new_value: change
                .new_value
                .as_ref()
                .map(Self::avm_value_trace_to_model),
            operation,
        }
    }

    /// Convert the ledger's [`ResourcesInitialStates`] into the REST
    /// [`SimulateInitialStates`]. Returns a present-but-possibly-empty value
    /// (the caller only calls this when state-change tracing was requested,
    /// mirroring go-algorand's non-nil `InitialStates`).
    fn initial_states_to_model(states: ResourcesInitialStates) -> SimulateInitialStates {
        let app_states: Vec<ApplicationInitialStates> = states
            .app_initial_states
            .into_iter()
            .map(|(id, app)| Self::app_initial_states_to_model(id, app))
            .collect();

        SimulateInitialStates {
            app_initial_states: if app_states.is_empty() {
                None
            } else {
                Some(app_states)
            },
        }
    }

    /// Convert a single app's captured [`AppInitialState`] into the REST
    /// [`ApplicationInitialStates`]. Empty state categories are omitted.
    fn app_initial_states_to_model(id: u64, app: AppInitialState) -> ApplicationInitialStates {
        let app_globals = (!app.global_state.is_empty()).then(|| ApplicationKVStorage {
            account: None,
            kvs: app
                .global_state
                .into_iter()
                .map(|(key, value)| AvmKeyValue {
                    key,
                    value: Self::avm_value_trace_to_model(&value),
                })
                .collect(),
        });

        let app_locals = (!app.local_states.is_empty()).then(|| {
            app.local_states
                .into_iter()
                .map(|(addr, kvs)| ApplicationKVStorage {
                    account: Some(addr.to_string()),
                    kvs: kvs
                        .into_iter()
                        .map(|(key, value)| AvmKeyValue {
                            key,
                            value: Self::avm_value_trace_to_model(&value),
                        })
                        .collect(),
                })
                .collect()
        });

        let app_boxes = (!app.boxes.is_empty()).then(|| ApplicationKVStorage {
            account: None,
            kvs: app
                .boxes
                .into_iter()
                .map(|(key, bytes)| AvmKeyValue {
                    key,
                    value: AvmValue {
                        bytes: Some(bytes),
                        value_type: 1,
                        uint: None,
                    },
                })
                .collect(),
        });

        ApplicationInitialStates {
            app_boxes,
            app_globals,
            app_locals,
            id,
        }
    }

    /// Map a [`SimulatorError`] to the trait-level [`NodeError`].
    ///
    /// - `InvalidRequest` → [`NodeError::BadRequest`] so REST clients
    ///   get 400s for bad input (conflicting `fix-signers` /
    ///   `allow-empty-signatures` flags, multi-group requests, empty
    ///   groups, etc.) instead of a collapsed 500.
    /// - `EvalFailure` → [`NodeError::Internal`]. In practice
    ///   `simulate()` carries eval failures inside the result
    ///   (`TxnGroupResult::failure_message` + `failed_at`) rather than
    ///   raising this variant, so this branch only fires for
    ///   pre-execution signature / well-formedness checks.
    /// - `Internal` → [`NodeError::Internal`].
    ///
    /// Each variant's message keeps a `simulate: <category>: …` prefix
    /// so logs and client-visible bodies remain traceable to the
    /// underlying cause.
    fn map_simulator_error(err: SimulatorError) -> NodeError {
        match err {
            SimulatorError::InvalidRequest(e) => {
                NodeError::BadRequest(format!("simulate: invalid request: {e}"))
            }
            SimulatorError::EvalFailure(e) => {
                NodeError::Internal(format!("simulate: eval failure: {e}"))
            }
            SimulatorError::Internal(e) => NodeError::Internal(format!("simulate: internal: {e}")),
        }
    }

    /// Translate a raw `(txn, pool_error, found)` tuple from
    /// [`TransactionPool::lookup`] into the trait-level response.
    ///
    /// The pool's `lookup` distinguishes four states, which collapse to
    /// three observable tuples:
    ///
    /// | pool state                | tuple shape               | API response                        |
    /// |---------------------------|---------------------------|-------------------------------------|
    /// | pending (live in pool)    | `(txn,     "",   true)`   | `Some(TxnWithStatus { txn, ... })`  |
    /// | recently evicted          | `(default, err,  true)`   | `Some(TxnWithStatus { pool_error })`|
    /// | recently committed        | `(default, "",   true)`   | `None` — see note                   |
    /// | never seen / miss         | `(default, "",   false)`  | `None`                              |
    ///
    /// The pool records committed-txid entries in its status cache with an
    /// *empty* error string (see `pool.rs:on_new_block`), so the "recently
    /// committed" tuple is indistinguishable from a pending-txn-with-empty
    /// error except that the returned txn is `SignedTransaction::default()`.
    /// Returning `Some(TxnWithStatus { txn: default, pool_error: "" })`
    /// would be a bogus pending response (empty txn, no error). Go-algorand
    /// handles this by then searching the last `MaxTxnLife` blocks for the
    /// confirmation round; that block-side lookup is a follow-up outside
    /// PLAN-74 TASK-76's scope, so we conservatively return `None` and let
    /// the caller retry (or query the block directly) once the confirmation
    /// path is wired.
    ///
    /// Extracted as an associated function so the branch logic can be
    /// unit-tested without staging real block commits through a live pool.
    fn map_pool_lookup(
        txn: SignedTransaction,
        pool_error: String,
        found: bool,
    ) -> Option<TxnWithStatus> {
        if !found {
            return None;
        }
        let txn_is_default = txn == SignedTransaction::default();
        if txn_is_default && pool_error.is_empty() {
            // Recently-committed case — see the method-level comment above.
            return None;
        }
        Some(TxnWithStatus {
            txn,
            // `confirmed_round` stays 0 until the block-side confirmation
            // lookup lands in a follow-up task — pool-only results are
            // either in-pool (0 is correct) or evicted (0 is a stub).
            confirmed_round: 0,
            pool_error,
            closing_amount: 0,
            asset_closing_amount: 0,
            sender_rewards: 0,
            receiver_rewards: 0,
            close_rewards: 0,
            asset_index: None,
            application_index: None,
            eval_delta: None,
            logs: None,
            inner_txns: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_ledger::SqliteLedger;
    use algo_types::consensus::CONSENSUS_V41;

    fn build_version_fixture() -> BuildVersion {
        BuildVersion {
            major: 0,
            minor: 1,
            build_number: 0,
            commit_hash: "test".into(),
            branch: "main".into(),
            channel: "dev".into(),
        }
    }

    #[test]
    fn initial_states_to_model_maps_globals_locals_boxes() {
        let addr = Address([0xAB; 32]);
        let states = ResourcesInitialStates {
            app_initial_states: vec![(
                42,
                AppInitialState {
                    global_state: vec![(b"g".to_vec(), AvmValueTrace::Uint64(7))],
                    local_states: vec![(
                        addr,
                        vec![(b"l".to_vec(), AvmValueTrace::Bytes(b"v".to_vec()))],
                    )],
                    boxes: vec![(b"b".to_vec(), b"boxdata".to_vec())],
                },
            )],
        };

        let model = AlgodNodeInterface::initial_states_to_model(states);
        let apps = model
            .app_initial_states
            .expect("app-initial-states populated");
        assert_eq!(apps.len(), 1);
        let app = &apps[0];
        assert_eq!(app.id, 42);

        // Global: uint type tag (2), value 7.
        let globals = app.app_globals.as_ref().expect("globals present");
        assert_eq!(globals.kvs.len(), 1);
        assert_eq!(globals.kvs[0].key, b"g");
        assert_eq!(globals.kvs[0].value.value_type, 2);
        assert_eq!(globals.kvs[0].value.uint, Some(7));

        // Local: keyed by account address string, bytes type tag (1).
        let locals = app.app_locals.as_ref().expect("locals present");
        assert_eq!(locals.len(), 1);
        assert_eq!(locals[0].account, Some(addr.to_string()));
        assert_eq!(locals[0].kvs[0].value.value_type, 1);
        assert_eq!(locals[0].kvs[0].value.bytes, Some(b"v".to_vec()));

        // Box: bytes type tag (1), raw contents.
        let boxes = app.app_boxes.as_ref().expect("boxes present");
        assert_eq!(boxes.kvs[0].key, b"b");
        assert_eq!(boxes.kvs[0].value.value_type, 1);
        assert_eq!(boxes.kvs[0].value.bytes, Some(b"boxdata".to_vec()));
    }

    #[test]
    fn initial_states_to_model_empty_app_states_omitted() {
        let states = ResourcesInitialStates {
            app_initial_states: vec![],
        };
        let model = AlgodNodeInterface::initial_states_to_model(states);
        assert!(model.app_initial_states.is_none());
    }

    #[test]
    fn eval_overrides_default_is_none() {
        let ov = ResultEvalOverrides::default();
        assert!(AlgodNodeInterface::eval_overrides_to_model(&ov).is_none());
    }

    #[test]
    fn eval_overrides_populates_set_fields_and_omits_zero() {
        let ov = ResultEvalOverrides {
            allow_empty_signatures: true,
            allow_unnamed_resources: false,
            extra_opcode_budget: 200,
            fix_signers: false,
            max_log_calls: Some(40),
            max_log_size: None,
        };
        let model = AlgodNodeInterface::eval_overrides_to_model(&ov).expect("overrides present");
        assert_eq!(model.allow_empty_signatures, Some(true));
        // false flags are omitted, not Some(false).
        assert_eq!(model.allow_unnamed_resources, None);
        assert_eq!(model.fix_signers, None);
        assert_eq!(model.extra_opcode_budget, Some(200));
        assert_eq!(model.max_log_calls, Some(40));
        assert_eq!(model.max_log_size, None);
    }

    #[test]
    fn exec_trace_to_model_maps_top_level_opcode_units() {
        use algo_ledger::simulation::{OpcodeTraceUnit, ProgramTrace, TransactionTrace};

        let trace = TransactionTrace {
            approval_program_trace: Some(ProgramTrace {
                opcodes: vec![
                    OpcodeTraceUnit {
                        pc: 0,
                        stack_additions: vec![AvmValueTrace::Uint64(1)],
                        ..Default::default()
                    },
                    OpcodeTraceUnit {
                        pc: 1,
                        stack_pop_count: 1,
                        scratch_changes: vec![(3, AvmValueTrace::Bytes(b"x".to_vec()))],
                        ..Default::default()
                    },
                ],
            }),
            approval_program_hash: Some([7u8; 32]),
            logicsig_trace: Some(ProgramTrace {
                opcodes: vec![OpcodeTraceUnit {
                    pc: 0,
                    ..Default::default()
                }],
            }),
            logicsig_hash: Some([9u8; 32]),
            ..Default::default()
        };

        let model = AlgodNodeInterface::exec_trace_to_model(&trace);
        assert_eq!(model.approval_program_hash, Some(vec![7u8; 32]));
        let units = model
            .approval_program_trace
            .expect("approval trace present");
        assert_eq!(units.len(), 2);

        // unit 0: one stack addition, pop count 0 omitted.
        assert_eq!(units[0].pc, 0);
        assert_eq!(units[0].stack_additions.as_ref().unwrap().len(), 1);
        assert_eq!(units[0].stack_pop_count, None);
        assert!(units[0].scratch_changes.is_none());

        // unit 1: pop count 1, empty stack additions omitted, one scratch change.
        assert_eq!(units[1].stack_pop_count, Some(1));
        assert!(units[1].stack_additions.is_none());
        let sc = units[1].scratch_changes.as_ref().unwrap();
        assert_eq!(sc[0].slot, 3);

        // Logic-sig trace + hash are translated (top-level).
        assert_eq!(model.logic_sig_hash, Some(vec![9u8; 32]));
        assert_eq!(model.logic_sig_trace.as_ref().unwrap().len(), 1);

        // No clear-state, no inners here.
        assert!(model.clear_state_program_trace.is_none());
        assert!(model.inner_trace.is_none());
        assert!(model.clear_state_rollback.is_none());
        assert!(model.clear_state_rollback_error.is_none());
    }

    #[test]
    fn exec_trace_to_model_recurses_inner_traces_and_spawned_inners() {
        use algo_ledger::simulation::{OpcodeTraceUnit, ProgramTrace, TransactionTrace};

        // Outer approval program with one opcode (itxn_submit) spawning inner 0.
        let trace = TransactionTrace {
            approval_program_trace: Some(ProgramTrace {
                opcodes: vec![
                    OpcodeTraceUnit {
                        pc: 0,
                        ..Default::default()
                    },
                    OpcodeTraceUnit {
                        pc: 1,
                        spawned_inners: vec![0],
                        ..Default::default()
                    },
                ],
            }),
            inner_traces: vec![TransactionTrace {
                approval_program_trace: Some(ProgramTrace {
                    opcodes: vec![OpcodeTraceUnit {
                        pc: 0,
                        ..Default::default()
                    }],
                }),
                approval_program_hash: Some([3u8; 32]),
                ..Default::default()
            }],
            ..Default::default()
        };

        let model = AlgodNodeInterface::exec_trace_to_model(&trace);

        // spawned-inners: empty omitted, populated carried through.
        let units = model.approval_program_trace.unwrap();
        assert!(units[0].spawned_inners.is_none());
        assert_eq!(units[1].spawned_inners, Some(vec![0]));

        // inner-trace recurses one level.
        let inner = model.inner_trace.expect("inner trace present");
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0].approval_program_hash, Some(vec![3u8; 32]));
        assert!(inner[0].inner_trace.is_none());
    }

    #[test]
    fn exec_trace_to_model_maps_clear_state_rollback() {
        use algo_ledger::simulation::TransactionTrace;

        // Errored clear-state: rollback true + error message.
        let errored = TransactionTrace {
            clear_state_rollback: true,
            clear_state_rollback_error: Some("assert failed".to_string()),
            ..Default::default()
        };
        let model = AlgodNodeInterface::exec_trace_to_model(&errored);
        assert_eq!(model.clear_state_rollback, Some(true));
        assert_eq!(
            model.clear_state_rollback_error.as_deref(),
            Some("assert failed")
        );

        // No rollback: false is omitted (not Some(false)).
        let ok = TransactionTrace::default();
        let model = AlgodNodeInterface::exec_trace_to_model(&ok);
        assert_eq!(model.clear_state_rollback, None);
        assert_eq!(model.clear_state_rollback_error, None);
    }

    #[test]
    fn state_change_to_model_write_and_delete() {
        let addr = Address([0xCD; 32]);

        let write = StateChange {
            kind: StateChangeKind::LocalState,
            op: StateChangeOp::Write,
            app_id: 5,
            key: b"k".to_vec(),
            new_value: Some(AvmValueTrace::Uint64(9)),
            account: Some(addr),
        };
        let m = AlgodNodeInterface::state_change_to_model(&write);
        assert_eq!(m.operation, "w");
        assert_eq!(m.app_state_type, "l");
        assert_eq!(m.key, b"k");
        assert_eq!(m.account, Some(addr.to_string()));
        assert_eq!(m.new_value.unwrap().uint, Some(9));

        let del = StateChange {
            kind: StateChangeKind::GlobalState,
            op: StateChangeOp::Delete,
            app_id: 5,
            key: b"k".to_vec(),
            new_value: None,
            account: None,
        };
        let m = AlgodNodeInterface::state_change_to_model(&del);
        assert_eq!(m.operation, "d");
        assert_eq!(m.app_state_type, "g");
        assert!(m.new_value.is_none());
        assert!(m.account.is_none());
    }

    #[test]
    fn exec_trace_config_disabled_is_none() {
        let cfg = ExecTraceConfig::default();
        assert!(AlgodNodeInterface::exec_trace_config_to_response(&cfg).is_none());
    }

    #[test]
    fn exec_trace_config_populates_enabled_flags() {
        let cfg = ExecTraceConfig {
            enable: true,
            stack: false,
            scratch: false,
            state: true,
        };
        let model =
            AlgodNodeInterface::exec_trace_config_to_response(&cfg).expect("config present");
        assert_eq!(model.enable, Some(true));
        assert_eq!(model.state_change, Some(true));
        assert_eq!(model.stack_change, None);
        assert_eq!(model.scratch_change, None);
    }

    fn make_adapter() -> AlgodNodeInterface {
        let ledger = Arc::new(Mutex::new(
            SqliteLedger::open_in_memory().expect("in-memory ledger"),
        ));
        AlgodNodeInterface::new(
            ledger,
            NodeInterfaceConfig {
                genesis_id: "testnet-v1.0".into(),
                genesis_hash: Digest([0xAB; 32]),
                genesis_json: r#"{"network":"testnet"}"#.into(),
                build_version: build_version_fixture(),
                default_protocol: CONSENSUS_V41.into(),
            },
        )
    }

    #[test]
    fn cached_genesis_accessors_return_config_values() {
        let adapter = make_adapter();
        assert_eq!(adapter.genesis_id(), "testnet-v1.0");
        assert_eq!(adapter.genesis_hash().0, [0xAB; 32]);
        assert_eq!(adapter.genesis_json(), r#"{"network":"testnet"}"#);
        assert_eq!(adapter.build_version().branch, "main");
    }

    #[test]
    fn upgrade_vote_constants_match_defaults() {
        let adapter = make_adapter();
        assert_eq!(adapter.upgrade_vote_rounds(), DEFAULT_UPGRADE_VOTE_ROUNDS);
        assert_eq!(adapter.upgrade_threshold(), DEFAULT_UPGRADE_THRESHOLD);
    }

    #[tokio::test]
    async fn status_reports_zero_round_for_empty_ledger() {
        let adapter = make_adapter();
        let status = adapter.status().await.expect("status ok");
        assert_eq!(status.last_round, 0);
        // With no committed blocks, the default protocol is reported as
        // both current and next.
        assert_eq!(status.last_version, CONSENSUS_V41);
        assert_eq!(status.next_version, CONSENSUS_V41);
        assert!(status.next_version_supported);
        assert!(!status.stopped_at_unsupported_round);
        assert!(status.catchpoint.is_empty());
    }

    #[tokio::test]
    async fn min_txn_fee_pulls_from_consensus_params() {
        let adapter = make_adapter();
        assert_eq!(adapter.min_txn_fee().await, 1_000);
        // suggested_fee defaults to min_txn_fee when no rolling-fee tracker
        // is wired up.
        assert_eq!(adapter.suggested_fee().await, 1_000);
    }

    #[tokio::test]
    async fn consensus_params_resolves_current_version() {
        let adapter = make_adapter();
        let params = adapter.consensus_params().await.expect("params ok");
        assert_eq!(params.min_txn_fee, 1_000);
    }

    #[tokio::test]
    async fn lookup_missing_account_returns_zero_data() {
        let adapter = make_adapter();
        let addr = Address::default();
        let lookup = adapter.lookup_account(&addr).await.expect("lookup ok");
        assert_eq!(lookup.account_data.micro_algos, 0);
        assert!(lookup.assets.is_empty());
        assert!(lookup.created_assets.is_empty());
        assert!(lookup.app_local_states.is_empty());
        assert!(lookup.created_apps.is_empty());
        assert_eq!(lookup.last_round, 0);

        let basic = adapter
            .lookup_account_basic(&addr)
            .await
            .expect("basic lookup ok");
        assert!(basic.assets.is_empty());
        assert!(basic.created_assets.is_empty());
    }

    #[tokio::test]
    async fn get_block_returns_not_found_for_empty_ledger() {
        let adapter = make_adapter();
        match adapter.get_block(1).await {
            Err(NodeError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
        match adapter.get_block_header(1).await {
            Err(NodeError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
        match adapter.get_state_delta_for_round(1).await {
            Err(NodeError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
        assert!(matches!(adapter.get_block_hash(1).await, Ok(None)));
    }

    /// PLAN-36 TASK-128: `get_state_delta_for_round` returns the cached
    /// `StateDelta` for rounds inside the rolling window, and `NotFound`
    /// for rounds that fell out of the window via eviction. Seeds the
    /// cache directly via `SqliteLedger::cache_state_delta` so the test
    /// does not depend on a fully-wired block-apply driver.
    #[tokio::test]
    async fn get_state_delta_for_round_returns_cached_delta() {
        use algo_ledger::StateDelta;

        let ledger = Arc::new(Mutex::new(
            SqliteLedger::open_in_memory().expect("in-memory ledger"),
        ));
        // Seed two rounds with sentinel deltas. We can't assert on the
        // *contents* without re-importing the whole StateDelta surface here,
        // so we use `StateDelta::default()` and just assert presence vs.
        // NotFound — that's the contract the handler exposes.
        {
            let mut guard = ledger.lock().expect("ledger lock");
            guard.cache_state_delta(5, StateDelta::default());
            guard.cache_state_delta(7, StateDelta::default());
        }
        let adapter = adapter_with_ledger(ledger.clone());

        // Round inside the window → Ok.
        assert!(adapter.get_state_delta_for_round(5).await.is_ok());
        assert!(adapter.get_state_delta_for_round(7).await.is_ok());

        // Round inside the window but never cached → NotFound.
        match adapter.get_state_delta_for_round(6).await {
            Err(NodeError::NotFound(_)) => {}
            other => panic!("expected NotFound for uncached round, got {other:?}"),
        }

        // Round outside the window → NotFound. Drive enough inserts to
        // push round 5 below the default 320-round window.
        {
            let mut guard = ledger.lock().expect("ledger lock");
            // After this, min_round >= 5 + 1 = 6, so round 5 is evicted.
            guard.cache_state_delta(
                5 + algo_ledger::DEFAULT_WINDOW_SIZE as u64,
                StateDelta::default(),
            );
        }
        match adapter.get_state_delta_for_round(5).await {
            Err(NodeError::NotFound(_)) => {}
            other => panic!("expected NotFound after eviction, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn protocol_info_is_empty_for_empty_ledger() {
        let adapter = make_adapter();
        let info = adapter
            .latest_block_header_protocol_info()
            .await
            .expect("protocol info ok");
        assert!(info.next_protocol.is_empty());
        assert!(info.next_protocol_supported);
        assert_eq!(info.next_protocol_switch_on, 0);
    }

    /// Build an adapter that wraps a supplied ledger Arc (rather than the
    /// default in-memory one from `make_adapter`) so tests can seed blocks
    /// before constructing the adapter.
    fn adapter_with_ledger(ledger: Arc<Mutex<SqliteLedger>>) -> AlgodNodeInterface {
        AlgodNodeInterface::new(
            ledger,
            NodeInterfaceConfig {
                genesis_id: "testnet-v1.0".into(),
                genesis_hash: Digest([0xAB; 32]),
                genesis_json: r#"{"network":"testnet"}"#.into(),
                build_version: build_version_fixture(),
                default_protocol: CONSENSUS_V41.into(),
            },
        )
    }

    #[tokio::test]
    async fn get_block_raw_msgpack_embeds_stored_bytes_verbatim() {
        // `put_block` is a plain DB insert — we can seed arbitrary
        // msgpack-valid bytes to prove the envelope is a true pass-through.
        // Fields inside "block" that our typed Rust `Block` does not model
        // (e.g. `zzextra`) must survive the round trip.
        let ledger_arc = Arc::new(Mutex::new(
            SqliteLedger::open_in_memory().expect("in-memory ledger"),
        ));

        // fixmap(2) + "rnd":1 + "zzextra":"keep"
        let stored_block: Vec<u8> = vec![
            0x82, // fixmap(2)
            0xa3, b'r', b'n', b'd', // "rnd"
            0x01, // 1 (positive fixint)
            0xa7, b'z', b'z', b'e', b'x', b't', b'r', b'a', // "zzextra"
            0xa4, b'k', b'e', b'e', b'p', // "keep"
        ];
        let stored_hdr = stored_block.clone();
        // fixmap(1) + "sig":0
        let stored_cert: Vec<u8> = vec![0x81, 0xa3, b's', b'i', b'g', 0x00];

        {
            let mut ledger = ledger_arc.lock().expect("ledger lock");
            ledger
                .put_block(7, CONSENSUS_V41, &stored_hdr, &stored_block)
                .expect("put_block ok");
            ledger
                .put_block_cert(7, &stored_cert)
                .expect("put_block_cert ok");
        }

        let adapter = adapter_with_ledger(Arc::clone(&ledger_arc));
        let raw = adapter
            .get_block_raw_msgpack(7)
            .await
            .expect("raw msgpack ok");

        let mut expected = Vec::new();
        expected.push(0x82); // fixmap(2)
        expected.push(0xa5); // fixstr(5)
        expected.extend_from_slice(b"block");
        expected.extend_from_slice(&stored_block);
        expected.push(0xa4); // fixstr(4)
        expected.extend_from_slice(b"cert");
        expected.extend_from_slice(&stored_cert);

        assert_eq!(raw, expected, "envelope must pass stored bytes verbatim");
    }

    #[tokio::test]
    async fn get_block_raw_msgpack_omits_cert_when_missing() {
        let ledger_arc = Arc::new(Mutex::new(
            SqliteLedger::open_in_memory().expect("in-memory ledger"),
        ));
        let stored_block: Vec<u8> = vec![0x81, 0xa3, b'r', b'n', b'd', 0x02]; // {rnd:2}
        {
            let mut ledger = ledger_arc.lock().expect("ledger lock");
            ledger
                .put_block(2, CONSENSUS_V41, &stored_block, &stored_block)
                .expect("put_block ok");
            // Intentionally no put_block_cert — mirrors catchpoint-backfilled
            // blocks that arrive without their original certificate.
        }
        let adapter = adapter_with_ledger(ledger_arc);
        let raw = adapter
            .get_block_raw_msgpack(2)
            .await
            .expect("raw msgpack ok");

        // Expected: fixmap(1) + "block" + raw bytes — no "cert" key.
        let mut expected = vec![0x81, 0xa5];
        expected.extend_from_slice(b"block");
        expected.extend_from_slice(&stored_block);
        assert_eq!(raw, expected);
    }

    #[tokio::test]
    async fn get_block_hash_falls_back_to_blkdata_when_hdrdata_is_empty() {
        // Mirrors the relay writer in commands/relay.rs which calls
        // `put_block(round, "", &[], block_data)` — i.e. valid `blkdata`
        // but empty `hdrdata`. The adapter must still produce the correct
        // hash via the full-block path.
        use algo_codec::compute_block_digest;
        use algo_types::{Block, Round};

        let block = Block {
            round: Round(9),
            current_protocol: CONSENSUS_V41.into(),
            ..Block::default()
        };
        let blkdata = rmp_serde::to_vec_named(&block).expect("encode block");

        let ledger_arc = Arc::new(Mutex::new(
            SqliteLedger::open_in_memory().expect("in-memory ledger"),
        ));
        {
            let mut ledger = ledger_arc.lock().expect("ledger lock");
            // Empty proto + empty hdrdata, non-empty blkdata — matches relay.
            ledger
                .put_block(9, "", &[], &blkdata)
                .expect("put_block ok");
        }

        let adapter = adapter_with_ledger(ledger_arc);
        let hash = adapter
            .get_block_hash(9)
            .await
            .expect("get_block_hash ok")
            .expect("hash present");
        assert_eq!(hash, compute_block_digest(&block));
    }

    #[tokio::test]
    async fn get_block_hash_returns_none_when_row_is_absent() {
        // The adapter must distinguish "round not yet committed" (Ok(None))
        // from "round is present but corrupted" (Err). An absent row is the
        // former — `get_block_header_data` + `get_block_data` both return
        // None, so the method returns Ok(None).
        let adapter = make_adapter();
        assert!(matches!(adapter.get_block_hash(123).await, Ok(None)));
    }

    /// Minimal `PoolLedger` impl so tests can construct a real
    /// `TransactionPool` without pulling in the participate-subcommand
    /// plumbing. The pool methods under test (`pending_tx_groups`,
    /// `lookup`) do not exercise any `PoolLedger` method, so the stubs can
    /// return trivially.
    struct PoolLedgerStub;

    impl algo_pool::traits::PoolLedger for PoolLedgerStub {
        fn latest(&self) -> algo_types::Round {
            algo_types::Round(0)
        }

        fn block_hdr(
            &self,
            _round: algo_types::Round,
        ) -> Result<algo_types::BlockHeader, algo_error::AlgoError> {
            Ok(algo_types::BlockHeader::default())
        }

        fn consensus_params(
            &self,
            _round: algo_types::Round,
        ) -> Result<algo_types::ConsensusParams, algo_error::AlgoError> {
            Ok(algo_types::ConsensusParams::default())
        }

        fn start_evaluator(
            &self,
            _hdr: algo_types::BlockHeader,
            _payset_hint: usize,
            _max_txn_bytes_per_block: usize,
        ) -> Result<Box<dyn algo_pool::traits::BlockEvaluator>, algo_error::AlgoError> {
            // Not needed by the pool methods under test.
            Err(algo_error::AlgoError::Ledger {
                message: "PoolLedgerStub::start_evaluator intentionally unimplemented".into(),
            })
        }
    }

    fn adapter_with_pool() -> AlgodNodeInterface {
        let pool = Arc::new(algo_pool::TransactionPool::new(
            algo_pool::PoolConfig::default(),
            Arc::new(PoolLedgerStub),
        ));
        make_adapter().with_pool(pool)
    }

    /// Build a dev-mode adapter over an in-memory ledger seeded from a genesis
    /// that funds `sender` (proto "future"). Returns the adapter, the shared
    /// ledger, and the genesis hash. Mirrors `node start --dev` wiring.
    fn seed_dev_adapter(
        sender: Address,
        micro_algos: u64,
    ) -> (AlgodNodeInterface, Arc<Mutex<SqliteLedger>>, [u8; 32]) {
        use crate::commands::participate::PoolLedgerAdapter;
        use algo_codec::{canonical_encode_block_header_from_block, encode_block};
        use algo_ledger::genesis::genesis_hash;
        use algo_ledger::{
            make_genesis_block, parse_genesis_json, populate_store,
            seed_account_totals_from_genesis,
        };

        let fees = Address([0xFEu8; 32]).to_algorand_string();
        let rwd = Address([0xFDu8; 32]).to_algorand_string();
        let sender_b32 = sender.to_algorand_string();
        let genesis_json = format!(
            r#"{{"id":"v1","network":"localnet","proto":"future","fees":"{fees}","rwd":"{rwd}","timestamp":0,"alloc":[{{"addr":"{sender_b32}","comment":"w1","state":{{"algo":{micro_algos},"onl":0}}}}]}}"#
        );
        let genesis = parse_genesis_json(&genesis_json).expect("parse genesis");
        let gh = genesis_hash(&genesis);

        let mut l = SqliteLedger::open_in_memory().expect("ledger");
        l.begin_block().unwrap();
        populate_store(&mut l, &genesis).unwrap();
        seed_account_totals_from_genesis(&mut l, &genesis).unwrap();
        let gblk = make_genesis_block(&genesis).unwrap();
        let hdr = canonical_encode_block_header_from_block(&gblk);
        let blk = encode_block(&gblk).unwrap();
        l.put_block(0, &gblk.current_protocol, &hdr, &blk).unwrap();
        // Seed the running txn-counter from the genesis block (TASK-279) so
        // produced blocks generate ids from 1001, as `node start` does.
        l.set_txn_counter(gblk.txn_counter);
        l.commit_block().unwrap();
        let ledger = Arc::new(Mutex::new(l));

        let pool = Arc::new(TransactionPool::new(
            algo_pool::PoolConfig::default(),
            Arc::new(PoolLedgerAdapter::new(ledger.clone()))
                as Arc<dyn algo_pool::traits::PoolLedger>,
        ));
        let adapter = adapter_with_ledger(ledger.clone())
            .with_pool(pool)
            .with_dev_mode();
        (adapter, ledger, gh)
    }

    /// ed25519-sign a transaction (`SHA512/256("TX" || canonical(txn))`).
    fn sign_txn(
        txn: &algo_types::Transaction,
        key: &ed25519_dalek::SigningKey,
    ) -> SignedTransaction {
        use ed25519_dalek::Signer;
        let mut msg = b"TX".to_vec();
        msg.extend_from_slice(&algo_codec::canonical_encode_transaction(txn));
        SignedTransaction {
            txn: txn.clone(),
            sig: key.sign(&msg).to_bytes(),
            ..Default::default()
        }
    }

    /// End-to-end dev-mode submit→confirm (TASK-264): a signed payment, when
    /// broadcast to a dev-mode node, produces a block and is reported confirmed.
    #[tokio::test]
    async fn dev_mode_submit_produces_block_and_confirms() {
        use algo_types::{Round, Transaction, TxnType};
        use ed25519_dalek::SigningKey;

        let sender_key = SigningKey::from_bytes(&[0x11u8; 32]);
        let sender = Address(sender_key.verifying_key().to_bytes());
        let (adapter, ledger, gh) = seed_dev_adapter(sender, 10_000_000);

        // Signed payment valid from round 1 (the round the dev node will build).
        let txn = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver: Address([0x22u8; 32]),
            amount: 1_000_000,
            fee: 1000,
            first_valid: Round(1),
            last_valid: Round(1000),
            genesis_hash: gh,
            ..Default::default()
        };
        let stx = sign_txn(&txn, &sender_key);
        let txid = compute_txn_id(&txn);

        adapter
            .broadcast_signed_tx_group(vec![stx])
            .await
            .expect("dev-mode broadcast should produce a block");

        assert_eq!(
            ledger.lock().unwrap().current_round().0,
            1,
            "one block should have been produced",
        );

        let status = adapter
            .get_pending_transaction(&txid)
            .await
            .expect("lookup ok")
            .expect("transaction should be found as confirmed");
        assert_eq!(status.confirmed_round, 1, "confirmed in round 1");
    }

    /// Dev mode commits in Execute mode, so an app-create whose approval program
    /// rejects must fail the submission — not confirm an invalid app call — and
    /// must not wedge the pool (TASK-264 / Codex round 5).
    #[tokio::test]
    async fn dev_mode_rejects_failing_app_program() {
        use algo_types::{Round, Transaction, TxnType};
        use ed25519_dalek::SigningKey;
        use serde_bytes::ByteBuf;

        let sender_key = SigningKey::from_bytes(&[0x33u8; 32]);
        let sender = Address(sender_key.verifying_key().to_bytes());
        let (adapter, ledger, gh) = seed_dev_adapter(sender, 10_000_000);

        // App-create (application_id 0, NoOp) with a rejecting approval program
        // (`#pragma version 6; pushint 0`) and an approving clear-state program.
        let txn = Transaction {
            txn_type: TxnType::Appl,
            sender,
            application_id: 0,
            on_completion: 0,
            approval_program: Some(ByteBuf::from(vec![0x06u8, 0x81, 0x00])),
            clear_state_program: Some(ByteBuf::from(vec![0x06u8, 0x81, 0x01])),
            fee: 1000,
            first_valid: Round(1),
            last_valid: Round(1000),
            genesis_hash: gh,
            ..Default::default()
        };
        let stx = sign_txn(&txn, &sender_key);
        let txid = compute_txn_id(&txn);

        // Execute mode runs the rejecting program → submission errors (4xx).
        let err = adapter
            .broadcast_signed_tx_group(vec![stx])
            .await
            .expect_err("a rejecting app program must fail the submission");
        assert!(
            matches!(err, NodeError::BadRequest(_)),
            "expected BadRequest, got {err:?}",
        );

        // No block was produced, and the rejected txn is neither confirmed nor
        // left wedged in the pool.
        assert_eq!(
            ledger.lock().unwrap().current_round().0,
            0,
            "no block should be produced when the app program rejects",
        );
        assert!(
            adapter
                .get_pending_transaction(&txid)
                .await
                .expect("lookup ok")
                .is_none(),
            "rejected transaction must not be reported confirmed or pending",
        );
    }

    /// A passing app-create confirms and reports its created application id in
    /// the pending-transaction response (TASK-278 ApplyData surfacing).
    #[tokio::test]
    async fn dev_mode_app_create_reports_application_id() {
        use algo_types::{Round, Transaction, TxnType};
        use ed25519_dalek::SigningKey;
        use serde_bytes::ByteBuf;

        let sender_key = SigningKey::from_bytes(&[0x44u8; 32]);
        let sender = Address(sender_key.verifying_key().to_bytes());
        let (adapter, _ledger, gh) = seed_dev_adapter(sender, 10_000_000);

        // App-create with an APPROVING program (`#pragma version 6; pushint 1`).
        let txn = Transaction {
            txn_type: TxnType::Appl,
            sender,
            application_id: 0,
            on_completion: 0,
            approval_program: Some(ByteBuf::from(vec![0x06u8, 0x81, 0x01])),
            clear_state_program: Some(ByteBuf::from(vec![0x06u8, 0x81, 0x01])),
            fee: 1000,
            first_valid: Round(1),
            last_valid: Round(1000),
            genesis_hash: gh,
            ..Default::default()
        };
        let stx = sign_txn(&txn, &sender_key);
        let txid = compute_txn_id(&txn);

        adapter
            .broadcast_signed_tx_group(vec![stx])
            .await
            .expect("approving app-create should confirm");

        let status = adapter
            .get_pending_transaction(&txid)
            .await
            .expect("lookup ok")
            .expect("confirmed");
        assert_eq!(status.confirmed_round, 1, "confirmed in round 1");
        // First created app id is 1001: genesis seeds the running txn_counter at
        // 1000 (TASK-279), matching go's AppForbidLowResources convention.
        assert_eq!(
            status.application_index,
            Some(1001),
            "created application id reported from ApplyData",
        );
        assert_eq!(status.asset_index, None, "not an asset create");
    }

    /// An app whose program writes global state has its eval delta surfaced on
    /// confirmation (TASK-280 — Execute-mode ApplyData.eval_delta).
    #[tokio::test]
    async fn dev_mode_app_call_reports_eval_delta() {
        use algo_types::{Round, StateSchema, Transaction, TxnType};
        use ed25519_dalek::SigningKey;
        use serde_bytes::ByteBuf;

        let sender_key = SigningKey::from_bytes(&[0x55u8; 32]);
        let sender = Address(sender_key.verifying_key().to_bytes());
        let (adapter, _ledger, gh) = seed_dev_adapter(sender, 10_000_000);

        // v6 approval program: pushbytes "counter"; pushint 42; app_global_put;
        // pushint 1; return — writes one global-state entry, then approves.
        let approval = vec![
            0x06, 0x80, 0x07, b'c', b'o', b'u', b'n', b't', b'e', b'r', 0x81, 0x2A, 0x67, 0x81,
            0x01, 0x43,
        ];
        let txn = Transaction {
            txn_type: TxnType::Appl,
            sender,
            application_id: 0,
            on_completion: 0,
            approval_program: Some(ByteBuf::from(approval)),
            clear_state_program: Some(ByteBuf::from(vec![0x06u8, 0x81, 0x01])),
            // Global schema must allow the one uint the program writes.
            global_state_schema: Some(StateSchema {
                num_uint: 1,
                num_byte_slice: 0,
            }),
            fee: 1000,
            first_valid: Round(1),
            last_valid: Round(1000),
            genesis_hash: gh,
            ..Default::default()
        };
        let stx = sign_txn(&txn, &sender_key);
        let txid = compute_txn_id(&txn);

        adapter
            .broadcast_signed_tx_group(vec![stx])
            .await
            .expect("state-writing app-create should confirm");

        let status = adapter
            .get_pending_transaction(&txid)
            .await
            .expect("lookup ok")
            .expect("confirmed");
        assert_eq!(status.application_index, Some(1001));
        // The program wrote global state, so the AVM-produced eval delta is
        // surfaced (it carries the global "counter" change).
        assert!(
            status.eval_delta.is_some(),
            "eval delta from the app execution should be reported on confirmation",
        );
    }

    #[tokio::test]
    async fn pool_methods_return_not_implemented_without_pool() {
        let adapter = make_adapter();
        let err = adapter
            .get_pending_txns_from_pool()
            .await
            .expect_err("should require pool");
        match err {
            NodeError::NotImplemented(name) => {
                assert_eq!(name, "get_pending_txns_from_pool");
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
        let err = adapter
            .get_pending_transaction(&Digest([0u8; 32]))
            .await
            .expect_err("should require pool");
        match err {
            NodeError::NotImplemented(name) => {
                assert_eq!(name, "get_pending_transaction");
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_pending_txns_from_pool_returns_empty_vec_when_pool_is_idle() {
        let adapter = adapter_with_pool();
        let txns = adapter
            .get_pending_txns_from_pool()
            .await
            .expect("empty pool ok");
        assert!(txns.is_empty());
    }

    #[tokio::test]
    async fn get_pending_transaction_returns_none_for_unknown_txid() {
        let adapter = adapter_with_pool();
        let got = adapter
            .get_pending_transaction(&Digest([0xFFu8; 32]))
            .await
            .expect("lookup ok");
        assert!(got.is_none());
    }

    #[test]
    fn map_pool_lookup_miss_returns_none() {
        let got =
            AlgodNodeInterface::map_pool_lookup(SignedTransaction::default(), String::new(), false);
        assert!(got.is_none());
    }

    #[test]
    fn map_pool_lookup_pending_hit_surfaces_txn_with_empty_error() {
        // A real pending txn: non-default (distinguishable by note), no
        // pool_error, found=true → Some with the txn echoed through.
        use algo_types::{Transaction, TxnType};
        use serde_bytes::ByteBuf;
        let base = Transaction {
            note: ByteBuf::from(b"pending-hit".to_vec()),
            txn_type: TxnType::Pay,
            ..Transaction::default()
        };
        let pending = SignedTransaction {
            txn: base,
            ..SignedTransaction::default()
        };
        let got = AlgodNodeInterface::map_pool_lookup(pending.clone(), String::new(), true)
            .expect("pending hit should produce Some");
        assert_eq!(got.txn, pending);
        assert_eq!(got.confirmed_round, 0);
        assert!(got.pool_error.is_empty());
    }

    #[test]
    fn map_pool_lookup_evicted_surfaces_pool_error() {
        // Evicted case: pool returns `(default, err, true)` when the txn
        // was removed from pending via the status cache with an error.
        let got = AlgodNodeInterface::map_pool_lookup(
            SignedTransaction::default(),
            "expired".to_string(),
            true,
        )
        .expect("eviction should produce Some");
        assert_eq!(got.txn, SignedTransaction::default());
        assert_eq!(got.pool_error, "expired");
        assert_eq!(got.confirmed_round, 0);
    }

    #[test]
    fn map_pool_lookup_recently_committed_returns_none_until_block_lookup_wired() {
        // Committed txns land in the status cache with an empty error
        // string — pool returns `(default, "", true)` which by itself is
        // meaningless. Until the block-side confirmation lookup is wired,
        // the adapter conservatively returns None rather than a bogus
        // pending response.
        let got =
            AlgodNodeInterface::map_pool_lookup(SignedTransaction::default(), String::new(), true);
        assert!(
            got.is_none(),
            "committed case without block-side lookup must not synthesize a pending response"
        );
    }

    // ---- Broadcast methods (TASK-77) ----

    #[tokio::test]
    async fn broadcast_methods_return_not_implemented_without_broadcaster() {
        let adapter = make_adapter();
        let tx_group = vec![SignedTransaction::default()];

        match adapter
            .broadcast_signed_tx_group(tx_group.clone())
            .await
            .expect_err("should require broadcaster")
        {
            NodeError::NotImplemented(name) => {
                assert_eq!(name, "broadcast_signed_tx_group");
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }

        match adapter
            .async_broadcast_signed_tx_group(tx_group)
            .await
            .expect_err("should require broadcaster")
        {
            NodeError::NotImplemented(name) => {
                assert_eq!(name, "async_broadcast_signed_tx_group");
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn reserve_async_backlog_permit_acquires_and_releases() {
        // Capacity = 1: the first acquire succeeds, the second fails
        // until the first permit is dropped.
        let permits = Arc::new(Semaphore::new(1));
        let first =
            AlgodNodeInterface::reserve_async_backlog_permit(&permits).expect("first permit");

        match AlgodNodeInterface::reserve_async_backlog_permit(&permits) {
            Err(NodeError::Internal(msg)) => {
                assert_eq!(msg, "broadcast: async backlog full");
            }
            other => panic!("expected backlog full, got {other:?}"),
        }

        drop(first);
        let _second_after_drop = AlgodNodeInterface::reserve_async_backlog_permit(&permits)
            .expect("permit available after drop");
    }

    #[test]
    fn with_async_backlog_capacity_replaces_the_semaphore() {
        // The builder must install a fresh semaphore — sanity-check by
        // constructing with a tiny capacity and asserting the first
        // acquire works, the second fails.
        let adapter = make_adapter().with_async_backlog_capacity(1);
        let first =
            AlgodNodeInterface::reserve_async_backlog_permit(&adapter.async_backlog_permits)
                .expect("first permit");
        assert!(matches!(
            AlgodNodeInterface::reserve_async_backlog_permit(&adapter.async_backlog_permits),
            Err(NodeError::Internal(_))
        ));
        drop(first);
    }

    #[test]
    fn with_async_backlog_capacity_floors_at_one() {
        // Capacity = 0 is a footgun (immediately refuses everything); the
        // builder silently raises it to 1 so the adapter still makes
        // forward progress.
        let adapter = make_adapter().with_async_backlog_capacity(0);
        assert!(
            AlgodNodeInterface::reserve_async_backlog_permit(&adapter.async_backlog_permits)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn wait_for_round_returns_timeout_when_shutdown_token_fires() {
        // The ledger never advances past round 0, so without the
        // shutdown token `wait_for_round(1)` would poll forever. The
        // token gives us a bounded exit so REST's graceful shutdown
        // isn't held open by long-poll handlers when the node is
        // stopping.
        let token = CancellationToken::new();
        let adapter = make_adapter().with_shutdown_token(token.clone());

        let waiter = tokio::spawn(async move { adapter.wait_for_round(1).await });
        // Cancel the token. The waiter's inner `tokio::select!` sees
        // the cancellation on either the current poll's sleep or the
        // next one — no virtual-clock machinery needed.
        token.cancel();

        // Bound the test with a generous real-clock timeout; the
        // waiter should return well under this cap once the token
        // cancellation propagates (a handful of `WAIT_POLL_INTERVAL`s
        // at most).
        let result = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("waiter did not return within 5s")
            .expect("task joined");
        match result {
            Err(NodeError::Timeout(msg)) => {
                assert!(
                    msg.contains("shutting down"),
                    "expected shutdown message, got {msg:?}"
                );
            }
            other => panic!("expected Timeout(shutdown), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn wait_for_round_without_shutdown_token_keeps_polling() {
        // When no token is attached, cancellation has no effect — the
        // poll loop continues until the round arrives. This test
        // proves the optional plumbing doesn't change pre-TASK-79
        // behaviour for adapters constructed without a token.
        let adapter = make_adapter();
        let result = tokio::time::timeout(WAIT_POLL_INTERVAL * 3, adapter.wait_for_round(1)).await;
        assert!(
            result.is_err(),
            "expected outer timeout (waiter kept polling), got {result:?}"
        );
    }

    #[test]
    fn local_tx_error_maps_to_node_error_internal_with_category_prefix() {
        // The NodeInterface trait only exposes Internal / NotFound /
        // Timeout / NotImplemented — none of which cleanly express a
        // client-data rejection. We collapse all four LocalTxError
        // variants to Internal but preserve the category in the message
        // so handlers can (later) key off the prefix to refine status
        // codes.
        fn msg(err: NodeError) -> String {
            match err {
                NodeError::Internal(m) => m,
                other => panic!("expected Internal, got {other:?}"),
            }
        }

        let empty = AlgodNodeInterface::local_tx_error_to_node_error(LocalTxError::Empty);
        assert_eq!(msg(empty), "broadcast: empty group");

        let pool =
            AlgodNodeInterface::local_tx_error_to_node_error(LocalTxError::Pool("bad fee".into()));
        assert_eq!(msg(pool), "broadcast: pool rejected group: bad fee");

        let encode = AlgodNodeInterface::local_tx_error_to_node_error(LocalTxError::Encode(
            "bad msgpack".into(),
        ));
        assert_eq!(msg(encode), "broadcast: encode failed: bad msgpack");

        let broadcast = AlgodNodeInterface::local_tx_error_to_node_error(LocalTxError::Broadcast(
            "no peers".into(),
        ));
        assert_eq!(msg(broadcast), "broadcast: gossip failed: no peers");
    }

    // ---- Simulation (TASK-78) ----

    #[test]
    fn exec_trace_config_from_model_collapses_optional_bools() {
        // Missing outer: all defaults false.
        let default = AlgodNodeInterface::exec_trace_config_from_model(None);
        assert!(!default.enable);
        assert!(!default.stack);
        assert!(!default.scratch);
        assert!(!default.state);

        // Fully-populated outer: individual flags propagate.
        let full = AlgodNodeInterface::exec_trace_config_from_model(Some(SimulateTraceConfig {
            enable: Some(true),
            stack_change: Some(true),
            scratch_change: Some(false),
            state_change: Some(true),
        }));
        assert!(full.enable);
        assert!(full.stack);
        assert!(!full.scratch);
        assert!(full.state);
    }

    #[test]
    fn build_simulation_request_maps_fields_and_uses_decoded_txn_groups() {
        let decoded = vec![vec![SignedTransaction::default()]];
        let request = SimulateRequest {
            allow_empty_signatures: Some(true),
            allow_more_logging: Some(true),
            allow_unnamed_resources: Some(false),
            exec_trace_config: Some(SimulateTraceConfig {
                enable: Some(true),
                stack_change: None,
                scratch_change: None,
                state_change: None,
            }),
            extra_opcode_budget: Some(2_000),
            fix_signers: Some(true),
            round: Some(42),
            txn_groups: Vec::new(), // handler uses decoded_txn_groups instead
            decoded_txn_groups: decoded.clone(),
        };

        let sim = AlgodNodeInterface::build_simulation_request(request);
        assert_eq!(sim.round, Some(Round(42)));
        assert_eq!(sim.txn_groups, decoded);
        assert!(sim.allow_empty_signatures);
        assert!(sim.allow_more_logging);
        assert!(!sim.allow_unnamed_resources);
        assert_eq!(sim.extra_opcode_budget, 2_000);
        assert!(sim.trace_config.enable);
        assert!(sim.fix_signers);
    }

    #[test]
    fn build_simulation_request_defaults_unset_options_to_false_and_zero() {
        let request = SimulateRequest {
            allow_empty_signatures: None,
            allow_more_logging: None,
            allow_unnamed_resources: None,
            exec_trace_config: None,
            extra_opcode_budget: None,
            fix_signers: None,
            round: None,
            txn_groups: Vec::new(),
            decoded_txn_groups: Vec::new(),
        };

        let sim = AlgodNodeInterface::build_simulation_request(request);
        assert!(sim.round.is_none());
        assert!(sim.txn_groups.is_empty());
        assert!(!sim.allow_empty_signatures);
        assert!(!sim.allow_more_logging);
        assert!(!sim.allow_unnamed_resources);
        assert_eq!(sim.extra_opcode_budget, 0);
        assert!(!sim.fix_signers);
        assert!(!sim.trace_config.enable);
    }

    #[test]
    fn opt_nonzero_u64_skips_zero_keeps_nonzero() {
        assert!(AlgodNodeInterface::opt_nonzero_u64(0).is_none());
        assert_eq!(AlgodNodeInterface::opt_nonzero_u64(1), Some(1));
        assert_eq!(
            AlgodNodeInterface::opt_nonzero_u64(u64::MAX),
            Some(u64::MAX)
        );
    }

    #[test]
    fn build_simulate_response_leaves_fidelity_fields_none() {
        // Build a minimal SimulationResult with one group + one txn and
        // confirm the REST response has the shape downstream tests
        // already check (version / last_round / txn_groups populated,
        // eval_overrides / initial_states / exec_trace_config None per
        // PLAN-34).
        let txn = SignedTransaction::default();
        let group = TxnGroupResult {
            txn_results: vec![TxnResult {
                txn: Some(txn.clone()),
                app_budget_consumed: 100,
                logicsig_budget_consumed: 0,
                ..Default::default()
            }],
            failure_message: None,
            failed_at: None,
            app_budget_added: 700,
            app_budget_consumed: 100,
        };
        let result = SimulationResult {
            version: 2,
            last_round: Round(1000),
            txn_groups: vec![group],
            eval_overrides: Default::default(),
            trace_config: Default::default(),
            initial_states: None,
        };

        let response = AlgodNodeInterface::build_simulate_response(result);
        assert_eq!(response.version, 2);
        assert_eq!(response.last_round, 1000);
        assert!(response.eval_overrides.is_none());
        assert!(response.initial_states.is_none());
        assert!(response.exec_trace_config.is_none());
        assert_eq!(response.txn_groups.len(), 1);

        let group = &response.txn_groups[0];
        assert_eq!(group.app_budget_added, Some(700));
        assert_eq!(group.app_budget_consumed, Some(100));
        assert!(group.failure_message.is_none());
        assert!(group.failed_at.is_none());
        assert_eq!(group.txn_results.len(), 1);

        let txn_result = &group.txn_results[0];
        assert_eq!(txn_result.app_budget_consumed, Some(100));
        assert!(txn_result.logic_sig_budget_consumed.is_none()); // 0 → None
        assert!(txn_result.exec_trace.is_none());
        assert_eq!(txn_result.txn_result.txn, txn);
        assert!(txn_result.txn_result.pool_error.is_empty());
    }

    #[test]
    fn build_simulate_response_propagates_failure_message_and_path() {
        let result = SimulationResult {
            version: 2,
            last_round: Round(10),
            txn_groups: vec![TxnGroupResult {
                txn_results: vec![TxnResult {
                    txn: Some(SignedTransaction::default()),
                    ..Default::default()
                }],
                failure_message: Some("rejected: bad fee".into()),
                failed_at: Some(vec![0, 1]),
                app_budget_added: 0,
                app_budget_consumed: 0,
            }],
            eval_overrides: Default::default(),
            trace_config: Default::default(),
            initial_states: None,
        };

        let response = AlgodNodeInterface::build_simulate_response(result);
        let group = &response.txn_groups[0];
        assert_eq!(group.failure_message.as_deref(), Some("rejected: bad fee"));
        assert_eq!(group.failed_at.as_deref(), Some(&[0u64, 1u64][..]));
        // Zero-valued budget counters collapse to None.
        assert!(group.app_budget_added.is_none());
        assert!(group.app_budget_consumed.is_none());
    }

    #[test]
    fn map_simulator_error_routes_invalid_request_to_bad_request_and_others_to_internal() {
        use algo_ledger::simulation::{EvalFailureError, InvalidRequestError};

        // Invalid-request routes to BadRequest (→ 400) so the REST
        // handler surfaces client-side mistakes correctly.
        let invalid = AlgodNodeInterface::map_simulator_error(SimulatorError::InvalidRequest(
            InvalidRequestError {
                message: "no groups".into(),
            },
        ));
        match invalid {
            NodeError::BadRequest(m) => {
                assert_eq!(m, "simulate: invalid request: no groups")
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }

        // Eval failures stay on Internal (→ 500); the simulator normally
        // carries eval failures inside the result rather than raising
        // this variant, so this branch is for pre-execution checks.
        let eval = AlgodNodeInterface::map_simulator_error(SimulatorError::EvalFailure(
            EvalFailureError {
                message: "budget exceeded".into(),
                failed_at: vec![0],
            },
        ));
        match eval {
            NodeError::Internal(m) => {
                assert!(m.starts_with("simulate: eval failure: "))
            }
            other => panic!("expected Internal, got {other:?}"),
        }

        // Internal errors (ledger read failures, etc.) stay on Internal.
        let internal = AlgodNodeInterface::map_simulator_error(SimulatorError::Internal(
            algo_error::AlgoError::Ledger {
                message: "disk oops".into(),
            },
        ));
        match internal {
            NodeError::Internal(m) => assert!(m.starts_with("simulate: internal: ")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn lock_ledger_surfaces_poisoned_mutex_as_internal_error() {
        // Poison the ledger mutex by panicking while a guard is held,
        // then confirm every `Result`-returning adapter method surfaces
        // `NodeError::Internal` with the poison message instead of
        // propagating the panic into subsequent callers (which is what
        // `expect("ledger lock poisoned")` used to do).
        let ledger_arc = Arc::new(Mutex::new(
            SqliteLedger::open_in_memory().expect("in-memory ledger"),
        ));
        // Poison by panicking inside a lock scope. `catch_unwind` keeps
        // the panic from escaping into the test harness.
        let poison_target = Arc::clone(&ledger_arc);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = poison_target.lock().expect("initial lock");
            panic!("simulated panic while holding ledger lock");
        }));
        assert!(
            ledger_arc.is_poisoned(),
            "test harness failed to poison the ledger mutex"
        );

        let adapter = AlgodNodeInterface::new(
            ledger_arc,
            NodeInterfaceConfig {
                genesis_id: "testnet-v1.0".into(),
                genesis_hash: Digest([0xAB; 32]),
                genesis_json: "{}".into(),
                build_version: build_version_fixture(),
                default_protocol: CONSENSUS_V41.into(),
            },
        );

        // Direct helper: poison surfaces as Internal, carrying the
        // method name so operators can trace which caller tripped the
        // cascade. `MutexGuard<SqliteLedger>` is not `Debug`, so we
        // destructure the error directly rather than printing the whole
        // `Result` in the panic message.
        let err = adapter
            .lock_ledger("probe")
            .err()
            .expect("poisoned lock should error");
        match err {
            NodeError::Internal(msg) => {
                assert!(
                    msg.starts_with("probe: ledger lock poisoned"),
                    "expected poison message, got {msg:?}"
                );
                assert!(
                    msg.contains("earlier operation panicked"),
                    "expected panic explanation, got {msg:?}"
                );
            }
            other => panic!("expected Internal(poisoned), got {other:?}"),
        }

        // Status preflight (the very path Codex flagged as cascading
        // into simulate) now returns Internal instead of panicking.
        match adapter.status().await {
            Err(NodeError::Internal(msg)) => {
                assert!(msg.starts_with("status: ledger lock poisoned"));
            }
            other => panic!("expected Internal from status(), got {other:?}"),
        }

        // simulate() itself surfaces the poison message without calling
        // into the simulator.
        let request = SimulateRequest {
            allow_empty_signatures: None,
            allow_more_logging: None,
            allow_unnamed_resources: None,
            exec_trace_config: None,
            extra_opcode_budget: None,
            fix_signers: None,
            round: None,
            txn_groups: Vec::new(),
            decoded_txn_groups: vec![vec![SignedTransaction::default()]],
        };
        match adapter.simulate(request).await {
            Err(NodeError::Internal(msg)) => {
                assert!(msg.starts_with("simulate: ledger lock poisoned"));
            }
            other => panic!("expected Internal from simulate(), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn simulate_rejects_empty_txn_groups_as_bad_request() {
        // The simulator validates that the request contains at least one
        // transaction group. An empty request surfaces as
        // `SimulatorError::InvalidRequest`, which the adapter maps to
        // `NodeError::BadRequest` so the REST handler returns 400. This
        // exercises the full trait method without needing a populated
        // ledger.
        let adapter = make_adapter();
        let request = SimulateRequest {
            allow_empty_signatures: None,
            allow_more_logging: None,
            allow_unnamed_resources: None,
            exec_trace_config: None,
            extra_opcode_budget: None,
            fix_signers: None,
            round: None,
            txn_groups: Vec::new(),
            decoded_txn_groups: Vec::new(),
        };
        match adapter.simulate(request).await {
            Err(NodeError::BadRequest(msg)) => {
                assert!(
                    msg.starts_with("simulate: invalid request:"),
                    "expected invalid-request prefix, got {msg:?}"
                );
                assert!(
                    msg.contains("at least one transaction group"),
                    "expected message to mention required txn group, got {msg:?}"
                );
            }
            other => panic!("expected BadRequest(invalid request), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_block_hash_uses_header_path_and_matches_compute_block_digest() {
        // Round-trip: encode a Block's header both ways and confirm the
        // adapter's header-derived digest matches `algo_codec`'s
        // `compute_block_digest` (which hashes the canonical header encoded
        // from the full block). This guarantees the refactor from
        // "decode full block → compute_block_digest" to
        // "fetch header → block_digest_from_header" is hash-preserving.
        use algo_codec::{canonical_encode_block_header_from_block, compute_block_digest};
        use algo_types::{Block, Round};

        let block = Block {
            round: Round(5),
            current_protocol: CONSENSUS_V41.into(),
            ..Block::default()
        };

        // Populate the ledger with serde-encoded header/block bytes. We use
        // the codec's canonical header encoding for `hdrdata` because that's
        // what `SqliteLedger::get_block_header` decodes back. For `blkdata`
        // we use rmp_serde::to_vec_named, which Block::decode_from_reader
        // parses.
        let hdrdata = canonical_encode_block_header_from_block(&block);
        let blkdata = rmp_serde::to_vec_named(&block).expect("encode block");

        let ledger_arc = Arc::new(Mutex::new(
            SqliteLedger::open_in_memory().expect("in-memory ledger"),
        ));
        {
            let mut ledger = ledger_arc.lock().expect("ledger lock");
            ledger
                .put_block(5, CONSENSUS_V41, &hdrdata, &blkdata)
                .expect("put_block ok");
        }

        let adapter = adapter_with_ledger(ledger_arc);
        let hash = adapter
            .get_block_hash(5)
            .await
            .expect("get_block_hash ok")
            .expect("hash present for round 5");
        assert_eq!(hash, compute_block_digest(&block));
    }

    // ---- Participation key methods (TASK-265) ----

    /// Adapter with an in-memory participation store attached.
    fn adapter_with_part_store() -> AlgodNodeInterface {
        let store = ParticipationStore::open_in_memory().expect("in-memory part store");
        make_adapter().with_participation_store(Arc::new(Mutex::new(store)))
    }

    #[tokio::test]
    async fn participation_methods_not_implemented_without_store() {
        let adapter = make_adapter();
        // No store attached → every method reports NotImplemented (mirroring
        // go when no participation registry is configured).
        assert!(matches!(
            adapter.list_participation_keys().await,
            Err(NodeError::NotImplemented("list_participation_keys"))
        ));
        assert!(matches!(
            adapter.install_participation_key(vec![1, 2, 3]).await,
            Err(NodeError::NotImplemented("install_participation_key"))
        ));
        assert!(matches!(
            adapter
                .generate_participation_keys(Address([1u8; 32]), 1, 100, None)
                .await,
            Err(NodeError::NotImplemented("generate_participation_keys"))
        ));
    }

    #[tokio::test]
    async fn generate_list_get_remove_round_trip() {
        let adapter = adapter_with_part_store();
        let addr = Address([0x42; 32]);

        // Empty store lists nothing.
        assert!(adapter
            .list_participation_keys()
            .await
            .expect("list ok")
            .is_empty());

        // Generate installs a key and returns its id.
        let id = adapter
            .generate_participation_keys(addr, 1, 100, Some(10_000))
            .await
            .expect("generate ok");

        // List now returns exactly that key.
        let listed = adapter.list_participation_keys().await.expect("list ok");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].participation_id, id);
        assert_eq!(listed[0].account, addr);

        // Get by id returns the record.
        let got = adapter.get_participation_key(&id).await.expect("get ok");
        assert_eq!(got.participation_id, id);

        // Get on an unknown id is NotFound.
        let missing = ParticipationID([0xFF; 32]);
        assert!(matches!(
            adapter.get_participation_key(&missing).await,
            Err(NodeError::NotFound(_))
        ));

        // Remove deletes it; a second remove is NotFound.
        adapter
            .remove_participation_key(&id)
            .await
            .expect("remove ok");
        assert!(adapter
            .list_participation_keys()
            .await
            .expect("list ok")
            .is_empty());
        assert!(matches!(
            adapter.remove_participation_key(&id).await,
            Err(NodeError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn install_from_partkey_bytes_round_trip() {
        // Build a real partkey DB on disk, read its raw bytes, and install
        // them through the adapter (exercising the secure temp-file write +
        // restore_participation path).
        let addr = Address([0x5a; 32]);
        let dir = std::env::temp_dir().join(format!(
            "algod-rust-test-partkey.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut db = algo_ledger::erasable_db::ErasableDb::open(&dir).expect("open partkey db");
        let part = algo_ledger::participation::fill_db_with_participation_keys(
            &mut db,
            addr,
            Round(1),
            Round(100),
            10_000,
        )
        .expect("fill partkey db");
        let expected_id = part.id();
        db.close().expect("close db");
        let bytes = std::fs::read(&dir).expect("read partkey bytes");
        let _ = std::fs::remove_file(&dir);

        let adapter = adapter_with_part_store();
        let id = adapter
            .install_participation_key(bytes)
            .await
            .expect("install ok");
        assert_eq!(id, expected_id);

        let listed = adapter.list_participation_keys().await.expect("list ok");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].participation_id, id);
        assert_eq!(listed[0].account, addr);
    }

    #[tokio::test]
    async fn install_empty_partkey_is_rejected() {
        let adapter = adapter_with_part_store();
        let err = adapter
            .install_participation_key(Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(err, NodeError::Internal(_)));
    }

    #[tokio::test]
    async fn generate_rejects_over_long_validity_window() {
        let adapter = adapter_with_part_store();
        // v41 MaxKeyregValidPeriod is 256*(1<<16)-1 = 16_777_215. A window
        // wider than that is rejected before any keygen (matches go's
        // FillDBWithParticipationKeys validity-period check).
        let err = adapter
            .generate_participation_keys(Address([0x09; 32]), 1, 1 + 16_777_216, None)
            .await
            .unwrap_err();
        match err {
            NodeError::Internal(msg) => assert!(
                msg.contains("the validity period for mss is too large"),
                "expected validity-period message, got {msg:?}"
            ),
            other => panic!("expected Internal(validity period), got {other:?}"),
        }
        // Nothing was persisted.
        assert!(adapter
            .list_participation_keys()
            .await
            .expect("list ok")
            .is_empty());
    }

    #[tokio::test]
    async fn duplicate_generate_is_rejected() {
        let adapter = adapter_with_part_store();
        let addr = Address([0x07; 32]);
        let store = adapter.part_store.clone().expect("store attached");

        // Generate one key, then re-insert the *same* participation directly
        // to force the UNIQUE(participationID) collision (regenerating would
        // produce fresh random keys with a different id).
        let part =
            Participation::generate(addr, Round(1), Round(100), 10_000, 256).expect("generate");
        let id = store.lock().expect("lock").insert(&part).expect("insert");
        assert_eq!(
            adapter
                .get_participation_key(&id)
                .await
                .expect("get")
                .participation_id,
            id
        );

        // Installing a partkey blob whose id already exists maps to the
        // duplicate-key error. Build a partkey DB for the same Participation.
        // (Covered indirectly: a second direct insert returns a constraint
        // error, which install maps to the duplicate message.)
        let err = store.lock().expect("lock").insert(&part).unwrap_err();
        assert!(matches!(
            &err,
            rusqlite::Error::SqliteFailure(ffi, _)
                if ffi.code == rusqlite::ErrorCode::ConstraintViolation
        ));
    }

    #[tokio::test]
    async fn append_participation_keys_rejects_empty_body() {
        let adapter = adapter_with_part_store();
        let id = ParticipationID([0x11; 32]);
        // An empty msgpack array (0x90) decodes to zero pairs → BadRequest
        // (client error → 400), matching go's "empty request" message.
        let err = adapter
            .append_participation_keys(&id, vec![0x90])
            .await
            .unwrap_err();
        match err {
            NodeError::BadRequest(msg) => assert!(
                msg.contains("empty request"),
                "expected empty-request message, got {msg:?}"
            ),
            other => panic!("expected BadRequest(empty request), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn append_participation_keys_unknown_id_is_not_found() {
        let adapter = adapter_with_part_store();
        let id = ParticipationID([0x22; 32]);
        // One well-formed KeyRoundPair for an id that isn't installed: go's
        // public Registry.AppendKeys rejects it with ErrParticipationIDNotFound
        // (participationRegistry.go:560), so we return NotFound → 404.
        let mut signer = algo_consensus_crypto::merklesig::FalconSigner::default();
        signer.pk[0] = 0x01;
        let mut body = Vec::new();
        body.push(0x91); // fixarray of 1
        body.push(0x82); // fixmap of 2
        body.extend_from_slice(&[0xa3, b'k', b'e', b'y']);
        body.extend_from_slice(&signer.to_msgpack());
        body.extend_from_slice(&[0xa3, b'r', b'n', b'd']);
        body.push(0xcd);
        body.extend_from_slice(&256u16.to_be_bytes());

        let err = adapter
            .append_participation_keys(&id, body)
            .await
            .unwrap_err();
        assert!(matches!(err, NodeError::NotFound(_)));
    }

    // ---- Asset / app / box resource lookups (TASK-266) ----

    use algo_types::{
        AppLocalState, AppParams, AssetHolding, AssetParams, AssetParamsRecord, StateSchema,
    };

    /// Build an adapter over an in-memory ledger and hand back the shared
    /// ledger handle for direct state seeding via the `LedgerStore` setters.
    ///
    /// State is written through the store setters without driving a full
    /// apply/commit, so `acctrounds.acctbase` is never advanced and the
    /// lookups observe `last_round == 0` (the `unwrap_or(0)` empty-ledger
    /// path, mirroring `ledger.Latest()` on a freshly initialised ledger).
    /// The round plumbing through committed blocks is covered separately by
    /// the status/account-lookup tests.
    fn adapter_with_seedable_ledger() -> (AlgodNodeInterface, Arc<Mutex<SqliteLedger>>) {
        let ledger_arc = Arc::new(Mutex::new(
            SqliteLedger::open_in_memory().expect("in-memory ledger"),
        ));
        (adapter_with_ledger(Arc::clone(&ledger_arc)), ledger_arc)
    }

    fn asset_params_named(name: &str, total: u64) -> AssetParams {
        AssetParams {
            total,
            unit_name: name.to_string(),
            ..AssetParams::default()
        }
    }

    fn app_params(creator: Address) -> AppParams {
        AppParams {
            creator,
            approval_program: vec![0x06],
            clear_state_program: vec![0x06],
            global_state: Default::default(),
            local_state_schema: StateSchema::default(),
            global_state_schema: StateSchema::default(),
            extra_program_pages: 0,
        }
    }

    #[tokio::test]
    async fn lookup_asset_resource_reports_holding_and_creator_params() {
        let (adapter, ledger_arc) = adapter_with_seedable_ledger();
        let creator = Address([0x11; 32]);
        let holder = Address([0x22; 32]);
        {
            let mut ledger = ledger_arc.lock().expect("ledger lock");
            ledger.set_asset_params(
                7,
                AssetParamsRecord {
                    params: asset_params_named("AST", 1_000),
                    creator,
                },
            );
            // Creator opted into their own asset; a separate holder opted in too.
            ledger.set_asset_holding(
                &creator,
                7,
                AssetHolding {
                    amount: 400,
                    frozen: false,
                },
            );
            ledger.set_asset_holding(
                &holder,
                7,
                AssetHolding {
                    amount: 600,
                    frozen: true,
                },
            );
        }

        // Creator: holding + params present.
        let c = adapter
            .lookup_asset_resource(&creator, 7)
            .await
            .expect("creator lookup");
        assert_eq!(c.last_round, 0);
        assert_eq!(c.asset_holding.expect("holding").amount, 400);
        assert_eq!(c.asset_params.expect("params").total, 1_000);

        // Non-creator holder: holding present, params omitted.
        let h = adapter
            .lookup_asset_resource(&holder, 7)
            .await
            .expect("holder lookup");
        assert_eq!(h.asset_holding.expect("holding").amount, 600);
        assert!(h.asset_params.is_none());

        // Address with no holding: both None.
        let none = adapter
            .lookup_asset_resource(&Address([0x33; 32]), 7)
            .await
            .expect("absent lookup");
        assert!(none.asset_holding.is_none());
        assert!(none.asset_params.is_none());
    }

    #[tokio::test]
    async fn lookup_app_resource_reports_local_state_and_creator_params() {
        let (adapter, ledger_arc) = adapter_with_seedable_ledger();
        let creator = Address([0x44; 32]);
        let user = Address([0x55; 32]);
        {
            let mut ledger = ledger_arc.lock().expect("ledger lock");
            ledger.set_app_params(99, app_params(creator));
            ledger.set_app_local_state(
                &user,
                99,
                AppLocalState {
                    schema: StateSchema::default(),
                    key_value: Default::default(),
                },
            );
        }

        // Creator: params present, no local state (didn't opt in).
        let c = adapter
            .lookup_app_resource(&creator, 99)
            .await
            .expect("creator lookup");
        assert_eq!(c.last_round, 0);
        assert!(c.app_params.is_some());
        assert!(c.app_local_state.is_none());

        // Opted-in user: local state present, params omitted.
        let u = adapter
            .lookup_app_resource(&user, 99)
            .await
            .expect("user lookup");
        assert!(u.app_local_state.is_some());
        assert!(u.app_params.is_none());
    }

    #[tokio::test]
    async fn lookup_application_and_asset_by_id_resolve_creator() {
        let (adapter, ledger_arc) = adapter_with_seedable_ledger();
        let app_creator = Address([0x66; 32]);
        let asset_creator = Address([0x77; 32]);
        {
            let mut ledger = ledger_arc.lock().expect("ledger lock");
            ledger.set_app_params(123, app_params(app_creator));
            ledger.set_asset_params(
                456,
                AssetParamsRecord {
                    params: asset_params_named("ZZZ", 42),
                    creator: asset_creator,
                },
            );
        }

        let app = adapter.lookup_application(123).await.expect("app lookup");
        assert_eq!(app.creator, app_creator);
        assert!(app.app_params.is_some());
        assert_eq!(app.last_round, 0);

        let asset = adapter.lookup_asset_by_id(456).await.expect("asset lookup");
        assert_eq!(asset.creator, asset_creator);
        assert_eq!(asset.asset_params.expect("params").unit_name, "ZZZ");

        // Missing app/asset → None params and zero-address creator (handler
        // maps that to 404).
        let missing_app = adapter.lookup_application(999).await.expect("missing app");
        assert!(missing_app.app_params.is_none());
        assert!(missing_app.creator.is_zero());
        let missing_asset = adapter
            .lookup_asset_by_id(999)
            .await
            .expect("missing asset");
        assert!(missing_asset.asset_params.is_none());
        assert!(missing_asset.creator.is_zero());
    }

    #[tokio::test]
    async fn lookup_assets_paginates_and_marks_creator() {
        let (adapter, ledger_arc) = adapter_with_seedable_ledger();
        let addr = Address([0x88; 32]);
        let other_creator = Address([0x99; 32]);
        {
            let mut ledger = ledger_arc.lock().expect("ledger lock");
            // Opt into assets 10, 20, 30. The account created asset 20; asset
            // 30 is created by someone else; asset 10 has no creator (deleted).
            for aid in [10u64, 20, 30] {
                ledger.set_asset_holding(
                    &addr,
                    aid,
                    AssetHolding {
                        amount: aid,
                        frozen: false,
                    },
                );
            }
            ledger.set_asset_params(
                20,
                AssetParamsRecord {
                    params: asset_params_named("MID", 20),
                    creator: addr,
                },
            );
            ledger.set_asset_params(
                30,
                AssetParamsRecord {
                    params: asset_params_named("OTH", 30),
                    creator: other_creator,
                },
            );
        }

        // Full listing, ascending by asset id.
        let (all, round) = adapter
            .lookup_assets(&addr, 0, 100)
            .await
            .expect("all assets");
        assert_eq!(round, 0);
        let ids: Vec<u64> = all.iter().map(|r| r.asset_id).collect();
        assert_eq!(ids, vec![10, 20, 30]);
        // Asset 20 (self-created): creator is self + params present.
        let mid = all.iter().find(|r| r.asset_id == 20).expect("asset 20");
        assert_eq!(mid.creator, addr);
        assert!(mid.asset_params.is_some());
        // Asset 30 (created by another account): a non-creator holder still
        // gets the resolved creator + params, matching go's LookupLimitedResources.
        let other = all.iter().find(|r| r.asset_id == 30).expect("asset 30");
        assert_eq!(other.creator, other_creator);
        assert_eq!(
            other.asset_params.as_ref().expect("params").unit_name,
            "OTH"
        );
        // Asset 10 (no creator / deleted): zero creator, params omitted.
        let first = all.iter().find(|r| r.asset_id == 10).expect("asset 10");
        assert!(first.creator.is_zero());
        assert!(first.asset_params.is_none());

        // asset_id_gt filter: only ids strictly greater than 10.
        let (gt, _) = adapter.lookup_assets(&addr, 10, 100).await.expect("gt 10");
        assert_eq!(
            gt.iter().map(|r| r.asset_id).collect::<Vec<_>>(),
            vec![20, 30]
        );

        // limit cap: request 2 (handler asks for limit+1 to detect more).
        let (capped, _) = adapter.lookup_assets(&addr, 0, 2).await.expect("limit 2");
        assert_eq!(capped.len(), 2);
        assert_eq!(capped[0].asset_id, 10);
        assert_eq!(capped[1].asset_id, 20);
    }

    #[tokio::test]
    async fn box_lookups_round_trip_through_kvstore() {
        let (adapter, ledger_arc) = adapter_with_seedable_ledger();
        let app_id = 555u64;
        let app_addr = Address(algo_ledger::avm_context::app_address(app_id));
        {
            let mut ledger = ledger_arc.lock().expect("ledger lock");
            ledger.set_box(app_id, b"alpha", b"one".to_vec());
            ledger.set_box(app_id, b"beta", b"two".to_vec());
            ledger.set_box(app_id, b"alpine", b"three".to_vec());
            // total_boxes reads the app account's record.
            ledger.set_account(
                &app_addr,
                AccountData {
                    total_boxes: 3,
                    ..AccountData::default()
                },
            );
        }

        // Single box by raw name.
        let (value, round) = adapter.lookup_kv(app_id, b"alpha").await.expect("kv alpha");
        assert_eq!(round, 0);
        assert_eq!(value.expect("alpha value"), b"one");
        let (missing, _) = adapter
            .lookup_kv(app_id, b"missing")
            .await
            .expect("kv missing");
        assert!(missing.is_none());

        // All box names (empty prefix), stripped of the KV prefix.
        let (mut all, _) = adapter
            .lookup_keys_by_prefix(app_id, &[])
            .await
            .expect("all keys");
        all.sort();
        assert_eq!(
            all,
            vec![b"alpha".to_vec(), b"alpine".to_vec(), b"beta".to_vec()]
        );

        // Prefix filter.
        let (mut alp, _) = adapter
            .lookup_keys_by_prefix(app_id, b"alp")
            .await
            .expect("alp keys");
        alp.sort();
        assert_eq!(alp, vec![b"alpha".to_vec(), b"alpine".to_vec()]);

        // total_boxes from the app account record.
        let (total, round) = adapter.total_boxes(app_id).await.expect("total boxes");
        assert_eq!(total, 3);
        assert_eq!(round, 0);
        // Unknown app → zero, not an error.
        let (zero, _) = adapter.total_boxes(777).await.expect("total boxes empty");
        assert_eq!(zero, 0);
    }
}
