//! Production `NodeInterface` implementation for the `algod-rust` binary.
//!
//! Backs the REST API crate's [`NodeInterface`] trait with a live
//! [`SqliteLedger`] and cached genesis / build metadata. This file is the
//! *skeleton* established by PLAN-74 / TASK-75 — it covers the read-only
//! surface (status, genesis, block lookups, state deltas, account state).
//! Downstream tasks layer additional methods onto the same struct:
//!
//! - Pool methods (`TASK-76`) — `pending_transactions`, `get_pending_transaction`
//! - Broadcast methods (`TASK-77`) — `broadcast_signed_tx_group`,
//!   `async_broadcast_signed_tx_group`
//! - Simulation (`TASK-78`) — `simulate`
//! - CLI wiring (`TASK-79`) — constructs [`AlgodNodeInterface`] in the
//!   `participate` / `serve` subcommands and passes it to the axum router
//!
//! Until TASK-79 lands, nothing in the binary constructs this type, which
//! would trigger `dead_code` / `clippy::dead_code` warnings. The tests at
//! the bottom of this module exercise every method, so the `#[allow]` below
//! is a scaffold — remove it once the binary wires the adapter up.
//!
//! Reference: `../go-algorand/daemon/algod/api/server/v2/handlers.go` @
//! `v4.5.1-stable` (the trait is modeled after `v2.NodeInterface`).

#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use algo_codec::{canonical_encode_block_header, compute_block_digest};
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::{SqliteLedger, StateDelta};
use algo_network::local_tx_broadcast::{LocalTxBroadcaster, LocalTxError};
use algo_pool::TransactionPool;
use algo_rest_api::node::{
    AccountLookup, BuildVersion, NodeError, NodeInterface, NodeStatus, ProtocolSwitchInfo,
    TxnWithStatus,
};
use algo_types::consensus::consensus_params_for_version;
use algo_types::{
    AccountData, Address, Block, BlockHeader, ConsensusParams, Digest, SignedTransaction,
};
use async_trait::async_trait;
use sha2::{Digest as _, Sha512_256};

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
    genesis_id: String,
    genesis_hash: Digest,
    genesis_json: String,
    build_version: BuildVersion,
    default_protocol: String,
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
            genesis_id: config.genesis_id,
            genesis_hash: config.genesis_hash,
            genesis_json: config.genesis_json,
            build_version: config.build_version,
            default_protocol: config.default_protocol,
        }
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

    /// Return the attached broadcaster (or [`NodeError::NotImplemented`]
    /// when absent) plus an `Arc` clone suitable for spawning onto
    /// `tokio::spawn` for the fire-and-forget variant.
    fn broadcaster(&self, method: &'static str) -> Result<Arc<LocalTxBroadcaster>, NodeError> {
        self.broadcaster
            .as_ref()
            .map(Arc::clone)
            .ok_or(NodeError::NotImplemented(method))
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
        let ledger = self.ledger.lock().expect("ledger lock poisoned");
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
        let ledger = self.ledger.lock().expect("ledger lock poisoned");
        let last_round = ledger
            .last_committed_round()
            .map_err(|e| NodeError::Internal(format!("last_committed_round: {e}")))?
            .unwrap_or(0);
        let account_data = ledger.get_account(addr).unwrap_or_default();
        Ok((last_round, account_data))
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
        let proto = {
            let ledger = self.ledger.lock().expect("ledger lock poisoned");
            self.resolve_protocol(&ledger)
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
        // Poll the ledger's last-committed round. The REST handler always
        // wraps this future in a `tokio::select!` with the caller's timeout,
        // so this loop cannot leak if `round` never arrives. See the comment
        // on `WAIT_POLL_INTERVAL` for the planned follow-up (notification
        // channel in TASK-79).
        loop {
            let last = {
                let ledger = self.ledger.lock().expect("ledger lock poisoned");
                ledger
                    .last_committed_round()
                    .map_err(|e| NodeError::Internal(format!("last_committed_round: {e}")))?
                    .unwrap_or(0)
            };
            if last >= round {
                return Ok(());
            }
            tokio::time::sleep(WAIT_POLL_INTERVAL).await;
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
            let ledger = self.ledger.lock().expect("ledger lock poisoned");
            ledger
                .get_block_data(round)
                .map_err(|e| NodeError::Internal(format!("get_block_data({round}): {e}")))?
        }
        .ok_or_else(|| NodeError::NotFound(format!("block round {round} not found")))?;

        Block::decode_from_bytes(&bytes)
            .map_err(|e| NodeError::Internal(format!("decode block {round}: {e}")))
    }

    async fn get_block_header(&self, round: u64) -> Result<BlockHeader, NodeError> {
        let ledger = self.ledger.lock().expect("ledger lock poisoned");
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
            let ledger = self.ledger.lock().expect("ledger lock poisoned");
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
            let ledger = self.ledger.lock().expect("ledger lock poisoned");
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

    async fn get_state_delta_for_round(&self, round: u64) -> Result<StateDelta, NodeError> {
        let bytes = {
            let ledger = self.ledger.lock().expect("ledger lock poisoned");
            ledger
                .get_state_delta(round)
                .map_err(|e| NodeError::Internal(format!("get_state_delta({round}): {e}")))?
        }
        .ok_or_else(|| NodeError::NotFound(format!("no state delta for round {round}")))?;

        rmp_serde::from_slice::<StateDelta>(&bytes)
            .map_err(|e| NodeError::Internal(format!("decode state delta {round}: {e}")))
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

    async fn consensus_params(&self) -> Result<ConsensusParams, NodeError> {
        let proto = {
            let ledger = self.ledger.lock().expect("ledger lock poisoned");
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
        Ok(Self::map_pool_lookup(txn, pool_error, found))
    }

    // ---- Broadcast methods (TASK-77) ----

    async fn broadcast_signed_tx_group(
        &self,
        tx_group: Vec<SignedTransaction>,
    ) -> Result<(), NodeError> {
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
        // Consequence: pool-rejection / encode / gossip failures after
        // the spawn are NOT surfaced through the return value. They are
        // logged inside `LocalTxBroadcaster::submit_group`
        // (`local_tx_broadcast.rs:200-222`) so operators still have
        // visibility. Callers that need synchronous rejection signals
        // should use `broadcast_signed_tx_group` instead.
        let broadcaster = self.broadcaster("async_broadcast_signed_tx_group")?;

        // Preflight the obviously-bad cases synchronously so clients see
        // immediate feedback rather than a silent drop. Keep this list
        // minimal — anything that needs pool state (duplicate detection,
        // fee check, signature verification) belongs in the async path.
        if tx_group.is_empty() {
            return Err(Self::local_tx_error_to_node_error(LocalTxError::Empty));
        }

        // Spawn the full ingest + gossip path. `LocalTxBroadcaster`
        // already emits structured warnings on every failure branch, so
        // no additional logging is needed here.
        tokio::spawn(async move {
            let _ = broadcaster.submit_group(tx_group).await;
        });
        Ok(())
    }
}

impl AlgodNodeInterface {
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
}
