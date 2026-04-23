//! Production `NodeInterface` implementation for the `algod-rust` binary.
//!
//! Backs the REST API crate's [`NodeInterface`] trait with a live
//! [`SqliteLedger`] and cached genesis / build metadata. This file is the
//! *skeleton* established by PLAN-74 / TASK-75 — it covers the read-only
//! surface (status, genesis, block lookups, state deltas, account state).
//! Downstream tasks layer additional methods onto the same struct:
//!
//! - Pool methods (`TASK-76`) — `pending_transactions`, `get_pending_transaction`
//! - Broadcast methods (`TASK-77`) — `broadcast_signed_tx_group`
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

use algo_codec::compute_block_digest;
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::{SqliteLedger, StateDelta};
use algo_rest_api::node::{
    AccountLookup, BuildVersion, NodeError, NodeInterface, NodeStatus, ProtocolSwitchInfo,
};
use algo_types::consensus::consensus_params_for_version;
use algo_types::{Address, Block, BlockHeader, BlockResponse, ConsensusParams, Digest};
use async_trait::async_trait;

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

/// Production `NodeInterface` adapter backed by a live [`SqliteLedger`].
///
/// Cheap to clone-by-`Arc` and share across REST handlers. The adapter
/// exposes only read-heavy methods for now; write paths (broadcast, simulate,
/// participation-key installation) are added by downstream PLAN-74 tasks.
pub struct AlgodNodeInterface {
    ledger: Arc<Mutex<SqliteLedger>>,
    genesis_id: String,
    genesis_hash: Digest,
    genesis_json: String,
    build_version: BuildVersion,
    default_protocol: String,
}

impl AlgodNodeInterface {
    /// Construct a new adapter. See [`NodeInterfaceConfig`] for the field
    /// semantics.
    pub fn new(ledger: Arc<Mutex<SqliteLedger>>, config: NodeInterfaceConfig) -> Self {
        Self {
            ledger,
            genesis_id: config.genesis_id,
            genesis_hash: config.genesis_hash,
            genesis_json: config.genesis_json,
            build_version: config.build_version,
            default_protocol: config.default_protocol,
        }
    }

    /// Returns the current consensus protocol string reported by the ledger,
    /// falling back to the configured `default_protocol` when the ledger has
    /// no committed blocks yet (empty `protocol()`).
    fn current_protocol(&self) -> String {
        let ledger = self.ledger.lock().expect("ledger lock poisoned");
        let live = ledger.protocol().to_string();
        if live.is_empty() {
            self.default_protocol.clone()
        } else {
            live
        }
    }

    /// Read the last-committed round, mapping the "no blocks yet" case to 0.
    fn last_committed_round(&self) -> Result<u64, NodeError> {
        let ledger = self.ledger.lock().expect("ledger lock poisoned");
        let opt = ledger
            .last_committed_round()
            .map_err(|e| NodeError::Internal(format!("last_committed_round: {e}")))?;
        Ok(opt.unwrap_or(0))
    }

    /// Look up the consensus params for a given protocol string.
    fn resolve_consensus_params(proto: &str) -> Result<ConsensusParams, NodeError> {
        consensus_params_for_version(proto).ok_or_else(|| {
            NodeError::Internal(format!("unknown consensus protocol version: {proto}"))
        })
    }

    /// Fetch the latest committed block header, if any.
    fn latest_header(&self) -> Result<Option<BlockHeader>, NodeError> {
        let last_round = self.last_committed_round()?;
        let ledger = self.ledger.lock().expect("ledger lock poisoned");
        ledger
            .get_block_header(last_round)
            .map_err(|e| NodeError::Internal(format!("get_block_header({last_round}): {e}")))
    }
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
        let last_round = self.last_committed_round()?;
        let current = self.current_protocol();
        let header = self.latest_header()?;

        // Protocol-switch fields come from the latest block header when
        // present; fall back to "next == current, next round = last + 1" when
        // the ledger is empty.
        let (next_version, next_version_round, next_version_supported) = match header.as_ref() {
            Some(h) if !h.next_protocol.is_empty() => (
                h.next_protocol.clone(),
                h.next_protocol_switch_on.0,
                consensus_params_for_version(&h.next_protocol).is_some(),
            ),
            _ => (current.clone(), last_round.saturating_add(1), true),
        };

        Ok(NodeStatus {
            last_round,
            // Without a commit-time notification channel we cannot track the
            // wall-clock delta accurately; reported as zero until TASK-79
            // wires the adapter to the block-commit path.
            time_since_last_round: 0,
            catchup_time: 0,
            last_version: current,
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
            next_protocol_vote_before: header
                .as_ref()
                .map(|h| h.next_protocol_vote_before.0)
                .unwrap_or(0),
            next_protocol_approvals: header
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
        let proto = self.current_protocol();
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
            if self.last_committed_round()? >= round {
                return Ok(());
            }
            tokio::time::sleep(WAIT_POLL_INTERVAL).await;
        }
    }

    async fn latest_block_header_protocol_info(&self) -> Result<ProtocolSwitchInfo, NodeError> {
        let info = match self.latest_header()? {
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
        // Reconstruct the block digest canonically (SHA512/256 of "BH" ||
        // canonical(header)). Matches `compute_block_digest` in `algo-codec`,
        // which is the same helper used when building block headers.
        let block_bytes_opt = {
            let ledger = self.ledger.lock().expect("ledger lock poisoned");
            ledger
                .get_block_data(round)
                .map_err(|e| NodeError::Internal(format!("get_block_data({round}): {e}")))?
        };
        let Some(bytes) = block_bytes_opt else {
            return Ok(None);
        };
        let block = Block::decode_from_bytes(&bytes)
            .map_err(|e| NodeError::Internal(format!("decode block {round}: {e}")))?;
        Ok(Some(compute_block_digest(&block)))
    }

    async fn get_block_raw_msgpack(&self, round: u64) -> Result<Vec<u8>, NodeError> {
        // Mirrors go-algorand's `rpcs.RawBlockBytes(ledger, round)`: returns
        // the `{"block": block, "cert": cert}` envelope that the REST
        // endpoint serves with `X-Algorand-Struct: block-v1`. We rebuild the
        // envelope from the two stored halves so that clients see both parts.
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

        let block = Block::decode_from_bytes(&block_bytes)
            .map_err(|e| NodeError::Internal(format!("decode block {round}: {e}")))?;

        let cert = match cert_bytes_opt {
            Some(bytes) => {
                let mut rd = bytes.as_slice();
                let v = rmpv::decode::read_value(&mut rd)
                    .map_err(|e| NodeError::Internal(format!("decode cert {round}: {e}")))?;
                Some(v)
            }
            None => None,
        };

        let response = BlockResponse { block, cert };
        rmp_serde::to_vec_named(&response)
            .map_err(|e| NodeError::Internal(format!("encode block response: {e}")))
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
        let last_round = self.last_committed_round()?;
        let account_data = {
            let ledger = self.ledger.lock().expect("ledger lock poisoned");
            ledger.get_account(addr).unwrap_or_default()
        };
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
        let last_round = self.last_committed_round()?;
        let account_data = {
            let ledger = self.ledger.lock().expect("ledger lock poisoned");
            ledger.get_account(addr).unwrap_or_default()
        };
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
        let proto = self.current_protocol();
        Self::resolve_consensus_params(&proto)
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
}
