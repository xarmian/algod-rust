//! Node interface trait for the REST API.
//!
//! The `NodeInterface` trait abstracts the node state that REST API handlers
//! need. This allows handlers to be tested with mock implementations and
//! decouples the API layer from the node internals.
//!
//! The trait methods are modeled after go-algorand's `v2.NodeInterface` in
//! `daemon/algod/api/server/v2/handlers.go`.

use algo_types::Digest;
use async_trait::async_trait;
use serde::Serialize;

/// Status of the node, consumed by REST API handlers.
///
/// Modeled after go-algorand's `node.StatusReport`.
#[derive(Debug, Clone)]
pub struct NodeStatus {
    /// The last committed round number.
    pub last_round: u64,

    /// Time since the last round was confirmed, in nanoseconds.
    pub time_since_last_round: i64,

    /// Catchup time in nanoseconds. Zero when the node is synced.
    pub catchup_time: i64,

    /// The consensus protocol version as of `last_round`.
    pub last_version: String,

    /// The next consensus protocol version (may equal `last_version`).
    pub next_version: String,

    /// The round at which `next_version` takes effect.
    pub next_version_round: u64,

    /// Whether this node supports `next_version`.
    pub next_version_supported: bool,

    /// Whether the node has stopped at an unsupported upgrade round.
    pub stopped_at_unsupported_round: bool,

    /// Non-empty when the node is performing fast catchup to a catchpoint.
    pub catchpoint: String,

    /// Optional: the last catchpoint seen.
    pub last_catchpoint: String,

    // -- Catchpoint catchup progress fields --
    /// Total number of accounts in the current catchpoint.
    pub catchpoint_total_accounts: u64,

    /// Number of accounts processed so far during catchpoint catchup.
    pub catchpoint_processed_accounts: u64,

    /// Number of accounts verified so far during catchpoint catchup.
    pub catchpoint_verified_accounts: u64,

    /// Total number of key-values (KVs) in the current catchpoint.
    pub catchpoint_total_kvs: u64,

    /// Number of KVs processed so far during catchpoint catchup.
    pub catchpoint_processed_kvs: u64,

    /// Number of KVs verified so far during catchpoint catchup.
    pub catchpoint_verified_kvs: u64,

    /// Total number of blocks required for the current catchpoint catchup.
    pub catchpoint_total_blocks: u64,

    /// Number of blocks acquired so far during catchpoint catchup.
    pub catchpoint_acquired_blocks: u64,

    // -- Upgrade / protocol voting fields --
    /// The round before which the next protocol vote must occur.
    /// Zero when there is no active upgrade vote.
    pub next_protocol_vote_before: u64,

    /// Number of yes-votes accumulated for the next protocol upgrade.
    pub next_protocol_approvals: u64,

    /// Whether this node votes to approve the upgrade.
    pub upgrade_approve: bool,

    /// Delay (in rounds) requested for the upgrade.
    pub upgrade_delay: u64,

    /// The protocol version being proposed for upgrade (may be empty).
    pub upgrade_propose: String,
}

/// Build version information for the `/versions` endpoint.
///
/// Mirrors go-algorand's `common.BuildVersion`.
#[derive(Debug, Clone, Serialize)]
pub struct BuildVersion {
    /// Major version number.
    pub major: u32,
    /// Minor version number.
    pub minor: u32,
    /// Build number.
    pub build_number: u32,
    /// Git commit hash.
    pub commit_hash: String,
    /// Git branch name.
    pub branch: String,
    /// Release channel (e.g. "stable", "beta", "dev").
    pub channel: String,
}

impl BuildVersion {
    /// Create a `BuildVersion` populated from build-time environment variables.
    ///
    /// Uses `CARGO_PKG_VERSION_MAJOR`, `CARGO_PKG_VERSION_MINOR`, and
    /// `CARGO_PKG_VERSION_PATCH` for version numbers, plus
    /// `ALGO_BUILD_COMMIT_HASH` and `ALGO_BUILD_BRANCH` emitted by `build.rs`.
    pub fn from_build_env() -> Self {
        Self {
            major: env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or(0),
            minor: env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or(0),
            build_number: env!("CARGO_PKG_VERSION_PATCH").parse().unwrap_or(0),
            commit_hash: env!("ALGO_BUILD_COMMIT_HASH").to_string(),
            branch: env!("ALGO_BUILD_BRANCH").to_string(),
            channel: String::new(),
        }
    }
}

/// Information about an upcoming protocol switch, used by the
/// `wait-for-block-after` handler to detect unsupported upgrades.
///
/// Mirrors the fields from go-algorand's `bookkeeping.BlockHeader`:
/// `NextProtocol`, `NextProtocolSwitchOn`, plus a derived
/// `next_protocol_supported` flag.
#[derive(Debug, Clone)]
pub struct ProtocolSwitchInfo {
    /// The next protocol version string. Empty when no upgrade is pending.
    pub next_protocol: String,

    /// Whether this node supports the next protocol version.
    pub next_protocol_supported: bool,

    /// The round at which the next protocol takes effect.
    pub next_protocol_switch_on: u64,
}

/// Trait abstracting the node state needed by REST API handlers.
///
/// Implementations provide access to genesis information, node status,
/// consensus parameters, and transaction fee suggestions.
///
/// All methods are async to support implementations that need to query
/// the ledger or network asynchronously.
#[async_trait]
pub trait NodeInterface: Send + Sync + 'static {
    /// The genesis ID string (e.g. "mainnet-v1.0", "testnet-v1.0").
    fn genesis_id(&self) -> &str;

    /// The 32-byte genesis block hash.
    fn genesis_hash(&self) -> &Digest;

    /// The full genesis file contents as a JSON string.
    fn genesis_json(&self) -> &str;

    /// Current node status (last round, sync state, protocol version, etc.).
    async fn status(&self) -> Result<NodeStatus, Box<dyn std::error::Error + Send + Sync>>;

    /// The suggested transaction fee in microAlgos.
    ///
    /// In go-algorand this comes from `node.SuggestedFee()` which returns
    /// the max of the minimum fee and the median fee from recent blocks.
    async fn suggested_fee(&self) -> u64;

    /// The minimum transaction fee for the current protocol, in microAlgos.
    ///
    /// This is a consensus parameter (`MinTxnFee`), typically 1000.
    async fn min_txn_fee(&self) -> u64;

    /// Build version information for the `/versions` endpoint.
    fn build_version(&self) -> &BuildVersion;

    /// The number of rounds in the upgrade voting window.
    ///
    /// Corresponds to `config.Consensus[protocol.ConsensusCurrentVersion].UpgradeVoteRounds`
    /// in go-algorand.
    fn upgrade_vote_rounds(&self) -> u64;

    /// The threshold of yes-votes required to approve a protocol upgrade.
    ///
    /// Corresponds to `config.Consensus[protocol.ConsensusCurrentVersion].UpgradeThreshold`
    /// in go-algorand.
    fn upgrade_threshold(&self) -> u64;

    /// Block until the given round is available (or an error occurs).
    ///
    /// Mirrors go-algorand's `ledger.WaitWithCancel(round)` -- the handler
    /// wraps this with `tokio::select!` to apply a timeout.
    async fn wait_for_round(
        &self,
        round: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Return protocol switch information from the latest block header.
    ///
    /// Used by `wait-for-block-after` to reject requests that would land
    /// after an unsupported protocol upgrade.
    async fn latest_block_header_protocol_info(
        &self,
    ) -> Result<ProtocolSwitchInfo, Box<dyn std::error::Error + Send + Sync>>;
}
