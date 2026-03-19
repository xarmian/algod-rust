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
}
