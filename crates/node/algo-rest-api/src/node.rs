//! Node interface trait for the REST API.
//!
//! The `NodeInterface` trait abstracts the node state that REST API handlers
//! need. This allows handlers to be tested with mock implementations and
//! decouples the API layer from the node internals.
//!
//! The trait methods are modeled after go-algorand's `v2.NodeInterface` in
//! `daemon/algod/api/server/v2/handlers.go`.

use std::collections::BTreeMap;

use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParams, ConsensusParams,
    Digest,
};
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

/// Result of looking up a single account by address.
///
/// Mirrors go-algorand's `AccountInformationResponse`. Non-existent accounts
/// return a zero-valued `AccountData` with the current round (not an error).
#[derive(Debug, Clone)]
pub struct AccountLookup {
    /// The account data (zero-valued if the account does not exist on-chain).
    pub account_data: AccountData,
    /// The last committed round at the time of the lookup.
    pub last_round: u64,
    /// The account balance excluding pending rewards. For simplicity this is
    /// currently set equal to `account_data.micro_algos`; a proper computation
    /// from reward tracking fields can be added later.
    pub amount_without_pending_rewards: u64,
    /// Asset holdings keyed by asset ID (populated by LookupLatest).
    pub assets: BTreeMap<u64, AssetHolding>,
    /// Created asset params keyed by asset ID (populated by LookupLatest).
    pub created_assets: BTreeMap<u64, AssetParams>,
    /// App local states keyed by app ID (populated by LookupLatest).
    pub app_local_states: BTreeMap<u64, AppLocalState>,
    /// Created app params keyed by app ID (populated by LookupLatest).
    pub created_apps: BTreeMap<u64, AppParams>,
}

/// Result of looking up a single asset resource (holding + params) for an
/// address/asset-id pair.
///
/// `asset_holding` is `Some` when the address has opted in to the asset.
/// `asset_params` is `Some` when the address is the asset creator.
#[derive(Debug, Clone)]
pub struct AssetResourceLookup {
    /// The asset holding, if the address has opted in.
    pub asset_holding: Option<AssetHolding>,
    /// The asset params, present only if the address is the creator.
    pub asset_params: Option<AssetParams>,
    /// The last committed round at the time of the lookup.
    pub last_round: u64,
}

/// Result of looking up a single app resource (local state + params) for an
/// address/app-id pair.
///
/// `app_local_state` is `Some` when the address has opted in to the app.
/// `app_params` is `Some` when the address is the app creator.
#[derive(Debug, Clone)]
pub struct AppResourceLookup {
    /// The app local state, if the address has opted in.
    pub app_local_state: Option<AppLocalState>,
    /// The app params, present only if the address is the creator.
    pub app_params: Option<AppParams>,
    /// The last committed round at the time of the lookup.
    pub last_round: u64,
}

/// Result of looking up an application by its ID.
///
/// Mirrors the fields used by go-algorand's `GetApplicationByID` handler.
/// The handler resolves the app creator via `GetCreator`, then looks up the
/// `AppParams` from the ledger.
#[derive(Debug, Clone)]
pub struct ApplicationLookup {
    /// The application parameters (approval program, clear program, schemas, etc.).
    /// `None` when the application does not exist.
    pub app_params: Option<AppParams>,
    /// The address that created this application.
    pub creator: Address,
    /// The last committed round at the time of the lookup.
    pub last_round: u64,
}

/// Result of looking up an asset by its ID.
///
/// Mirrors the fields used by go-algorand's `GetAssetByID` handler.
/// The handler resolves the asset creator via `GetCreator`, then looks up the
/// `AssetParams` from the ledger.
#[derive(Debug, Clone)]
pub struct AssetLookup {
    /// The asset parameters (total, decimals, name, etc.).
    /// `None` when the asset does not exist.
    pub asset_params: Option<AssetParams>,
    /// The address that created this asset.
    pub creator: Address,
    /// The last committed round at the time of the lookup.
    pub last_round: u64,
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

    // ---- Account / resource lookup methods ----

    /// Look up an account by address.
    ///
    /// Non-existent accounts return a zero-valued `AccountData` with the
    /// current round — they do NOT produce an error.
    async fn lookup_account(
        &self,
        _addr: &Address,
    ) -> Result<AccountLookup, Box<dyn std::error::Error + Send + Sync>> {
        Err("lookup_account not implemented".into())
    }

    /// Look up a single asset resource (holding + params) for an address.
    ///
    /// Returns the asset holding (if opted in) and asset params (if the
    /// address is the creator).
    async fn lookup_asset_resource(
        &self,
        _addr: &Address,
        _asset_id: u64,
    ) -> Result<AssetResourceLookup, Box<dyn std::error::Error + Send + Sync>> {
        Err("lookup_asset_resource not implemented".into())
    }

    /// Look up a single app resource (local state + params) for an address.
    ///
    /// Returns the app local state (if opted in) and app params (if the
    /// address is the creator).
    async fn lookup_app_resource(
        &self,
        _addr: &Address,
        _app_id: u64,
    ) -> Result<AppResourceLookup, Box<dyn std::error::Error + Send + Sync>> {
        Err("lookup_app_resource not implemented".into())
    }

    /// Return the consensus parameters for the current protocol version.
    async fn consensus_params(
        &self,
    ) -> Result<ConsensusParams, Box<dyn std::error::Error + Send + Sync>> {
        Err("consensus_params not implemented".into())
    }

    /// Maximum number of asset/app resources returned per account lookup.
    ///
    /// Configurable, default 100,000. Mirrors go-algorand's
    /// `config.MaxAPIResourcesPerAccount`.
    fn max_api_resources_per_account(&self) -> u64 {
        100_000
    }

    // ---- Application / asset / box lookup methods ----

    /// Look up an application by its ID.
    ///
    /// Resolves the creator via `GetCreator`, then looks up the `AppParams`.
    /// Returns `ApplicationLookup` with `app_params: None` when the
    /// application does not exist.
    async fn lookup_application(
        &self,
        _app_id: u64,
    ) -> Result<ApplicationLookup, Box<dyn std::error::Error + Send + Sync>> {
        Err("lookup_application not implemented".into())
    }

    /// Look up an asset by its ID.
    ///
    /// Resolves the creator via `GetCreator`, then looks up the `AssetParams`.
    /// Returns `AssetLookup` with `asset_params: None` when the asset does
    /// not exist.
    async fn lookup_asset_by_id(
        &self,
        _asset_id: u64,
    ) -> Result<AssetLookup, Box<dyn std::error::Error + Send + Sync>> {
        Err("lookup_asset_by_id not implemented".into())
    }

    /// Look up a single application box by its raw box name.
    ///
    /// Returns the raw box value bytes, or `None` if the box does not exist,
    /// together with the current round. The `key` parameter is the raw box
    /// name (not the full KV-store key). The implementation is responsible
    /// for constructing the full KV key internally (e.g. via `MakeBoxKey`).
    ///
    /// Mirrors go-algorand's `ledger.LookupKv(round, key)`.
    async fn lookup_kv(
        &self,
        _app_id: u64,
        _key: &[u8],
    ) -> Result<(Option<Vec<u8>>, u64), Box<dyn std::error::Error + Send + Sync>> {
        Err("lookup_kv not implemented".into())
    }

    /// List all box names for an application that match a given prefix.
    ///
    /// Returns already-stripped box names (without the KV prefix) together
    /// with the current round. The `prefix` parameter is typically empty to
    /// list all boxes. The implementation handles KV prefix construction and
    /// stripping internally.
    ///
    /// Mirrors go-algorand's `ledger.LookupKeysByPrefix(round, prefix, maxKeys)`.
    async fn lookup_keys_by_prefix(
        &self,
        _app_id: u64,
        _prefix: &[u8],
    ) -> Result<(Vec<Vec<u8>>, u64), Box<dyn std::error::Error + Send + Sync>> {
        Err("lookup_keys_by_prefix not implemented".into())
    }

    /// Return the total number of boxes for an application, via an O(1)
    /// account record lookup.
    ///
    /// Returns `(total_boxes, round)`. This is used by the boxes endpoint
    /// to check the box count against the API limit *before* scanning all
    /// box keys, matching go-algorand's approach of checking
    /// `record.TotalBoxes` from the account record.
    async fn total_boxes(
        &self,
        _app_id: u64,
    ) -> Result<(u64, u64), Box<dyn std::error::Error + Send + Sync>> {
        Err("total_boxes not implemented".into())
    }

    /// Maximum number of boxes per application that the API will return.
    ///
    /// Configurable, default 100,000. Mirrors go-algorand's
    /// `config.MaxAPIBoxPerApplication`.
    fn max_api_box_per_application(&self) -> u64 {
        100_000
    }
}
