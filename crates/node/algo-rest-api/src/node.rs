//! Node interface trait for the REST API.
//!
//! The `NodeInterface` trait abstracts the node state that REST API handlers
//! need. This allows handlers to be tested with mock implementations and
//! decouples the API layer from the node internals.
//!
//! The trait methods are modeled after go-algorand's `v2.NodeInterface` in
//! `daemon/algod/api/server/v2/handlers.go`.

use std::collections::BTreeMap;

use algo_ledger::participation::{ParticipationID, ParticipationRecord};
use algo_ledger::{StateDelta, StateDeltaSubset};
use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParams, Block, BlockHeader,
    ConsensusParams, Digest, SignedTransaction,
};
use async_trait::async_trait;
use serde::Serialize;

use crate::models;

/// Typed error enum for `NodeInterface` methods.
///
/// Replaces `Box<dyn std::error::Error + Send + Sync>` to enable type-safe
/// error dispatch in handlers (instead of fragile string matching).
#[derive(Debug, Clone, thiserror::Error)]
pub enum NodeError {
    /// Resource not found (block, state proof, etc.) — handlers map to 404.
    #[error("{0}")]
    NotFound(String),

    /// Client-supplied request was invalid (bad input, conflicting
    /// options, out-of-domain values) — handlers map to 400. Use this
    /// variant when the failure is attributable to the caller's input,
    /// not a node-side problem. Introduced so adapter-level errors like
    /// `simulate: invalid request: ...` and `broadcast: empty group`
    /// surface as 4xx responses instead of being collapsed into 500.
    #[error("{0}")]
    BadRequest(String),

    /// Operation timed out — handlers map to 408.
    #[error("{0}")]
    Timeout(String),

    /// Default trait method stub — handlers map to 500.
    #[error("{0} not implemented")]
    NotImplemented(&'static str),

    /// Internal / unexpected error — handlers map to 500.
    #[error("{0}")]
    Internal(String),
}

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

/// Supply information returned by the ledger.
///
/// Mirrors go-algorand's `ledger.LatestTotals()` output.
#[derive(Debug, Clone)]
pub struct SupplyInfo {
    /// The round at which the totals were computed.
    pub round: u64,
    /// Total money of participating accounts, in microAlgos.
    pub total_money: u64,
    /// Total money of online accounts at `round`, in microAlgos.
    pub online_money: u64,
    /// Online stake at the agreement lookback round for `round` (same
    /// `BalanceRound`/lookback used for sortition/committee sizing), in
    /// microAlgos. Distinct from `online_money`, which is `round`'s own
    /// online total. Mirrors go-algorand's
    /// `LedgerForAPI().OnlineCirculation(BalanceRound(round), round)`
    /// (`daemon/algod/api/server/v2/handlers.go` `GetSupply`, v4.6.0-stable).
    pub online_stake: u64,
}

/// One transaction group's state delta together with the IDs (each txn ID and
/// the group ID) that resolve to it. Mirrors go-algorand's
/// `eval.TxnGroupDeltaWithIds`; serialized as `{ "Ids": [...], "Delta": {...} }`.
#[derive(Debug, Clone, Serialize)]
pub struct TxnGroupDeltaWithIds {
    /// Base32 transaction/group IDs that map to `delta`.
    #[serde(rename = "Ids")]
    pub ids: Vec<String>,
    /// The group's state delta, narrowed to go-algorand's `StateDeltaSubset`
    /// wire shape (no `Totals`/`StateProofNext`/`PrevTimestamp` — those are
    /// round-scoped fields that don't apply to a single group).
    #[serde(rename = "Delta")]
    pub delta: StateDeltaSubset,
}

/// State proof data returned by the node.
///
/// Mirrors the fields used to build go-algorand's `model.StateProofResponse`.
#[derive(Debug, Clone)]
pub struct StateProofData {
    /// The msgpack-encoded state proof bytes.
    pub state_proof: Vec<u8>,
    /// Block headers commitment from the state proof message.
    pub block_headers_commitment: Vec<u8>,
    /// Voters commitment from the state proof message.
    pub voters_commitment: Vec<u8>,
    /// Natural log of proven weight.
    pub ln_proven_weight: u64,
    /// First attested round in the state proof message.
    pub first_attested_round: u64,
    /// Last attested round in the state proof message.
    pub last_attested_round: u64,
}

/// Information about a single transaction: whether it has appeared in a
/// block yet, and whether it was kicked out of the txpool.
///
/// Mirrors go-algorand's `node.TxnWithStatus`.
#[derive(Debug, Clone)]
pub struct TxnWithStatus {
    /// The signed transaction.
    pub txn: SignedTransaction,

    /// Zero indicates the transaction has not been confirmed.
    pub confirmed_round: u64,

    /// Non-empty when the transaction was kicked out of the pool.
    pub pool_error: String,

    // -- ApplyData fields (populated when confirmed_round != 0) --
    /// Closing amount in microAlgos.
    pub closing_amount: u64,

    /// Asset closing amount.
    pub asset_closing_amount: u64,

    /// Rewards to sender.
    pub sender_rewards: u64,

    /// Rewards to receiver.
    pub receiver_rewards: u64,

    /// Rewards to close-to address.
    pub close_rewards: u64,

    /// Created/configured asset ID (from ApplyData).
    pub asset_index: Option<u64>,

    /// Created application ID (from ApplyData).
    pub application_index: Option<u64>,

    /// Eval delta (opaque, passed through for JSON/msgpack encoding).
    /// Contains global-state-delta, local-state-delta, inner-txns, logs.
    pub eval_delta: Option<rmpv::Value>,

    /// Logs from app execution.
    pub logs: Option<Vec<Vec<u8>>>,

    /// Inner transactions.
    pub inner_txns: Option<Vec<TxnWithStatus>>,
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
    async fn status(&self) -> Result<NodeStatus, NodeError>;

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
    async fn wait_for_round(&self, round: u64) -> Result<(), NodeError>;

    /// Return protocol switch information from the latest block header.
    ///
    /// Used by `wait-for-block-after` to reject requests that would land
    /// after an unsupported protocol upgrade.
    async fn latest_block_header_protocol_info(&self) -> Result<ProtocolSwitchInfo, NodeError>;

    // ---- Block lookup methods ----

    /// Return the block hash (digest) for a given round.
    ///
    /// Returns `Ok(Some(digest))` when the block exists, `Ok(None)` when
    /// the round is not yet available (analogous to go-algorand's
    /// `ErrNoEntry`), and `Err` for internal errors.
    ///
    /// Used by `GET /v2/blocks/{round}/hash`.
    async fn get_block_hash(&self, _round: u64) -> Result<Option<Digest>, NodeError> {
        Err(NodeError::NotImplemented("get_block_hash"))
    }

    // ---- Account / resource lookup methods ----

    /// Look up an account by address.
    ///
    /// Non-existent accounts return a zero-valued `AccountData` with the
    /// current round — they do NOT produce an error.
    async fn lookup_account(&self, _addr: &Address) -> Result<AccountLookup, NodeError> {
        Err(NodeError::NotImplemented("lookup_account"))
    }

    /// Lightweight account lookup that skips resource maps (assets, apps, etc.).
    ///
    /// Used when `exclude=all` is passed to the account information endpoint,
    /// allowing implementations to avoid loading potentially large resource
    /// collections from the ledger.
    async fn lookup_account_basic(&self, _addr: &Address) -> Result<AccountLookup, NodeError> {
        Err(NodeError::NotImplemented("lookup_account_basic"))
    }

    /// Look up a single asset resource (holding + params) for an address.
    ///
    /// Returns the asset holding (if opted in) and asset params (if the
    /// address is the creator).
    async fn lookup_asset_resource(
        &self,
        _addr: &Address,
        _asset_id: u64,
    ) -> Result<AssetResourceLookup, NodeError> {
        Err(NodeError::NotImplemented("lookup_asset_resource"))
    }

    /// Look up a single app resource (local state + params) for an address.
    ///
    /// Returns the app local state (if opted in) and app params (if the
    /// address is the creator).
    async fn lookup_app_resource(
        &self,
        _addr: &Address,
        _app_id: u64,
    ) -> Result<AppResourceLookup, NodeError> {
        Err(NodeError::NotImplemented("lookup_app_resource"))
    }

    /// Return the consensus parameters for the current protocol version.
    async fn consensus_params(&self) -> Result<ConsensusParams, NodeError> {
        Err(NodeError::NotImplemented("consensus_params"))
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
    async fn lookup_application(&self, _app_id: u64) -> Result<ApplicationLookup, NodeError> {
        Err(NodeError::NotImplemented("lookup_application"))
    }

    /// Look up an asset by its ID.
    ///
    /// Resolves the creator via `GetCreator`, then looks up the `AssetParams`.
    /// Returns `AssetLookup` with `asset_params: None` when the asset does
    /// not exist.
    async fn lookup_asset_by_id(&self, _asset_id: u64) -> Result<AssetLookup, NodeError> {
        Err(NodeError::NotImplemented("lookup_asset_by_id"))
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
    ) -> Result<(Option<Vec<u8>>, u64), NodeError> {
        Err(NodeError::NotImplemented("lookup_kv"))
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
    ) -> Result<(Vec<Vec<u8>>, u64), NodeError> {
        Err(NodeError::NotImplemented("lookup_keys_by_prefix"))
    }

    /// Paginated, prefix-filtered box listing with an exclusive-start
    /// cursor, used by the cursor-pagination mode of
    /// `GET /v2/applications/{id}/boxes` (issue #536).
    ///
    /// `prefix` filters box names to those starting with it (an empty
    /// slice matches all boxes for the application). `cursor`, when
    /// `Some`, excludes box names lexicographically `<=` the cursor.
    /// `limit`, when `Some`, caps the number of entries returned.
    /// `include_values` controls whether box values are populated
    /// alongside names.
    ///
    /// Returns `(results, round, more_data)` where each result is
    /// `(box_name, value)` with `value` present only when
    /// `include_values` is true, and `more_data` indicates whether at
    /// least one more qualifying box exists beyond what was returned.
    ///
    /// Mirrors go-algorand's `Ledger.LookupKvPairsByPrefix` in
    /// `ledger/ledger.go`.
    async fn lookup_kv_pairs_by_prefix(
        &self,
        _app_id: u64,
        _prefix: &[u8],
        _cursor: Option<&[u8]>,
        _limit: Option<u64>,
        _include_values: bool,
    ) -> Result<(algo_ledger::store_trait::BoxPage, u64, bool), NodeError> {
        Err(NodeError::NotImplemented("lookup_kv_pairs_by_prefix"))
    }

    /// Historical variant of [`Self::lookup_kv_pairs_by_prefix`]: reconstructs
    /// box state as of `round`, a round strictly older than the latest
    /// committed round (issue #570).
    ///
    /// Returns `Ok(None)` when `round` cannot be served historically --
    /// outside the node's retained lookback window, mirroring go-algorand's
    /// own `RoundOffsetError` for a round older than `accountUpdates.deltas`'
    /// bounded lookback (`ledger/acctupdates.go`) -- so the caller can fall
    /// back to its existing "historical round queries are not supported"
    /// response with a window-boundary-specific message. The default
    /// implementation always returns `Ok(None)` (equivalent to "not
    /// supported"), matching this trait's general pattern of `NodeInterface`
    /// methods defaulting to unimplemented behavior for backends that don't
    /// override them, without forcing every existing implementor (test
    /// mocks, etc.) to add a stub.
    async fn lookup_kv_pairs_by_prefix_at_round(
        &self,
        _app_id: u64,
        _round: u64,
        _prefix: &[u8],
        _cursor: Option<&[u8]>,
        _limit: Option<u64>,
        _include_values: bool,
    ) -> Result<Option<(algo_ledger::store_trait::BoxPage, bool)>, NodeError> {
        Ok(None)
    }

    /// Return the total number of boxes for an application, via an O(1)
    /// account record lookup.
    ///
    /// Returns `(total_boxes, round)`. This is used by the boxes endpoint
    /// to check the box count against the API limit *before* scanning all
    /// box keys, matching go-algorand's approach of checking
    /// `record.TotalBoxes` from the account record.
    async fn total_boxes(&self, _app_id: u64) -> Result<(u64, u64), NodeError> {
        Err(NodeError::NotImplemented("total_boxes"))
    }

    /// Maximum number of boxes per application that the API will return.
    ///
    /// Configurable, default 100,000. Mirrors go-algorand's
    /// `config.MaxAPIBoxPerApplication`.
    fn max_api_box_per_application(&self) -> u64 {
        100_000
    }

    // ---- Block lookup methods ----

    /// Look up a block by round number.
    ///
    /// Returns the parsed `Block` for JSON-mode responses.
    /// Returns a "not found" error when the round has not been committed.
    ///
    /// Mirrors go-algorand's `ledger.Block(round)`.
    async fn get_block(&self, _round: u64) -> Result<Block, NodeError> {
        Err(NodeError::NotImplemented("get_block"))
    }

    /// Look up a block header by round number.
    ///
    /// Returns the parsed `BlockHeader` for header-only responses.
    /// Returns a "not found" error when the round has not been committed.
    ///
    /// Mirrors go-algorand's `ledger.BlockHdr(round)`.
    async fn get_block_header(&self, _round: u64) -> Result<BlockHeader, NodeError> {
        Err(NodeError::NotImplemented("get_block_header"))
    }

    /// Find the state proof transaction that covers the given round.
    ///
    /// Scans blocks from `round + 1` up to the latest round looking for
    /// a state proof transaction whose `Message.FirstAttestedRound ..=
    /// Message.LastAttestedRound` range contains `round`.
    ///
    /// Returns `(first_attested_round, last_attested_round)` on success.
    /// Returns an error if no state proof is found or state proofs are
    /// not enabled for this round's protocol version.
    ///
    /// Mirrors go-algorand's `GetStateProofTransactionForRound`.
    async fn get_state_proof_transaction_for_round(
        &self,
        _round: u64,
    ) -> Result<(u64, u64), NodeError> {
        Err(NodeError::NotImplemented(
            "get_state_proof_transaction_for_round",
        ))
    }

    /// Return supply information (round, total money, online money).
    ///
    /// Mirrors go-algorand's `ledger.LatestTotals()`.
    async fn get_supply(&self) -> Result<SupplyInfo, NodeError> {
        Err(NodeError::NotImplemented("get_supply"))
    }

    /// Return full state proof data for a given round.
    ///
    /// Mirrors go-algorand's `GetStateProof` handler which finds the state
    /// proof transaction covering the round and extracts all message fields.
    async fn get_state_proof_for_round(&self, _round: u64) -> Result<StateProofData, NodeError> {
        Err(NodeError::NotImplemented("get_state_proof_for_round"))
    }

    /// Return raw block+cert bytes for a given round (msgpack pass-through).
    ///
    /// The returned bytes are the exact msgpack encoding of the block
    /// response (block + certificate), suitable for returning directly
    /// with the `X-Algorand-Struct: block-v1` header.
    ///
    /// Mirrors go-algorand's `rpcs.RawBlockBytes(ledger, round)`.
    async fn get_block_raw_msgpack(&self, _round: u64) -> Result<Vec<u8>, NodeError> {
        Err(NodeError::NotImplemented("get_block_raw_msgpack"))
    }

    // ---- Transaction pool / broadcast methods ----

    /// Broadcast a signed transaction group to the network.
    ///
    /// Validates the transactions, adds them to the pool, and relays
    /// via gossip. Returns an error if validation or pool insertion fails.
    ///
    /// Mirrors go-algorand's `Node.BroadcastSignedTxGroup`.
    async fn broadcast_signed_tx_group(
        &self,
        _tx_group: Vec<SignedTransaction>,
    ) -> Result<(), NodeError> {
        Err(NodeError::NotImplemented("broadcast_signed_tx_group"))
    }

    /// Look up a pending transaction by its ID.
    ///
    /// Searches the transaction pool first, then recent confirmed blocks.
    /// Returns `None` if the transaction is not found in either place.
    ///
    /// Mirrors go-algorand's `Node.GetPendingTransaction`.
    async fn get_pending_transaction(
        &self,
        _txid: &Digest,
    ) -> Result<Option<TxnWithStatus>, NodeError> {
        Err(NodeError::NotImplemented("get_pending_transaction"))
    }

    /// Return all pending transactions from the pool.
    ///
    /// Mirrors go-algorand's `Node.GetPendingTxnsFromPool`.
    async fn get_pending_txns_from_pool(&self) -> Result<Vec<SignedTransaction>, NodeError> {
        Err(NodeError::NotImplemented("get_pending_txns_from_pool"))
    }

    /// Maximum transaction group size from consensus params.
    ///
    /// Used by the raw transaction handler to validate group size
    /// before broadcasting.
    fn max_tx_group_size(&self) -> usize {
        16 // Default from go-algorand consensus
    }

    /// Whether the Developer API is enabled in the node configuration.
    ///
    /// When false, `/v2/teal/compile` and `/v2/teal/disassemble` return 404.
    /// Mirrors go-algorand's `Config().EnableDeveloperAPI`.
    fn enable_developer_api(&self) -> bool {
        false
    }

    /// Whether the Experimental API is enabled in the node configuration.
    ///
    /// When false, experimental endpoints (`/v2/experimental`,
    /// `/v2/accounts/:address/assets`, `/v2/transactions/async`) return 404.
    /// Mirrors go-algorand's `Config().EnableExperimentalAPI`.
    fn enable_experimental_api(&self) -> bool {
        false
    }

    /// Broadcast a signed transaction group asynchronously (fire-and-forget).
    ///
    /// Unlike `broadcast_signed_tx_group`, this does not wait for pool
    /// validation to complete before returning.
    ///
    /// Mirrors go-algorand's `Node.AsyncBroadcastSignedTxGroup`.
    async fn async_broadcast_signed_tx_group(
        &self,
        _tx_group: Vec<SignedTransaction>,
    ) -> Result<(), NodeError> {
        Err(NodeError::NotImplemented("async_broadcast_signed_tx_group"))
    }

    /// Look up multiple asset resources for an address, paginated by asset ID.
    ///
    /// Returns assets with `asset_id > asset_id_gt`, up to `limit` records,
    /// along with the round at which the lookup was performed.
    ///
    /// Mirrors go-algorand's `ledger.LookupAssets(addr, asset_id_gt, limit)`.
    async fn lookup_assets(
        &self,
        _addr: &Address,
        _asset_id_gt: u64,
        _limit: u64,
    ) -> Result<(Vec<AssetResourceWithIDs>, u64), NodeError> {
        Err(NodeError::NotImplemented("lookup_assets"))
    }

    /// Look up multiple app resources for an address, paginated by app ID.
    ///
    /// Returns apps with `app_id > app_id_gt`, up to `limit` records, along
    /// with the round at which the lookup was performed. `include_params`
    /// mirrors go's bandwidth-saving flag: when `false`, implementations
    /// may skip populating `app_params` on the returned records (the
    /// `creator` field, needed for the `deleted` flag, is still resolved).
    ///
    /// Mirrors go-algorand's `ledger.LookupApplications(addr, app_id_gt,
    /// limit, includeParams)`.
    async fn lookup_applications(
        &self,
        _addr: &Address,
        _app_id_gt: u64,
        _limit: u64,
        _include_params: bool,
    ) -> Result<(Vec<AppResourceWithIDs>, u64), NodeError> {
        Err(NodeError::NotImplemented("lookup_applications"))
    }

    // ---- Simulation methods ----

    /// Simulate a transaction group without submitting it.
    ///
    /// Mirrors go-algorand's `Node.Simulate` which takes a
    /// `simulation.Request` and returns a `simulation.Result`.
    /// The handler passes the REST model types directly for now;
    /// a dedicated simulation engine will be added later.
    async fn simulate(
        &self,
        _request: models::SimulateRequest,
    ) -> Result<models::SimulateResponse, NodeError> {
        Err(NodeError::NotImplemented("simulate"))
    }

    // ---- Ledger state delta methods ----

    /// Return the ledger state delta for a given round.
    ///
    /// Returns a typed `StateDelta` that the handler encodes in the
    /// negotiated format (JSON or msgpack).
    ///
    /// Mirrors go-algorand's `LedgerForAPI().GetStateDeltaForRound(round)`.
    async fn get_state_delta_for_round(&self, _round: u64) -> Result<StateDelta, NodeError> {
        Err(NodeError::NotImplemented("get_state_delta_for_round"))
    }

    /// Return the state delta for a transaction group identified by a txn ID or
    /// group ID. `NotImplemented` when the tracer is disabled (501, matching
    /// go's `GetTracer` type assertion failure); `NotFound` when the ID is
    /// unknown.
    ///
    /// Returns [`StateDeltaSubset`] (not the full [`StateDelta`]), matching
    /// go-algorand's `GetLedgerStateDeltaForTransactionGroup`, which returns
    /// `eval.StateDeltaSubset` — a type with no `Totals`/`StateProofNext`/
    /// `PrevTimestamp` fields, unlike the full round-level delta.
    async fn get_txn_group_delta(&self, _id: &Digest) -> Result<StateDeltaSubset, NodeError> {
        Err(NodeError::NotImplemented("get_txn_group_delta"))
    }

    /// Return all transaction-group deltas (with their IDs) for a round.
    /// `NotImplemented` when the tracer is disabled; `NotFound` when the round
    /// is outside the retained window.
    async fn get_txn_group_deltas_for_round(
        &self,
        _round: u64,
    ) -> Result<Vec<TxnGroupDeltaWithIds>, NodeError> {
        Err(NodeError::NotImplemented("get_txn_group_deltas_for_round"))
    }

    // ---- Participation key methods ----

    /// List all participation keys.
    ///
    /// Mirrors go-algorand's `Node.ListParticipationKeys`.
    async fn list_participation_keys(&self) -> Result<Vec<ParticipationRecord>, NodeError> {
        Err(NodeError::NotImplemented("list_participation_keys"))
    }

    /// Get a single participation key by its ID.
    ///
    /// Mirrors go-algorand's `Node.GetParticipationKey`.
    async fn get_participation_key(
        &self,
        _id: &ParticipationID,
    ) -> Result<ParticipationRecord, NodeError> {
        Err(NodeError::NotImplemented("get_participation_key"))
    }

    /// Install a participation key from raw bytes (e.g. from a key file).
    ///
    /// Mirrors go-algorand's `Node.InstallParticipationKey`.
    async fn install_participation_key(
        &self,
        _data: Vec<u8>,
    ) -> Result<ParticipationID, NodeError> {
        Err(NodeError::NotImplemented("install_participation_key"))
    }

    /// Remove a participation key by its ID.
    ///
    /// Mirrors go-algorand's `Node.RemoveParticipationKey`.
    async fn remove_participation_key(&self, _id: &ParticipationID) -> Result<(), NodeError> {
        Err(NodeError::NotImplemented("remove_participation_key"))
    }

    /// Append state proof keys to an existing participation key.
    ///
    /// Mirrors go-algorand's `Node.AppendParticipationKeys`.
    async fn append_participation_keys(
        &self,
        _id: &ParticipationID,
        _keys: Vec<u8>,
    ) -> Result<(), NodeError> {
        Err(NodeError::NotImplemented("append_participation_keys"))
    }

    /// Generate participation keys and install them.
    ///
    /// Mirrors go-algorand's `generateKeyHandler` which generates keys
    /// and installs them via `InstallParticipationKey`.
    async fn generate_participation_keys(
        &self,
        _address: Address,
        _first: u64,
        _last: u64,
        _dilution: Option<u64>,
    ) -> Result<ParticipationID, NodeError> {
        Err(NodeError::NotImplemented("generate_participation_keys"))
    }

    // ---- Operational control methods ----

    /// Start a catchpoint catchup.
    ///
    /// Mirrors go-algorand's `Node.StartCatchup(catchpoint)`.
    async fn start_catchup(
        &self,
        _catchpoint: &str,
        _min_rounds: u64,
    ) -> Result<CatchupStartResult, NodeError> {
        Err(NodeError::NotImplemented("start_catchup"))
    }

    /// Abort a catchpoint catchup.
    ///
    /// Mirrors go-algorand's `Node.AbortCatchup(catchpoint)`.
    async fn abort_catchup(&self, _catchpoint: &str) -> Result<(), NodeError> {
        Err(NodeError::NotImplemented("abort_catchup"))
    }

    /// Whether the node is running in dev mode.
    fn is_dev_mode(&self) -> bool {
        false
    }

    /// Whether the node is running in follower mode.
    fn is_follower_mode(&self) -> bool {
        false
    }

    /// Consensus-participation metrics as a JSON document, or `None` when this
    /// node is not participating in consensus (issue #473).
    ///
    /// Returned as an opaque `serde_json::Value` on purpose: the counters live
    /// in `algo-agreement`, and this crate deliberately does not depend on the
    /// agreement stack (it would drag the pool, validator, and AVM into every
    /// REST build). The node adapter — which already depends on both — does
    /// the conversion, and this trait only carries the payload.
    ///
    /// `None` is the "endpoint not configured" case: `GET
    /// /v2/participation/status` answers 404 rather than an empty document, so
    /// a scraper can distinguish "node isn't participating" from "node is
    /// participating and has cast zero votes so far".
    fn participation_status(&self) -> Option<serde_json::Value> {
        None
    }

    /// The same counters rendered as Prometheus text exposition, or `None`
    /// when this node is not participating in consensus.
    ///
    /// Served by `GET /metrics`. Rendering happens in `algo-agreement` (see
    /// `ParticipationSnapshot::to_prometheus_text`) so the workspace needs no
    /// `prometheus` crate dependency.
    fn metrics_exposition(&self) -> Option<String> {
        None
    }

    /// Get the block timestamp offset (dev mode only).
    ///
    /// Returns `Err` if not in dev mode, `Ok(None)` if never set,
    /// `Ok(Some(offset))` otherwise.
    async fn get_block_timestamp_offset(&self) -> Result<Option<u64>, NodeError> {
        Err(NodeError::NotImplemented("get_block_timestamp_offset"))
    }

    /// Set the block timestamp offset (dev mode only).
    async fn set_block_timestamp_offset(&self, _offset: i64) -> Result<(), NodeError> {
        Err(NodeError::NotImplemented("set_block_timestamp_offset"))
    }

    /// Get the sync round (follower mode).
    ///
    /// Returns 0 if not set.
    async fn get_sync_round(&self) -> Result<u64, NodeError> {
        Err(NodeError::NotImplemented("get_sync_round"))
    }

    /// Set the sync round (follower mode).
    async fn set_sync_round(&self, _round: u64) -> Result<(), NodeError> {
        Err(NodeError::NotImplemented("set_sync_round"))
    }

    /// Unset the sync round (follower mode).
    async fn unset_sync_round(&self) -> Result<(), NodeError> {
        Err(NodeError::NotImplemented("unset_sync_round"))
    }

    /// Get the node configuration as a JSON value.
    async fn get_config_json(&self) -> Result<serde_json::Value, NodeError> {
        Err(NodeError::NotImplemented("get_config_json"))
    }

    /// Get debug profiling settings.
    ///
    /// Returns `(mutex_rate, block_rate)`.
    async fn get_debug_settings_prof(&self) -> Result<(u64, u64), NodeError> {
        Err(NodeError::NotImplemented("get_debug_settings_prof"))
    }

    /// Set debug profiling settings.
    ///
    /// Returns the old values as `(old_mutex_rate, old_block_rate)`.
    async fn set_debug_settings_prof(
        &self,
        _mutex_rate: Option<u64>,
        _block_rate: Option<u64>,
    ) -> Result<(Option<u64>, Option<u64>), NodeError> {
        Err(NodeError::NotImplemented("set_debug_settings_prof"))
    }

    /// The latest round available for catchup min-rounds check.
    fn latest_round_for_catchup(&self) -> u64 {
        0
    }

    /// Returns the node's currently connected peers, split into inbound
    /// (accepted) and outbound (dialed) lists.
    ///
    /// Mirrors go-algorand's `Node.GetPeers() (inboundPeers []network.Peer,
    /// outboundPeers []network.Peer, err error)` (`handlers.go:156`), which
    /// backs `GET /v2/node/peers`. Only the address and transport type are
    /// exposed here — matching go's `network.PeerConnectionInfo`, which the
    /// handler type-asserts each `network.Peer` against — since that's all
    /// `PeerStatus` in the API response carries.
    ///
    /// Default stub: [`NodeError::NotImplemented`]. A full node backed by
    /// the network layer (`algo-network`'s `GossipNode::get_peers`)
    /// overrides this.
    async fn get_peers(&self) -> Result<(Vec<PeerInfo>, Vec<PeerInfo>), NodeError> {
        Err(NodeError::NotImplemented("get_peers"))
    }
}

/// Network transport type for a connected peer.
///
/// Mirrors go-algorand's `network.PeerNetworkType` (`Websocket` / `LibP2P`),
/// as reported via `network.PeerConnectionInfo.GetNetworkType()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerNetworkType {
    /// Gossip over the legacy WebSocket transport.
    Ws,
    /// Gossip over the libp2p transport.
    P2p,
}

/// A single connected peer, as reported by the network layer.
///
/// Mirrors the fields go-algorand's `convertPeers` reads off
/// `network.PeerConnectionInfo` (`GetAddress()` / `GetNetworkType()`) before
/// mapping them onto `model.PeerStatus`. Connection direction (inbound vs.
/// outbound) is not carried here — it's implied by which of
/// [`NodeInterface::get_peers`]'s two returned lists a `PeerInfo` came from,
/// matching go's own `GetPeers` signature.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The peer's network address (e.g. `"1.2.3.4:4160"`).
    pub network_address: String,
    /// The transport this peer is connected over.
    pub network_type: PeerNetworkType,
}

/// Result of a catchup start operation.
///
/// Mirrors the possible outcomes from go-algorand's `Node.StartCatchup`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatchupStartResult {
    /// Catchup was newly created (201).
    Created,
    /// Catchup was already in progress for this catchpoint (200).
    AlreadyInProgress,
    /// Unable to start catchup (400).
    Unable(String),
    /// Error starting catchup (408).
    StartError(String),
}

/// A single asset resource record with identifying fields, used for
/// paginated asset lookups.
///
/// Mirrors go-algorand's `ledgercore.AssetResourceWithIDs`.
#[derive(Debug, Clone)]
pub struct AssetResourceWithIDs {
    /// The asset ID.
    pub asset_id: u64,
    /// The asset holding, if the address has opted in.
    pub asset_holding: Option<AssetHolding>,
    /// The address that created this asset. Zero address if not the creator.
    pub creator: Address,
    /// The asset params, present only if the address is the creator.
    pub asset_params: Option<AssetParams>,
}

/// A single app resource record with identifying fields, used for
/// paginated application lookups.
///
/// Mirrors go-algorand's `ledgercore.AppResourceWithIDs`. Unlike
/// [`AssetResourceWithIDs`] — where a row only exists when the address
/// holds the asset — an app row surfaces when the address EITHER has app
/// local state OR is the app's creator (a "params-only" row, e.g. a
/// creator that closed out its own local state), matching go's
/// `AccountApplicationsInformation` handler, which drops a record only
/// when *both* `AppLocalState` and `AppParams` are nil.
#[derive(Debug, Clone)]
pub struct AppResourceWithIDs {
    /// The app ID.
    pub app_id: u64,
    /// The app local state, if the address has opted in.
    pub app_local_state: Option<AppLocalState>,
    /// The address that created this app. Zero address if the app no
    /// longer exists (deleted) — the handler maps that to `deleted: true`.
    pub creator: Address,
    /// The app params, present only when the app still exists AND the
    /// caller requested `include-params`.
    pub app_params: Option<AppParams>,
}
