use algo_types::Digest;
use serde::{Deserialize, Serialize};

/// Node status as returned by `GET /v2/status`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeStatus {
    /// The last committed round.
    #[serde(rename = "last-round")]
    pub last_round: u64,

    /// Time since last round in nanoseconds.
    #[serde(rename = "time-since-last-round", default)]
    pub time_since_last_round: u64,

    /// Catchup time in nanoseconds (0 when synced).
    #[serde(rename = "catchup-time", default)]
    pub catchup_time: u64,

    /// Last consensus protocol version.
    #[serde(rename = "last-version", default)]
    pub last_version: String,

    /// Next consensus protocol version.
    #[serde(rename = "next-version", default)]
    pub next_version: String,

    /// Round at which the next version takes effect.
    #[serde(rename = "next-version-round", default)]
    pub next_version_round: u64,

    /// Whether the next version is supported by this node.
    #[serde(rename = "next-version-supported", default)]
    pub next_version_supported: bool,

    /// Whether the node has stopped at the upgrade round.
    #[serde(rename = "stopped-at-unsupported-round", default)]
    pub stopped_at_unsupported_round: bool,

    /// The last catchpoint seen by the node.
    #[serde(rename = "last-catchpoint", default)]
    pub last_catchpoint: Option<String>,

    /// Catchpoint label being downloaded; `None` (or empty) outside
    /// catchpoint catchup. Mirrors Go's `model.NodeStatusResponse.Catchpoint`.
    #[serde(rename = "catchpoint", default)]
    pub catchpoint: Option<String>,

    /// Catchpoint catchup progress (account-trie download).
    #[serde(rename = "catchpoint-total-accounts", default)]
    pub catchpoint_total_accounts: Option<u64>,
    #[serde(rename = "catchpoint-processed-accounts", default)]
    pub catchpoint_processed_accounts: Option<u64>,
    #[serde(rename = "catchpoint-verified-accounts", default)]
    pub catchpoint_verified_accounts: Option<u64>,
    #[serde(rename = "catchpoint-total-kvs", default)]
    pub catchpoint_total_kvs: Option<u64>,
    #[serde(rename = "catchpoint-processed-kvs", default)]
    pub catchpoint_processed_kvs: Option<u64>,
    #[serde(rename = "catchpoint-verified-kvs", default)]
    pub catchpoint_verified_kvs: Option<u64>,

    /// Catchpoint block-replay progress.
    #[serde(rename = "catchpoint-acquired-blocks", default)]
    pub catchpoint_acquired_blocks: Option<u64>,
    #[serde(rename = "catchpoint-total-blocks", default)]
    pub catchpoint_total_blocks: Option<u64>,

    /// Consensus-upgrade-voting fields. Optional in Go's model; we
    /// default-zero everywhere `nilToZero` would in
    /// `cmd/goal/node.go:480-494`.
    #[serde(rename = "upgrade-next-protocol-vote-before", default)]
    pub upgrade_next_protocol_vote_before: Option<u64>,
    #[serde(rename = "upgrade-votes-required", default)]
    pub upgrade_votes_required: Option<u64>,
    #[serde(rename = "upgrade-no-votes", default)]
    pub upgrade_no_votes: Option<u64>,
    #[serde(rename = "upgrade-yes-votes", default)]
    pub upgrade_yes_votes: Option<u64>,
    #[serde(rename = "upgrade-vote-rounds", default)]
    pub upgrade_vote_rounds: Option<u64>,
}

/// `GET /versions` (or `/v2/versions`) response. Mirrors Go's
/// `daemon/algod/api/spec/common/model.go:25` (`Version`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlgodVersions {
    #[serde(rename = "versions", default)]
    pub versions: Vec<String>,
    #[serde(rename = "genesis_id", default)]
    pub genesis_id: String,
    /// Standard-base64-encoded 32-byte genesis hash. Kept as the raw
    /// string so callers print byte-exactly what Go does.
    #[serde(rename = "genesis_hash_b64", default)]
    pub genesis_hash_b64: String,
}

/// Account information as returned by `GET /v2/accounts/{addr}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub address: String,
    pub amount: u64,
    #[serde(rename = "amount-without-pending-rewards")]
    pub amount_without_pending_rewards: u64,
    #[serde(rename = "pending-rewards")]
    pub pending_rewards: u64,
    pub rewards: u64,
    pub status: String,
    #[serde(rename = "auth-addr", default)]
    pub auth_addr: Option<String>,
    #[serde(rename = "min-balance", default)]
    pub min_balance: u64,
    /// Round at which this information was current.
    pub round: u64,
    /// Total number of assets this account has opted into.
    #[serde(rename = "total-assets-opted-in", default)]
    pub total_assets_opted_in: u64,
    /// Total number of assets created by this account.
    #[serde(rename = "total-created-assets", default)]
    pub total_created_assets: u64,
    /// Total number of apps this account has opted into.
    #[serde(rename = "total-apps-opted-in", default)]
    pub total_apps_opted_in: u64,
    /// Total number of apps created by this account.
    #[serde(rename = "total-created-apps", default)]
    pub total_created_apps: u64,
}

/// A transaction identifier — the base32-encoded SHA-512/256 of the canonical
/// msgpack encoding of the `Transaction` struct. Algod returns this from
/// `POST /v2/transactions` and accepts it in `GET /v2/transactions/pending/{txid}`.
///
/// Ported reference: `../go-algorand/data/transactions/transaction.go` —
/// `Transaction.ID()`; serialized form is the 52-character Algorand base32
/// (no padding).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TxId(pub String);

impl TxId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for TxId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Response from `POST /v2/transactions`.
///
/// Ported reference: `../go-algorand/daemon/algod/api/server/v2/handlers.go:1090`
/// (`RawTransaction` handler) and `model.PostTransactionsResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostTransactionResponse {
    /// The txid of the first transaction in the submitted group.
    #[serde(rename = "txId")]
    pub tx_id: String,
}

/// Suggested parameters for constructing a new transaction.
///
/// Ported reference: `../go-algorand/daemon/algod/api/server/v2/handlers.go:1459`
/// (`TransactionParams` handler) and `model.TransactionParametersResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestedParams {
    /// Last consensus protocol version the node has seen.
    #[serde(rename = "consensus-version")]
    pub consensus_version: String,

    /// The suggested per-byte fee (microAlgos). The effective fee for a
    /// transaction is `max(fee * txn_size_bytes, min_fee)`.
    pub fee: u64,

    /// Genesis hash for the current network.
    #[serde(rename = "genesis-hash", with = "digest_base64")]
    pub genesis_hash: Digest,

    /// Genesis ID for the current network (e.g. `"devnet-v1"`).
    #[serde(rename = "genesis-id")]
    pub genesis_id: String,

    /// The last committed round when the node generated this response.
    #[serde(rename = "last-round")]
    pub last_round: u64,

    /// The minimum per-transaction fee (microAlgos) enforced by consensus.
    #[serde(rename = "min-fee")]
    pub min_fee: u64,
}

/// Information about a transaction in the pool or in the recently committed
/// blocks, as returned by `GET /v2/transactions/pending/{txid}`.
///
/// Ported reference: `../go-algorand/daemon/algod/api/server/v2/handlers.go:1486`
/// (`PreEncodedTxInfo`). This Rust mirror decodes only the fields the e2e
/// harness needs (confirmation tracking + pool-error surface); inner txns,
/// state deltas, logs, and asset/app indices are intentionally omitted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PendingTxnInfo {
    /// Set when the transaction has been included in a block; `None` while
    /// the transaction is still in the pool.
    #[serde(rename = "confirmed-round", default)]
    pub confirmed_round: Option<u64>,

    /// Non-empty when the transaction pool rejected the transaction.
    /// Empty string (the default) means the transaction is healthy.
    #[serde(rename = "pool-error", default)]
    pub pool_error: String,
}

impl PendingTxnInfo {
    /// Returns true when the node has committed this transaction to a block.
    pub fn is_committed(&self) -> bool {
        self.confirmed_round.is_some()
    }

    /// Returns true when the pool has rejected this transaction.
    pub fn is_rejected(&self) -> bool {
        !self.pool_error.is_empty()
    }
}

/// Serde adapter for the algod-returned genesis hash, which is JSON-encoded
/// as a standard-base64 string (with padding). We decode straight to `Digest`
/// so callers don't have to handle the encoding.
mod digest_base64 {
    use algo_types::Digest;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Digest, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(d.0))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Digest, D::Error> {
        let raw = String::deserialize(d)?;
        let bytes = STANDARD.decode(raw.as_bytes()).map_err(D::Error::custom)?;
        if bytes.len() != 32 {
            return Err(D::Error::custom(format!(
                "genesis-hash must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Digest(out))
    }
}
