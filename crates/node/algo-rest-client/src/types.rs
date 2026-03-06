use serde::{Deserialize, Serialize};

/// Node status as returned by `GET /v2/status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
