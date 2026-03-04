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
