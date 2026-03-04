use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{Address, Round};

/// Algorand block header.
///
/// Field names use `#[serde(rename)]` to match go-algorand's msgpack short names.
///
/// Note: We do NOT use `#[serde(flatten)]` because rmp-serde has known issues
/// with flatten and binary types. Instead, unknown fields are silently ignored
/// via `#[serde(deny_unknown_fields)]` being absent (the default).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Round number.
    #[serde(rename = "rnd")]
    pub round: Round,

    /// Previous block hash.
    #[serde(rename = "prev", default, skip_serializing_if = "is_empty_bytes")]
    pub branch: ByteBuf,

    /// Sortition seed.
    #[serde(rename = "seed", default, skip_serializing_if = "is_empty_bytes")]
    pub seed: ByteBuf,

    /// Transaction commitment (root of payset merkle tree).
    #[serde(rename = "txn", default, skip_serializing_if = "is_empty_bytes")]
    pub txn_commitment: ByteBuf,

    /// Block timestamp (seconds since epoch).
    #[serde(rename = "ts", default)]
    pub timestamp: i64,

    /// Genesis ID string (e.g., "mainnet-v1.0").
    #[serde(rename = "gen", default, skip_serializing_if = "String::is_empty")]
    pub genesis_id: String,

    /// Genesis hash.
    #[serde(rename = "gh", default, skip_serializing_if = "is_empty_bytes")]
    pub genesis_hash: ByteBuf,

    /// Block proposer address.
    #[serde(rename = "prp", default, skip_serializing_if = "Address::is_zero")]
    pub proposer: Address,

    /// Rewards state: fee sink address.
    #[serde(rename = "fees", default, skip_serializing_if = "Address::is_zero")]
    pub fee_sink: Address,

    /// Rewards state: rewards pool address.
    #[serde(rename = "rwd", default, skip_serializing_if = "Address::is_zero")]
    pub rewards_pool: Address,

    /// Rewards state: earnings per unit since last recalculation.
    #[serde(rename = "earn", default, skip_serializing_if = "is_zero_u64")]
    pub rewards_level: u64,

    /// Rewards state: per-unit reward rate.
    #[serde(rename = "rate", default, skip_serializing_if = "is_zero_u64")]
    pub rewards_rate: u64,

    /// Rewards state: leftover rewards fraction.
    #[serde(rename = "frac", default, skip_serializing_if = "is_zero_u64")]
    pub rewards_residue: u64,

    /// Rewards state: round at which rates were last recalculated.
    #[serde(rename = "rwcalr", default)]
    pub rewards_recalculation_round: Round,

    /// Current protocol version string.
    #[serde(rename = "proto", default, skip_serializing_if = "String::is_empty")]
    pub current_protocol: String,

    /// Next protocol version (if upgrade is in progress).
    #[serde(
        rename = "nextproto",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub next_protocol: String,

    /// Next protocol approvals count.
    #[serde(rename = "nextyes", default, skip_serializing_if = "is_zero_u64")]
    pub next_protocol_approvals: u64,

    /// Next protocol switch-on round.
    #[serde(rename = "nextswitch", default)]
    pub next_protocol_switch_on: Round,

    /// Next protocol voting deadline.
    #[serde(rename = "nextbefore", default)]
    pub next_protocol_vote_before: Round,

    /// Transaction counter.
    #[serde(rename = "tc", default, skip_serializing_if = "is_zero_u64")]
    pub txn_counter: u64,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

fn is_empty_bytes(v: &ByteBuf) -> bool {
    v.is_empty()
}
