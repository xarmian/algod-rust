use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{Address, Round, SignedTransaction};

/// An Algorand block as returned by the REST API.
///
/// In Algorand's msgpack encoding, header fields and the payset (`txns`)
/// are all at the same map level. We model them in a single flat struct
/// rather than using `#[serde(flatten)]`, which has known issues with rmp-serde
/// and binary types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Block {
    // ── Header fields ─────────────────────────────────────────
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

    /// Genesis ID string.
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

    // ── Payset ────────────────────────────────────────────────
    /// Payset: the list of signed transactions in this block.
    #[serde(rename = "txns", default, skip_serializing_if = "Vec::is_empty")]
    pub payset: Vec<SignedTransaction>,
}

/// The top-level response from `GET /v2/blocks/{round}?format=msgpack`.
///
/// The REST API wraps the block in a `{"block": ...}` envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockResponse {
    /// The block content.
    pub block: Block,

    /// Certificate (opaque for Phase 0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<rmpv::Value>,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

fn is_empty_bytes(v: &ByteBuf) -> bool {
    v.is_empty()
}
