use serde::{Deserialize, Serialize};

use crate::serde_bytes_array::{is_zero_32, is_zero_64, serde_bytes_32, serde_bytes_64, zeros_64};
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

    /// Previous block hash (crypto.Digest = [32]byte in Go).
    #[serde(
        rename = "prev",
        default,
        skip_serializing_if = "is_zero_32",
        with = "serde_bytes_32"
    )]
    pub branch: [u8; 32],

    /// Sortition seed (committee.Seed = [32]byte in Go).
    #[serde(
        rename = "seed",
        default,
        skip_serializing_if = "is_zero_32",
        with = "serde_bytes_32"
    )]
    pub seed: [u8; 32],

    /// Transaction commitment (crypto.Digest = [32]byte in Go).
    #[serde(
        rename = "txn",
        default,
        skip_serializing_if = "is_zero_32",
        with = "serde_bytes_32"
    )]
    pub txn_commitment: [u8; 32],

    /// Block timestamp (seconds since epoch).
    #[serde(rename = "ts", default)]
    pub timestamp: i64,

    /// Genesis ID string.
    #[serde(rename = "gen", default, skip_serializing_if = "String::is_empty")]
    pub genesis_id: String,

    /// Genesis hash (crypto.Digest = [32]byte in Go).
    #[serde(
        rename = "gh",
        default,
        skip_serializing_if = "is_zero_32",
        with = "serde_bytes_32"
    )]
    pub genesis_hash: [u8; 32],

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

    // ── Additional header fields (needed for block digest) ───
    /// Fees collected in this block (consensus v39+).
    #[serde(rename = "fc", default, skip_serializing_if = "is_zero_u64")]
    pub fees_collected: u64,

    /// Bonus (block incentive bonus, consensus v39+).
    #[serde(rename = "bi", default, skip_serializing_if = "is_zero_u64")]
    pub bonus: u64,

    /// Proposer payout (consensus v39+).
    #[serde(rename = "pp", default, skip_serializing_if = "is_zero_u64")]
    pub proposer_payout: u64,

    /// SHA512/256 digest of the previous block header (crypto.Sha512Digest = [64]byte in Go).
    #[serde(
        rename = "prev512",
        default = "zeros_64",
        skip_serializing_if = "is_zero_64",
        with = "serde_bytes_64"
    )]
    pub prev512: [u8; 64],

    /// SHA256 merkle root of the payset (crypto.Digest = [32]byte in Go).
    #[serde(
        rename = "txn256",
        default,
        skip_serializing_if = "is_zero_32",
        with = "serde_bytes_32"
    )]
    pub txn256: [u8; 32],

    /// SHA512/256 merkle root variant of the payset (crypto.Sha512Digest = [64]byte in Go).
    #[serde(
        rename = "txn512",
        default = "zeros_64",
        skip_serializing_if = "is_zero_64",
        with = "serde_bytes_64"
    )]
    pub txn512: [u8; 64],

    /// State proof tracking (opaque -- uses integer map keys).
    #[serde(rename = "spt", default, skip_serializing_if = "Option::is_none")]
    pub state_proof_tracking: Option<rmpv::Value>,

    // ── Upgrade Vote fields ─────────────────────────────────────
    /// Proposed upgrade protocol version.
    #[serde(
        rename = "upgradeprop",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub upgrade_propose: String,

    /// Proposed upgrade delay (rounds).
    #[serde(rename = "upgradedelay", default, skip_serializing_if = "is_zero_u64")]
    pub upgrade_delay: u64,

    /// Whether this block votes to approve the current upgrade proposal.
    #[serde(rename = "upgradeyes", default, skip_serializing_if = "is_false")]
    pub upgrade_approve: bool,

    // ── Participation Updates fields ────────────────────────────
    /// Expired participation accounts (removed from participation).
    #[serde(
        rename = "partupdrmv",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expired_participation_accounts: Option<Vec<Address>>,

    /// Absent participation accounts.
    #[serde(
        rename = "partupdabs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub absent_participation_accounts: Option<Vec<Address>>,

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

fn is_false(v: &bool) -> bool {
    !v
}
