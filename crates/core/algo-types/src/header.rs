use serde::{Deserialize, Serialize};

use crate::serde_bytes_array::{is_zero_32, is_zero_64, serde_bytes_32, serde_bytes_64, zeros_64};
use crate::{rmp_decode, Address, Round};

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

    /// Genesis ID string (e.g., "mainnet-v1.0").
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
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !v
}

impl Default for BlockHeader {
    fn default() -> Self {
        Self {
            round: Round::default(),
            branch: [0u8; 32],
            seed: [0u8; 32],
            txn_commitment: [0u8; 32],
            timestamp: 0,
            genesis_id: String::new(),
            genesis_hash: [0u8; 32],
            proposer: Address::default(),
            fee_sink: Address::default(),
            rewards_pool: Address::default(),
            rewards_level: 0,
            rewards_rate: 0,
            rewards_residue: 0,
            rewards_recalculation_round: Round::default(),
            current_protocol: String::new(),
            next_protocol: String::new(),
            next_protocol_approvals: 0,
            next_protocol_switch_on: Round::default(),
            next_protocol_vote_before: Round::default(),
            txn_counter: 0,
            fees_collected: 0,
            bonus: 0,
            proposer_payout: 0,
            prev512: [0u8; 64],
            txn256: [0u8; 32],
            txn512: [0u8; 64],
            state_proof_tracking: None,
            upgrade_propose: String::new(),
            upgrade_delay: 0,
            upgrade_approve: false,
            expired_participation_accounts: None,
            absent_participation_accounts: None,
        }
    }
}

// ════════════════════════════════════════════════════════════════
// Standalone msgpack decoder (rmp-based, no serde overhead)
// ════════════════════════════════════════════════════════════════

/// Type alias for decoder methods to avoid shadowing serde's Result usage.
type DecodeResult<T> = algo_error::Result<T>;

impl BlockHeader {
    /// Decode a BlockHeader from a msgpack map using raw rmp.
    ///
    /// Uses two-level key dispatch: (key_len, first_byte) for fast routing.
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut h = Self::default();
        let mut has_rnd = false;
        for _ in 0..len {
            let key = rmp_decode::read_key_bytes(rd)?;
            match (key.len(), key.first().copied().unwrap_or(0)) {
                // ── 2-byte keys ──────────────────────────────────
                (2, b'b') if key == b"bi" => h.bonus = rmp_decode::read_u64(rd)?,
                (2, b'f') if key == b"fc" => h.fees_collected = rmp_decode::read_u64(rd)?,
                (2, b'g') if key == b"gh" => {
                    h.genesis_hash = rmp_decode::read_fixed_bytes::<32>(rd)?
                }
                (2, b'p') if key == b"pp" => h.proposer_payout = rmp_decode::read_u64(rd)?,
                (2, b't') => match key {
                    b"tc" => h.txn_counter = rmp_decode::read_u64(rd)?,
                    b"ts" => h.timestamp = rmp_decode::read_i64(rd)?,
                    _ => rmp_decode::skip_value(rd)?,
                },
                // ── 3-byte keys ──────────────────────────────────
                (3, b'g') if key == b"gen" => h.genesis_id = rmp_decode::read_string(rd)?,
                (3, b'p') if key == b"prp" => h.proposer = rmp_decode::read_address(rd)?,
                (3, b'r') => match key {
                    b"rnd" => {
                        h.round = Round(rmp_decode::read_u64(rd)?);
                        has_rnd = true;
                    }
                    b"rwd" => h.rewards_pool = rmp_decode::read_address(rd)?,
                    _ => rmp_decode::skip_value(rd)?,
                },
                (3, b's') if key == b"spt" => {
                    h.state_proof_tracking = rmp_decode::read_optional_rmpv(rd)?
                }
                (3, b't') if key == b"txn" => {
                    h.txn_commitment = rmp_decode::read_fixed_bytes::<32>(rd)?
                }
                // ── 4-byte keys ──────────────────────────────────
                (4, b'e') if key == b"earn" => h.rewards_level = rmp_decode::read_u64(rd)?,
                (4, b'f') => match key {
                    b"fees" => h.fee_sink = rmp_decode::read_address(rd)?,
                    b"frac" => h.rewards_residue = rmp_decode::read_u64(rd)?,
                    _ => rmp_decode::skip_value(rd)?,
                },
                (4, b'p') if key == b"prev" => h.branch = rmp_decode::read_fixed_bytes::<32>(rd)?,
                (4, b'r') if key == b"rate" => h.rewards_rate = rmp_decode::read_u64(rd)?,
                (4, b's') if key == b"seed" => h.seed = rmp_decode::read_fixed_bytes::<32>(rd)?,
                // ── 5-byte keys ──────────────────────────────────
                (5, b'p') if key == b"proto" => h.current_protocol = rmp_decode::read_string(rd)?,
                // ── 6-byte keys ──────────────────────────────────
                (6, b'r') if key == b"rwcalr" => {
                    h.rewards_recalculation_round = Round(rmp_decode::read_u64(rd)?)
                }
                (6, b't') => match key {
                    b"txn256" => h.txn256 = rmp_decode::read_fixed_bytes::<32>(rd)?,
                    b"txn512" => h.txn512 = rmp_decode::read_fixed_bytes::<64>(rd)?,
                    _ => rmp_decode::skip_value(rd)?,
                },
                // ── 7-byte keys ──────────────────────────────────
                (7, b'n') if key == b"nextyes" => {
                    h.next_protocol_approvals = rmp_decode::read_u64(rd)?
                }
                (7, b'p') if key == b"prev512" => {
                    h.prev512 = rmp_decode::read_fixed_bytes::<64>(rd)?
                }
                // ── 9-byte keys ──────────────────────────────────
                (9, b'n') if key == b"nextproto" => h.next_protocol = rmp_decode::read_string(rd)?,
                // ── 10-byte keys ─────────────────────────────────
                (10, b'n') => match key {
                    b"nextswitch" => h.next_protocol_switch_on = Round(rmp_decode::read_u64(rd)?),
                    b"nextbefore" => h.next_protocol_vote_before = Round(rmp_decode::read_u64(rd)?),
                    _ => rmp_decode::skip_value(rd)?,
                },
                (10, b'p') => match key {
                    b"partupdrmv" => {
                        h.expired_participation_accounts =
                            rmp_decode::read_optional_vec(rd, rmp_decode::read_address)?
                    }
                    b"partupdabs" => {
                        h.absent_participation_accounts =
                            rmp_decode::read_optional_vec(rd, rmp_decode::read_address)?
                    }
                    _ => rmp_decode::skip_value(rd)?,
                },
                // ── upgrade* keys ────────────────────────────────
                (_, b'u') => match key {
                    b"upgradeprop" => h.upgrade_propose = rmp_decode::read_string(rd)?,
                    b"upgradedelay" => h.upgrade_delay = rmp_decode::read_u64(rd)?,
                    b"upgradeyes" => h.upgrade_approve = rmp_decode::read_bool(rd)?,
                    _ => rmp_decode::skip_value(rd)?,
                },
                // Unknown fields are skipped
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        // The serde path requires `rnd` (no #[serde(default)]), so validate here.
        if !has_rnd {
            return Err(algo_error::AlgoError::Codec {
                source: "BlockHeader: missing required 'rnd' field".into(),
                context: "rmp_decode".into(),
            });
        }
        Ok(h)
    }

    /// Decode a BlockHeader from msgpack bytes.
    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}
