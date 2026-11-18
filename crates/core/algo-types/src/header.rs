// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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
    ///
    /// `default` (issue #827 theme 4): go's canonical/omitempty msgpack
    /// encoding omits `rnd` entirely when it's the zero value (genesis),
    /// exactly like every other zero-valued field on this struct — so a
    /// generic decoder must tolerate its absence rather than erroring,
    /// matching go's own msgp-generated `UnmarshalMsg` (a missing field
    /// simply leaves the zero value already in place). Caught by
    /// `crates/core/algo-ledger/src/catchpoint/verify.rs`'s
    /// `reconstruct_lease_table` failing to decode a `TxTailRound` embedding
    /// a genesis (round 0) header during a live catchpoint-catchup's
    /// post-import lookback-block replay.
    #[serde(rename = "rnd", default)]
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

    // ── Load tracking fields (vFuture only) ─────────────────────
    /// Degree to which this block is full, as a fixed-point fraction with 6
    /// digits of precision (1,000,000 = completely full). Go: `Load`
    /// (`basics.Micros`, future only — v4.7.0-beta, PR #6548).
    #[serde(rename = "ld", default, skip_serializing_if = "is_zero_u64")]
    pub load: u64,

    /// Congestion-tax fee required, beyond `MinFee`, for "normal" transactions
    /// in this block — also a fixed-point `basics.Micros` value. Go:
    /// `CongestionTax` (future only — v4.7.0-beta, PR #6548).
    #[serde(rename = "ct", default, skip_serializing_if = "is_zero_u64")]
    pub congestion_tax: u64,
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
            load: 0,
            congestion_tax: 0,
        }
    }
}

// ════════════════════════════════════════════════════════════════
// Standalone msgpack decoder (rmp-based, no serde overhead)
// ════════════════════════════════════════════════════════════════

/// Type alias for decoder methods to avoid shadowing serde's Result usage.
type DecodeResult<T> = algo_error::Result<T>;

/// `bounds.MaxProposedExpiredOnlineAccounts` (32 since v31): go's
/// `allocbound` of `partupdrmv`.
pub(crate) const MAX_PROPOSED_EXPIRED_ONLINE_ACCOUNTS: usize = 32;
/// `bounds.MaxMarkAbsent` (`Payouts.MaxMarkAbsent`, 32): `partupdabs`.
pub(crate) const MAX_MARK_ABSENT: usize = 32;

/// A `basics.Address` slice element, read with `ReadExactBytes` into the
/// element already there.
pub(crate) fn read_address_elem_into(rd: &mut &[u8], e: &mut Address) -> DecodeResult<()> {
    rmp_decode::read_fixed_bytes_into_go_compat(rd, &mut e.0)
}

/// The key dispatch of a `bookkeeping.BlockHeader` field into `$h` (a
/// `BlockHeader` or a `Block`, which carry the same header fields), shared
/// by both readers. Every field is decoded INTO its current value, as go's
/// generated `UnmarshalMsg` does (issue #2424). `$extra` arms come first,
/// `$fallback` arms last.
macro_rules! header_key_match {
    ($h:ident, $key:ident, $rd:ident, { $($extra:tt)* }, { $($fallback:tt)* }) => {
        match ($key.len(), $key.first().copied().unwrap_or(0)) {
            $($extra)*
            // ── 2-byte keys ──────────────────────────────────
            (2, b'b') if $key == b"bi" => $h.bonus = rmp_decode::read_u64($rd)?,
            (2, b'c') if $key == b"ct" => $h.congestion_tax = rmp_decode::read_u64($rd)?,
            (2, b'f') if $key == b"fc" => $h.fees_collected = rmp_decode::read_u64($rd)?,
            (2, b'g') if $key == b"gh" => {
                rmp_decode::read_fixed_bytes_into_go_compat($rd, &mut $h.genesis_hash)?
            }
            (2, b'l') if $key == b"ld" => $h.load = rmp_decode::read_u64($rd)?,
            (2, b'p') if $key == b"pp" => $h.proposer_payout = rmp_decode::read_u64($rd)?,
            (2, b't') if $key == b"tc" => $h.txn_counter = rmp_decode::read_u64($rd)?,
            (2, b't') if $key == b"ts" => $h.timestamp = rmp_decode::read_i64($rd)?,
            // ── 3-byte keys ──────────────────────────────────
            (3, b'g') if $key == b"gen" => {
                $h.genesis_id =
                    rmp_decode::read_bounded_string($rd, rmp_decode::MAX_GENESIS_ID_LEN)?
            }
            (3, b'p') if $key == b"prp" => {
                rmp_decode::read_fixed_bytes_into_go_compat($rd, &mut $h.proposer.0)?
            }
            // Canonically/omitempty-encoded blocks omit "rnd" entirely at
            // round 0 (the genesis block): the zero value is the default.
            (3, b'r') if $key == b"rnd" => $h.round = Round(rmp_decode::read_u64($rd)?),
            (3, b'r') if $key == b"rwd" => {
                rmp_decode::read_fixed_bytes_into_go_compat($rd, &mut $h.rewards_pool.0)?
            }
            // go's map, decoded and re-encoded the way go does (issue #2424)
            (3, b's') if $key == b"spt" => crate::go_eval_delta::read_state_proof_tracking_into(
                $rd,
                &mut $h.state_proof_tracking,
            )?,
            (3, b't') if $key == b"txn" => {
                rmp_decode::read_fixed_bytes_into_go_compat($rd, &mut $h.txn_commitment)?
            }
            // ── 4-byte keys ──────────────────────────────────
            (4, b'e') if $key == b"earn" => $h.rewards_level = rmp_decode::read_u64($rd)?,
            (4, b'f') if $key == b"fees" => {
                rmp_decode::read_fixed_bytes_into_go_compat($rd, &mut $h.fee_sink.0)?
            }
            (4, b'f') if $key == b"frac" => $h.rewards_residue = rmp_decode::read_u64($rd)?,
            (4, b'p') if $key == b"prev" => {
                rmp_decode::read_fixed_bytes_into_go_compat($rd, &mut $h.branch)?
            }
            (4, b'r') if $key == b"rate" => $h.rewards_rate = rmp_decode::read_u64($rd)?,
            (4, b's') if $key == b"seed" => {
                rmp_decode::read_fixed_bytes_into_go_compat($rd, &mut $h.seed)?
            }
            // ── 5-byte keys ──────────────────────────────────
            (5, b'p') if $key == b"proto" => {
                $h.current_protocol =
                    rmp_decode::read_bounded_string($rd, rmp_decode::MAX_CONSENSUS_VERSION_LEN)?
            }
            // ── 6-byte keys ──────────────────────────────────
            (6, b'r') if $key == b"rwcalr" => {
                $h.rewards_recalculation_round = Round(rmp_decode::read_u64($rd)?)
            }
            (6, b't') if $key == b"txn256" => {
                rmp_decode::read_fixed_bytes_into_go_compat($rd, &mut $h.txn256)?
            }
            (6, b't') if $key == b"txn512" => {
                rmp_decode::read_fixed_bytes_into_go_compat($rd, &mut $h.txn512)?
            }
            // ── 7-byte keys ──────────────────────────────────
            (7, b'n') if $key == b"nextyes" => {
                $h.next_protocol_approvals = rmp_decode::read_u64($rd)?
            }
            (7, b'p') if $key == b"prev512" => {
                rmp_decode::read_fixed_bytes_into_go_compat($rd, &mut $h.prev512)?
            }
            // ── 9-byte keys ──────────────────────────────────
            (9, b'n') if $key == b"nextproto" => {
                $h.next_protocol =
                    rmp_decode::read_bounded_string($rd, rmp_decode::MAX_CONSENSUS_VERSION_LEN)?
            }
            // ── 10-byte keys ─────────────────────────────────
            (10, b'n') if $key == b"nextswitch" => {
                $h.next_protocol_switch_on = Round(rmp_decode::read_u64($rd)?)
            }
            (10, b'n') if $key == b"nextbefore" => {
                $h.next_protocol_vote_before = Round(rmp_decode::read_u64($rd)?)
            }
            (10, b'p') if $key == b"partupdrmv" => rmp_decode::read_slice_into_opt(
                $rd,
                &mut $h.expired_participation_accounts,
                $crate::header::MAX_PROPOSED_EXPIRED_ONLINE_ACCOUNTS,
                Address::default,
                $crate::header::read_address_elem_into,
            )?,
            (10, b'p') if $key == b"partupdabs" => rmp_decode::read_slice_into_opt(
                $rd,
                &mut $h.absent_participation_accounts,
                $crate::header::MAX_MARK_ABSENT,
                Address::default,
                $crate::header::read_address_elem_into,
            )?,
            // ── upgrade* keys ────────────────────────────────
            (11, b'u') if $key == b"upgradeprop" => {
                $h.upgrade_propose =
                    rmp_decode::read_bounded_string($rd, rmp_decode::MAX_CONSENSUS_VERSION_LEN)?
            }
            (12, b'u') if $key == b"upgradedelay" => {
                $h.upgrade_delay = rmp_decode::read_u64($rd)?
            }
            (10, b'u') if $key == b"upgradeyes" => {
                $h.upgrade_approve = rmp_decode::read_bool($rd)?
            }
            $($fallback)*
        }
    };
}
pub(crate) use header_key_match;

impl BlockHeader {
    /// Decode a BlockHeader from a msgpack map using raw rmp.
    ///
    /// Uses two-level key dispatch: (key_len, first_byte) for fast routing.
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let _session = rmp_decode::decode_session();
        let mut h = Self::default();
        Self::decode_into(rd, &mut h)?;
        Ok(h)
    }

    /// Decode into an already decoded header (issue #2424). A missing `rnd`
    /// means round 0: go-algorand's msgpack omits zero-valued fields, and the
    /// **genesis block** is the one header that carries round 0.
    pub(crate) fn decode_into(rd: &mut &[u8], h: &mut Self) -> DecodeResult<()> {
        let len = rmp_decode::read_struct_map_len(rd, h)?;
        for _ in 0..len {
            let key = rmp_decode::read_key_bytes(rd)?;
            header_key_match!(h, key, rd, {}, {
                // go's msgp decoder: msgp.ErrNoField (issue #2394)
                _ => rmp_decode::unknown_key(rd, key)?,
            });
        }
        Ok(())
    }

    /// Decode a BlockHeader from msgpack bytes.
    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}
