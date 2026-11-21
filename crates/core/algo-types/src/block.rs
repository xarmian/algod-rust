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
use crate::{rmp_decode, Address, Round, SignedTransaction};

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
    ///
    /// `#[serde(default)]` because canonically/omitempty-encoded blocks
    /// omit "rnd" entirely at round 0 (e.g. the genesis block).
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

impl Default for Block {
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
            payset: Vec::new(),
        }
    }
}

// ════════════════════════════════════════════════════════════════
// Standalone msgpack decoders (rmp-based, no serde overhead)
// ════════════════════════════════════════════════════════════════

/// Type alias for decoder methods to avoid shadowing serde's Result usage.
type DecodeResult<T> = algo_error::Result<T>;

impl Block {
    /// Decode a Block from a msgpack map using raw rmp.
    ///
    /// Block is a flat struct containing all BlockHeader fields plus a `txns` payset.
    /// Uses two-level key dispatch: (key_len, first_byte) for fast routing.
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        Self::decode_with_extra_keys(rd, &[])
    }

    /// [`Self::decode_from_reader`] for a map that carries `extra_keys` next
    /// to the block's own: go's `unauthenticatedProposal` embeds a `Block`
    /// beside `sdpf`/`oper`/`oprop`, `transmittedPayload` also `pv`. Those
    /// top-level keys are skipped (the caller reads them); any other unknown
    /// key, at any level, is `msgp.ErrNoField` as in go (issue #2394).
    pub fn decode_with_extra_keys(rd: &mut &[u8], extra_keys: &[&[u8]]) -> DecodeResult<Self> {
        let _session = rmp_decode::decode_session();
        let mut b = Self::default();
        Self::decode_into(rd, &mut b, extra_keys)?;
        Ok(b)
    }

    /// Decode into an already decoded block, as go's generated `UnmarshalMsg`
    /// does (issue #2424: a repeated key decodes into the populated field).
    pub(crate) fn decode_into(
        rd: &mut &[u8],
        b: &mut Self,
        extra_keys: &[&[u8]],
    ) -> DecodeResult<()> {
        let mut keys = rmp_decode::struct_keys(rd, b, "bookkeeping.Block")?;
        while let Some(key) = keys.next(rd)? {
            crate::header::header_key_match!(b, key, rd, {
                // go's `Payset` (`//msgp:allocbound Payset 100000`)
                (4, b't') if key == b"txns" => {
                    rmp_decode::read_slice_into(
                        rd,
                        &mut b.payset,
                        rmp_decode::MAX_PAYSET_LEN,
                        SignedTransaction::default,
                        |rd, t| SignedTransaction::decode_into(rd, t, true),
                    )?;
                }
            }, {
                // go's msgp decoder: msgp.ErrNoField (issue #2394)
                _ if extra_keys.contains(&key) => rmp_decode::skip_value(rd)?,
                _ => rmp_decode::unknown_key(rd, key)?,
            });
        }
        Ok(())
    }

    /// Decode a Block from msgpack bytes.
    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl BlockResponse {
    /// Decode a BlockResponse (go `rpcs.EncodedBlockCert`) from a msgpack
    /// map using raw rmp.
    ///
    /// The REST API wraps the block in a `{"block": ..., "cert": ...}`
    /// envelope. `block` is decoded into the populated block on a repeated
    /// key like go's; `cert` is kept opaque, with every occurrence's raw
    /// entries (see [`merge_raw_struct`]), for `decode_bundle` to read the
    /// way go's `Certificate.UnmarshalMsg` does.
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let _session = rmp_decode::decode_session();
        // go's `EncodedBlockCert`, a struct like any other: its array form is
        // `[block, cert]` (a `nil` reads as the zero response)
        let mut keys = rmp_decode::struct_keys(rd, &mut (), "rpcs.EncodedBlockCert")?;
        let mut block = Block::default();
        let mut cert = None;
        while let Some(key) = keys.next(rd)? {
            match (key.len(), key.first().copied().unwrap_or(0)) {
                (5, b'b') if key == b"block" => Block::decode_into(rd, &mut block, &[])?,
                (4, b'c') if key == b"cert" => {
                    let v = rmp_decode::read_checked_optional_rmpv(
                        rd,
                        &crate::msgp_schema::CERTIFICATE,
                    )?;
                    cert = merge_raw_struct(cert, v);
                }
                _ => rmp_decode::unknown_key(rd, key)?,
            }
        }
        // go's `EncodedBlockCert` has no required field: a response without
        // `block` decodes to the zero block (which then fails every check of
        // a fetched block, never the decode).
        Ok(BlockResponse { block, cert })
    }

    /// Decode a BlockResponse from msgpack bytes.
    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

/// An opaque struct value decoded again under a repeated key: go decodes the
/// second occurrence INTO the first, which (for a struct) is the same as
/// decoding one map holding the first occurrence's entries followed by the
/// second's. `nil` resets the struct (go `(*z) = T{}`), i.e. drops the
/// earlier entries.
fn merge_raw_struct(prev: Option<rmpv::Value>, next: Option<rmpv::Value>) -> Option<rmpv::Value> {
    match (prev, next) {
        (Some(rmpv::Value::Map(mut a)), Some(rmpv::Value::Map(b))) => {
            a.extend(b);
            Some(rmpv::Value::Map(a))
        }
        (_, next) => next,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// go's `//msgp:allocbound Payset 100000` is checked on the array header,
    /// before any element is read (issue #2427): a payset header claiming one
    /// more is `msgp.ErrOverflow`, whatever follows it.
    #[test]
    fn payset_over_its_allocbound_fails_on_the_header() {
        let block = |n: u32| {
            let mut b = vec![0x81, 0xa4, b't', b'x', b'n', b's', 0xdd];
            b.extend_from_slice(&n.to_be_bytes());
            b
        };
        let over = Block::decode_from_bytes(&block(100_001)).unwrap_err();
        assert!(format!("{over:?}").contains("allocation bound"), "{over:?}");
        // at the bound the header passes and the (missing) elements fail
        let at = Block::decode_from_bytes(&block(100_000)).unwrap_err();
        assert!(!format!("{at:?}").contains("allocation bound"), "{at:?}");
    }
}
