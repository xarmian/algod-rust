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

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use thiserror::Error;

use algo_types::AccountData;

// ---------------------------------------------------------------------------
// Go `msgp.Raw` field support
// ---------------------------------------------------------------------------
//
// Several catchpoint record fields are typed `msgp.Raw` in go-algorand
// (`../go-algorand/ledger/encoded/recordsV6.go`): `BalanceRecordV6.AccountData`
// (`"b"`), the values of `BalanceRecordV6.Resources` (`"c"`),
// `OnlineAccountRecordV6.Data` and `OnlineRoundParamsRecordV6.Data`
// (both `"data"`). Go writes a `msgp.Raw` by splicing the already-encoded
// bytes straight into the stream, so in a real go-algorand catchpoint file
// these fields appear as an *embedded msgpack map*, not as a msgpack `bin`
// blob.
//
// The Rust model keeps them as `ByteBuf` (the raw blob is stored verbatim in
// SQLite and hashed as-is), so decoding needs to accept both shapes:
//
//   * `bin`  — produced by `rmp_serde::to_vec_named` on these types (used by
//     this crate's own test fixtures and by any writer that round-trips the
//     serde impls);
//   * anything else (in practice a `map`) — produced by go-algorand and by
//     [`crate::catchpoint::writer`], which mirrors Go's canonical encoding.
//
// [`deserialize_msgp_raw`] and [`deserialize_msgp_raw_map`] normalize both
// into the raw blob bytes. Serialization is unchanged (`ByteBuf` -> `bin`);
// the go-canonical writer hand-rolls its encoding rather than going through
// serde, exactly as `verify.rs` does for hash-critical paths.

/// Re-encode a decoded msgpack value back into its raw byte form.
///
/// `Value::Binary` is treated as an already-unwrapped raw blob (the `bin`
/// shape described above); every other value is re-encoded. `rmpv` preserves
/// map entry order and the str/bin distinction, and writes integers in their
/// shortest form.
///
/// **Caveat:** the embedded-map path is byte-exact only for *canonically*
/// encoded input — i.e. integers already in shortest form. go-codec (and this
/// workspace's `algo_codec::canonical_encode_*`) always emit shortest-form
/// integers, so every blob produced by go-algorand or by algod-rust survives
/// verbatim; a hand-crafted blob with an over-wide integer would be rewritten
/// (and would therefore hash differently). The `bin` path is always
/// byte-exact.
fn msgp_raw_bytes<E: serde::de::Error>(value: rmpv::Value) -> Result<Vec<u8>, E> {
    match value {
        rmpv::Value::Binary(b) => Ok(b),
        rmpv::Value::Nil => Ok(Vec::new()),
        other => {
            let mut buf = Vec::new();
            rmpv::encode::write_value(&mut buf, &other)
                .map_err(|e| E::custom(format!("re-encode msgp.Raw field: {e}")))?;
            Ok(buf)
        }
    }
}

/// `serde` adapter for a Go `msgp.Raw` field.
fn deserialize_msgp_raw<'de, D>(deserializer: D) -> Result<ByteBuf, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = rmpv::Value::deserialize(deserializer)?;
    Ok(ByteBuf::from(msgp_raw_bytes::<D::Error>(value)?))
}

/// `serde` adapter for a `map[uint64]msgp.Raw` field.
fn deserialize_msgp_raw_map<'de, D>(deserializer: D) -> Result<HashMap<u64, ByteBuf>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: HashMap<u64, rmpv::Value> = HashMap::deserialize(deserializer)?;
    let mut out = HashMap::with_capacity(raw.len());
    for (k, v) in raw {
        out.insert(k, ByteBuf::from(msgp_raw_bytes::<D::Error>(v)?));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Catchpoint file format version constants
// From go-algorand/ledger/catchpointtracker.go
// These are Go octal literals: 0200 = 128, 0201 = 129, 0202 = 130, 0203 = 131
// ---------------------------------------------------------------------------

/// V5: catchpoint file version for database schema V0-V5.
pub const CATCHPOINT_FILE_VERSION_V5: u64 = 0o200; // 128
/// V6: introduced accounts and resources separation.
pub const CATCHPOINT_FILE_VERSION_V6: u64 = 0o201; // 129
/// V7: added state proof verification data and versioning for CatchpointLabel.
pub const CATCHPOINT_FILE_VERSION_V7: u64 = 0o202; // 130
/// V8: added online accounts and online round params data + hashes (current).
pub const CATCHPOINT_FILE_VERSION_V8: u64 = 0o203; // 131

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during catchpoint parsing and processing.
#[derive(Debug, Error)]
pub enum CatchpointError {
    #[error("unsupported catchpoint file version: {0}")]
    UnsupportedVersion(u64),

    #[error("invalid catchpoint header: {0}")]
    InvalidHeader(String),

    #[error("missing catchpoint header (content.msgpack)")]
    MissingHeader,

    #[error("catchpoint I/O error")]
    Io(#[from] std::io::Error),

    #[error("catchpoint decode error: {0}")]
    DecodeError(String),

    #[error("catchpoint Snappy decompression error: {0}")]
    SnappyError(String),

    #[error("catchpoint integrity error: {0}")]
    IntegrityError(String),

    #[error("catchpoint import error: {0}")]
    ImportError(String),

    #[error("catchpoint cutover error: {0}")]
    CutoverError(String),

    #[error("catchpoint checkpoint error: {0}")]
    CheckpointError(String),

    #[error("catchpoint sqlite error")]
    SqliteError(#[from] rusqlite::Error),

    #[error("catchpoint label parsing failed: {0}")]
    LabelParsingFailed(String),

    #[error("catchpoint verification error: {0}")]
    VerificationError(String),
}

// ---------------------------------------------------------------------------
// CatchpointLabel — parsed representation of "{round}#{base32_hash}"
// ---------------------------------------------------------------------------

/// A parsed catchpoint label.
///
/// Corresponds to the result of Go's `ledgercore.ParseCatchpointLabel`.
/// Format: `{round}#{base32_hash}` where hash is base32 standard encoding
/// (no padding) of a 32-byte SHA-512/256 digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchpointLabel {
    /// The round number from the label.
    pub round: u64,
    /// The 32-byte hash digest from the label.
    pub hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// AccountTotals / AlgoCount  (named-key msgpack, from ledgercore/totals.go)
// ---------------------------------------------------------------------------

/// Represents a total of algos for a certain class of accounts (by Status).
/// Corresponds to Go `ledgercore.AlgoCount`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgoCount {
    /// Sum of algos (in microAlgos) of all accounts in this class.
    #[serde(rename = "mon", default)]
    pub money: u64,

    /// Total number of whole reward units in accounts.
    #[serde(rename = "rwd", default)]
    pub reward_units: u64,
}

/// Totals of algos in the system grouped by account status.
/// Corresponds to Go `ledgercore.AccountTotals`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountTotals {
    #[serde(rename = "online", default)]
    pub online: AlgoCount,

    #[serde(rename = "offline", default)]
    pub offline: AlgoCount,

    #[serde(rename = "notpart", default)]
    pub not_participating: AlgoCount,

    /// Total number of algos received per reward unit since genesis.
    #[serde(rename = "rwdlvl", default)]
    pub rewards_level: u64,
}

// ---------------------------------------------------------------------------
// CatchpointFileHeader  (from ledger/catchpointfileheader.go)
// ---------------------------------------------------------------------------

/// The content of "content.msgpack" inside the catchpoint tar archive.
/// Corresponds to Go `CatchpointFileHeader`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatchpointFileHeader {
    #[serde(rename = "version", default)]
    pub version: u64,

    #[serde(rename = "balancesRound", default)]
    pub balances_round: u64,

    #[serde(rename = "blocksRound", default)]
    pub blocks_round: u64,

    #[serde(rename = "accountTotals", default)]
    pub totals: AccountTotals,

    #[serde(rename = "accountsCount", default)]
    pub total_accounts: u64,

    #[serde(rename = "chunksCount", default)]
    pub total_chunks: u64,

    #[serde(rename = "kvsCount", default)]
    pub total_kvs: u64,

    #[serde(rename = "onlineAccountsCount", default)]
    pub total_online_accounts: u64,

    #[serde(rename = "onlineRoundParamsCount", default)]
    pub total_online_round_params: u64,

    #[serde(rename = "catchpoint", default)]
    pub catchpoint: String,

    /// Block header digest (32 bytes, SHA-512/256).
    #[serde(rename = "blockHeaderDigest", default)]
    pub block_header_digest: ByteBuf,
}

// ---------------------------------------------------------------------------
// Chunk container  (from ledger/catchpointfilewriter.go)
// ---------------------------------------------------------------------------

/// The current encoding of "balances.X.msgpack" files in the catchpoint snapshot.
/// Corresponds to Go `CatchpointSnapshotChunkV6`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CatchpointSnapshotChunkV6 {
    /// Account balance records.
    #[serde(rename = "bl", default)]
    pub balances: Vec<BalanceRecordV6>,

    /// Key-value (box) records.
    #[serde(rename = "kv", default)]
    pub kvs: Vec<KVRecordV6>,

    /// Online account records (V8+).
    #[serde(rename = "oa", default)]
    pub online_accounts: Vec<OnlineAccountRecordV6>,

    /// Online round params records (V8+).
    #[serde(rename = "orp", default)]
    pub online_round_params: Vec<OnlineRoundParamsRecordV6>,
}

// ---------------------------------------------------------------------------
// BalanceRecordV6  (from ledger/encoded/recordsV6.go)
// ---------------------------------------------------------------------------

/// Encoded account balance record in catchpoint V6+ format.
/// Corresponds to Go `encoded.BalanceRecordV6`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BalanceRecordV6 {
    /// 32-byte account address.
    #[serde(rename = "a", default)]
    pub address: ByteBuf,

    /// Raw msgp-encoded `baseAccountData` blob (decoded separately in Wave 2).
    #[serde(rename = "b", default, deserialize_with = "deserialize_msgp_raw")]
    pub account_data: ByteBuf,

    /// Map of creatable index -> raw msgp-encoded `resourcesData`.
    #[serde(rename = "c", default, deserialize_with = "deserialize_msgp_raw_map")]
    pub resources: HashMap<u64, ByteBuf>,

    /// Flag indicating whether there are more records for the same account.
    #[serde(rename = "e", default)]
    pub expecting_more_entries: bool,
}

// ---------------------------------------------------------------------------
// KVRecordV6  (from ledger/encoded/recordsV6.go)
// ---------------------------------------------------------------------------

/// Encoded key-value (box) record.
/// Corresponds to Go `encoded.KVRecordV6`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KVRecordV6 {
    #[serde(rename = "k", default)]
    pub key: ByteBuf,

    #[serde(rename = "v", default)]
    pub value: ByteBuf,
}

// ---------------------------------------------------------------------------
// OnlineAccountRecordV6  (from ledger/encoded/recordsV6.go)
// ---------------------------------------------------------------------------

/// Encoded online account record for catchpoint files.
/// Corresponds to Go `encoded.OnlineAccountRecordV6`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnlineAccountRecordV6 {
    /// 32-byte account address.
    #[serde(rename = "addr", default)]
    pub address: ByteBuf,

    /// Round at which this online account was last updated.
    #[serde(rename = "upd", default)]
    pub updated_round: u64,

    /// Normalized online balance.
    #[serde(rename = "nob", default)]
    pub normalized_online_balance: u64,

    /// Vote last valid round.
    #[serde(rename = "vlv", default)]
    pub vote_last_valid: u64,

    /// Raw msgp-encoded `BaseOnlineAccountData`.
    #[serde(rename = "data", default, deserialize_with = "deserialize_msgp_raw")]
    pub data: ByteBuf,
}

// ---------------------------------------------------------------------------
// OnlineRoundParamsRecordV6  (from ledger/encoded/recordsV6.go)
// ---------------------------------------------------------------------------

/// Encoded online round params record for catchpoint files.
/// Corresponds to Go `encoded.OnlineRoundParamsRecordV6`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnlineRoundParamsRecordV6 {
    #[serde(rename = "rnd", default)]
    pub round: u64,

    /// Raw msgp-encoded `OnlineRoundParamsData`.
    #[serde(rename = "data", default, deserialize_with = "deserialize_msgp_raw")]
    pub data: ByteBuf,
}

// ---------------------------------------------------------------------------
// Intermediate decode structs (for Wave 2 positional msgp decoding)
// ---------------------------------------------------------------------------

/// Decoded form of Go's `baseAccountData` from `trackerdb/data.go`.
///
/// Fields are ordered to match Go's codec tags (a-z, then A-F for voting data,
/// then z for update_round). The embedded `BaseVotingData` fields (A-F) are
/// inlined here since Rust doesn't have struct embedding.
#[derive(Debug, Clone, PartialEq)]
pub struct CatchpointBaseAccountData {
    // --- baseAccountData fields (codec a-q) ---
    /// Account status (0=Offline, 1=Online, 2=NotParticipating). Codec: "a"
    pub status: u8,
    /// MicroAlgos balance. Codec: "b"
    pub micro_algos: u64,
    /// Rewards base. Codec: "c"
    pub rewards_base: u64,
    /// Rewarded microAlgos. Codec: "d"
    pub rewarded_micro_algos: u64,
    /// Auth address (32 bytes, zero if not rekeyed). Codec: "e"
    pub auth_addr: [u8; 32],
    /// Total app schema num uint. Codec: "f"
    pub total_app_schema_num_uint: u64,
    /// Total app schema num byte slice. Codec: "g"
    pub total_app_schema_num_byte_slice: u64,
    /// Total extra app pages. Codec: "h"
    pub total_extra_app_pages: u32,
    /// Total asset params (number of assets created). Codec: "i"
    pub total_asset_params: u64,
    /// Total assets (number of assets opted into). Codec: "j"
    pub total_assets: u64,
    /// Total app params (number of apps created). Codec: "k"
    pub total_app_params: u64,
    /// Total app local states (number of apps opted into). Codec: "l"
    pub total_app_local_states: u64,
    /// Total boxes. Codec: "m"
    pub total_boxes: u64,
    /// Total box bytes. Codec: "n"
    pub total_box_bytes: u64,
    /// Incentive eligible (V40+). Codec: "o"
    pub incentive_eligible: bool,
    /// Last proposed round. Codec: "p"
    pub last_proposed: u64,
    /// Last heartbeat round. Codec: "q"
    pub last_heartbeat: u64,

    // --- BaseVotingData fields (embedded, codec A-F) ---
    /// One-time signature verifier key (32 bytes). Codec: "A"
    pub vote_id: [u8; 32],
    /// VRF verifier key (32 bytes). Codec: "B"
    pub selection_id: [u8; 32],
    /// Vote first valid round. Codec: "C"
    pub vote_first_valid: u64,
    /// Vote last valid round. Codec: "D"
    pub vote_last_valid: u64,
    /// Vote key dilution. Codec: "E"
    pub vote_key_dilution: u64,
    /// State proof ID / Merkle signature commitment (64 bytes). Codec: "F"
    pub state_proof_id: [u8; 64],

    // --- update round (codec z) ---
    /// Round that last modified this account data. Codec: "z"
    pub update_round: u64,
}

impl Default for CatchpointBaseAccountData {
    fn default() -> Self {
        Self {
            status: 0,
            micro_algos: 0,
            rewards_base: 0,
            rewarded_micro_algos: 0,
            auth_addr: [0u8; 32],
            total_app_schema_num_uint: 0,
            total_app_schema_num_byte_slice: 0,
            total_extra_app_pages: 0,
            total_asset_params: 0,
            total_assets: 0,
            total_app_params: 0,
            total_app_local_states: 0,
            total_boxes: 0,
            total_box_bytes: 0,
            incentive_eligible: false,
            last_proposed: 0,
            last_heartbeat: 0,
            vote_id: [0u8; 32],
            selection_id: [0u8; 32],
            vote_first_valid: 0,
            vote_last_valid: 0,
            vote_key_dilution: 0,
            state_proof_id: [0u8; 64],
            update_round: 0,
        }
    }
}

impl From<&CatchpointBaseAccountData> for AccountData {
    fn from(src: &CatchpointBaseAccountData) -> Self {
        use algo_types::AccountStatus;

        let status = AccountStatus::from(src.status);
        let vote_id = if src.vote_id == [0u8; 32] {
            None
        } else {
            Some(src.vote_id)
        };
        let selection_id = if src.selection_id == [0u8; 32] {
            None
        } else {
            Some(src.selection_id)
        };
        let state_proof_id = if src.state_proof_id == [0u8; 64] {
            None
        } else {
            Some(src.state_proof_id)
        };
        let auth_addr = if src.auth_addr == [0u8; 32] {
            None
        } else {
            Some(algo_types::Address(src.auth_addr))
        };

        AccountData {
            status,
            micro_algos: src.micro_algos,
            rewards_base: src.rewards_base,
            rewarded_micro_algos: src.rewarded_micro_algos,
            auth_addr,
            total_app_schema: algo_types::StateSchema {
                num_uint: src.total_app_schema_num_uint,
                num_byte_slice: src.total_app_schema_num_byte_slice,
            },
            total_extra_app_pages: src.total_extra_app_pages,
            total_created_assets: src.total_asset_params,
            total_assets_opted_in: src.total_assets,
            total_created_apps: src.total_app_params,
            total_apps_opted_in: src.total_app_local_states,
            total_boxes: src.total_boxes,
            total_box_bytes: src.total_box_bytes,
            incentive_eligible: src.incentive_eligible,
            last_proposed: src.last_proposed,
            last_heartbeat: src.last_heartbeat,
            vote_id,
            selection_id,
            state_proof_id,
            vote_first_valid: src.vote_first_valid,
            vote_last_valid: src.vote_last_valid,
            vote_key_dilution: src.vote_key_dilution,
            update_round: src.update_round,
            asset_params: BTreeMap::new(),
            assets: BTreeMap::new(),
            app_local_states: BTreeMap::new(),
            app_params: BTreeMap::new(),
        }
    }
}

/// Decoded form of Go's `resourcesData` from `trackerdb/data.go`.
///
/// Contains flattened asset params, asset holding, app local state, and app
/// global params fields.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CatchpointResourcesData {
    // --- asset parameters (basics.AssetParams), codec a-k ---
    /// Total supply. Codec: "a"
    pub total: u64,
    /// Decimals. Codec: "b"
    pub decimals: u32,
    /// Default frozen. Codec: "c"
    pub default_frozen: bool,
    /// Unit name. Codec: "d"
    pub unit_name: String,
    /// Asset name. Codec: "e"
    pub asset_name: String,
    /// URL. Codec: "f"
    pub url: String,
    /// Metadata hash (32 bytes). Codec: "g"
    pub metadata_hash: [u8; 32],
    /// Manager address (32 bytes). Codec: "h"
    pub manager: [u8; 32],
    /// Reserve address (32 bytes). Codec: "i"
    pub reserve: [u8; 32],
    /// Freeze address (32 bytes). Codec: "j"
    pub freeze: [u8; 32],
    /// Clawback address (32 bytes). Codec: "k"
    pub clawback: [u8; 32],

    // --- asset holding (basics.AssetHolding), codec l-m ---
    /// Amount held. Codec: "l"
    pub amount: u64,
    /// Frozen flag. Codec: "m"
    pub frozen: bool,

    // --- application local state (basics.AppLocalState), codec n-p ---
    /// Local state schema num uint. Codec: "n"
    pub schema_num_uint: u64,
    /// Local state schema num byte slice. Codec: "o"
    pub schema_num_byte_slice: u64,
    /// Local key-value store. Codec: "p"
    /// Stored as raw bytes; decoded separately if needed.
    pub key_value: Vec<u8>,

    // --- application global params (basics.AppParams), codec q-x ---
    /// Approval program. Codec: "q"
    pub approval_program: Vec<u8>,
    /// Clear-state program. Codec: "r"
    pub clear_state_program: Vec<u8>,
    /// Global state key-value. Codec: "s"
    /// Stored as raw bytes; decoded separately if needed.
    pub global_state: Vec<u8>,
    /// Local state schema num uint (from AppParams). Codec: "t"
    pub local_state_schema_num_uint: u64,
    /// Local state schema num byte slice (from AppParams). Codec: "u"
    pub local_state_schema_num_byte_slice: u64,
    /// Global state schema num uint. Codec: "v"
    pub global_state_schema_num_uint: u64,
    /// Global state schema num byte slice. Codec: "w"
    pub global_state_schema_num_byte_slice: u64,
    /// Extra program pages. Codec: "x"
    pub extra_program_pages: u32,

    // --- resource flags and metadata, codec y-z, A-B ---
    /// Resource flags (bitmask). Codec: "y"
    pub resource_flags: u8,
    /// Update round. Codec: "z"
    pub update_round: u64,
    /// App version. Codec: "A"
    pub version: u64,
    /// Size sponsor address (32 bytes). Codec: "B"
    pub size_sponsor: [u8; 32],
    /// ForeignBoxReads flag. Codec: "C". Issue #659.
    pub foreign_box_reads: bool,
    /// FamilyBoxAccess flag. Codec: "D". Issue #659.
    pub family_box_access: bool,
}

/// Decoded form of Go's `BaseOnlineAccountData` from `trackerdb/data.go`.
///
/// Contains inlined `BaseVotingData` fields plus online-specific fields.
#[derive(Debug, Clone, PartialEq)]
pub struct CatchpointBaseOnlineAccountData {
    // --- BaseVotingData fields (codec A-F) ---
    /// One-time signature verifier key (32 bytes). Codec: "A"
    pub vote_id: [u8; 32],
    /// VRF verifier key (32 bytes). Codec: "B"
    pub selection_id: [u8; 32],
    /// Vote first valid round. Codec: "C"
    pub vote_first_valid: u64,
    /// Vote last valid round. Codec: "D"
    pub vote_last_valid: u64,
    /// Vote key dilution. Codec: "E"
    pub vote_key_dilution: u64,
    /// State proof ID / Merkle signature commitment (64 bytes). Codec: "F"
    pub state_proof_id: [u8; 64],

    // --- Online-specific fields ---
    /// Last proposed round. Codec: "V"
    pub last_proposed: u64,
    /// Last heartbeat round. Codec: "W"
    pub last_heartbeat: u64,
    /// Incentive eligible. Codec: "X"
    pub incentive_eligible: bool,
    /// MicroAlgos balance. Codec: "Y"
    pub micro_algos: u64,
    /// Rewards base. Codec: "Z"
    pub rewards_base: u64,
}

impl Default for CatchpointBaseOnlineAccountData {
    fn default() -> Self {
        Self {
            vote_id: [0u8; 32],
            selection_id: [0u8; 32],
            vote_first_valid: 0,
            vote_last_valid: 0,
            vote_key_dilution: 0,
            state_proof_id: [0u8; 64],
            last_proposed: 0,
            last_heartbeat: 0,
            incentive_eligible: false,
            micro_algos: 0,
            rewards_base: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// State proof verification context types (from ledgercore/stateproofverification.go)
// ---------------------------------------------------------------------------

/// Wrapper for the state proof verification context data in catchpoint files.
/// Corresponds to Go's `catchpointStateProofVerificationContext`.
///
/// The `stateProofVerificationContext.msgpack` tar entry contains this wrapper,
/// which holds an array of individual verification contexts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatchpointStateProofVerificationWrapper {
    /// Array of state proof verification contexts.
    #[serde(rename = "spd", default)]
    pub data: Vec<StateProofVerificationContext>,
}

/// A single state proof verification context.
/// Corresponds to Go's `ledgercore.StateProofVerificationContext`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateProofVerificationContext {
    /// Last attested round for this state proof verification context.
    #[serde(rename = "spround", default)]
    pub last_attested_round: u64,

    /// Voters commitment (vector commitment root).
    #[serde(rename = "vc", default)]
    pub voters_commitment: ByteBuf,

    /// Online total weight (total stake attesting).
    #[serde(rename = "pw", default)]
    pub online_total_weight: u64,

    /// Version field for the verification context.
    /// Go codec tag: `"v"`. Must be preserved during decode/re-encode to
    /// avoid corrupting the state proof verification hash.
    #[serde(rename = "v", default, skip_serializing_if = "String::is_empty")]
    pub version: String,
}

/// Decoded form of Go's `OnlineRoundParamsData` from `ledgercore/totals.go`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CatchpointOnlineRoundParamsData {
    /// Online supply. Codec: "online"
    pub online_supply: u64,
    /// Rewards level. Codec: "rwdlvl"
    pub rewards_level: u64,
    /// Current protocol version string. Codec: "proto"
    pub current_protocol: String,
}

// ---------------------------------------------------------------------------
// ResourceFlags constants — re-exported from `algo_codec::resource_flags`
// ---------------------------------------------------------------------------
//
// PLAN-189 / TASK-190 consolidated these to a single source of truth in
// `algo_codec::canonical::resource_flags` (which mirrors go-algorand's
// `trackerdb.ResourceFlags` enum at
// `../go-algorand/ledger/store/trackerdb/data.go:62-75`). The aliases
// below keep existing call sites working without churn.

/// Resource contains holding data. Re-export of
/// [`algo_codec::resource_flags::HOLDING`].
pub const RESOURCE_FLAGS_HOLDING: u8 = algo_codec::resource_flags::HOLDING;
/// Resource is completely empty (should not be persisted). Re-export
/// of [`algo_codec::resource_flags::NOT_HOLDING`].
pub const RESOURCE_FLAGS_NOT_HOLDING: u8 = algo_codec::resource_flags::NOT_HOLDING;
/// Resource contains asset/app params (ownership). Re-export of
/// [`algo_codec::resource_flags::OWNERSHIP`].
pub const RESOURCE_FLAGS_OWNERSHIP: u8 = algo_codec::resource_flags::OWNERSHIP;
/// Empty asset resource marker. Re-export of
/// [`algo_codec::resource_flags::EMPTY_ASSET`].
pub const RESOURCE_FLAGS_EMPTY_ASSET: u8 = algo_codec::resource_flags::EMPTY_ASSET;
/// Empty app resource marker. Re-export of
/// [`algo_codec::resource_flags::EMPTY_APP`].
pub const RESOURCE_FLAGS_EMPTY_APP: u8 = algo_codec::resource_flags::EMPTY_APP;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_constants_are_correct() {
        // Go uses octal literals: 0200, 0201, 0202, 0203
        assert_eq!(CATCHPOINT_FILE_VERSION_V5, 128);
        assert_eq!(CATCHPOINT_FILE_VERSION_V6, 129);
        assert_eq!(CATCHPOINT_FILE_VERSION_V7, 130);
        assert_eq!(CATCHPOINT_FILE_VERSION_V8, 131);
    }

    #[test]
    fn catchpoint_file_header_default() {
        let header = CatchpointFileHeader::default();
        assert_eq!(header.version, 0);
        assert_eq!(header.balances_round, 0);
        assert_eq!(header.total_accounts, 0);
        assert!(header.catchpoint.is_empty());
    }

    #[test]
    fn account_totals_default() {
        let totals = AccountTotals::default();
        assert_eq!(totals.online.money, 0);
        assert_eq!(totals.offline.reward_units, 0);
        assert_eq!(totals.rewards_level, 0);
    }

    #[test]
    fn balance_record_v6_default() {
        let record = BalanceRecordV6::default();
        assert!(record.address.is_empty());
        assert!(record.account_data.is_empty());
        assert!(record.resources.is_empty());
        assert!(!record.expecting_more_entries);
    }

    #[test]
    fn chunk_default() {
        let chunk = CatchpointSnapshotChunkV6::default();
        assert!(chunk.balances.is_empty());
        assert!(chunk.kvs.is_empty());
        assert!(chunk.online_accounts.is_empty());
        assert!(chunk.online_round_params.is_empty());
    }

    #[test]
    fn catchpoint_base_account_data_to_account_data() {
        let src = CatchpointBaseAccountData {
            status: 1, // Online
            micro_algos: 1_000_000,
            rewards_base: 100,
            total_asset_params: 3,
            total_assets: 5,
            total_app_params: 2,
            total_app_local_states: 4,
            ..Default::default()
        };
        let dst = AccountData::from(&src);
        assert_eq!(dst.status, algo_types::AccountStatus::Online);
        assert_eq!(dst.micro_algos, 1_000_000);
        assert_eq!(dst.rewards_base, 100);
        assert_eq!(dst.total_created_assets, 3);
        assert_eq!(dst.total_assets_opted_in, 5);
        assert_eq!(dst.total_created_apps, 2);
        assert_eq!(dst.total_apps_opted_in, 4);
    }

    #[test]
    fn error_display() {
        let err = CatchpointError::UnsupportedVersion(999);
        assert!(err.to_string().contains("999"));

        let err = CatchpointError::MissingHeader;
        assert!(err.to_string().contains("content.msgpack"));
    }
}
