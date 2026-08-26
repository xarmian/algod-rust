//! StateDelta types mirroring go-algorand's `ledger/ledgercore` package.
//!
//! These types represent the state changes produced by evaluating a block.
//! Field names use `#[serde(rename = "...")]` to match Go's canonical encoding.

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use algo_types::{Address, BlockHeader, Digest, Round, StateSchema};

// ---------------------------------------------------------------------------
// Helper predicates for skip_serializing_if
// ---------------------------------------------------------------------------

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !v
}

fn is_default_round(v: &Round) -> bool {
    v.0 == 0
}

fn is_default_address(v: &Address) -> bool {
    v.0 == [0u8; 32]
}

// ---------------------------------------------------------------------------
// AlgoCount / AccountTotals  (totals.go)
// ---------------------------------------------------------------------------

/// Represents a count of Algos (money + reward units) for a category of accounts.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AlgoCount {
    /// Total MicroAlgos held by this category.
    #[serde(rename = "mon", default, skip_serializing_if = "is_zero_u64")]
    pub money: u64,

    /// Reward units (used for reward distribution).
    #[serde(rename = "rwd", default, skip_serializing_if = "is_zero_u64")]
    pub reward_units: u64,
}

/// Aggregate totals across all accounts, broken down by status.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AccountTotals {
    /// Totals for online accounts.
    #[serde(rename = "online", default)]
    pub online: AlgoCount,

    /// Totals for offline accounts.
    #[serde(rename = "offline", default)]
    pub offline: AlgoCount,

    /// Totals for non-participating accounts.
    #[serde(rename = "notpart", default)]
    pub not_participating: AlgoCount,

    /// Current rewards level.
    #[serde(rename = "rwdlvl", default, skip_serializing_if = "is_zero_u64")]
    pub rewards_level: u64,
}

// ---------------------------------------------------------------------------
// KvValueDelta
// ---------------------------------------------------------------------------

/// Delta for a single key-value box entry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KvValueDelta {
    /// New value (empty if deleted).
    #[serde(
        rename = "Data",
        default,
        serialize_with = "serialize_kv_bytes",
        deserialize_with = "deserialize_kv_bytes"
    )]
    pub data: Vec<u8>,

    /// Previous value.
    #[serde(
        rename = "OldData",
        default,
        serialize_with = "serialize_kv_bytes",
        deserialize_with = "deserialize_kv_bytes"
    )]
    pub old_data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// KvValueDelta byte-field wire encoding (issue #573)
// ---------------------------------------------------------------------------
//
// Two real conformance bugs were found here while building the live
// `/v2/deltas/{round}` comparison test for this issue, both fixed below:
//
// 1. **Base64 vs number-array.** go-algorand's `ledgercore.KvValueDelta.
//    Data`/`.OldData` are plain `[]byte` with no struct tags at all, so its
//    REST API encodes them through the same generic go-codec (ugorji)
//    handle every other `[]byte` API field uses: base64 for the
//    human-readable JSON handle, raw bytes for the msgpack handle.
//    `#[serde(with = "serde_bytes")]` alone does not reproduce this —
//    serde_json's `Serializer::serialize_bytes` has no native "bytes" type
//    and falls back to a JSON array of numbers (verified empirically: a
//    plain `serde_bytes`-tagged `Vec<u8>` field serialized as
//    `[104,101,108,108,111]` for `b"hello"`, not `"aGVsbG8="`).
//
// 2. **`skip_serializing_if` where go never omits.** Unlike most other types
//    in this file, `KvValueDelta` carries no `_struct \`codec:",omitempty,
//    omitemptyarray"\`` directive on the Go side (contrast
//    `ledgercore.AlgoCount`/`AccountTotals`, which do) — go-codec's
//    `OmitEmpty` defaults to false absent that directive, so a real node's
//    response always includes both `Data` and `OldData` keys, with JSON
//    `null` (msgpack nil) for an unset (nil in Go) value rather than
//    omitting the key. Live-verified: a box-create round's real response is
//    `{"Data":"...","OldData":null}`, not `{"Data":"..."}`. `serialize_kv_
//    bytes` below always emits the field, using `serialize_none()` (JSON
//    `null` / msgpack nil, matching a nil Go `[]byte`) for an empty value.
fn serialize_kv_bytes<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    if bytes.is_empty() {
        return serializer.serialize_none();
    }
    if serializer.is_human_readable() {
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use base64::Engine as _;
        serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
    } else {
        serde_bytes::serialize(bytes, serializer)
    }
}

fn deserialize_kv_bytes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    if deserializer.is_human_readable() {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            None => Ok(Vec::new()),
            Some(s) => {
                use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
                use base64::Engine as _;
                BASE64_STANDARD
                    .decode(s.as_bytes())
                    .map_err(serde::de::Error::custom)
            }
        }
    } else {
        let opt = Option::<serde_bytes::ByteBuf>::deserialize(deserializer)?;
        Ok(opt.map(serde_bytes::ByteBuf::into_vec).unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// KvMods key-type note (issues #570, #573)
// ---------------------------------------------------------------------------
//
// go-algorand's `ledgercore.StateDelta.KvMods` is `map[string][]byte`, where
// the key is the *raw* KV-store key (`"bx:" + big-endian(app_id) + box_name`,
// see `apps.MakeBoxKey`) cast to a Go `string` without any UTF-8 validation —
// box names are arbitrary bytes, not guaranteed valid UTF-8, and neither is
// the embedded big-endian `app_id` (any app id whose byte pattern doesn't
// happen to form valid UTF-8 triggers this, which is the common case, not a
// rare one). Rust's `String` cannot losslessly hold that, so `kv_mods` is
// keyed by `Vec<u8>` internally (matching this crate's own existing
// convention for box keys, e.g. `avm_context.rs`'s
// `available_boxes: HashMap<(u64, Vec<u8>), bool>` and `sqlite.rs`'s
// `make_box_key`) — this is what the round-reconstruction logic in
// `SqliteLedger` uses, and it stays byte-exact for every key.
//
// The wire encoding differs by format, matching go's own codec exactly:
// - **JSON**: go's `encoding/json`-compatible codec cannot emit invalid
//   UTF-8 inside a JSON string and substitutes the Unicode replacement
//   character (U+FFFD) for invalid byte sequences when marshaling a Go
//   string — reproduced here via `String::from_utf8_lossy`.
// - **msgpack**: go's codec writes the raw string bytes verbatim (a
//   msgpack "str" payload has no UTF-8 validity requirement, unlike JSON).
//   Issue #573's live-verification test caught this codepath actually
//   applying `from_utf8_lossy` unconditionally (a #570 bug, not just a
//   theoretical gap for non-UTF-8 *box names*): since the embedded app_id
//   bytes are binary, the lossy conversion corrupted the key for ordinary
//   ASCII box names too, any time the app_id's bytes formed an invalid
//   partial UTF-8 sequence. Fixed by tunneling the raw bytes through an
//   unchecked `&str` for the non-human-readable path — see the `unsafe`
//   block's safety comment below.
fn serialize_kv_mods<S: Serializer>(
    map: &HashMap<Vec<u8>, KvValueDelta>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let human_readable = serializer.is_human_readable();
    let mut m = serializer.serialize_map(Some(map.len()))?;
    for (k, v) in map {
        if human_readable {
            m.serialize_entry(&String::from_utf8_lossy(k), v)?;
        } else {
            // SAFETY: msgpack's "str" format has no UTF-8 validity
            // requirement for its payload (unlike JSON strings), and this
            // branch only runs for non-human-readable formats (msgpack, via
            // `rmp_serde`, the only such format this crate feeds through
            // this function). `serde::Serializer::serialize_str` only
            // accepts `&str`, so we tunnel the raw key bytes through a
            // `&str` that may not be valid UTF-8; `rmp_serde` copies the
            // `&str`'s bytes directly onto the wire without revalidating
            // them, so this reproduces go's exact msgpack output — the
            // `str` type here never has its characters inspected, only its
            // raw byte buffer written out.
            let raw = unsafe { std::str::from_utf8_unchecked(k) };
            m.serialize_entry(raw, v)?;
        }
    }
    m.end()
}

fn deserialize_kv_mods<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<HashMap<Vec<u8>, KvValueDelta>, D::Error> {
    if deserializer.is_human_readable() {
        let m: HashMap<String, KvValueDelta> = HashMap::deserialize(deserializer)?;
        Ok(m.into_iter().map(|(k, v)| (k.into_bytes(), v)).collect())
    } else {
        struct RawKeyMapVisitor;
        impl<'de> serde::de::Visitor<'de> for RawKeyMapVisitor {
            type Value = HashMap<Vec<u8>, KvValueDelta>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a map of raw byte keys to KvValueDelta")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut out = HashMap::with_capacity(map.size_hint().unwrap_or(0));
                while let Some((k, v)) = map.next_entry::<serde_bytes::ByteBuf, KvValueDelta>()? {
                    out.insert(k.into_vec(), v);
                }
                Ok(out)
            }
        }
        deserializer.deserialize_map(RawKeyMapVisitor)
    }
}

// ---------------------------------------------------------------------------
// IncludedTransactions
// ---------------------------------------------------------------------------

/// Metadata for a transaction included in a block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncludedTransactions {
    /// Last valid round for the transaction.
    #[serde(
        rename = "LastValid",
        default,
        skip_serializing_if = "is_default_round"
    )]
    pub last_valid: Round,

    /// Intra-block index.
    #[serde(rename = "Intra", default, skip_serializing_if = "is_zero_u64")]
    pub intra: u64,
}

// ---------------------------------------------------------------------------
// ModifiedCreatable
// ---------------------------------------------------------------------------

/// Tracks creation/deletion of an asset or application.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModifiedCreatable {
    /// Creatable type: 0 = asset, 1 = app.
    #[serde(rename = "Ctype", default, skip_serializing_if = "is_zero_u64")]
    pub ctype: u64,

    /// Whether this creatable was created (true) or deleted (false).
    #[serde(rename = "Created", default, skip_serializing_if = "is_false")]
    pub created: bool,

    /// Creator address.
    #[serde(
        rename = "Creator",
        default,
        skip_serializing_if = "is_default_address"
    )]
    pub creator: Address,

    /// Number of deltas referencing this creatable.
    #[serde(rename = "Ndeltas", default, skip_serializing_if = "is_zero_i64")]
    pub ndeltas: i64,
}

// ---------------------------------------------------------------------------
// Txlease
// ---------------------------------------------------------------------------

/// Transaction lease key (sender + lease hash).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Txlease {
    /// Sender address.
    #[serde(rename = "Sender")]
    pub sender: Address,

    /// 32-byte lease value.
    #[serde(rename = "Lease", with = "serde_bytes")]
    pub lease: [u8; 32],
}

// ---------------------------------------------------------------------------
// VotingData
// ---------------------------------------------------------------------------

/// Voting-related fields from basics.VotingData.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VotingData {
    /// VoteID (one-time-signature verifier).
    #[serde(rename = "VoteID", default, skip_serializing_if = "is_zero_bytes_32")]
    #[serde(with = "serde_bytes")]
    pub vote_id: [u8; 32],

    /// Selection public key.
    #[serde(
        rename = "SelectionID",
        default,
        skip_serializing_if = "is_zero_bytes_32"
    )]
    #[serde(with = "serde_bytes")]
    pub selection_id: [u8; 32],

    /// State proof public key (64 bytes).
    #[serde(
        rename = "StateProofID",
        default = "default_64_bytes",
        skip_serializing_if = "is_zero_bytes_64"
    )]
    #[serde(with = "serde_bytes")]
    pub state_proof_id: [u8; 64],

    /// First round votes are valid.
    #[serde(
        rename = "VoteFirstValid",
        default,
        skip_serializing_if = "is_default_round"
    )]
    pub vote_first_valid: Round,

    /// Last round votes are valid.
    #[serde(
        rename = "VoteLastValid",
        default,
        skip_serializing_if = "is_default_round"
    )]
    pub vote_last_valid: Round,

    /// Key dilution for key registration.
    #[serde(
        rename = "VoteKeyDilution",
        default,
        skip_serializing_if = "is_zero_u64"
    )]
    pub vote_key_dilution: u64,
}

impl Default for VotingData {
    fn default() -> Self {
        VotingData {
            vote_id: [0u8; 32],
            selection_id: [0u8; 32],
            state_proof_id: [0u8; 64],
            vote_first_valid: Round(0),
            vote_last_valid: Round(0),
            vote_key_dilution: 0,
        }
    }
}

fn default_64_bytes() -> [u8; 64] {
    [0u8; 64]
}

fn is_zero_bytes_32(v: &[u8; 32]) -> bool {
    *v == [0u8; 32]
}

fn is_zero_bytes_64(v: &[u8; 64]) -> bool {
    *v == [0u8; 64]
}

// ---------------------------------------------------------------------------
// AccountBaseData (ledgercore/accountdata.go)
// ---------------------------------------------------------------------------

/// Core account data fields (ledgercore.AccountBaseData).
///
/// This is the ledgercore version, NOT basics.AccountData — it omits the
/// per-resource maps and tracks aggregate counts instead.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AccountBaseData {
    /// Account status (0=Offline, 1=Online, 2=NotParticipating).
    #[serde(rename = "Status", default, skip_serializing_if = "is_zero_u64")]
    pub status: u64,

    /// Account balance in MicroAlgos.
    #[serde(rename = "MicroAlgos", default, skip_serializing_if = "is_zero_u64")]
    pub micro_algos: u64,

    /// Rewards base for computing pending rewards.
    #[serde(rename = "RewardsBase", default, skip_serializing_if = "is_zero_u64")]
    pub rewards_base: u64,

    /// Total rewards earned (MicroAlgos).
    #[serde(
        rename = "RewardedMicroAlgos",
        default,
        skip_serializing_if = "is_zero_u64"
    )]
    pub rewarded_micro_algos: u64,

    /// Spending key (authorized address).
    #[serde(
        rename = "AuthAddr",
        default,
        skip_serializing_if = "is_default_address"
    )]
    pub auth_addr: Address,

    /// Whether the account is eligible for block incentives (v40+).
    #[serde(
        rename = "IncentiveEligible",
        default,
        skip_serializing_if = "is_false"
    )]
    pub incentive_eligible: bool,

    /// Aggregate of all application schemas for min-balance calculation.
    #[serde(rename = "TotalAppSchema", default)]
    pub total_app_schema: StateSchema,

    /// Total extra app pages.
    #[serde(
        rename = "TotalExtraAppPages",
        default,
        skip_serializing_if = "is_zero_u32"
    )]
    pub total_extra_app_pages: u32,

    /// Total number of created applications.
    #[serde(
        rename = "TotalAppParams",
        default,
        skip_serializing_if = "is_zero_u64"
    )]
    pub total_app_params: u64,

    /// Total number of opted-in app local states.
    #[serde(
        rename = "TotalAppLocalStates",
        default,
        skip_serializing_if = "is_zero_u64"
    )]
    pub total_app_local_states: u64,

    /// Total number of created asset params.
    #[serde(
        rename = "TotalAssetParams",
        default,
        skip_serializing_if = "is_zero_u64"
    )]
    pub total_asset_params: u64,

    /// Total number of opted-in assets.
    #[serde(rename = "TotalAssets", default, skip_serializing_if = "is_zero_u64")]
    pub total_assets: u64,

    /// Total number of boxes.
    #[serde(rename = "TotalBoxes", default, skip_serializing_if = "is_zero_u64")]
    pub total_boxes: u64,

    /// Total byte size of all boxes.
    #[serde(rename = "TotalBoxBytes", default, skip_serializing_if = "is_zero_u64")]
    pub total_box_bytes: u64,

    /// Last round this account proposed a block.
    #[serde(
        rename = "LastProposed",
        default,
        skip_serializing_if = "is_default_round"
    )]
    pub last_proposed: Round,

    /// Last heartbeat round.
    #[serde(
        rename = "LastHeartbeat",
        default,
        skip_serializing_if = "is_default_round"
    )]
    pub last_heartbeat: Round,
}

// ---------------------------------------------------------------------------
// LedgercoreAccountData (ledgercore/accountdata.go)
// ---------------------------------------------------------------------------

/// Ledgercore's AccountData = AccountBaseData + VotingData.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LedgercoreAccountData {
    /// Base account data.
    #[serde(flatten)]
    pub base: AccountBaseData,

    /// Voting-related data.
    #[serde(flatten)]
    pub voting: VotingData,
}

// ---------------------------------------------------------------------------
// BalanceRecord
// ---------------------------------------------------------------------------

/// A balance record pairing an address with its account data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BalanceRecord {
    /// Account address.
    #[serde(rename = "Addr")]
    pub addr: Address,

    /// Account data (embedded / flattened in Go).
    #[serde(flatten)]
    pub account_data: LedgercoreAccountData,
}

// ---------------------------------------------------------------------------
// Delta types for app/asset resources
// ---------------------------------------------------------------------------

/// Delta for asset holdings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AssetHoldingDelta {
    /// Updated holding (None if not changed or deleted).
    #[serde(rename = "Holding", default, skip_serializing_if = "Option::is_none")]
    pub holding: Option<AssetHoldingRecord>,

    /// Whether the holding was deleted.
    #[serde(rename = "Deleted", default, skip_serializing_if = "is_false")]
    pub deleted: bool,
}

/// Asset holding record matching Go's basics.AssetHolding serialization.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AssetHoldingRecord {
    /// Amount of the asset held.
    #[serde(rename = "Amount", default, skip_serializing_if = "is_zero_u64")]
    pub amount: u64,

    /// Whether the asset is frozen.
    #[serde(rename = "Frozen", default, skip_serializing_if = "is_false")]
    pub frozen: bool,
}

/// Delta for asset parameters.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AssetParamsDelta {
    /// Updated asset params (None if not changed or deleted).
    #[serde(rename = "Params", default, skip_serializing_if = "Option::is_none")]
    pub params: Option<AssetParamsRecord>,

    /// Whether the asset was deleted.
    #[serde(rename = "Deleted", default, skip_serializing_if = "is_false")]
    pub deleted: bool,
}

/// Asset params record for state delta serialization.
///
/// Uses Go field names for the canonical encoding. We define a separate type
/// here instead of reusing `algo_types::AssetParams` (which uses short msgpack
/// tags like `"t"`, `"dc"` etc.) because go-algorand's ledgercore path
/// serializes asset params with full Go field names.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AssetParamsRecord {
    #[serde(rename = "Total", default, skip_serializing_if = "is_zero_u64")]
    pub total: u64,
    #[serde(rename = "Decimals", default, skip_serializing_if = "is_zero_u32")]
    pub decimals: u32,
    #[serde(rename = "DefaultFrozen", default, skip_serializing_if = "is_false")]
    pub default_frozen: bool,
    #[serde(rename = "UnitName", default, skip_serializing_if = "String::is_empty")]
    pub unit_name: String,
    #[serde(
        rename = "AssetName",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub asset_name: String,
    #[serde(rename = "URL", default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    #[serde(
        rename = "MetadataHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub metadata_hash: Option<[u8; 32]>,
    #[serde(
        rename = "Manager",
        default,
        skip_serializing_if = "is_default_address"
    )]
    pub manager: Address,
    #[serde(
        rename = "Reserve",
        default,
        skip_serializing_if = "is_default_address"
    )]
    pub reserve: Address,
    #[serde(rename = "Freeze", default, skip_serializing_if = "is_default_address")]
    pub freeze: Address,
    #[serde(
        rename = "Clawback",
        default,
        skip_serializing_if = "is_default_address"
    )]
    pub clawback: Address,
}

/// Delta for application local state.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AppLocalStateDelta {
    /// Updated local state (None if not changed or deleted).
    #[serde(
        rename = "LocalState",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub local_state: Option<AppLocalStateRecord>,

    /// Whether the local state was deleted.
    #[serde(rename = "Deleted", default, skip_serializing_if = "is_false")]
    pub deleted: bool,
}

/// Application local state for state delta serialization.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AppLocalStateRecord {
    #[serde(rename = "Schema", default)]
    pub schema: StateSchema,
    #[serde(rename = "KeyValue", default, skip_serializing_if = "Option::is_none")]
    pub key_value: Option<HashMap<String, TealValueRecord>>,
}

/// TEAL value for state delta serialization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TealValueRecord {
    /// Type: 1 = bytes, 2 = uint.
    #[serde(rename = "Type", default, skip_serializing_if = "is_zero_u64")]
    pub value_type: u64,
    /// Bytes value.
    #[serde(rename = "Bytes", default, skip_serializing_if = "String::is_empty")]
    pub bytes: String,
    /// Uint value.
    #[serde(rename = "Uint", default, skip_serializing_if = "is_zero_u64")]
    pub uint: u64,
}

/// Delta for application parameters.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AppParamsDelta {
    /// Updated app params (None if not changed or deleted).
    #[serde(rename = "Params", default, skip_serializing_if = "Option::is_none")]
    pub params: Option<AppParamsRecord>,

    /// Whether the app was deleted.
    #[serde(rename = "Deleted", default, skip_serializing_if = "is_false")]
    pub deleted: bool,
}

/// Application parameters for state delta serialization.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AppParamsRecord {
    #[serde(
        rename = "ApprovalProgram",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    #[serde(with = "serde_bytes")]
    pub approval_program: Vec<u8>,
    #[serde(
        rename = "ClearStateProgram",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    #[serde(with = "serde_bytes")]
    pub clear_state_program: Vec<u8>,
    #[serde(
        rename = "GlobalState",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub global_state: Option<HashMap<String, TealValueRecord>>,
    #[serde(rename = "LocalStateSchema", default)]
    pub local_state_schema: StateSchema,
    #[serde(rename = "GlobalStateSchema", default)]
    pub global_state_schema: StateSchema,
    #[serde(
        rename = "ExtraProgramPages",
        default,
        skip_serializing_if = "is_zero_u32"
    )]
    pub extra_program_pages: u32,
}

// ---------------------------------------------------------------------------
// Resource records
// ---------------------------------------------------------------------------

/// Application resource record in an AccountDeltas.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppResourceRecord {
    /// Application index.
    #[serde(rename = "Aidx")]
    pub aidx: u64,

    /// Account address.
    #[serde(rename = "Addr")]
    pub addr: Address,

    /// App params delta.
    #[serde(rename = "Params", default)]
    pub params: AppParamsDelta,

    /// App local state delta.
    #[serde(rename = "State", default)]
    pub state: AppLocalStateDelta,
}

/// Asset resource record in an AccountDeltas.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetResourceRecord {
    /// Asset index.
    #[serde(rename = "Aidx")]
    pub aidx: u64,

    /// Account address.
    #[serde(rename = "Addr")]
    pub addr: Address,

    /// Asset params delta.
    #[serde(rename = "Params", default)]
    pub params: AssetParamsDelta,

    /// Asset holding delta.
    #[serde(rename = "Holding", default)]
    pub holding: AssetHoldingDelta,
}

// ---------------------------------------------------------------------------
// AccountDeltas
// ---------------------------------------------------------------------------

/// Collection of account changes from evaluating a block.
///
/// Private cache fields from Go are omitted.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AccountDeltas {
    /// Balance records (address + account data).
    #[serde(rename = "Accts", default, skip_serializing_if = "Vec::is_empty")]
    pub accts: Vec<BalanceRecord>,

    /// Application resource changes.
    #[serde(
        rename = "AppResources",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub app_resources: Vec<AppResourceRecord>,

    /// Asset resource changes.
    #[serde(
        rename = "AssetResources",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub asset_resources: Vec<AssetResourceRecord>,
}

// ---------------------------------------------------------------------------
// StateDelta
// ---------------------------------------------------------------------------

/// The complete set of state changes produced by evaluating a block.
///
/// This mirrors go-algorand's `ledgercore.StateDelta`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StateDelta {
    /// Account deltas (balance + resource changes).
    #[serde(rename = "Accts", default)]
    pub accts: AccountDeltas,

    /// Key-value (box) modifications, keyed by the raw KV-store key bytes
    /// (`"bx:" + big-endian(app_id) + box_name`). See the key-type note
    /// above [`KvValueDelta`] (issue #570) for why this is `Vec<u8>`
    /// internally but renders as a (possibly lossy) string on the wire.
    #[serde(
        rename = "KvMods",
        default,
        skip_serializing_if = "HashMap::is_empty",
        serialize_with = "serialize_kv_mods",
        deserialize_with = "deserialize_kv_mods"
    )]
    pub kv_mods: HashMap<Vec<u8>, KvValueDelta>,

    /// Transaction IDs included in the block.
    #[serde(rename = "Txids", default, skip_serializing_if = "HashMap::is_empty")]
    pub txids: HashMap<Digest, IncludedTransactions>,

    /// Transaction leases. Represented as a Vec of pairs since `Txlease`
    /// (a struct) cannot be used as a JSON map key. Go-algorand nils this
    /// field in JSON anyway. For msgpack we use a list of (key, value) pairs.
    ///
    /// TODO: go-algorand's codec encodes this as a msgpack map, not an array
    /// of pairs. A custom serde implementation may be needed for byte-level
    /// msgpack conformance.
    #[serde(rename = "Txleases", default, skip_serializing_if = "Option::is_none")]
    pub txleases: Option<Vec<(Txlease, Round)>>,

    /// Created/deleted assets and applications.
    #[serde(
        rename = "Creatables",
        default,
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub creatables: HashMap<u64, ModifiedCreatable>,

    /// Block header (None when not set).
    #[serde(rename = "Hdr", default, skip_serializing_if = "Option::is_none")]
    pub hdr: Option<BlockHeader>,

    /// Next expected state proof round.
    #[serde(
        rename = "StateProofNext",
        default,
        skip_serializing_if = "is_default_round"
    )]
    pub state_proof_next: Round,

    /// Previous block timestamp.
    #[serde(rename = "PrevTimestamp", default, skip_serializing_if = "is_zero_i64")]
    pub prev_timestamp: i64,

    /// Aggregate account totals after applying this block.
    #[serde(rename = "Totals", default)]
    pub totals: AccountTotals,
}

// ---------------------------------------------------------------------------
// StateDeltaSubset
// ---------------------------------------------------------------------------

/// A sparse subset of [`StateDelta`]'s fields, scoped to a single transaction
/// group rather than a whole round.
///
/// Mirrors go-algorand's `ledger/eval.StateDeltaSubset`
/// (`ledger/eval/txntracer.go`), which the reference node uses for its
/// `GET /v2/deltas/txn/group/{id}` and `GET /v2/deltas/{round}/txn/group`
/// responses. It deliberately omits [`StateDelta`]'s round-only fields —
/// `StateProofNext`, `PrevTimestamp`, and `Totals` — which are meaningless
/// for a single group and which go-algorand's `StateDeltaSubset` type does
/// not declare at all, so they never appear in its wire encoding. Using the
/// full [`StateDelta`] for these two endpoints would instead always emit a
/// `Totals` key (its sub-fields have no `skip_serializing_if`), a byte-level
/// conformance mismatch — see issue #191.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StateDeltaSubset {
    /// Account deltas (balance + resource changes).
    #[serde(rename = "Accts", default)]
    pub accts: AccountDeltas,

    /// Key-value (box) modifications, keyed by the raw KV-store key bytes.
    /// See the key-type note above [`KvValueDelta`] (issue #570).
    #[serde(
        rename = "KvMods",
        default,
        skip_serializing_if = "HashMap::is_empty",
        serialize_with = "serialize_kv_mods",
        deserialize_with = "deserialize_kv_mods"
    )]
    pub kv_mods: HashMap<Vec<u8>, KvValueDelta>,

    /// Transaction IDs included in the group.
    #[serde(rename = "Txids", default, skip_serializing_if = "HashMap::is_empty")]
    pub txids: HashMap<Digest, IncludedTransactions>,

    /// Transaction leases. See [`StateDelta::txleases`] for representation
    /// notes.
    #[serde(rename = "Txleases", default, skip_serializing_if = "Option::is_none")]
    pub txleases: Option<Vec<(Txlease, Round)>>,

    /// Created/deleted assets and applications.
    #[serde(
        rename = "Creatables",
        default,
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub creatables: HashMap<u64, ModifiedCreatable>,

    /// Block header (None when not set).
    #[serde(rename = "Hdr", default, skip_serializing_if = "Option::is_none")]
    pub hdr: Option<BlockHeader>,
}

impl From<StateDelta> for StateDeltaSubset {
    /// Extract the group-scoped subset, dropping `StateProofNext`,
    /// `PrevTimestamp`, and `Totals` — mirrors go's `convertStateDelta`
    /// (`ledger/eval/txntracer.go`).
    fn from(delta: StateDelta) -> Self {
        StateDeltaSubset {
            accts: delta.accts,
            kv_mods: delta.kv_mods,
            txids: delta.txids,
            txleases: delta.txleases,
            creatables: delta.creatables,
            hdr: delta.hdr,
        }
    }
}

#[cfg(test)]
mod state_delta_subset_tests {
    use super::*;

    /// go-algorand's `StateDeltaSubset` has no `Totals`/`StateProofNext`/
    /// `PrevTimestamp` fields at all, so its JSON encoding never contains
    /// those keys — regardless of what the source round's full `StateDelta`
    /// carried. Issue #191.
    #[test]
    fn json_encoding_omits_round_scoped_fields_even_when_source_delta_has_them() {
        let full = StateDelta {
            state_proof_next: Round(42),
            prev_timestamp: 1_700_000_000,
            totals: AccountTotals {
                online: AlgoCount {
                    money: 5_000_000,
                    reward_units: 10,
                },
                ..Default::default()
            },
            accts: AccountDeltas {
                accts: vec![BalanceRecord {
                    addr: Address([0xAA; 32]),
                    account_data: LedgercoreAccountData::default(),
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        let subset: StateDeltaSubset = full.into();
        let json = serde_json::to_value(&subset).expect("subset must serialize");
        let obj = json.as_object().expect("subset encodes as a JSON object");

        assert!(
            !obj.contains_key("Totals"),
            "StateDeltaSubset must never emit a Totals key (go-algorand's \
             type has no such field): {obj:?}"
        );
        assert!(
            !obj.contains_key("StateProofNext"),
            "StateDeltaSubset must never emit a StateProofNext key: {obj:?}"
        );
        assert!(
            !obj.contains_key("PrevTimestamp"),
            "StateDeltaSubset must never emit a PrevTimestamp key: {obj:?}"
        );
        // Fields StateDeltaSubset does carry must still round-trip.
        assert!(
            obj.contains_key("Accts"),
            "Accts must still be present: {obj:?}"
        );
    }
}

#[cfg(test)]
mod kv_value_delta_wire_format_tests {
    use super::*;

    /// Issue #573: go-algorand's `ledgercore.KvValueDelta.Data`/`.OldData`
    /// are untagged `[]byte`, which its REST API's JSON codec handle
    /// base64-encodes (the same convention every other `[]byte` API field
    /// uses) — not a JSON array of byte values. Pins the fix for the
    /// mismatch discovered while building the live `/v2/deltas/{round}`
    /// comparison test: a plain `#[serde(with = "serde_bytes")]` field
    /// serializes as `[104,101,...]` under `serde_json`, not
    /// `"aGVsbG8h"`, because `serde_json::Serializer::serialize_bytes` has
    /// no native byte-string form and falls back to a JSON array.
    #[test]
    fn json_encodes_data_and_old_data_as_base64_strings() {
        let kv = KvValueDelta {
            data: b"hello!".to_vec(),
            old_data: b"bye".to_vec(),
        };
        let json = serde_json::to_value(&kv).expect("must serialize");
        assert_eq!(
            json["Data"],
            serde_json::Value::String("aGVsbG8h".to_string()),
            "Data must be base64-encoded like go's real JSON output: {json}"
        );
        assert_eq!(
            json["OldData"],
            serde_json::Value::String("Ynll".to_string()),
            "OldData must be base64-encoded like go's real JSON output: {json}"
        );
    }

    /// The msgpack wire form is unaffected by the JSON fix above: go's
    /// msgpack codec handle writes `[]byte` fields as raw msgpack bin
    /// bytes, not base64, so algod-rust's msgpack output must too.
    #[test]
    fn msgpack_encodes_data_and_old_data_as_raw_bytes() {
        let kv = KvValueDelta {
            data: b"hello!".to_vec(),
            old_data: vec![],
        };
        let bytes = rmp_serde::to_vec_named(&kv).expect("must serialize to msgpack");
        let decoded: rmpv::Value = rmpv::decode::read_value(&mut &bytes[..])
            .expect("must decode as an rmpv value for structural inspection");
        let map = decoded.as_map().expect("KvValueDelta encodes as a map");
        let data_val = map
            .iter()
            .find(|(k, _)| k.as_str() == Some("Data"))
            .map(|(_, v)| v)
            .expect("map must contain a Data entry");
        assert_eq!(
            data_val.as_slice(),
            Some(b"hello!".as_slice()),
            "Data must round-trip as raw msgpack bytes, not base64: {data_val:?}"
        );

        // Round-trips back through the typed deserializer too.
        let round_tripped: KvValueDelta =
            rmp_serde::from_slice(&bytes).expect("must deserialize back");
        assert_eq!(round_tripped, kv);
    }

    /// The base64 JSON encoding round-trips back into the original bytes
    /// through `deserialize_kv_bytes`.
    #[test]
    fn json_round_trips_through_base64() {
        let kv = KvValueDelta {
            data: b"box-value-with-\x00\xffbytes".to_vec(),
            old_data: vec![],
        };
        let json = serde_json::to_string(&kv).expect("serialize");
        let round_tripped: KvValueDelta = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round_tripped, kv);
    }

    /// Issue #573 (live-verified against a real go-algorand v4.7.0-stable
    /// node): unlike most types in this file, `KvValueDelta` carries no
    /// `_struct \`codec:",omitempty,omitemptyarray"\`` directive on the Go
    /// side, so a real node's JSON response always includes both `Data` and
    /// `OldData`, using `null` for an unset (nil in Go) value rather than
    /// omitting the key. A box-create round's real response looks like
    /// `{"Data":"...","OldData":null}`.
    #[test]
    fn json_never_omits_data_or_old_data_uses_null_when_empty() {
        let kv = KvValueDelta {
            data: b"created".to_vec(),
            old_data: vec![],
        };
        let json = serde_json::to_value(&kv).expect("must serialize");
        let obj = json.as_object().expect("KvValueDelta encodes as an object");
        assert!(
            obj.contains_key("Data"),
            "Data key must always be present: {obj:?}"
        );
        assert!(
            obj.contains_key("OldData"),
            "OldData key must always be present (never omitted), matching go's \
             no-omitempty KvValueDelta: {obj:?}"
        );
        assert_eq!(
            obj["OldData"],
            serde_json::Value::Null,
            "an empty/unset value must serialize as JSON null, not an empty \
             string or an omitted key: {obj:?}"
        );

        let round_tripped: KvValueDelta = serde_json::from_value(json).expect("deserialize");
        assert_eq!(round_tripped, kv);
    }

    /// Issue #573 (live-verified): the msgpack encoding must likewise
    /// always include both keys, with msgpack nil (not an empty bin/str)
    /// for an unset value.
    #[test]
    fn msgpack_never_omits_data_or_old_data_uses_nil_when_empty() {
        let kv = KvValueDelta {
            data: b"created".to_vec(),
            old_data: vec![],
        };
        let bytes = rmp_serde::to_vec_named(&kv).expect("serialize");
        let decoded: rmpv::Value =
            rmpv::decode::read_value(&mut &bytes[..]).expect("decode as rmpv");
        let map = decoded.as_map().expect("KvValueDelta encodes as a map");
        let old_data = map
            .iter()
            .find(|(k, _)| k.as_str() == Some("OldData"))
            .map(|(_, v)| v.clone())
            .expect("OldData entry must always be present, not omitted");
        assert!(
            old_data.is_nil(),
            "an empty/unset value must serialize as msgpack nil: {old_data:?}"
        );

        let round_tripped: KvValueDelta = rmp_serde::from_slice(&bytes).expect("deserialize");
        assert_eq!(round_tripped, kv);
    }

    /// Issue #573 (live-verified): `serialize_kv_mods`'s msgpack path must
    /// write the *raw* key bytes, not the same `from_utf8_lossy` conversion
    /// JSON uses. Regression for a real bug caught by the live comparison
    /// test: an app id whose big-endian bytes happen to form an invalid
    /// partial UTF-8 sequence (common, not rare -- e.g. app id 1007 =
    /// `0x03EF`, where the trailing `0xEF` byte starts a 3-byte UTF-8
    /// sequence with no valid continuation bytes after it) got silently
    /// mangled into the 3-byte U+FFFD replacement character even though
    /// msgpack itself has no UTF-8 validity requirement for "str" payloads.
    #[test]
    fn msgpack_kv_mods_key_is_raw_bytes_not_lossy_utf8() {
        let mut key = Vec::new();
        key.extend_from_slice(b"bx:");
        key.extend_from_slice(&1007u64.to_be_bytes()); // trailing 0xEF byte
        key.extend_from_slice(b"svc-box");
        assert!(
            String::from_utf8(key.clone()).is_err(),
            "fixture key must actually be invalid UTF-8 for this regression to mean anything"
        );

        let mut kv_mods = HashMap::new();
        kv_mods.insert(
            key.clone(),
            KvValueDelta {
                data: b"v".to_vec(),
                old_data: vec![],
            },
        );
        let delta = StateDelta {
            kv_mods,
            ..Default::default()
        };

        let bytes = rmp_serde::to_vec_named(&delta).expect("serialize");
        let decoded: rmpv::Value =
            rmpv::decode::read_value(&mut &bytes[..]).expect("decode as rmpv");
        let kv_mods_val = decoded
            .as_map()
            .and_then(|m| m.iter().find(|(k, _)| k.as_str() == Some("KvMods")))
            .map(|(_, v)| v.clone())
            .expect("StateDelta must have a KvMods entry");
        let map = kv_mods_val.as_map().expect("KvMods encodes as a map");
        assert_eq!(map.len(), 1);
        let (wire_key, _) = &map[0];
        // `Value::as_slice()` returns the raw payload bytes for a String
        // value even when it isn't valid UTF-8 (unlike `as_str()`, which
        // returns `None` in that case) -- exactly what this assertion needs.
        let raw_key_bytes = wire_key
            .as_slice()
            .unwrap_or_else(|| panic!("KvMods key must decode as a msgpack str: {wire_key:?}"))
            .to_vec();
        assert_eq!(
            raw_key_bytes, key,
            "msgpack KvMods key must be the exact raw bytes, not a lossy-UTF8 substitution"
        );
    }
}
