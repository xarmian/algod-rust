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

fn is_false(v: &bool) -> bool {
    !v
}

fn is_default_address(v: &Address) -> bool {
    v.0 == [0u8; 32]
}

/// Issue #608 (live-verification found this): go-algorand's
/// `basics.AppLocalState`/`basics.StateSchemas` (the latter embedded into
/// `basics.AppParams`) each declare their own `_struct codec:",omitempty,
/// omitemptyarray"` marker, so a zero-value `StateSchema` field (`hsch` on
/// `AppLocalState`; `lsch`/`gsch` on `AppParams`, via the embedded struct)
/// is omitted from the wire *entirely*, not just serialized as `{}` --
/// unlike the "never omit" container types documented above this helper,
/// which declare no such marker. A real go node's opt-in-round response for
/// an app with no declared local/global schema shows no `"hsch"` key at
/// all; algod-rust previously always emitted `"hsch": {}` (its two
/// subfields already individually omit at zero, but the containing key
/// itself did not).
fn is_default_state_schema(v: &StateSchema) -> bool {
    *v == StateSchema::default()
}

// ---------------------------------------------------------------------------
// Never-omit container helpers (issue #576)
// ---------------------------------------------------------------------------
//
// go-algorand's go-codec (ugorji) `OmitEmpty` defaults to `false`; a Go
// struct only gets field-omission behavior when it declares a `_struct
// struct{} `codec:",omitempty,omitemptyarray"`` marker (see `AlgoCount`/
// `AccountTotals` above, and `basics.AssetHolding`/`AssetParams`/
// `AppLocalState`/`AppParams`/`TealValue`/`StateSchema`, which all declare
// it). Most of the *other* types in this file (`ledgercore.AccountBaseData`,
// `basics.VotingData`, `ledgercore.ModifiedCreatable`, `ledgercore.
// StateDelta` itself, its `AccountDeltas`/resource-delta wrapper types, ...)
// declare no such marker, so a real node's response always includes every
// field -- using JSON `null`/msgpack nil for a nil Go map or slice rather
// than omitting the key. These two helpers reproduce that "always present,
// null when empty" wire form for `HashMap`/`Vec` fields on those types.
fn serialize_map_or_null<K, V, S>(map: &HashMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
where
    K: Serialize + Eq + std::hash::Hash,
    V: Serialize,
    S: Serializer,
{
    if map.is_empty() {
        serializer.serialize_none()
    } else {
        map.serialize(serializer)
    }
}

fn deserialize_map_or_null<'de, K, V, D>(deserializer: D) -> Result<HashMap<K, V>, D::Error>
where
    K: Deserialize<'de> + Eq + std::hash::Hash,
    V: Deserialize<'de>,
    D: Deserializer<'de>,
{
    let opt = Option::<HashMap<K, V>>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

fn serialize_vec_or_null<T, S>(vec: &[T], serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    if vec.is_empty() {
        serializer.serialize_none()
    } else {
        vec.serialize(serializer)
    }
}

fn deserialize_vec_or_null<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    let opt = Option::<Vec<T>>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Fixed-size byte-array wire encoding (issue #576, following #573's
// serialize_kv_bytes precedent)
// ---------------------------------------------------------------------------
//
// go-codec treats a fixed-size `[N]byte` array exactly like `[]byte` for
// encoding purposes (see go-codec's `encode.go`, the `rtelemIsByte`/
// `seqTypeArray` branch) -- base64 for the JSON handle, raw bytes for the
// msgpack handle. Unlike a `[]byte` slice, a Go array is never nil, so
// (unlike `serialize_kv_bytes`) there is no empty/null case to special-case
// here: the actual (possibly all-zero) bytes are always written.
fn serialize_bytes_array<S: Serializer, const N: usize>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use base64::Engine as _;
        serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
    } else {
        serde_bytes::serialize(bytes.as_slice(), serializer)
    }
}

// Deliberately does NOT branch on `deserializer.is_human_readable()` (unlike
// `serialize_bytes_array` above, and unlike `deserialize_kv_bytes` below).
// `VotingData` -- the only user of this function -- is `#[serde(flatten)]`ed
// into `LedgercoreAccountData`, and serde's derive implements `flatten` on
// the *deserialize* side by first buffering the remaining input into a
// generic `serde::__private::de::Content` value, whose `Deserializer` impl
// hard-codes `is_human_readable() == true` regardless of the real wire
// format (a documented serde limitation: flatten does not propagate the
// original format's human-readability). Branching on it here silently
// mis-detected msgpack as JSON and tried to base64-decode raw msgpack bytes,
// breaking every msgpack round-trip through a flattened `VotingData` --
// caught by this file's own `debug_repro_*` bisection while chasing an
// `Invalid symbol 0, offset 0` panic in `algo-rest-api`'s state-delta
// integration tests, one layer removed from anything KvMods/KvValueDelta
// exercises (neither is ever flattened). Using `deserialize_any` instead
// asks "what shape is this value" (a `Content::Bytes`/`Content::Str` case
// preserves the real original kind even though its `is_human_readable()`
// lies), which sidesteps the bug entirely and works unflattened too.
fn deserialize_bytes_array<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    struct BytesArrayVisitor<const N: usize>;

    fn bytes_to_array<E: serde::de::Error, const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], E> {
        let len = bytes.len();
        bytes
            .try_into()
            .map_err(|_| E::custom(format!("expected {N} bytes, got {len}")))
    }

    impl<'de, const N: usize> serde::de::Visitor<'de> for BytesArrayVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "a base64 string or {N} raw bytes")
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
            use base64::Engine as _;
            bytes_to_array(BASE64_STANDARD.decode(v.as_bytes()).map_err(E::custom)?)
        }

        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            bytes_to_array(v.to_vec())
        }

        fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
            bytes_to_array(v)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut out = Vec::with_capacity(N);
            while let Some(b) = seq.next_element::<u8>()? {
                out.push(b);
            }
            bytes_to_array(out)
        }
    }

    deserializer.deserialize_any(BytesArrayVisitor::<N>)
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
    // Issue #576: `ledgercore.StateDelta` carries no `_struct codec:",
    // omitempty,omitemptyarray"` marker, so a nil `KvMods` map (the common
    // case -- untouched until `AddKvMod` is called) must still serialize the
    // "KvMods" key, with JSON `null`/msgpack nil rather than `{}`.
    if map.is_empty() {
        return serializer.serialize_none();
    }
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
        // Issue #576: an empty/untouched KvMods now round-trips through
        // `null` rather than an omitted key or `{}`.
        let m: Option<HashMap<String, KvValueDelta>> = Option::deserialize(deserializer)?;
        Ok(m.unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k.into_bytes(), v))
            .collect())
    } else {
        struct RawKeyMapVisitor;
        impl<'de> serde::de::Visitor<'de> for RawKeyMapVisitor {
            type Value = HashMap<Vec<u8>, KvValueDelta>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a map of raw byte keys to KvValueDelta, or nil")
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

            // Issue #576: an empty/untouched KvMods serializes as msgpack
            // nil, not an empty map -- accept both on the read side.
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(HashMap::new())
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(HashMap::new())
            }
        }
        // `deserialize_any` (rather than `deserialize_map`) lets the wire
        // format pick which `visit_*` method to call, so both a real map and
        // a nil value are handled correctly.
        deserializer.deserialize_any(RawKeyMapVisitor)
    }
}

// ---------------------------------------------------------------------------
// Txids key wire encoding (issue #576)
// ---------------------------------------------------------------------------
//
// go-algorand's `ledgercore.StateDelta.Txids` is `map[transactions.Txid]
// IncludedTransactions`, where `Txid` is `crypto.Digest` ([32]byte) -- unlike
// `KvMods`'s genuinely-`string`-typed keys, this is a *non-string* Go map key
// type. go-codec's `Canonical` map-key path (both `JSONStrictHandle` and
// `CodecHandle` set `Canonical = true`) has no special case for an array-kind
// key, so it falls to the generic "encode the key with the same handle used
// for values" branch (`encode.go`'s `kMapCanonical` default case) -- meaning
// a Txid key gets the exact same encoding a `[32]byte` *value* would: base64
// for the JSON handle, raw bytes as a msgpack "bin" (not "str", since
// `CodecHandle.WriteExt = true`) for the msgpack handle. A plain
// `HashMap<Digest, _>` cannot represent this at all for JSON --
// `serde_json` requires map keys to serialize as strings, and `Digest`
// (a newtype `[u8; 32]`) does not, so populating `Txids` and serializing to
// JSON previously panicked/errored with "key must be a string" the moment a
// round had at least one transaction (i.e. virtually always) -- a
// pre-existing bug this fix also resolves as a prerequisite for exercising
// issue #576's "Txids is never omitted" behavior at all.
fn serialize_txids<S: Serializer>(
    map: &HashMap<Digest, IncludedTransactions>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    if map.is_empty() {
        return serializer.serialize_none();
    }
    let human_readable = serializer.is_human_readable();
    let mut m = serializer.serialize_map(Some(map.len()))?;
    for (k, v) in map {
        if human_readable {
            use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
            use base64::Engine as _;
            m.serialize_key(&BASE64_STANDARD.encode(k.0))?;
        } else {
            m.serialize_key(serde_bytes::Bytes::new(&k.0))?;
        }
        m.serialize_value(v)?;
    }
    m.end()
}

fn deserialize_txids<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<HashMap<Digest, IncludedTransactions>, D::Error> {
    fn digest_from_bytes<E: serde::de::Error>(bytes: Vec<u8>) -> Result<Digest, E> {
        let len = bytes.len();
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| E::custom(format!("expected a 32-byte Txid key, got {len} bytes")))?;
        Ok(Digest(arr))
    }

    if deserializer.is_human_readable() {
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use base64::Engine as _;
        let m: Option<HashMap<String, IncludedTransactions>> = Option::deserialize(deserializer)?;
        m.unwrap_or_default()
            .into_iter()
            .map(|(k, v)| {
                let bytes = BASE64_STANDARD
                    .decode(k.as_bytes())
                    .map_err(serde::de::Error::custom)?;
                Ok((digest_from_bytes(bytes)?, v))
            })
            .collect()
    } else {
        struct TxidKeyMapVisitor;
        impl<'de> serde::de::Visitor<'de> for TxidKeyMapVisitor {
            type Value = HashMap<Digest, IncludedTransactions>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "a map of 32-byte Txid keys to IncludedTransactions, or nil"
                )
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut out = HashMap::with_capacity(map.size_hint().unwrap_or(0));
                while let Some((k, v)) =
                    map.next_entry::<serde_bytes::ByteBuf, IncludedTransactions>()?
                {
                    out.insert(digest_from_bytes(k.into_vec())?, v);
                }
                Ok(out)
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(HashMap::new())
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(HashMap::new())
            }
        }
        deserializer.deserialize_any(TxidKeyMapVisitor)
    }
}

// ---------------------------------------------------------------------------
// IncludedTransactions
// ---------------------------------------------------------------------------

/// Metadata for a transaction included in a block.
///
/// go-algorand's `ledgercore.IncludedTransactions` carries no `_struct
/// codec:",omitempty,omitemptyarray"` marker, so both fields are always
/// present on the wire (issue #576) -- never skipped, even when zero.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncludedTransactions {
    /// Last valid round for the transaction.
    #[serde(rename = "LastValid", default)]
    pub last_valid: Round,

    /// Intra-block index.
    #[serde(rename = "Intra", default)]
    pub intra: u64,
}

// ---------------------------------------------------------------------------
// ModifiedCreatable
// ---------------------------------------------------------------------------

/// Tracks creation/deletion of an asset or application.
///
/// go-algorand's `ledgercore.ModifiedCreatable` carries no `_struct
/// codec:",omitempty,omitemptyarray"` marker, so every field is always
/// present on the wire (issue #576) -- never skipped, even when zero.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModifiedCreatable {
    /// Creatable type: 0 = asset, 1 = app.
    #[serde(rename = "Ctype", default)]
    pub ctype: u64,

    /// Whether this creatable was created (true) or deleted (false).
    #[serde(rename = "Created", default)]
    pub created: bool,

    /// Creator address.
    #[serde(rename = "Creator", default)]
    pub creator: Address,

    /// Number of deltas referencing this creatable.
    #[serde(rename = "Ndeltas", default)]
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
///
/// go-algorand's `basics.VotingData` carries no `_struct codec:",omitempty,
/// omitemptyarray"` marker, so every field is always present on the wire
/// (issue #576) -- never skipped, even when zero. The three byte-array
/// fields additionally need `serialize_bytes_array`/`deserialize_bytes_array`
/// (issue #576, following #573's `serialize_kv_bytes` precedent): go-codec's
/// JSON handle base64-encodes fixed-size `[N]byte` arrays exactly like
/// `[]byte` slices, which a plain `#[serde(with = "serde_bytes")]` field does
/// not reproduce under `serde_json` (falls back to a JSON array of numbers).
/// Unlike `KvValueDelta.Data`/`.OldData`, a Go array is never nil, so there
/// is no empty/null case here -- the actual (possibly all-zero) bytes are
/// always written, never `null`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VotingData {
    /// VoteID (one-time-signature verifier).
    #[serde(
        rename = "VoteID",
        default,
        serialize_with = "serialize_bytes_array",
        deserialize_with = "deserialize_bytes_array"
    )]
    pub vote_id: [u8; 32],

    /// Selection public key.
    #[serde(
        rename = "SelectionID",
        default,
        serialize_with = "serialize_bytes_array",
        deserialize_with = "deserialize_bytes_array"
    )]
    pub selection_id: [u8; 32],

    /// State proof public key (64 bytes).
    #[serde(
        rename = "StateProofID",
        default = "default_64_bytes",
        serialize_with = "serialize_bytes_array",
        deserialize_with = "deserialize_bytes_array"
    )]
    pub state_proof_id: [u8; 64],

    /// First round votes are valid.
    #[serde(rename = "VoteFirstValid", default)]
    pub vote_first_valid: Round,

    /// Last round votes are valid.
    #[serde(rename = "VoteLastValid", default)]
    pub vote_last_valid: Round,

    /// Key dilution for key registration.
    #[serde(rename = "VoteKeyDilution", default)]
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

// ---------------------------------------------------------------------------
// AccountBaseData (ledgercore/accountdata.go)
// ---------------------------------------------------------------------------

/// Core account data fields (ledgercore.AccountBaseData).
///
/// This is the ledgercore version, NOT basics.AccountData — it omits the
/// per-resource maps and tracks aggregate counts instead.
///
/// go-algorand's `ledgercore.AccountBaseData` carries no `_struct
/// codec:",omitempty,omitemptyarray"` marker, so every field is always
/// present on the wire (issue #576) -- never skipped, even when zero.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AccountBaseData {
    /// Account status (0=Offline, 1=Online, 2=NotParticipating).
    #[serde(rename = "Status", default)]
    pub status: u64,

    /// Account balance in MicroAlgos.
    #[serde(rename = "MicroAlgos", default)]
    pub micro_algos: u64,

    /// Rewards base for computing pending rewards.
    #[serde(rename = "RewardsBase", default)]
    pub rewards_base: u64,

    /// Total rewards earned (MicroAlgos).
    #[serde(rename = "RewardedMicroAlgos", default)]
    pub rewarded_micro_algos: u64,

    /// Spending key (authorized address).
    #[serde(rename = "AuthAddr", default)]
    pub auth_addr: Address,

    /// Whether the account is eligible for block incentives (v40+).
    #[serde(rename = "IncentiveEligible", default)]
    pub incentive_eligible: bool,

    /// Aggregate of all application schemas for min-balance calculation.
    #[serde(rename = "TotalAppSchema", default)]
    pub total_app_schema: StateSchema,

    /// Total extra app pages.
    #[serde(rename = "TotalExtraAppPages", default)]
    pub total_extra_app_pages: u32,

    /// Total number of created applications.
    #[serde(rename = "TotalAppParams", default)]
    pub total_app_params: u64,

    /// Total number of opted-in app local states.
    #[serde(rename = "TotalAppLocalStates", default)]
    pub total_app_local_states: u64,

    /// Total number of created asset params.
    #[serde(rename = "TotalAssetParams", default)]
    pub total_asset_params: u64,

    /// Total number of opted-in assets.
    #[serde(rename = "TotalAssets", default)]
    pub total_assets: u64,

    /// Total number of boxes.
    #[serde(rename = "TotalBoxes", default)]
    pub total_boxes: u64,

    /// Total byte size of all boxes.
    #[serde(rename = "TotalBoxBytes", default)]
    pub total_box_bytes: u64,

    /// Last round this account proposed a block.
    #[serde(rename = "LastProposed", default)]
    pub last_proposed: Round,

    /// Last heartbeat round.
    #[serde(rename = "LastHeartbeat", default)]
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
///
/// go-algorand's `ledgercore.AssetHoldingDelta` carries no `_struct
/// codec:",omitempty,omitemptyarray"` marker, so both fields are always
/// present on the wire (issue #576) -- `Holding` as `null` when unset
/// (mirroring Go's nil `*basics.AssetHolding`), `Deleted` even when `false`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AssetHoldingDelta {
    /// Updated holding (None if not changed or deleted).
    #[serde(rename = "Holding", default)]
    pub holding: Option<AssetHoldingRecord>,

    /// Whether the holding was deleted.
    #[serde(rename = "Deleted", default)]
    pub deleted: bool,
}

/// Asset holding record matching Go's basics.AssetHolding serialization.
///
/// `basics.AssetHolding` declares go-codec short tags (`codec:"a"`,
/// `codec:"f"`), and the `/v2/deltas/{round}` handler encodes the real
/// `ledgercore.StateDelta` (and therefore the real `basics.AssetHolding`)
/// directly via `codec.NewEncoderBytes(&output, handle).Encode(obj)` with no
/// intermediate model conversion (`daemon/algod/api/server/v2/handlers.go`'s
/// `GetLedgerStateDelta`/`utils.go`'s `encode`) -- so the wire form uses
/// those short tags, not the full Go field names (issue #579, live-verified
/// against a real go-algorand v4.7.0-stable node's `/v2/deltas/{round}`
/// response).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AssetHoldingRecord {
    /// Amount of the asset held. Go codec tag: `"a"`.
    #[serde(rename = "a", default, skip_serializing_if = "is_zero_u64")]
    pub amount: u64,

    /// Whether the asset is frozen. Go codec tag: `"f"`.
    #[serde(rename = "f", default, skip_serializing_if = "is_false")]
    pub frozen: bool,
}

/// Delta for asset parameters.
///
/// go-algorand's `ledgercore.AssetParamsDelta` carries no `_struct
/// codec:",omitempty,omitemptyarray"` marker, so both fields are always
/// present on the wire (issue #576) -- `Params` as `null` when unset
/// (mirroring Go's nil `*basics.AssetParams`), `Deleted` even when `false`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AssetParamsDelta {
    /// Updated asset params (None if not changed or deleted).
    #[serde(rename = "Params", default)]
    pub params: Option<AssetParamsRecord>,

    /// Whether the asset was deleted.
    #[serde(rename = "Deleted", default)]
    pub deleted: bool,
}

/// Asset params record for state delta serialization.
///
/// We define a separate type here instead of reusing `algo_types::AssetParams`
/// only to keep this module's `*Record` types self-contained; the wire form
/// is identical either way. go-algorand's `ledgercore.AssetParamsDelta.Params`
/// is a `*basics.AssetParams` -- the real type, not a copy with different
/// tags -- and the `/v2/deltas/{round}` handler encodes the real
/// `ledgercore.StateDelta` directly with no intermediate model conversion
/// (`daemon/algod/api/server/v2/handlers.go`'s `GetLedgerStateDelta`), so its
/// wire form uses `basics.AssetParams`'s real go-codec short tags (issue
/// #579, live-verified against a real go-algorand v4.7.0-stable node's
/// `/v2/deltas/{round}` response) -- **not** the full Go field names this
/// type previously hard-coded.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AssetParamsRecord {
    /// Go codec tag: `"t"`.
    #[serde(rename = "t", default, skip_serializing_if = "is_zero_u64")]
    pub total: u64,
    /// Go codec tag: `"dc"`.
    #[serde(rename = "dc", default, skip_serializing_if = "is_zero_u32")]
    pub decimals: u32,
    /// Go codec tag: `"df"`.
    #[serde(rename = "df", default, skip_serializing_if = "is_false")]
    pub default_frozen: bool,
    /// Go codec tag: `"un"`.
    #[serde(rename = "un", default, skip_serializing_if = "String::is_empty")]
    pub unit_name: String,
    /// Go codec tag: `"an"`.
    #[serde(rename = "an", default, skip_serializing_if = "String::is_empty")]
    pub asset_name: String,
    /// Go codec tag: `"au"`.
    #[serde(rename = "au", default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    /// Go codec tag: `"am"`.
    #[serde(rename = "am", default, skip_serializing_if = "Option::is_none")]
    pub metadata_hash: Option<[u8; 32]>,
    /// Go codec tag: `"m"`.
    #[serde(rename = "m", default, skip_serializing_if = "is_default_address")]
    pub manager: Address,
    /// Go codec tag: `"r"`.
    #[serde(rename = "r", default, skip_serializing_if = "is_default_address")]
    pub reserve: Address,
    /// Go codec tag: `"f"`.
    #[serde(rename = "f", default, skip_serializing_if = "is_default_address")]
    pub freeze: Address,
    /// Go codec tag: `"c"`.
    #[serde(rename = "c", default, skip_serializing_if = "is_default_address")]
    pub clawback: Address,
}

/// Delta for application local state.
///
/// go-algorand's `ledgercore.AppLocalStateDelta` carries no `_struct
/// codec:",omitempty,omitemptyarray"` marker, so both fields are always
/// present on the wire (issue #576) -- `LocalState` as `null` when unset
/// (mirroring Go's nil `*basics.AppLocalState`), `Deleted` even when `false`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AppLocalStateDelta {
    /// Updated local state (None if not changed or deleted).
    #[serde(rename = "LocalState", default)]
    pub local_state: Option<AppLocalStateRecord>,

    /// Whether the local state was deleted.
    #[serde(rename = "Deleted", default)]
    pub deleted: bool,
}

/// Application local state for state delta serialization.
///
/// `basics.AppLocalState` declares go-codec short tags (`codec:"hsch"` for
/// `Schema`, `codec:"tkv"` for `KeyValue`), not the full field names (issue
/// #579 -- same bug class as `AssetParamsRecord`/`TealValueRecord`, found by
/// the same audit).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AppLocalStateRecord {
    /// Go codec tag: `"hsch"`. Omitted entirely (not `{}`) when zero --
    /// see `is_default_state_schema`'s doc comment (issue #608).
    #[serde(
        rename = "hsch",
        default,
        skip_serializing_if = "is_default_state_schema"
    )]
    pub schema: StateSchema,
    /// Go codec tag: `"tkv"`.
    #[serde(rename = "tkv", default, skip_serializing_if = "Option::is_none")]
    pub key_value: Option<HashMap<String, TealValueRecord>>,
}

/// TEAL value for state delta serialization.
///
/// `basics.TealValue` declares go-codec short tags (`codec:"tt"`/`"tb"`/
/// `"ui"`), not the full field names (issue #579, live-verified against a
/// real go-algorand v4.7.0-stable node's `/v2/deltas/{round}` response).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TealValueRecord {
    /// Type: 1 = bytes, 2 = uint. Go codec tag: `"tt"`.
    #[serde(rename = "tt", default, skip_serializing_if = "is_zero_u64")]
    pub value_type: u64,
    /// Bytes value. Go codec tag: `"tb"`.
    #[serde(rename = "tb", default, skip_serializing_if = "String::is_empty")]
    pub bytes: String,
    /// Uint value. Go codec tag: `"ui"`.
    #[serde(rename = "ui", default, skip_serializing_if = "is_zero_u64")]
    pub uint: u64,
}

/// Delta for application parameters.
///
/// go-algorand's `ledgercore.AppParamsDelta` carries no `_struct
/// codec:",omitempty,omitemptyarray"` marker, so both fields are always
/// present on the wire (issue #576) -- `Params` as `null` when unset
/// (mirroring Go's nil `*basics.AppParams`), `Deleted` even when `false`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AppParamsDelta {
    /// Updated app params (None if not changed or deleted).
    #[serde(rename = "Params", default)]
    pub params: Option<AppParamsRecord>,

    /// Whether the app was deleted.
    #[serde(rename = "Deleted", default)]
    pub deleted: bool,
}

/// Application parameters for state delta serialization.
///
/// `basics.AppParams` declares go-codec short tags (`codec:"approv"`,
/// `codec:"clearp"`, `codec:"gs"`, `codec:"lsch"`/`"gsch"` via its embedded
/// `StateSchemas`, `codec:"epp"`, `codec:"v"`, `codec:"ss"`), not the full
/// field names (issue #579, live-verified against a real go-algorand
/// v4.7.0-stable node's `/v2/deltas/{round}` response).
///
/// Issue #583: `Version`/`SizeSponsor` are carried here with their correct
/// short tags, but nothing in algod-rust populates them yet with a real
/// value -- `algo_types::AppParams` (the ledger's own app-params type)
/// doesn't track either field at all, and more fundamentally
/// `AccountDeltas::app_resources` (where an `AppParamsRecord` would live)
/// is never populated from real apply-time state in the first place
/// (`TODO(#190)` in `apply.rs`, `Vec::new()` always) -- so this type is
/// not yet constructed anywhere outside its own tests. Both gaps are
/// pre-existing and out of scope here; this fix only closes the
/// wire-format gap so that whichever future work populates
/// `app_resources` (superseding the stale `#190` TODO -- that issue is
/// closed) has a complete, correctly-tagged type to fill in.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AppParamsRecord {
    /// Go codec tag: `"approv"`.
    #[serde(rename = "approv", default, skip_serializing_if = "Vec::is_empty")]
    #[serde(with = "serde_bytes")]
    pub approval_program: Vec<u8>,
    /// Go codec tag: `"clearp"`.
    #[serde(rename = "clearp", default, skip_serializing_if = "Vec::is_empty")]
    #[serde(with = "serde_bytes")]
    pub clear_state_program: Vec<u8>,
    /// Go codec tag: `"gs"`.
    #[serde(rename = "gs", default, skip_serializing_if = "Option::is_none")]
    pub global_state: Option<HashMap<String, TealValueRecord>>,
    /// Go codec tag: `"lsch"` (via embedded `basics.StateSchemas`). Omitted
    /// entirely (not `{}`) when zero -- see `is_default_state_schema`'s doc
    /// comment (issue #608).
    #[serde(
        rename = "lsch",
        default,
        skip_serializing_if = "is_default_state_schema"
    )]
    pub local_state_schema: StateSchema,
    /// Go codec tag: `"gsch"` (via embedded `basics.StateSchemas`). Omitted
    /// entirely (not `{}`) when zero -- same rationale as `lsch` above.
    #[serde(
        rename = "gsch",
        default,
        skip_serializing_if = "is_default_state_schema"
    )]
    pub global_state_schema: StateSchema,
    /// Go codec tag: `"epp"`.
    #[serde(rename = "epp", default, skip_serializing_if = "is_zero_u32")]
    pub extra_program_pages: u32,
    /// Go codec tag: `"v"`.
    #[serde(rename = "v", default, skip_serializing_if = "is_zero_u64")]
    pub version: u64,
    /// Go codec tag: `"ss"`. Non-zero only when the app pays MBR for extra
    /// program pages / global schema via a sponsoring account.
    #[serde(rename = "ss", default, skip_serializing_if = "is_default_address")]
    pub size_sponsor: Address,
    /// Go codec tag: `"fbr"`. Same not-yet-populated caveat as
    /// `version`/`size_sponsor` above (issue #659) -- `app_resources` isn't
    /// constructed from real apply-time state yet.
    #[serde(rename = "fbr", default, skip_serializing_if = "is_false")]
    pub foreign_box_reads: bool,
    /// Go codec tag: `"fba"`. Same caveat as `foreign_box_reads` above.
    #[serde(rename = "fba", default, skip_serializing_if = "is_false")]
    pub family_box_access: bool,
}

#[cfg(test)]
mod issue_579_short_codec_tag_wire_format_tests {
    use super::*;

    /// Issue #579: `basics.AssetParams` declares go-codec short tags
    /// (`codec:"t"`, `codec:"dc"`, ...), not the full Go field names this
    /// type previously hard-coded. Live-verified against a real
    /// go-algorand v4.7.0-stable node's `/v2/deltas/{round}` JSON response
    /// for an asset-config transaction: the real wire form is
    /// `{"t":...,"dc":...,"df":true,...}`, never `{"Total":...}`.
    #[test]
    fn asset_params_record_json_uses_go_short_codec_tags() {
        let params = AssetParamsRecord {
            total: 1_000_000,
            decimals: 2,
            default_frozen: true,
            unit_name: "UNIT".to_string(),
            asset_name: "Asset".to_string(),
            url: "https://example.com".to_string(),
            metadata_hash: Some([7u8; 32]),
            manager: Address([1u8; 32]),
            reserve: Address([2u8; 32]),
            freeze: Address([3u8; 32]),
            clawback: Address([4u8; 32]),
        };
        let json = serde_json::to_value(&params).expect("must serialize");
        let obj = json.as_object().expect("encodes as a JSON object");

        for short_tag in ["t", "dc", "df", "un", "an", "au", "am", "m", "r", "f", "c"] {
            assert!(
                obj.contains_key(short_tag),
                "AssetParamsRecord JSON must use go's short codec tag {short_tag:?}: {obj:?}"
            );
        }
        for full_name in [
            "Total",
            "Decimals",
            "DefaultFrozen",
            "UnitName",
            "AssetName",
            "URL",
            "MetadataHash",
            "Manager",
            "Reserve",
            "Freeze",
            "Clawback",
        ] {
            assert!(
                !obj.contains_key(full_name),
                "AssetParamsRecord JSON must NOT use the full Go field name \
                 {full_name:?} -- go-algorand's real wire form uses the \
                 short codec tag instead: {obj:?}"
            );
        }

        // Round-trip through the short tags.
        let back: AssetParamsRecord = serde_json::from_value(json).expect("must deserialize");
        assert_eq!(back, params);
    }

    /// Same bug class as `AssetParamsRecord`: `basics.AssetHolding` declares
    /// `codec:"a"`/`codec:"f"`, not `Amount`/`Frozen`.
    #[test]
    fn asset_holding_record_json_uses_go_short_codec_tags() {
        let holding = AssetHoldingRecord {
            amount: 7,
            frozen: true,
        };
        let json = serde_json::to_value(&holding).expect("must serialize");
        assert_eq!(json["a"], serde_json::json!(7));
        assert_eq!(json["f"], serde_json::json!(true));
        assert!(json.get("Amount").is_none());
        assert!(json.get("Frozen").is_none());
    }

    /// Same bug class: `basics.TealValue` declares `codec:"tt"`/`"tb"`/
    /// `"ui"`, not `Type`/`Bytes`/`Uint`.
    #[test]
    fn teal_value_record_json_uses_go_short_codec_tags() {
        let value = TealValueRecord {
            value_type: 2,
            bytes: String::new(),
            uint: 42,
        };
        let json = serde_json::to_value(&value).expect("must serialize");
        assert_eq!(json["tt"], serde_json::json!(2));
        assert_eq!(json["ui"], serde_json::json!(42));
        assert!(json.get("Type").is_none());
        assert!(json.get("Uint").is_none());
    }

    /// Same bug class: `basics.AppLocalState` declares `codec:"hsch"`/
    /// `"tkv"`, not `Schema`/`KeyValue`.
    #[test]
    fn app_local_state_record_json_uses_go_short_codec_tags() {
        let mut kv = HashMap::new();
        kv.insert(
            "k".to_string(),
            TealValueRecord {
                value_type: 2,
                bytes: String::new(),
                uint: 1,
            },
        );
        let record = AppLocalStateRecord {
            schema: StateSchema {
                num_uint: 1,
                num_byte_slice: 0,
            },
            key_value: Some(kv),
        };
        let json = serde_json::to_value(&record).expect("must serialize");
        assert!(json.get("hsch").is_some());
        assert!(json.get("tkv").is_some());
        assert!(json.get("Schema").is_none());
        assert!(json.get("KeyValue").is_none());
    }

    /// Same bug class: `basics.AppParams` declares `codec:"approv"`/
    /// `"clearp"`/`"gs"`/`"lsch"`/`"gsch"`/`"epp"`, not the full field
    /// names.
    #[test]
    fn app_params_record_json_uses_go_short_codec_tags() {
        let record = AppParamsRecord {
            approval_program: vec![0x06, 0x81, 0x01],
            clear_state_program: vec![0x06, 0x81, 0x01],
            global_state: None,
            local_state_schema: StateSchema {
                num_uint: 1,
                num_byte_slice: 2,
            },
            global_state_schema: StateSchema {
                num_uint: 3,
                num_byte_slice: 4,
            },
            extra_program_pages: 1,
            version: 0,
            size_sponsor: Address([0u8; 32]),
            foreign_box_reads: false,
            family_box_access: false,
        };
        let json = serde_json::to_value(&record).expect("must serialize");
        let obj = json.as_object().expect("encodes as a JSON object");

        for short_tag in ["approv", "clearp", "lsch", "gsch", "epp"] {
            assert!(
                obj.contains_key(short_tag),
                "AppParamsRecord JSON must use go's short codec tag {short_tag:?}: {obj:?}"
            );
        }
        for full_name in [
            "ApprovalProgram",
            "ClearStateProgram",
            "GlobalState",
            "LocalStateSchema",
            "GlobalStateSchema",
            "ExtraProgramPages",
        ] {
            assert!(
                !obj.contains_key(full_name),
                "AppParamsRecord JSON must NOT use the full Go field name \
                 {full_name:?}: {obj:?}"
            );
        }
    }

    /// Issue #583: `basics.AppParams` also declares `Version` (`codec:"v"`)
    /// and `SizeSponsor` (`codec:"ss"`) -- fields the #579 short-codec-tag
    /// rewrite of `AppParamsRecord` didn't carry at all (a distinct
    /// missing-fields bug, not a naming bug). Because `AppParams` declares
    /// the `_struct codec:",omitempty,omitemptyarray"` marker, both fields
    /// are omitted from the wire when zero-valued (pinned by the sibling
    /// `..._omitted_when_zero` test below) but must appear under their
    /// short tags -- never the full Go field name -- when non-zero.
    #[test]
    fn app_params_record_json_uses_go_short_codec_tags_for_version_and_size_sponsor() {
        let record = AppParamsRecord {
            approval_program: vec![0x06, 0x81, 0x01],
            clear_state_program: vec![0x06, 0x81, 0x01],
            global_state: None,
            local_state_schema: StateSchema::default(),
            global_state_schema: StateSchema::default(),
            extra_program_pages: 0,
            version: 7,
            size_sponsor: Address([9u8; 32]),
            foreign_box_reads: false,
            family_box_access: false,
        };
        let json = serde_json::to_value(&record).expect("must serialize");
        let obj = json.as_object().expect("encodes as a JSON object");

        assert_eq!(obj["v"], serde_json::json!(7), "obj: {obj:?}");
        assert!(obj.contains_key("ss"), "obj: {obj:?}");
        assert!(obj.get("Version").is_none(), "obj: {obj:?}");
        assert!(obj.get("SizeSponsor").is_none(), "obj: {obj:?}");

        let back: AppParamsRecord = serde_json::from_value(json).expect("must deserialize");
        assert_eq!(back, record);
    }

    /// Issue #659: `AppParams` also declares `ForeignBoxReads`
    /// (`codec:"fbr"`) and `FamilyBoxAccess` (`codec:"fba"`) -- same
    /// short-tag and `omitempty`-when-zero contract as `Version`/
    /// `SizeSponsor` above.
    #[test]
    fn app_params_record_json_uses_go_short_codec_tags_for_foreign_box_fields() {
        let record = AppParamsRecord {
            approval_program: vec![0x06, 0x81, 0x01],
            clear_state_program: vec![0x06, 0x81, 0x01],
            global_state: None,
            local_state_schema: StateSchema::default(),
            global_state_schema: StateSchema::default(),
            extra_program_pages: 0,
            version: 0,
            size_sponsor: Address([0u8; 32]),
            foreign_box_reads: true,
            family_box_access: true,
        };
        let json = serde_json::to_value(&record).expect("must serialize");
        let obj = json.as_object().expect("encodes as a JSON object");

        assert_eq!(obj["fbr"], serde_json::json!(true), "obj: {obj:?}");
        assert_eq!(obj["fba"], serde_json::json!(true), "obj: {obj:?}");
        assert!(obj.get("ForeignBoxReads").is_none(), "obj: {obj:?}");
        assert!(obj.get("FamilyBoxAccess").is_none(), "obj: {obj:?}");

        let back: AppParamsRecord = serde_json::from_value(json).expect("must deserialize");
        assert_eq!(back, record);

        // `false` (the default) must be omitted entirely, like `v`/`ss`.
        let default_record = AppParamsRecord {
            foreign_box_reads: false,
            family_box_access: false,
            ..record
        };
        let json = serde_json::to_value(&default_record).expect("must serialize");
        let obj = json.as_object().expect("encodes as a JSON object");
        assert!(!obj.contains_key("fbr"), "obj: {obj:?}");
        assert!(!obj.contains_key("fba"), "obj: {obj:?}");
    }

    /// `Version`/`SizeSponsor` zero-valued must be omitted entirely (go's
    /// `_struct codec:",omitempty,omitemptyarray"` marker on `AppParams`),
    /// matching every other field on this type.
    #[test]
    fn app_params_record_omits_zero_version_and_size_sponsor() {
        let record = AppParamsRecord {
            approval_program: Vec::new(),
            clear_state_program: Vec::new(),
            global_state: None,
            local_state_schema: StateSchema::default(),
            global_state_schema: StateSchema::default(),
            extra_program_pages: 0,
            version: 0,
            size_sponsor: Address([0u8; 32]),
            foreign_box_reads: false,
            family_box_access: false,
        };
        let json = serde_json::to_value(&record).expect("must serialize");
        let obj = json.as_object().expect("encodes as a JSON object");
        assert!(!obj.contains_key("v"), "obj: {obj:?}");
        assert!(!obj.contains_key("ss"), "obj: {obj:?}");
        assert!(!obj.contains_key("fbr"), "obj: {obj:?}");
        assert!(!obj.contains_key("fba"), "obj: {obj:?}");
    }

    /// Issue #608 (live-verified against a real go-algorand v4.7.0-stable
    /// node): an opt-in round for an app with no declared local schema
    /// produced `"LocalState": {}` from algod-rust's `/v2/deltas/{round}`
    /// but `"LocalState": {}` with no `hsch` key at all from go -- go's
    /// `basics.AppLocalState` declares `_struct codec:",omitempty,
    /// omitemptyarray"`, so a zero-value `Schema` field is omitted
    /// entirely, not serialized as `"hsch": {}`. Confirms
    /// `is_default_state_schema`'s skip_serializing_if fixes this.
    #[test]
    fn app_local_state_record_omits_zero_schema() {
        let record = AppLocalStateRecord {
            schema: StateSchema::default(),
            key_value: None,
        };
        let json = serde_json::to_value(&record).expect("must serialize");
        let obj = json.as_object().expect("encodes as a JSON object");
        assert!(
            !obj.contains_key("hsch"),
            "zero-value schema must be omitted entirely, not serialized as {{}}: {obj:?}"
        );

        let back: AppLocalStateRecord = serde_json::from_value(json).expect("must deserialize");
        assert_eq!(back, record);
    }

    /// Same bug class as `app_local_state_record_omits_zero_schema`, for
    /// `AppParamsRecord`'s `lsch`/`gsch` (go's embedded `StateSchemas`
    /// carries the identical `_struct codec:",omitempty,omitemptyarray"`
    /// marker). Not directly live-verified (this repo's live app
    /// create/update harness never populates a non-default schema), but the
    /// same go source construct as the live-verified `hsch` case above, so
    /// fixed the same way rather than leaving an inconsistent gap.
    #[test]
    fn app_params_record_omits_zero_schema() {
        let record = AppParamsRecord {
            approval_program: Vec::new(),
            clear_state_program: Vec::new(),
            global_state: None,
            local_state_schema: StateSchema::default(),
            global_state_schema: StateSchema::default(),
            extra_program_pages: 0,
            version: 0,
            size_sponsor: Address([0u8; 32]),
            foreign_box_reads: false,
            family_box_access: false,
        };
        let json = serde_json::to_value(&record).expect("must serialize");
        let obj = json.as_object().expect("encodes as a JSON object");
        assert!(!obj.contains_key("lsch"), "obj: {obj:?}");
        assert!(!obj.contains_key("gsch"), "obj: {obj:?}");

        let back: AppParamsRecord = serde_json::from_value(json).expect("must deserialize");
        assert_eq!(back, record);
    }
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
///
/// go-algorand's `ledgercore.AccountDeltas` carries no `_struct
/// codec:",omitempty,omitemptyarray"` marker, so every field is always
/// present on the wire (issue #576). The three fields differ in their
/// empty-value wire form, matching how go-algorand allocates them:
/// - `Accts` is unconditionally allocated (non-nil) by `MakeAccountDeltas`
///   at the start of every round's state-delta construction
///   (`PopulateStateDelta`), so it is always `[]` (never `null`) when empty
///   -- a plain `Vec` with no `skip_serializing_if` reproduces that.
/// - `AppResources`/`AssetResources` are left as Go nil slices until the
///   first `UpsertAppResource`/`UpsertAssetResource` call, so for a round
///   that never touches app/asset resources (the common case, e.g. a plain
///   payment) they serialize as `null`, not `[]` -- `serialize_vec_or_null`/
///   `deserialize_vec_or_null` reproduce that.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AccountDeltas {
    /// Balance records (address + account data).
    #[serde(rename = "Accts", default)]
    pub accts: Vec<BalanceRecord>,

    /// Application resource changes.
    #[serde(
        rename = "AppResources",
        default,
        serialize_with = "serialize_vec_or_null",
        deserialize_with = "deserialize_vec_or_null"
    )]
    pub app_resources: Vec<AppResourceRecord>,

    /// Asset resource changes.
    #[serde(
        rename = "AssetResources",
        default,
        serialize_with = "serialize_vec_or_null",
        deserialize_with = "deserialize_vec_or_null"
    )]
    pub asset_resources: Vec<AssetResourceRecord>,
}

// ---------------------------------------------------------------------------
// StateDelta
// ---------------------------------------------------------------------------

/// The complete set of state changes produced by evaluating a block.
///
/// This mirrors go-algorand's `ledgercore.StateDelta`.
///
/// go-algorand's `ledgercore.StateDelta` carries no `_struct codec:",
/// omitempty,omitemptyarray"` marker, so every field is always present on
/// the wire (issue #576) -- never skipped. `KvMods`/`Txids`/`Creatables`
/// (nil Go maps until first populated) and `Txleases`/`Hdr` (nil Go
/// pointers/maps) serialize as `null` when empty/unset rather than an
/// omitted key or `{}`/`[]`.
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
        serialize_with = "serialize_kv_mods",
        deserialize_with = "deserialize_kv_mods"
    )]
    pub kv_mods: HashMap<Vec<u8>, KvValueDelta>,

    /// Transaction IDs included in the block.
    #[serde(
        rename = "Txids",
        default,
        serialize_with = "serialize_txids",
        deserialize_with = "deserialize_txids"
    )]
    pub txids: HashMap<Digest, IncludedTransactions>,

    /// Transaction leases. Represented as a Vec of pairs since `Txlease`
    /// (a struct) cannot be used as a JSON map key. Go-algorand nils this
    /// field in JSON anyway. For msgpack we use a list of (key, value) pairs.
    ///
    /// TODO: go-algorand's codec encodes this as a msgpack map, not an array
    /// of pairs. A custom serde implementation may be needed for byte-level
    /// msgpack conformance.
    #[serde(rename = "Txleases", default)]
    pub txleases: Option<Vec<(Txlease, Round)>>,

    /// Created/deleted assets and applications.
    #[serde(
        rename = "Creatables",
        default,
        serialize_with = "serialize_map_or_null",
        deserialize_with = "deserialize_map_or_null"
    )]
    pub creatables: HashMap<u64, ModifiedCreatable>,

    /// Block header (None when not set).
    #[serde(rename = "Hdr", default)]
    pub hdr: Option<BlockHeader>,

    /// Next expected state proof round.
    #[serde(rename = "StateProofNext", default)]
    pub state_proof_next: Round,

    /// Previous block timestamp.
    #[serde(rename = "PrevTimestamp", default)]
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
///
/// Unlike `ledgercore.StateDelta` (see [`StateDelta`]'s docs), go's
/// `ledger/eval.StateDeltaSubset` **does** declare the `_struct codec:",
/// omitempty,omitemptyarray"` marker (`ledger/eval/txntracer.go`), so this
/// type's own `skip_serializing_if`s on `KvMods`/`Txids`/`Txleases`/
/// `Creatables` are correct as-is (issue #576's audit): despite the
/// near-identical field list, `StateDeltaSubset` and `StateDelta` are
/// different Go types with opposite default-omission behavior.
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
    ///
    /// Uses the same `serialize_txids`/`deserialize_txids` helpers as
    /// [`StateDelta::txids`] (see their doc comment) -- a plain
    /// `HashMap<Digest, _>` cannot serialize to JSON at all (`Digest` is not
    /// a string-serializable map key), a pre-existing bug independent of
    /// this field's (correct, unchanged) `skip_serializing_if`.
    #[serde(
        rename = "Txids",
        default,
        skip_serializing_if = "HashMap::is_empty",
        serialize_with = "serialize_txids",
        deserialize_with = "deserialize_txids"
    )]
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

    /// Regression: `#[serde(flatten)]`'s *deserialize* side (used by
    /// `LedgercoreAccountData` to compose `AccountBaseData` + `VotingData`)
    /// buffers the remaining input into serde's generic `Content` type,
    /// whose `Deserializer::is_human_readable()` always answers `true`
    /// regardless of the real wire format -- so `deserialize_bytes_array`
    /// branching on that flag (as it originally did, mirroring
    /// `deserialize_kv_bytes`) mis-decoded raw msgpack bytes as base64 the
    /// moment `VotingData` sat under a `flatten`. Pins the fix (dispatch via
    /// `deserialize_any`'s visitor instead, which sees the value's real
    /// shape) directly against the minimal case that first exposed it.
    #[test]
    fn voting_data_behind_flatten_round_trips_through_msgpack() {
        #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
        struct Inner {
            #[serde(
                serialize_with = "serialize_bytes_array",
                deserialize_with = "deserialize_bytes_array"
            )]
            id: [u8; 32],
        }
        #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
        struct Outer {
            #[serde(flatten)]
            inner: Inner,
        }
        let w = Outer::default();
        let bytes = rmp_serde::to_vec_named(&w).expect("serialize");
        let decoded: Outer = rmp_serde::from_slice(&bytes).expect("deserialize");
        assert_eq!(decoded, w);
    }

    /// Same regression, exercised through the real (not minimal) types:
    /// `AccountDeltas` -> `BalanceRecord` -> `LedgercoreAccountData`
    /// (flattened `AccountBaseData` + `VotingData`), matching exactly what
    /// `algo-rest-api`'s `mock_with_delta()` integration-test helper builds.
    #[test]
    fn account_deltas_default_voting_data_msgpack_roundtrip() {
        let deltas = AccountDeltas {
            accts: vec![BalanceRecord {
                addr: Address([1u8; 32]),
                account_data: LedgercoreAccountData::default(),
            }],
            app_resources: Vec::new(),
            asset_resources: Vec::new(),
        };
        let bytes = rmp_serde::to_vec_named(&deltas).expect("serialize");
        let decoded: AccountDeltas = rmp_serde::from_slice(&bytes).expect("deserialize");
        assert_eq!(decoded, deltas);
    }

    /// Full end-to-end regression matching `algo-rest-api`'s
    /// `mock_with_delta()` integration-test fixture exactly (the scenario
    /// that first surfaced the flatten/msgpack bug above, via
    /// `get_state_delta_msgpack_returns_200_with_txleases`).
    #[test]
    fn state_delta_mock_with_delta_shape_msgpack_roundtrip() {
        let delta = StateDelta {
            accts: AccountDeltas {
                accts: vec![BalanceRecord {
                    addr: Address([1u8; 32]),
                    account_data: LedgercoreAccountData::default(),
                }],
                app_resources: Vec::new(),
                asset_resources: Vec::new(),
            },
            kv_mods: HashMap::new(),
            txids: HashMap::new(),
            txleases: Some(vec![(
                Txlease {
                    sender: Address([2u8; 32]),
                    lease: [3u8; 32],
                },
                Round(100),
            )]),
            creatables: HashMap::new(),
            hdr: None,
            state_proof_next: Round(0),
            prev_timestamp: 0,
            totals: AccountTotals::default(),
        };
        let bytes = rmp_serde::to_vec_named(&delta).expect("serialize");
        let decoded: StateDelta = rmp_serde::from_slice(&bytes).expect("deserialize");
        assert_eq!(decoded, delta);
    }
}

#[cfg(test)]
mod issue_576_never_omit_tests {
    //! Issue #576: field-by-field audit of every `skip_serializing_if` in
    //! this file against go-algorand's actual `_struct codec:",omitempty,
    //! omitemptyarray"` marker presence/absence. Every type below carries no
    //! such marker on the Go side (`ledger/ledgercore/statedelta.go`,
    //! `ledger/ledgercore/accountdata.go`, `data/basics/userBalance.go`), so
    //! a real node's JSON response always includes every one of these
    //! fields -- these tests pin that a Rust-side zero/empty value still
    //! produces the key, using `null` for a nil Go map/slice/pointer rather
    //! than an omitted key or `{}`/`[]`.
    use super::*;

    fn obj(json: &serde_json::Value) -> &serde_json::Map<String, serde_json::Value> {
        json.as_object().expect("must serialize as a JSON object")
    }

    #[test]
    fn account_base_data_zero_value_serializes_every_field() {
        let json = serde_json::to_value(AccountBaseData::default()).expect("serialize");
        let obj = obj(&json);
        for key in [
            "Status",
            "MicroAlgos",
            "RewardsBase",
            "RewardedMicroAlgos",
            "AuthAddr",
            "IncentiveEligible",
            "TotalAppSchema",
            "TotalExtraAppPages",
            "TotalAppParams",
            "TotalAppLocalStates",
            "TotalAssetParams",
            "TotalAssets",
            "TotalBoxes",
            "TotalBoxBytes",
            "LastProposed",
            "LastHeartbeat",
        ] {
            assert!(
                obj.contains_key(key),
                "AccountBaseData must always emit {key} (no omitempty on the Go side): {obj:?}"
            );
        }
    }

    #[test]
    fn voting_data_zero_value_serializes_every_field_and_base64_encodes_keys() {
        let json = serde_json::to_value(VotingData::default()).expect("serialize");
        let obj = obj(&json);
        for key in [
            "VoteID",
            "SelectionID",
            "StateProofID",
            "VoteFirstValid",
            "VoteLastValid",
            "VoteKeyDilution",
        ] {
            assert!(
                obj.contains_key(key),
                "VotingData must always emit {key} (no omitempty on the Go side): {obj:?}"
            );
        }
        // A Go [32]byte/[64]byte array is never nil -- even the all-zero
        // VoteID/SelectionID/StateProofID must be a real base64 string, not
        // null and not a JSON array of numbers.
        assert_eq!(
            obj["VoteID"],
            serde_json::Value::String(
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 32])
            ),
            "a zero VoteID must still base64-encode its 32 zero bytes, not omit/null/array: {obj:?}"
        );
        assert_eq!(
            obj["StateProofID"],
            serde_json::Value::String(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [0u8; 64]
            )),
            "a zero StateProofID must still base64-encode its 64 zero bytes: {obj:?}"
        );

        let round_tripped: VotingData = serde_json::from_value(json).expect("deserialize");
        assert_eq!(round_tripped, VotingData::default());
    }

    #[test]
    fn voting_data_nonzero_vote_id_round_trips_through_json_and_msgpack() {
        let vd = VotingData {
            vote_id: [0x11; 32],
            selection_id: [0x22; 32],
            state_proof_id: [0x33; 64],
            vote_first_valid: Round(10),
            vote_last_valid: Round(20),
            vote_key_dilution: 30,
        };
        let json = serde_json::to_value(&vd).expect("serialize");
        assert_eq!(
            json["VoteID"],
            serde_json::Value::String(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [0x11u8; 32]
            ))
        );
        let round_tripped: VotingData = serde_json::from_value(json).expect("deserialize");
        assert_eq!(round_tripped, vd);

        let bytes = rmp_serde::to_vec_named(&vd).expect("msgpack serialize");
        let round_tripped_mp: VotingData = rmp_serde::from_slice(&bytes).expect("msgpack decode");
        assert_eq!(round_tripped_mp, vd);
    }

    #[test]
    fn modified_creatable_zero_value_serializes_every_field() {
        let json = serde_json::to_value(ModifiedCreatable {
            ctype: 0,
            created: false,
            creator: Address([0u8; 32]),
            ndeltas: 0,
        })
        .expect("serialize");
        let obj = obj(&json);
        for key in ["Ctype", "Created", "Creator", "Ndeltas"] {
            assert!(
                obj.contains_key(key),
                "ModifiedCreatable must always emit {key}: {obj:?}"
            );
        }
    }

    #[test]
    fn included_transactions_zero_value_serializes_every_field() {
        let json = serde_json::to_value(IncludedTransactions {
            last_valid: Round(0),
            intra: 0,
        })
        .expect("serialize");
        let obj = obj(&json);
        assert!(obj.contains_key("LastValid"), "{obj:?}");
        assert!(obj.contains_key("Intra"), "{obj:?}");
    }

    #[test]
    fn resource_delta_wrappers_always_emit_both_fields_null_and_false() {
        let json = serde_json::to_value(AssetHoldingDelta::default()).expect("serialize");
        let holding_obj = obj(&json);
        assert_eq!(
            holding_obj["Holding"],
            serde_json::Value::Null,
            "{holding_obj:?}"
        );
        assert_eq!(
            holding_obj["Deleted"],
            serde_json::Value::Bool(false),
            "{holding_obj:?}"
        );

        let json = serde_json::to_value(AssetParamsDelta::default()).expect("serialize");
        let asset_params_obj = obj(&json);
        assert_eq!(
            asset_params_obj["Params"],
            serde_json::Value::Null,
            "{asset_params_obj:?}"
        );
        assert_eq!(
            asset_params_obj["Deleted"],
            serde_json::Value::Bool(false),
            "{asset_params_obj:?}"
        );

        let json = serde_json::to_value(AppLocalStateDelta::default()).expect("serialize");
        let local_state_obj = obj(&json);
        assert_eq!(
            local_state_obj["LocalState"],
            serde_json::Value::Null,
            "{local_state_obj:?}"
        );
        assert_eq!(
            local_state_obj["Deleted"],
            serde_json::Value::Bool(false),
            "{local_state_obj:?}"
        );

        let json = serde_json::to_value(AppParamsDelta::default()).expect("serialize");
        let app_params_obj = obj(&json);
        assert_eq!(
            app_params_obj["Params"],
            serde_json::Value::Null,
            "{app_params_obj:?}"
        );
        assert_eq!(
            app_params_obj["Deleted"],
            serde_json::Value::Bool(false),
            "{app_params_obj:?}"
        );
    }

    #[test]
    fn account_deltas_accts_is_empty_array_but_resources_are_null_when_empty() {
        // AccountDeltas.Accts is unconditionally allocated (non-nil) by
        // go-algorand's MakeAccountDeltas at the start of every round's
        // state-delta construction, so it must be `[]`, never `null`, when
        // empty. AppResources/AssetResources are left nil until the first
        // Upsert*Resource call, so they must be `null`, not `[]`.
        let json = serde_json::to_value(AccountDeltas::default()).expect("serialize");
        let obj = obj(&json);
        assert_eq!(
            obj["Accts"],
            serde_json::Value::Array(vec![]),
            "empty Accts must serialize as [] (always-allocated in go): {obj:?}"
        );
        assert_eq!(
            obj["AppResources"],
            serde_json::Value::Null,
            "untouched AppResources must serialize as null (nil in go): {obj:?}"
        );
        assert_eq!(
            obj["AssetResources"],
            serde_json::Value::Null,
            "untouched AssetResources must serialize as null (nil in go): {obj:?}"
        );

        let round_tripped: AccountDeltas = serde_json::from_value(json).expect("deserialize");
        assert_eq!(round_tripped, AccountDeltas::default());
    }

    #[test]
    fn account_deltas_populated_resources_round_trip_through_json_and_msgpack() {
        let deltas = AccountDeltas {
            accts: vec![],
            app_resources: vec![AppResourceRecord {
                aidx: 7,
                addr: Address([0x01; 32]),
                params: AppParamsDelta::default(),
                state: AppLocalStateDelta::default(),
            }],
            asset_resources: vec![],
        };
        let json = serde_json::to_value(&deltas).expect("serialize");
        let obj = obj(&json);
        assert!(obj["AppResources"].is_array());
        let round_tripped: AccountDeltas = serde_json::from_value(json).expect("deserialize");
        assert_eq!(round_tripped, deltas);

        let bytes = rmp_serde::to_vec_named(&deltas).expect("msgpack serialize");
        let round_tripped_mp: AccountDeltas =
            rmp_serde::from_slice(&bytes).expect("msgpack decode");
        assert_eq!(round_tripped_mp, deltas);
    }

    #[test]
    fn state_delta_default_never_omits_a_field_and_uses_null_for_empty_maps() {
        let json = serde_json::to_value(StateDelta::default()).expect("serialize");
        let obj = obj(&json);
        for key in [
            "Accts",
            "KvMods",
            "Txids",
            "Txleases",
            "Creatables",
            "Hdr",
            "StateProofNext",
            "PrevTimestamp",
            "Totals",
        ] {
            assert!(
                obj.contains_key(key),
                "StateDelta must always emit {key} (no omitempty on ledgercore.StateDelta): {obj:?}"
            );
        }
        assert_eq!(
            obj["KvMods"],
            serde_json::Value::Null,
            "an untouched (nil in go) KvMods must serialize as null, not {{}}: {obj:?}"
        );
        assert_eq!(
            obj["Txids"],
            serde_json::Value::Null,
            "an untouched (nil in go) Txids must serialize as null, not {{}}: {obj:?}"
        );
        assert_eq!(
            obj["Creatables"],
            serde_json::Value::Null,
            "an untouched (nil in go) Creatables must serialize as null, not {{}}: {obj:?}"
        );
        assert_eq!(obj["Txleases"], serde_json::Value::Null, "{obj:?}");
        assert_eq!(obj["Hdr"], serde_json::Value::Null, "{obj:?}");
        assert_eq!(obj["StateProofNext"], serde_json::json!(0), "{obj:?}");
        assert_eq!(obj["PrevTimestamp"], serde_json::json!(0), "{obj:?}");
        // Accts is unconditionally allocated in go, so it's [] not null.
        assert_eq!(obj["Accts"]["Accts"], serde_json::Value::Array(vec![]));

        let round_tripped: StateDelta = serde_json::from_value(json).expect("deserialize");
        assert_eq!(round_tripped, StateDelta::default());
    }

    #[test]
    fn state_delta_populated_maps_round_trip_through_json_and_msgpack() {
        let mut txids = HashMap::new();
        txids.insert(
            Digest([0x42; 32]),
            IncludedTransactions {
                last_valid: Round(100),
                intra: 3,
            },
        );
        let mut creatables = HashMap::new();
        creatables.insert(
            5,
            ModifiedCreatable {
                ctype: 1,
                created: true,
                creator: Address([0x09; 32]),
                ndeltas: 1,
            },
        );
        let delta = StateDelta {
            txids,
            creatables,
            state_proof_next: Round(42),
            prev_timestamp: 1_700_000_000,
            ..Default::default()
        };

        let json = serde_json::to_value(&delta).expect("serialize");
        let obj = obj(&json);
        assert!(obj["Txids"].is_object());
        assert!(obj["Creatables"].is_object());
        let round_tripped: StateDelta = serde_json::from_value(json).expect("deserialize");
        assert_eq!(round_tripped, delta);

        let bytes = rmp_serde::to_vec_named(&delta).expect("msgpack serialize");
        let round_tripped_mp: StateDelta = rmp_serde::from_slice(&bytes).expect("msgpack decode");
        assert_eq!(round_tripped_mp, delta);
    }

    #[test]
    fn state_delta_kv_mods_null_round_trips_through_msgpack() {
        // Regression for the msgpack decode side of the KvMods null-when-
        // empty fix: `deserialize_kv_mods`'s non-human-readable branch must
        // accept a nil value (not just a real map), since a real node emits
        // msgpack nil for an untouched KvMods.
        let delta = StateDelta::default();
        let bytes = rmp_serde::to_vec_named(&delta).expect("msgpack serialize");
        let decoded: rmpv::Value =
            rmpv::decode::read_value(&mut &bytes[..]).expect("decode as rmpv");
        let kv_mods_val = decoded
            .as_map()
            .and_then(|m| m.iter().find(|(k, _)| k.as_str() == Some("KvMods")))
            .map(|(_, v)| v.clone())
            .expect("StateDelta must always have a KvMods entry");
        assert!(
            kv_mods_val.is_nil(),
            "an untouched KvMods must serialize as msgpack nil: {kv_mods_val:?}"
        );

        let round_tripped: StateDelta = rmp_serde::from_slice(&bytes).expect("msgpack decode");
        assert_eq!(round_tripped, delta);
    }

    #[test]
    fn state_delta_subset_still_omits_empty_map_fields_unlike_state_delta() {
        // Regression guard for the opposite finding of this issue's audit:
        // `ledger/eval.StateDeltaSubset` (unlike `ledgercore.StateDelta`)
        // *does* declare the omitempty marker, so its skip_serializing_ifs
        // must remain unchanged -- an empty KvMods/Txids/Creatables/
        // Txleases/Hdr must still be an *omitted key*, not null.
        let subset = StateDeltaSubset::default();
        let json = serde_json::to_value(&subset).expect("serialize");
        let obj = obj(&json);
        for key in ["KvMods", "Txids", "Txleases", "Creatables", "Hdr"] {
            assert!(
                !obj.contains_key(key),
                "StateDeltaSubset must omit {key} when empty (go's marker is present): {obj:?}"
            );
        }
    }
}
