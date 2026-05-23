//! Fixture-driven byte-identity tests for `resources.data` BLOBs
//! (PLAN-189 / TASK-194).
//!
//! End-to-end proof that the algo-ledger encoders
//! (`encode_asset_holding_with_round`, `encode_asset_params_with_round`,
//! `encode_app_params_with_round`, `encode_app_local_state_with_round`,
//! and their `build_*_resource_data` builders for combined rows)
//! produce output byte-identical to what go-algorand writes into
//! `resources.data` for the equivalent struct value.
//!
//! The fixtures themselves were captured in TASK-119 by the
//! `extract-trackerdb-fixtures` make target. Each fixture's filename
//! encodes `<addrhex>_<aidx>_<ctype>.canonical.hex`, where ctype `0` is
//! an asset resource and ctype `1` is an app resource (matching
//! go-algorand's `basics.AssetCreatable`/`AppCreatable`).
//!
//! Test flow per fixture:
//!   1. Read the hex-encoded blob from disk.
//!   2. Walk the rmpv `Value` map into a partial `ResourcesData` (only
//!      the fields relevant to the row's ctype + flag combination).
//!   3. Build the corresponding Rust `AssetHolding`/`AssetParams`/etc.
//!   4. Encode via the algo-ledger encoder + builder.
//!   5. Assert byte-identity with the source blob.
//!
//! `SKIP` with a clear message if the fixture directory is empty (the
//! corpus is gitignored on a fresh clone until you run the extract
//! target locally).

use std::collections::BTreeMap;
use std::path::PathBuf;

use algo_codec::resource_flags;
use algo_ledger::sqlite::{
    build_app_resource_data, build_asset_resource_data, encode_app_local_state_with_round,
    encode_app_params_with_round, encode_asset_holding_with_round, encode_asset_params_with_round,
};
use algo_types::{
    Address, AppLocalState, AppParams, AssetHolding, AssetParams, StateSchema, TealValue,
};

const RESOURCES_FIXTURES_DIR: &str = "../algo-codec/tests/fixtures/trackerdb/resourcesdata";

fn fixtures_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join(RESOURCES_FIXTURES_DIR)
}

fn load_hex_files() -> Vec<(String, Vec<u8>)> {
    let dir = fixtures_root();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.ends_with(".canonical.hex") {
            continue;
        }
        let raw = std::fs::read_to_string(&path).expect("read fixture");
        let bytes = hex::decode(raw.trim()).expect("hex decode");
        out.push((name.to_string(), bytes));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Extracted view of a Go-encoded resources.data row, populated by
/// walking the rmpv Map. Only the fields needed to reconstruct an
/// equivalent Rust struct are captured.
#[derive(Debug, Default)]
struct RowFields {
    // Asset params (a-k)
    total: u64,
    decimals: u32,
    default_frozen: bool,
    unit_name: String,
    asset_name: String,
    url: String,
    metadata_hash: Option<[u8; 32]>,
    manager: Option<[u8; 32]>,
    reserve: Option<[u8; 32]>,
    freeze: Option<[u8; 32]>,
    clawback: Option<[u8; 32]>,
    // Asset holding (l, m)
    amount: u64,
    frozen: bool,
    // App local state (n, o, p) — canonical schema u64s + kv map
    local_schema_nui: u64,
    local_schema_nbs: u64,
    local_kv: BTreeMap<Vec<u8>, TealValue>,
    // App params (q, r, s, t, u, v, w, x)
    approval: Vec<u8>,
    clear_state: Vec<u8>,
    global_state: BTreeMap<Vec<u8>, TealValue>,
    local_state_schema_nui: u64,
    local_state_schema_nbs: u64,
    global_state_schema_nui: u64,
    global_state_schema_nbs: u64,
    extra_program_pages: u32,
    // Flags + metadata
    raw_y: u64,
    update_round: u64,
}

fn as_array32(v: &rmpv::Value) -> Option<[u8; 32]> {
    let slice = v.as_slice()?;
    if slice.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(slice);
    Some(arr)
}

fn decode_teal_value(v: &rmpv::Value) -> Option<TealValue> {
    let rmpv::Value::Map(inner) = v else {
        return None;
    };
    let mut tt: u64 = 0;
    let mut ui: u64 = 0;
    let mut tb: Vec<u8> = Vec::new();
    for (k, val) in inner {
        match k.as_str().unwrap_or("") {
            "tt" => tt = val.as_u64().unwrap_or(0),
            "ui" => ui = val.as_u64().unwrap_or(0),
            "tb" => {
                if let Some(b) = val.as_slice() {
                    tb = b.to_vec();
                }
            }
            _ => {}
        }
    }
    Some(match tt {
        1 => TealValue::Bytes(tb),
        _ => TealValue::Uint(ui),
    })
}

fn decode_teal_kv(v: &rmpv::Value) -> BTreeMap<Vec<u8>, TealValue> {
    let mut out = BTreeMap::new();
    let rmpv::Value::Map(pairs) = v else {
        return out;
    };
    for (k, val) in pairs {
        let key_bytes = match k {
            rmpv::Value::String(s) => s.as_bytes().to_vec(),
            rmpv::Value::Binary(b) => b.clone(),
            _ => continue,
        };
        if let Some(tv) = decode_teal_value(val) {
            out.insert(key_bytes, tv);
        }
    }
    out
}

fn walk(blob: &[u8]) -> RowFields {
    let val = rmpv::decode::read_value(&mut &blob[..]).expect("rmpv decode fixture");
    let rmpv::Value::Map(pairs) = val else {
        panic!("expected msgpack map at top level");
    };

    let mut f = RowFields::default();
    for (k, v) in pairs {
        match k.as_str().unwrap_or("") {
            // Asset params (a-k)
            "a" => f.total = v.as_u64().unwrap_or(0),
            "b" => f.decimals = v.as_u64().unwrap_or(0) as u32,
            "c" => f.default_frozen = v.as_bool().unwrap_or(false),
            "d" => f.unit_name = v.as_str().unwrap_or("").to_string(),
            "e" => f.asset_name = v.as_str().unwrap_or("").to_string(),
            "f" => f.url = v.as_str().unwrap_or("").to_string(),
            "g" => f.metadata_hash = as_array32(&v),
            "h" => f.manager = as_array32(&v),
            "i" => f.reserve = as_array32(&v),
            "j" => f.freeze = as_array32(&v),
            "k" => f.clawback = as_array32(&v),
            // Asset holding (l, m)
            "l" => f.amount = v.as_u64().unwrap_or(0),
            "m" => f.frozen = v.as_bool().unwrap_or(false),
            // App local state canonical schema (n, o) and kv (p)
            "n" => f.local_schema_nui = v.as_u64().unwrap_or(0),
            "o" => f.local_schema_nbs = v.as_u64().unwrap_or(0),
            "p" => f.local_kv = decode_teal_kv(&v),
            // App params (q, r, s, t, u, v, w, x)
            "q" => f.approval = v.as_slice().unwrap_or(&[]).to_vec(),
            "r" => f.clear_state = v.as_slice().unwrap_or(&[]).to_vec(),
            "s" => f.global_state = decode_teal_kv(&v),
            "t" => f.local_state_schema_nui = v.as_u64().unwrap_or(0),
            "u" => f.local_state_schema_nbs = v.as_u64().unwrap_or(0),
            "v" => f.global_state_schema_nui = v.as_u64().unwrap_or(0),
            "w" => f.global_state_schema_nbs = v.as_u64().unwrap_or(0),
            "x" => f.extra_program_pages = v.as_u64().unwrap_or(0) as u32,
            // Flags + metadata
            "y" => f.raw_y = v.as_u64().unwrap_or(0),
            "z" => f.update_round = v.as_u64().unwrap_or(0),
            _ => {}
        }
    }
    f
}

fn maybe_address(opt: &Option<[u8; 32]>) -> Option<Address> {
    opt.map(Address)
}

fn rebuild_asset_holding(f: &RowFields) -> AssetHolding {
    AssetHolding {
        amount: f.amount,
        frozen: f.frozen,
    }
}

fn rebuild_asset_params(f: &RowFields) -> AssetParams {
    AssetParams {
        total: f.total,
        decimals: f.decimals,
        default_frozen: f.default_frozen,
        unit_name: f.unit_name.clone(),
        asset_name: f.asset_name.clone(),
        url: f.url.clone(),
        metadata_hash: f.metadata_hash,
        manager: maybe_address(&f.manager),
        reserve: maybe_address(&f.reserve),
        freeze: maybe_address(&f.freeze),
        clawback: maybe_address(&f.clawback),
    }
}

fn rebuild_app_local_state(f: &RowFields) -> AppLocalState {
    AppLocalState {
        schema: StateSchema {
            num_uint: f.local_schema_nui,
            num_byte_slice: f.local_schema_nbs,
        },
        key_value: f.local_kv.clone(),
    }
}

fn rebuild_app_params(f: &RowFields) -> AppParams {
    AppParams {
        // Creator is stored in `assetcreators` table, NOT in the resource
        // BLOB. Using a placeholder is correct because the encoder ignores
        // it.
        creator: Address([0u8; 32]),
        approval_program: f.approval.clone(),
        clear_state_program: f.clear_state.clone(),
        global_state: f.global_state.clone(),
        local_state_schema: StateSchema {
            num_uint: f.local_state_schema_nui,
            num_byte_slice: f.local_state_schema_nbs,
        },
        global_state_schema: StateSchema {
            num_uint: f.global_state_schema_nui,
            num_byte_slice: f.global_state_schema_nbs,
        },
        extra_program_pages: f.extra_program_pages,
    }
}

/// Classify a row by its `y` flag bits (Go's bitwise enum):
///   `(y & NOT_HOLDING) == 0` ⇒ holding subset valid
///   `(y & OWNERSHIP)   != 0` ⇒ ownership subset valid
fn has_holding(raw_y: u64) -> bool {
    (raw_y & resource_flags::NOT_HOLDING as u64) == 0
        && (raw_y & resource_flags::EMPTY_ASSET as u64) == 0
        && (raw_y & resource_flags::EMPTY_APP as u64) == 0
}

fn has_ownership(raw_y: u64) -> bool {
    (raw_y & resource_flags::OWNERSHIP as u64) != 0
}

/// Parse `<addrhex>_<aidx>_<ctype>.canonical.hex` and return `ctype`.
/// `ctype == 0` means asset; `ctype == 1` means app.
fn ctype_from_name(name: &str) -> u8 {
    let stem = name.strip_suffix(".canonical.hex").unwrap_or(name);
    let mut parts = stem.rsplit('_');
    let ctype_str = parts.next().expect("ctype segment");
    ctype_str.parse::<u8>().expect("ctype is u8")
}

#[test]
fn resourcesdata_byte_identity_via_ledger_encoders() {
    let fixtures = load_hex_files();
    if fixtures.is_empty() {
        eprintln!(
            "SKIPPED: no resourcesdata fixtures at {}. Run `make extract-trackerdb-fixtures` \
             against a populated localnet to generate them.",
            fixtures_root().display()
        );
        return;
    }

    let mut checked = 0;
    for (name, expected) in &fixtures {
        let ctype = ctype_from_name(name);
        let fields = walk(expected);

        let actual = match (ctype, has_holding(fields.raw_y), has_ownership(fields.raw_y)) {
            // Asset rows
            (0, true, false) => {
                let h = rebuild_asset_holding(&fields);
                encode_asset_holding_with_round(&h, fields.update_round)
            }
            (0, false, true) => {
                let p = rebuild_asset_params(&fields);
                let creator = Address([0u8; 32]);
                encode_asset_params_with_round(&p, &creator, fields.update_round)
            }
            (0, true, true) => {
                // Combined creator-with-own-holding row.
                let h = rebuild_asset_holding(&fields);
                let p = rebuild_asset_params(&fields);
                let rd =
                    build_asset_resource_data(Some(&h), Some(&p), fields.update_round);
                algo_codec::canonical_encode_resources_data(&rd)
            }

            // App rows
            (1, true, false) => {
                let s = rebuild_app_local_state(&fields);
                encode_app_local_state_with_round(&s, fields.update_round)
            }
            (1, false, true) => {
                let p = rebuild_app_params(&fields);
                encode_app_params_with_round(&p, fields.update_round)
            }
            (1, true, true) => {
                let s = rebuild_app_local_state(&fields);
                let p = rebuild_app_params(&fields);
                let rd = build_app_resource_data(Some(&s), Some(&p), fields.update_round);
                algo_codec::canonical_encode_resources_data(&rd)
            }

            (ctype, h, o) => panic!(
                "unexpected fixture shape: ctype={ctype} has_holding={h} has_ownership={o} for {name}"
            ),
        };

        assert_eq!(
            hex::encode(&actual),
            hex::encode(expected),
            "byte-identity mismatch for {name} (ctype={ctype}, y={})",
            fields.raw_y
        );
        checked += 1;
    }

    println!("resourcesdata byte-identity via algo-ledger encoders: {checked} fixtures ✓");
}
