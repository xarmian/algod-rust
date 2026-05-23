//! Byte-exact conformance tests for trackerdb BLOB canonical encoders
//! against Go-produced fixtures captured by
//! `make extract-trackerdb-fixtures` (PLAN-36 G8 / TASK-119).
//!
//! Each test walks `tests/fixtures/trackerdb/<type>/*.canonical.hex`,
//! decodes one row, re-encodes it through the canonical encoder under
//! test, and asserts byte-identity. A missing or empty fixture
//! directory is tolerated with a `SKIPPED` print so the test suite
//! stays green on checkouts that haven't yet run the capture step.
//!
//! Today the only encoder under test is
//! `canonical_encode_base_account_data` (TASK-120). The shared
//! decoder helper at the bottom intentionally lives in this file —
//! it's a minimal `rmpv::Value` → `AccountData` walker used only for
//! "decode fixture → re-encode → assert" round-trips. The catchpoint
//! decoder (`msgp_compat::decode_base_account_data`) is out of scope
//! for TASK-120.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use algo_codec::{
    canonical_encode_base_account_data, canonical_encode_base_online_account_data,
    canonical_encode_online_round_params_data, canonical_encode_resources_data,
    canonical_encode_txtail_round, BaseOnlineAccountData, OnlineRoundParamsData, ResourcesData,
};
use algo_types::{AccountData, AccountStatus, Address};

/// Root of the trackerdb fixture corpus, relative to the crate manifest.
fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trackerdb")
}

/// Read every `<basename>.canonical.hex` file under `dir`, returning
/// `(basename, raw_bytes)` pairs. Returns an empty Vec when the dir
/// doesn't exist or contains no fixtures — callers print SKIPPED.
fn load_canonical_hex_dir(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(it) => it,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".canonical.hex") else {
            continue;
        };
        let raw =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let bytes = hex::decode(raw.trim())
            .unwrap_or_else(|e| panic!("invalid hex in {}: {e}", path.display()));
        out.push((stem.to_string(), bytes));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn base_account_data_byte_exact_against_go_fixtures() {
    let dir = fixtures_root().join("baseaccountdata");
    let fixtures = load_canonical_hex_dir(&dir);
    if fixtures.is_empty() {
        eprintln!(
            "SKIPPED: no baseaccountdata fixtures at {}. \
             Run `make extract-trackerdb-fixtures` against a populated localnet to generate them.",
            dir.display()
        );
        return;
    }

    let mut checked = 0;
    for (name, expected) in &fixtures {
        let acct = decode_base_account_data_value(expected)
            .unwrap_or_else(|e| panic!("decode fixture baseaccountdata/{name}.canonical.hex: {e}"));
        let actual = canonical_encode_base_account_data(&acct);
        assert_eq!(
            hex::encode(&actual),
            hex::encode(expected),
            "byte-exact mismatch for baseaccountdata/{name}.canonical.hex"
        );
        checked += 1;
    }
    println!("baseaccountdata: {checked} fixtures byte-exact ✓");
}

/// PLAN-36 G8 (TASK-120): round-trip property — decode any fixture,
/// re-encode through the canonical encoder, decode again, and confirm
/// the second decode yields the same `AccountData`. Guards against an
/// encoder that drops fields the decoder retains (e.g. omitempty drift).
#[test]
fn base_account_data_round_trip_via_value() {
    let dir = fixtures_root().join("baseaccountdata");
    let fixtures = load_canonical_hex_dir(&dir);
    if fixtures.is_empty() {
        eprintln!("SKIPPED: no baseaccountdata fixtures at {}.", dir.display());
        return;
    }

    for (name, raw) in &fixtures {
        let first = decode_base_account_data_value(raw)
            .unwrap_or_else(|e| panic!("decode baseaccountdata/{name}.canonical.hex: {e}"));
        let encoded = canonical_encode_base_account_data(&first);
        let second = decode_base_account_data_value(&encoded)
            .unwrap_or_else(|e| panic!("re-decode after encode baseaccountdata/{name}: {e}"));
        assert_eq!(first, second, "round-trip drift on baseaccountdata/{name}");
    }
}

// ---------------------------------------------------------------------------
// BaseOnlineAccountData byte-exact + round-trip (PLAN-36 G8 / TASK-121)
// ---------------------------------------------------------------------------

#[test]
fn base_online_account_data_byte_exact_against_go_fixtures() {
    let dir = fixtures_root().join("baseonlineaccountdata");
    let fixtures = load_canonical_hex_dir(&dir);
    if fixtures.is_empty() {
        eprintln!(
            "SKIPPED: no baseonlineaccountdata fixtures at {}. \
             Run `make extract-trackerdb-fixtures` against a populated localnet to generate them.",
            dir.display()
        );
        return;
    }

    let mut checked = 0;
    for (name, expected) in &fixtures {
        let decoded = decode_base_online_account_data_value(expected)
            .unwrap_or_else(|e| panic!("decode baseonlineaccountdata/{name}.canonical.hex: {e}"));
        let actual = canonical_encode_base_online_account_data(&decoded);
        assert_eq!(
            hex::encode(&actual),
            hex::encode(expected),
            "byte-exact mismatch for baseonlineaccountdata/{name}.canonical.hex"
        );
        checked += 1;
    }
    println!("baseonlineaccountdata: {checked} fixtures byte-exact ✓");
}

#[test]
fn base_online_account_data_round_trip_via_value() {
    let dir = fixtures_root().join("baseonlineaccountdata");
    let fixtures = load_canonical_hex_dir(&dir);
    if fixtures.is_empty() {
        eprintln!(
            "SKIPPED: no baseonlineaccountdata fixtures at {}.",
            dir.display()
        );
        return;
    }

    for (name, raw) in &fixtures {
        let first = decode_base_online_account_data_value(raw)
            .unwrap_or_else(|e| panic!("decode baseonlineaccountdata/{name}.canonical.hex: {e}"));
        let encoded = canonical_encode_base_online_account_data(&first);
        let second = decode_base_online_account_data_value(&encoded)
            .unwrap_or_else(|e| panic!("re-decode after encode baseonlineaccountdata/{name}: {e}"));
        assert_eq!(
            first, second,
            "round-trip drift on baseonlineaccountdata/{name}"
        );
    }
}

/// Minimal rmpv-walker for trackerdb `BaseOnlineAccountData`. Only used
/// to decode fixtures back into a struct so the round-trip + byte-exact
/// tests can re-encode them; the production decoder for this BLOB
/// lives in `algo_ledger::catchpoint::msgp_compat` (out of scope here).
fn decode_base_online_account_data_value(data: &[u8]) -> Result<BaseOnlineAccountData, String> {
    let val: rmpv::Value =
        rmpv::decode::read_value(&mut &data[..]).map_err(|e| format!("rmpv decode: {e}"))?;
    let pairs = match val {
        rmpv::Value::Map(m) => m,
        other => return Err(format!("expected msgpack map, got {other:?}")),
    };

    let mut d = BaseOnlineAccountData::default();
    for (k, v) in pairs {
        let key = k.as_str().ok_or_else(|| format!("non-string key: {k:?}"))?;
        match key {
            "A" => d.vote_id = as_array32(&v)?,
            "B" => d.selection_id = as_array32(&v)?,
            "C" => d.vote_first_valid = as_u64(&v),
            "D" => d.vote_last_valid = as_u64(&v),
            "E" => d.vote_key_dilution = as_u64(&v),
            "F" => d.state_proof_id = as_array64(&v)?,
            "V" => d.last_proposed = as_u64(&v),
            "W" => d.last_heartbeat = as_u64(&v),
            "X" => d.incentive_eligible = v.as_bool().unwrap_or(false),
            "Y" => d.micro_algos = as_u64(&v),
            "Z" => d.rewards_base = as_u64(&v),
            other => return Err(format!("unexpected BaseOnlineAccountData tag {other:?}")),
        }
    }
    Ok(d)
}

// ---------------------------------------------------------------------------
// ResourcesData byte-exact + round-trip (PLAN-36 G8 / TASK-122)
// ---------------------------------------------------------------------------

#[test]
fn resources_data_byte_exact_against_go_fixtures() {
    let dir = fixtures_root().join("resourcesdata");
    let fixtures = load_canonical_hex_dir(&dir);
    if fixtures.is_empty() {
        eprintln!(
            "SKIPPED: no resourcesdata fixtures at {}. \
             Run `make extract-trackerdb-fixtures` against a populated localnet to generate them.",
            dir.display()
        );
        return;
    }

    let mut checked = 0;
    for (name, expected) in &fixtures {
        let decoded = decode_resources_data_value(expected)
            .unwrap_or_else(|e| panic!("decode resourcesdata/{name}.canonical.hex: {e}"));
        let actual = canonical_encode_resources_data(&decoded);
        assert_eq!(
            hex::encode(&actual),
            hex::encode(expected),
            "byte-exact mismatch for resourcesdata/{name}.canonical.hex"
        );
        checked += 1;
    }
    println!("resourcesdata: {checked} fixtures byte-exact ✓");
}

#[test]
fn resources_data_round_trip_via_value() {
    let dir = fixtures_root().join("resourcesdata");
    let fixtures = load_canonical_hex_dir(&dir);
    if fixtures.is_empty() {
        eprintln!("SKIPPED: no resourcesdata fixtures at {}.", dir.display());
        return;
    }

    for (name, raw) in &fixtures {
        let first = decode_resources_data_value(raw)
            .unwrap_or_else(|e| panic!("decode resourcesdata/{name}.canonical.hex: {e}"));
        let encoded = canonical_encode_resources_data(&first);
        let second = decode_resources_data_value(&encoded)
            .unwrap_or_else(|e| panic!("re-decode after encode resourcesdata/{name}: {e}"));
        assert_eq!(first, second, "round-trip drift on resourcesdata/{name}");
    }
}

/// Minimal rmpv-walker for trackerdb `ResourcesData`. Only used by the
/// fixture-driven tests; the production decoder lives in
/// `algo_ledger::catchpoint::msgp_compat`.
///
/// For the `p` (local key-value) and `s` (global state) fields the
/// walker stores the **raw msgpack bytes** of the nested map exactly
/// as encoded by Go — that's the contract `canonical_encode_resources_data`
/// expects when re-encoding (it embeds those bytes verbatim).
fn decode_resources_data_value(data: &[u8]) -> Result<ResourcesData, String> {
    let val: rmpv::Value =
        rmpv::decode::read_value(&mut &data[..]).map_err(|e| format!("rmpv decode: {e}"))?;
    let pairs = match val {
        rmpv::Value::Map(m) => m,
        other => return Err(format!("expected msgpack map, got {other:?}")),
    };

    let mut d = ResourcesData::default();
    for (k, v) in pairs {
        let key = k.as_str().ok_or_else(|| format!("non-string key: {k:?}"))?;
        match key {
            // Asset params (a-k).
            "a" => d.total = as_u64(&v),
            "b" => d.decimals = as_u64(&v) as u32,
            "c" => d.default_frozen = v.as_bool().unwrap_or(false),
            "d" => d.unit_name = as_str(&v)?,
            "e" => d.asset_name = as_str(&v)?,
            "f" => d.url = as_str(&v)?,
            "g" => d.metadata_hash = as_array32(&v)?,
            "h" => d.manager = as_array32(&v)?,
            "i" => d.reserve = as_array32(&v)?,
            "j" => d.freeze = as_array32(&v)?,
            "k" => d.clawback = as_array32(&v)?,
            // Asset holding (l-m).
            "l" => d.amount = as_u64(&v),
            "m" => d.frozen = v.as_bool().unwrap_or(false),
            // App local state (n-p).
            "n" => d.schema_num_uint = as_u64(&v),
            "o" => d.schema_num_byte_slice = as_u64(&v),
            "p" => d.key_value = reencode_map_value(&v)?,
            // App params (q-x).
            "q" => d.approval_program = as_bytes(&v)?,
            "r" => d.clear_state_program = as_bytes(&v)?,
            "s" => d.global_state = reencode_map_value(&v)?,
            "t" => d.local_state_schema_num_uint = as_u64(&v),
            "u" => d.local_state_schema_num_byte_slice = as_u64(&v),
            "v" => d.global_state_schema_num_uint = as_u64(&v),
            "w" => d.global_state_schema_num_byte_slice = as_u64(&v),
            "x" => d.extra_program_pages = as_u64(&v) as u32,
            // Flags + metadata (y, z, A, B).
            "y" => d.resource_flags = as_u64(&v) as u8,
            "z" => d.update_round = as_u64(&v),
            "A" => d.version = as_u64(&v),
            "B" => d.size_sponsor = as_array32(&v)?,
            other => return Err(format!("unexpected ResourcesData tag {other:?}")),
        }
    }
    Ok(d)
}

fn as_str(v: &rmpv::Value) -> Result<String, String> {
    v.as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("expected string, got {v:?}"))
}

fn as_bytes(v: &rmpv::Value) -> Result<Vec<u8>, String> {
    v.as_slice()
        .map(|b| b.to_vec())
        .ok_or_else(|| format!("expected bytes, got {v:?}"))
}

/// Re-encode a generic `rmpv::Value::Map` to canonical msgpack bytes
/// for embedding through `add_map`. Because the fixtures already came
/// from Go (which produced canonical output), a re-encode through
/// `rmpv::encode::write_value` over the same key order produces the
/// same bytes.
fn reencode_map_value(v: &rmpv::Value) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, v).map_err(|e| format!("re-encode map: {e}"))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// OnlineRoundParamsData byte-exact + round-trip (PLAN-36 G8 / TASK-123)
// ---------------------------------------------------------------------------

#[test]
fn online_round_params_data_byte_exact_against_go_fixtures() {
    let dir = fixtures_root().join("onlineroundparams");
    let fixtures = load_canonical_hex_dir(&dir);
    if fixtures.is_empty() {
        eprintln!(
            "SKIPPED: no onlineroundparams fixtures at {}. \
             Run `make extract-trackerdb-fixtures` against a populated localnet to generate them.",
            dir.display()
        );
        return;
    }

    let mut checked = 0;
    for (name, expected) in &fixtures {
        let decoded = decode_online_round_params_data_value(expected)
            .unwrap_or_else(|e| panic!("decode onlineroundparams/{name}.canonical.hex: {e}"));
        let actual = canonical_encode_online_round_params_data(&decoded);
        assert_eq!(
            hex::encode(&actual),
            hex::encode(expected),
            "byte-exact mismatch for onlineroundparams/{name}.canonical.hex"
        );
        checked += 1;
    }
    println!("onlineroundparams: {checked} fixtures byte-exact ✓");
}

#[test]
fn online_round_params_data_round_trip_via_value() {
    let dir = fixtures_root().join("onlineroundparams");
    let fixtures = load_canonical_hex_dir(&dir);
    if fixtures.is_empty() {
        eprintln!(
            "SKIPPED: no onlineroundparams fixtures at {}.",
            dir.display()
        );
        return;
    }

    for (name, raw) in &fixtures {
        let first = decode_online_round_params_data_value(raw)
            .unwrap_or_else(|e| panic!("decode onlineroundparams/{name}.canonical.hex: {e}"));
        let encoded = canonical_encode_online_round_params_data(&first);
        let second = decode_online_round_params_data_value(&encoded)
            .unwrap_or_else(|e| panic!("re-decode after encode onlineroundparams/{name}: {e}"));
        assert_eq!(
            first, second,
            "round-trip drift on onlineroundparams/{name}"
        );
    }
}

/// Minimal rmpv-walker for `OnlineRoundParamsData`. Used only by the
/// fixture-driven tests; the production decoder lives in
/// `algo_ledger::catchpoint::msgp_compat`.
fn decode_online_round_params_data_value(data: &[u8]) -> Result<OnlineRoundParamsData, String> {
    let val: rmpv::Value =
        rmpv::decode::read_value(&mut &data[..]).map_err(|e| format!("rmpv decode: {e}"))?;
    let pairs = match val {
        rmpv::Value::Map(m) => m,
        other => return Err(format!("expected msgpack map, got {other:?}")),
    };
    let mut d = OnlineRoundParamsData::default();
    for (k, v) in pairs {
        let key = k.as_str().ok_or_else(|| format!("non-string key: {k:?}"))?;
        match key {
            "online" => d.online_supply = as_u64(&v),
            "proto" => d.current_protocol = as_str(&v)?,
            "rwdlvl" => d.rewards_level = as_u64(&v),
            other => return Err(format!("unexpected OnlineRoundParamsData tag {other:?}")),
        }
    }
    Ok(d)
}

// ---------------------------------------------------------------------------
// TxTailRound byte-exact + round-trip (PLAN-36 G8 / TASK-124)
//
// `canonical_encode_txtail_round` already existed (block-derived). This
// adds fixture coverage using actual `txtail.data` BLOBs captured from
// go-algorand, plus the round-trip property.
// ---------------------------------------------------------------------------

#[test]
fn txtail_round_byte_exact_against_go_fixtures() {
    use algo_types::TxTailRound;

    let dir = fixtures_root().join("txtailround");
    let fixtures = load_canonical_hex_dir(&dir);
    if fixtures.is_empty() {
        eprintln!(
            "SKIPPED: no txtailround fixtures at {}. \
             Run `make extract-trackerdb-fixtures` against a populated localnet to generate them.",
            dir.display()
        );
        return;
    }

    let mut checked = 0;
    for (name, expected) in &fixtures {
        // Use rmp_serde to decode the Go-produced bytes through the
        // existing `TxTailRound` serde derive. The encoder is the
        // unit under test here; the decode side is incidental.
        let decoded: TxTailRound = rmp_serde::from_slice(expected)
            .unwrap_or_else(|e| panic!("rmp_serde decode txtailround/{name}: {e}"));
        let actual = canonical_encode_txtail_round(&decoded);
        assert_eq!(
            hex::encode(&actual),
            hex::encode(expected),
            "byte-exact mismatch for txtailround/{name}.canonical.hex"
        );
        checked += 1;
    }
    println!("txtailround: {checked} fixtures byte-exact ✓");
}

#[test]
fn txtail_round_round_trip_via_value() {
    use algo_types::TxTailRound;

    let dir = fixtures_root().join("txtailround");
    let fixtures = load_canonical_hex_dir(&dir);
    if fixtures.is_empty() {
        eprintln!("SKIPPED: no txtailround fixtures at {}.", dir.display());
        return;
    }

    for (name, raw) in &fixtures {
        let first: TxTailRound = rmp_serde::from_slice(raw)
            .unwrap_or_else(|e| panic!("rmp_serde decode txtailround/{name}: {e}"));
        let encoded = canonical_encode_txtail_round(&first);
        let second: TxTailRound = rmp_serde::from_slice(&encoded)
            .unwrap_or_else(|e| panic!("re-decode after encode txtailround/{name}: {e}"));
        assert_eq!(first, second, "round-trip drift on txtailround/{name}");
    }
}

// ---------------------------------------------------------------------------
// Local minimal decoder.
//
// Reads a msgpack map of trackerdb BaseAccountData tags into the
// algo-types AccountData base fields. Resource maps (apar/appl/appp/asset)
// are *not* part of trackerdb's BaseAccountData and remain at their
// `Default` values on the result struct.
// ---------------------------------------------------------------------------

fn decode_base_account_data_value(data: &[u8]) -> Result<AccountData, String> {
    let val: rmpv::Value =
        rmpv::decode::read_value(&mut &data[..]).map_err(|e| format!("rmpv decode: {e}"))?;
    let pairs = match val {
        rmpv::Value::Map(m) => m,
        other => return Err(format!("expected msgpack map, got {other:?}")),
    };

    let mut acct = AccountData {
        // Mirror what the live ledger does — resource maps default empty.
        asset_params: BTreeMap::new(),
        assets: BTreeMap::new(),
        app_local_states: BTreeMap::new(),
        app_params: BTreeMap::new(),
        ..AccountData::default()
    };

    for (k, v) in pairs {
        let key = k.as_str().ok_or_else(|| format!("non-string key: {k:?}"))?;
        match key {
            "a" => acct.status = AccountStatus::from(as_u64(&v) as u8),
            "b" => acct.micro_algos = as_u64(&v),
            "c" => acct.rewards_base = as_u64(&v),
            "d" => acct.rewarded_micro_algos = as_u64(&v),
            "e" => acct.auth_addr = Some(Address(as_array32(&v)?)),
            "f" => acct.total_app_schema.num_uint = as_u64(&v),
            "g" => acct.total_app_schema.num_byte_slice = as_u64(&v),
            "h" => acct.total_extra_app_pages = as_u64(&v) as u32,
            "i" => acct.total_created_assets = as_u64(&v),
            "j" => acct.total_assets_opted_in = as_u64(&v),
            "k" => acct.total_created_apps = as_u64(&v),
            "l" => acct.total_apps_opted_in = as_u64(&v),
            "m" => acct.total_boxes = as_u64(&v),
            "n" => acct.total_box_bytes = as_u64(&v),
            "o" => acct.incentive_eligible = v.as_bool().unwrap_or(false),
            "p" => acct.last_proposed = as_u64(&v),
            "q" => acct.last_heartbeat = as_u64(&v),
            "A" => acct.vote_id = Some(as_array32(&v)?),
            "B" => acct.selection_id = Some(as_array32(&v)?),
            "C" => acct.vote_first_valid = as_u64(&v),
            "D" => acct.vote_last_valid = as_u64(&v),
            "E" => acct.vote_key_dilution = as_u64(&v),
            "F" => acct.state_proof_id = Some(as_array64(&v)?),
            "z" => acct.update_round = as_u64(&v),
            other => return Err(format!("unexpected BaseAccountData tag {other:?}")),
        }
    }

    Ok(acct)
}

fn as_u64(v: &rmpv::Value) -> u64 {
    v.as_u64().unwrap_or(0)
}

fn as_array32(v: &rmpv::Value) -> Result<[u8; 32], String> {
    let bytes = v
        .as_slice()
        .ok_or_else(|| format!("expected bytes, got {v:?}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn as_array64(v: &rmpv::Value) -> Result<[u8; 64], String> {
    let bytes = v
        .as_slice()
        .ok_or_else(|| format!("expected bytes, got {v:?}"))?;
    if bytes.len() != 64 {
        return Err(format!("expected 64 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(bytes);
    Ok(out)
}
