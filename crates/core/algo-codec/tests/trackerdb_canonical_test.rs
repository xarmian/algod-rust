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

use algo_codec::canonical_encode_base_account_data;
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
