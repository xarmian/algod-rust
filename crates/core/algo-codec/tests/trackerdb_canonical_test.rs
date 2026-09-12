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
    canonical_encode_state_proof_verification_context, canonical_encode_teal_key_value,
    canonical_encode_txtail_round, BaseOnlineAccountData, OnlineRoundParamsData, ResourcesData,
    StateProofVerificationContext,
};
use algo_types::{AccountData, AccountStatus, Address, BlockHeader, StateSchema, TealValue};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

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

/// go's `TestBaseAccountDataDecodeEmpty`
/// (`ledger/store/trackerdb/data_test.go`): decoding zero-length input must
/// error (there's no valid empty msgpack encoding of a missing value), while
/// decoding an explicit empty msgpack map (`0x80`) must succeed and yield an
/// all-default `BaseAccountData`/`AccountData`. Uses the same
/// `decode_base_account_data_value` helper the byte-exact/round-trip tests
/// above exercise against real fixtures.
#[test]
fn base_account_data_decode_empty() {
    let err = decode_base_account_data_value(&[])
        .expect_err("decoding zero-length input must error, not silently default");
    assert!(
        !err.is_empty(),
        "expected a non-empty error message for zero-length input"
    );

    let empty_map = decode_base_account_data_value(&[0x80])
        .expect("decoding an explicit empty msgpack map must succeed");
    assert_eq!(
        empty_map,
        AccountData {
            asset_params: BTreeMap::new(),
            assets: BTreeMap::new(),
            app_local_states: BTreeMap::new(),
            app_params: BTreeMap::new(),
            ..AccountData::default()
        },
        "an empty map must decode to an all-default account"
    );
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
            // Flags + metadata (y, z, A, B, C, D).
            "y" => d.resource_flags = as_u64(&v) as u8,
            "z" => d.update_round = as_u64(&v),
            "A" => d.version = as_u64(&v),
            "B" => d.size_sponsor = as_array32(&v)?,
            // Issue #659: `foreign_box_reads`/`family_box_access` (codec
            // `C`/`D`) were added to `canonical_encode_resources_data`
            // but never wired into this test-only decoder — dead until
            // the randomized round-trip test below started setting them
            // to `true` (existing byte-exact fixtures apparently never
            // captured a row with either flag set, since `add_bool`
            // omits `false` from the wire).
            "C" => d.foreign_box_reads = v.as_bool().unwrap_or(false),
            "D" => d.family_box_access = v.as_bool().unwrap_or(false),
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
// StateProofVerificationContext byte-exact + round-trip (PLAN-36 G8 / TASK-125)
//
// State-proof rows only exist on networks that have actually produced
// state proofs — a fresh localnet won't have any, so the captured
// fixture dir typically contains only `_meta.json` with `row_count: 0`.
// Both tests SKIP gracefully in that case (matching the behavior the
// task body explicitly tolerates).
// ---------------------------------------------------------------------------

#[test]
fn state_proof_verification_context_byte_exact_against_go_fixtures() {
    let dir = fixtures_root().join("stateproof");
    let fixtures = load_canonical_hex_dir(&dir);
    if fixtures.is_empty() {
        eprintln!(
            "SKIPPED: no stateproof fixtures at {}. State-proof rows \
             land only on networks that have produced ≥256 rounds with \
             state-proof participation enabled — see `_meta.json` for \
             provenance of the empty capture.",
            dir.display()
        );
        return;
    }

    let mut checked = 0;
    for (name, expected) in &fixtures {
        let decoded = decode_state_proof_verification_context_value(expected)
            .unwrap_or_else(|e| panic!("decode stateproof/{name}.canonical.hex: {e}"));
        let actual = canonical_encode_state_proof_verification_context(&decoded);
        assert_eq!(
            hex::encode(&actual),
            hex::encode(expected),
            "byte-exact mismatch for stateproof/{name}.canonical.hex"
        );
        checked += 1;
    }
    println!("stateproof: {checked} fixtures byte-exact ✓");
}

#[test]
fn state_proof_verification_context_round_trip_via_value() {
    let dir = fixtures_root().join("stateproof");
    let fixtures = load_canonical_hex_dir(&dir);
    if fixtures.is_empty() {
        eprintln!("SKIPPED: no stateproof fixtures at {}.", dir.display());
        return;
    }

    for (name, raw) in &fixtures {
        let first = decode_state_proof_verification_context_value(raw)
            .unwrap_or_else(|e| panic!("decode stateproof/{name}.canonical.hex: {e}"));
        let encoded = canonical_encode_state_proof_verification_context(&first);
        let second = decode_state_proof_verification_context_value(&encoded)
            .unwrap_or_else(|e| panic!("re-decode after encode stateproof/{name}: {e}"));
        assert_eq!(first, second, "round-trip drift on stateproof/{name}");
    }
}

/// PLAN-36 G8 (TASK-125): an additional algebraic round-trip on
/// synthetic data, so the encoder is exercised end-to-end even when
/// the localnet capture didn't produce real fixtures. Covers the
/// per-field omitempty contract that fixture absence would otherwise
/// leave unverified.
#[test]
fn state_proof_verification_context_round_trip_synthetic() {
    let cases = [
        StateProofVerificationContext::default(),
        StateProofVerificationContext {
            last_attested_round: 256,
            voters_commitment: vec![0xab; 32],
            online_total_weight: 10_000_000,
            version: "future".into(),
        },
        // Only the trio fields populated, no version — exercises the
        // `v` omitempty path.
        StateProofVerificationContext {
            last_attested_round: 512,
            voters_commitment: vec![1, 2, 3, 4],
            online_total_weight: 42,
            version: String::new(),
        },
    ];
    for (i, ctx) in cases.iter().enumerate() {
        let encoded = canonical_encode_state_proof_verification_context(ctx);
        let decoded = decode_state_proof_verification_context_value(&encoded)
            .unwrap_or_else(|e| panic!("round-trip case[{i}]: {e}"));
        assert_eq!(*ctx, decoded, "synthetic round-trip drift case[{i}]");
    }
}

/// Issue #1059: `algo_codec::StateProofVerificationContext` gained a
/// `Serialize` impl so `catchpoint/importer.rs`'s `rmp_serde::to_vec_named`
/// re-encode path can use this one shared type instead of maintaining a
/// third hand-copied mirror in `catchpoint::types`. Confirm: (1) the
/// rename tags match go's `spround`/`vc`/`pw`/`v`, (2) only `version` is
/// omitted when empty — the exact behavior
/// `catchpoint::types::StateProofVerificationContext` had before this
/// consolidation, which the importer's re-encode path must not change —
/// and (3) the type round-trips through `rmp_serde`'s own Serialize impl
/// (not just the hand-rolled canonical encoder exercised above).
#[test]
fn state_proof_verification_context_serialize_via_rmp_serde_matches_prior_shape() {
    let ctx = StateProofVerificationContext {
        last_attested_round: 120,
        voters_commitment: Vec::new(),
        online_total_weight: 100,
        version: String::new(),
    };
    let bytes = rmp_serde::to_vec_named(&ctx).expect("serialize via rmp_serde");
    let val: rmpv::Value = rmpv::decode::read_value(&mut &bytes[..]).expect("decode as rmpv");
    let map = val.as_map().expect("must encode as a map");
    let keys: Vec<&str> = map.iter().map(|(k, _)| k.as_str().unwrap()).collect();
    assert!(keys.contains(&"spround"), "missing spround tag: {keys:?}");
    assert!(keys.contains(&"vc"), "missing vc tag: {keys:?}");
    assert!(keys.contains(&"pw"), "missing pw tag: {keys:?}");
    assert!(
        !keys.contains(&"v"),
        "empty version must be omitted from the wire, matching \
         catchpoint::types::StateProofVerificationContext's prior \
         skip_serializing_if behavior: {keys:?}"
    );

    let round_tripped: StateProofVerificationContext =
        rmp_serde::from_slice(&bytes).expect("decode via rmp_serde");
    assert_eq!(round_tripped, ctx);

    // A non-empty version must be present on the wire.
    let ctx_with_version = StateProofVerificationContext {
        version: "future".into(),
        ..ctx
    };
    let bytes_with_version =
        rmp_serde::to_vec_named(&ctx_with_version).expect("serialize via rmp_serde");
    let val_with_version: rmpv::Value =
        rmpv::decode::read_value(&mut &bytes_with_version[..]).expect("decode as rmpv");
    let map_with_version = val_with_version.as_map().expect("must encode as a map");
    assert!(
        map_with_version
            .iter()
            .any(|(k, _)| k.as_str() == Some("v")),
        "non-empty version must be present: {map_with_version:?}"
    );
    let round_tripped_with_version: StateProofVerificationContext =
        rmp_serde::from_slice(&bytes_with_version).expect("decode via rmp_serde");
    assert_eq!(round_tripped_with_version, ctx_with_version);
}

// ---------------------------------------------------------------------------
// Randomized encoding round-trips (Phase 17 issue #1322).
//
// Mirrors go-algorand's `TestRandomizedEncodingX` family
// (`ledger/store/trackerdb/msgp_gen_test.go`, `ledger/ledgercore/msgp_gen_test.go`),
// each a thin `protocol.RunEncodingTest(t, &SomeType{})` call: generate many
// instances of the type with randomized field values, msgpack round-trip
// each, and assert equality. go's version uses reflection to randomize
// *any* msgp-generated struct; algod-rust's trackerdb codecs are
// hand-written (not derive-generated), so each type here gets its own
// small random-instance generator, following the same
// `assert_randomized_roundtrip` pattern already established for
// `algo-consensus-crypto`'s merklearray/merklesig codecs
// (`crates/core/algo-consensus-crypto/tests/randomized_encoding_test.rs`,
// Phase 17 issue #826 theme 3). This closes the gap the prior
// fixture-based `*_round_trip_via_value` tests above left open: fixtures
// only exercise whatever field combinations happened to land on a live
// localnet, not the full omitempty/zero-value boundary space per field.
//
// Covers (docs/phase17/parity_ledger_core.md rows, all previously
// `partial`):
// - TestRandomizedEncodingBaseAccountData
// - TestRandomizedEncodingBaseOnlineAccountData
// - TestMarshalUnmarshalBaseVotingData / TestRandomizedEncodingBaseVotingData
//   (BaseVotingData has no standalone Rust type — it's the embedded `A`-`F`
//   tag block inlined into both `AccountData`'s base fields and
//   `BaseOnlineAccountData`; exercising it as embedded fields inside both
//   parent randomized round-trips is the direct on-disk-shape equivalent,
//   not a step down from testing an isolated struct)
// - TestRandomizedEncodingResourcesData
// - TestRandomizedEncodingStateProofVerificationContext
// - TestRandomizedEncodingTxTailRound / TestRandomizedEncodingTxTailRoundLease
//   (`TxTailRoundLease` has no standalone wire encoder — it's only ever
//   encoded as an element of `TxTailRound.leases` via `rmp_serde`, so it is
//   exercised embedded, matching how it actually reaches the wire)
// ---------------------------------------------------------------------------

/// Number of randomized iterations per type, matching the spirit of go's
/// `protocol.RunEncodingTest` (`protocol/codec_tester.go`), which runs the
/// generate/encode/decode/compare cycle 1000 times per type.
const RANDOMIZED_ITERATIONS: usize = 500;

/// Shared randomized round-trip driver: generate `RANDOMIZED_ITERATIONS`
/// random instances of `T` via `gen`, encode each with `encode`, decode with
/// `decode`, and assert the decoded value equals the original exactly (not
/// merely self-consistent across a second encode/decode).
///
/// `seed` is a fixed, per-call constant so a failure reproduces
/// deterministically across CI runs (no OS-randomness dependency).
fn assert_randomized_roundtrip<T: PartialEq + std::fmt::Debug>(
    seed: u64,
    mut gen: impl FnMut(&mut ChaCha20Rng) -> T,
    encode: impl Fn(&T) -> Vec<u8>,
    decode: impl Fn(&[u8]) -> T,
) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    for i in 0..RANDOMIZED_ITERATIONS {
        let original = gen(&mut rng);
        let encoded = encode(&original);
        let decoded = decode(&encoded);
        assert_eq!(
            decoded, original,
            "randomized round-trip mismatch at iteration {i} (seed {seed:#x})"
        );
    }
}

fn gen_bytes32(rng: &mut ChaCha20Rng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}

fn gen_bytes64(rng: &mut ChaCha20Rng) -> [u8; 64] {
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    b
}

/// A 32-byte array that is never all-zero, so `Some(_)` round-trips through
/// the canonical encoders' `add_option_fixed_bytes`/`add_bytes`, which treat
/// an all-zero payload as omitempty (matching Go's zero-value omission) —
/// generating an all-zero `Some` would make the property under test
/// (`decoded == original`) fail for a reason that has nothing to do with a
/// real encoder bug.
fn gen_nonzero_bytes32(rng: &mut ChaCha20Rng) -> [u8; 32] {
    loop {
        let b = gen_bytes32(rng);
        if b.iter().any(|&x| x != 0) {
            return b;
        }
    }
}

fn gen_nonzero_bytes64(rng: &mut ChaCha20Rng) -> [u8; 64] {
    loop {
        let b = gen_bytes64(rng);
        if b.iter().any(|&x| x != 0) {
            return b;
        }
    }
}

fn gen_option_bytes32(rng: &mut ChaCha20Rng) -> Option<[u8; 32]> {
    if rng.gen_bool(0.5) {
        Some(gen_nonzero_bytes32(rng))
    } else {
        None
    }
}

fn gen_option_bytes64(rng: &mut ChaCha20Rng) -> Option<[u8; 64]> {
    if rng.gen_bool(0.5) {
        Some(gen_nonzero_bytes64(rng))
    } else {
        None
    }
}

fn gen_option_address(rng: &mut ChaCha20Rng) -> Option<Address> {
    if rng.gen_bool(0.5) {
        Some(Address(gen_nonzero_bytes32(rng)))
    } else {
        None
    }
}

fn gen_string(rng: &mut ChaCha20Rng, max_len: usize) -> String {
    let len = rng.gen_range(0..=max_len);
    (0..len)
        .map(|_| char::from(rng.gen_range(b'a'..=b'z')))
        .collect()
}

fn gen_bytes_vec(rng: &mut ChaCha20Rng, max_len: usize) -> Vec<u8> {
    let len = rng.gen_range(0..=max_len);
    let mut v = vec![0u8; len];
    rng.fill_bytes(&mut v);
    v
}

/// Random `AccountData`, populated only in the fields
/// `canonical_encode_base_account_data` actually reads (the
/// `trackerdb.BaseAccountData` shape) — the resource maps
/// (`asset_params`/`assets`/`app_local_states`/`app_params`) are never
/// part of that BLOB and stay at their `Default` (empty) value, matching
/// what `decode_base_account_data_value` itself always produces.
fn gen_base_account_data(rng: &mut ChaCha20Rng) -> AccountData {
    AccountData {
        status: AccountStatus::from(rng.gen_range(0u8..=2)),
        micro_algos: rng.gen(),
        rewards_base: rng.gen(),
        rewarded_micro_algos: rng.gen(),
        auth_addr: gen_option_address(rng),
        total_app_schema: StateSchema {
            num_uint: rng.gen(),
            num_byte_slice: rng.gen(),
        },
        total_extra_app_pages: rng.gen(),
        total_created_assets: rng.gen(),
        total_assets_opted_in: rng.gen(),
        total_created_apps: rng.gen(),
        total_apps_opted_in: rng.gen(),
        total_boxes: rng.gen(),
        total_box_bytes: rng.gen(),
        incentive_eligible: rng.gen(),
        last_proposed: rng.gen(),
        last_heartbeat: rng.gen(),
        update_round: rng.gen(),
        vote_id: gen_option_bytes32(rng),
        selection_id: gen_option_bytes32(rng),
        state_proof_id: gen_option_bytes64(rng),
        vote_first_valid: rng.gen(),
        vote_last_valid: rng.gen(),
        vote_key_dilution: rng.gen(),
        asset_params: BTreeMap::new(),
        assets: BTreeMap::new(),
        app_local_states: BTreeMap::new(),
        app_params: BTreeMap::new(),
    }
}

#[test]
fn base_account_data_randomized_roundtrip() {
    assert_randomized_roundtrip(
        0xba5e_acc0,
        gen_base_account_data,
        canonical_encode_base_account_data,
        |data| decode_base_account_data_value(data).expect("decode randomized baseaccountdata"),
    );
}

fn gen_base_online_account_data(rng: &mut ChaCha20Rng) -> BaseOnlineAccountData {
    BaseOnlineAccountData {
        vote_id: gen_nonzero_or_zero_bytes32(rng),
        selection_id: gen_nonzero_or_zero_bytes32(rng),
        vote_first_valid: rng.gen(),
        vote_last_valid: rng.gen(),
        vote_key_dilution: rng.gen(),
        state_proof_id: gen_nonzero_or_zero_bytes64(rng),
        last_proposed: rng.gen(),
        last_heartbeat: rng.gen(),
        incentive_eligible: rng.gen(),
        micro_algos: rng.gen(),
        rewards_base: rng.gen(),
    }
}

/// Unlike the `Option<[u8; 32]>` fields on `AccountData`, `BaseOnlineAccountData`
/// stores these as bare `[u8; 32]` — there is no `None` state to distinguish
/// from "all zero", so an actual all-zero array is a legitimate value here
/// (it round-trips as an omitted-then-defaulted-back-to-zero field, which is
/// the correct value either way). Bias towards nonzero so most iterations
/// still exercise the tag-present path, but don't forbid zero outright.
fn gen_nonzero_or_zero_bytes32(rng: &mut ChaCha20Rng) -> [u8; 32] {
    if rng.gen_bool(0.9) {
        gen_nonzero_bytes32(rng)
    } else {
        [0u8; 32]
    }
}

fn gen_nonzero_or_zero_bytes64(rng: &mut ChaCha20Rng) -> [u8; 64] {
    if rng.gen_bool(0.9) {
        gen_nonzero_bytes64(rng)
    } else {
        [0u8; 64]
    }
}

#[test]
fn base_online_account_data_randomized_roundtrip() {
    assert_randomized_roundtrip(
        0xba5e_0271,
        gen_base_online_account_data,
        canonical_encode_base_online_account_data,
        |data| {
            decode_base_online_account_data_value(data)
                .expect("decode randomized baseonlineaccountdata")
        },
    );
}

/// Random small `TealKeyValue` map, pre-encoded to the canonical raw
/// msgpack bytes that `ResourcesData::key_value`/`global_state` store —
/// mirrors what a real caller (e.g. `canonical_encode_teal_key_value`
/// itself) would hand `ResourcesData`.
///
/// Keys and `TealValue::Bytes` payloads are restricted to ASCII
/// (`gen_string`) rather than arbitrary bytes: `canonical_encode_teal_key_value`
/// always writes both using msgpack **str** format (matching Go's
/// `map[string]TealValue`/`TealValue.Bytes string` typing), and this
/// file's test-only `reencode_map_value` helper (used by
/// `decode_resources_data_value` to re-embed the nested map after a
/// generic rmpv decode) re-encodes a decoded str-typed value that
/// happens to contain invalid UTF-8 as msgpack **bin** instead — an
/// artifact of the test harness's generic rmpv round-trip, not of the
/// production `ResourcesData` codec under test. Arbitrary non-UTF8
/// bytes would spuriously fail this test for a reason unrelated to
/// `canonical_encode_resources_data`/`decode_resources_data_value`'s own
/// correctness.
fn gen_teal_key_value_bytes(rng: &mut ChaCha20Rng) -> Vec<u8> {
    let n = rng.gen_range(0..=4);
    let mut map = BTreeMap::new();
    for _ in 0..n {
        let key = gen_string(rng, 8).into_bytes();
        let value = if rng.gen_bool(0.5) {
            TealValue::Uint(rng.gen())
        } else {
            TealValue::Bytes(gen_string(rng, 16).into_bytes())
        };
        map.insert(key, value);
    }
    if map.is_empty() {
        // `ResourcesData::key_value`/`global_state`'s doc contract is
        // "Empty (`Vec::new()`) when absent" — i.e. an absent map is
        // the zero-length byte vec, not the encoder's 1-byte
        // canonical-empty-map representation (`0x80`). `add_map`
        // (`canonical.rs`) special-cases exactly that 1-byte
        // representation as omitempty on the wire, so the decoder's
        // default (`Vec::new()`) is what a round-trip actually
        // produces for "no entries" — matching `Vec::new()` here keeps
        // the generator honest about what real callers must supply.
        Vec::new()
    } else {
        canonical_encode_teal_key_value(&map)
    }
}

fn gen_resources_data(rng: &mut ChaCha20Rng) -> ResourcesData {
    ResourcesData {
        total: rng.gen(),
        decimals: rng.gen(),
        default_frozen: rng.gen(),
        unit_name: gen_string(rng, 8),
        asset_name: gen_string(rng, 12),
        url: gen_string(rng, 16),
        metadata_hash: gen_nonzero_or_zero_bytes32(rng),
        manager: gen_nonzero_or_zero_bytes32(rng),
        reserve: gen_nonzero_or_zero_bytes32(rng),
        freeze: gen_nonzero_or_zero_bytes32(rng),
        clawback: gen_nonzero_or_zero_bytes32(rng),
        amount: rng.gen(),
        frozen: rng.gen(),
        schema_num_uint: rng.gen(),
        schema_num_byte_slice: rng.gen(),
        key_value: gen_teal_key_value_bytes(rng),
        approval_program: gen_bytes_vec(rng, 32),
        clear_state_program: gen_bytes_vec(rng, 32),
        global_state: gen_teal_key_value_bytes(rng),
        local_state_schema_num_uint: rng.gen(),
        local_state_schema_num_byte_slice: rng.gen(),
        global_state_schema_num_uint: rng.gen(),
        global_state_schema_num_byte_slice: rng.gen(),
        extra_program_pages: rng.gen(),
        resource_flags: rng.gen(),
        update_round: rng.gen(),
        version: rng.gen(),
        size_sponsor: gen_nonzero_or_zero_bytes32(rng),
        foreign_box_reads: rng.gen(),
        family_box_access: rng.gen(),
    }
}

#[test]
fn resources_data_randomized_roundtrip() {
    assert_randomized_roundtrip(
        0x2e50_11ce,
        gen_resources_data,
        canonical_encode_resources_data,
        |data| decode_resources_data_value(data).expect("decode randomized resourcesdata"),
    );
}

fn gen_state_proof_verification_context(rng: &mut ChaCha20Rng) -> StateProofVerificationContext {
    StateProofVerificationContext {
        last_attested_round: rng.gen(),
        voters_commitment: gen_bytes_vec(rng, 64),
        online_total_weight: rng.gen(),
        version: gen_string(rng, 12),
    }
}

#[test]
fn state_proof_verification_context_randomized_roundtrip() {
    assert_randomized_roundtrip(
        0x5940_0f00,
        gen_state_proof_verification_context,
        canonical_encode_state_proof_verification_context,
        |data| {
            decode_state_proof_verification_context_value(data)
                .expect("decode randomized stateproof context")
        },
    );
}

fn gen_txtail_round_lease(rng: &mut ChaCha20Rng) -> algo_types::TxTailRoundLease {
    algo_types::TxTailRoundLease {
        sender: if rng.gen_bool(0.9) {
            Address(gen_nonzero_bytes32(rng))
        } else {
            Address::ZERO
        },
        lease: if rng.gen_bool(0.9) {
            serde_bytes::ByteBuf::from(gen_nonzero_bytes32(rng).to_vec())
        } else {
            serde_bytes::ByteBuf::from(Vec::new())
        },
        txn_idx: rng.gen(),
    }
}

/// Random `TxTailRound`. The embedded `hdr: BlockHeader` only has its
/// scalar top-level fields randomized (round/timestamp/txn_counter) —
/// `BlockHeader`'s own byte-exact msgpack shape (including nested
/// `StateProofTrackingData`) is already covered end-to-end by
/// `block_json_test`/block-header conformance fixtures elsewhere; the
/// property under test here is `TxTailRound`/`TxTailRoundLease`'s own
/// field set (`txn_ids`/`last_valid`/`leases`), which is what
/// `TestRandomizedEncodingTxTailRound`/`TestRandomizedEncodingTxTailRoundLease`
/// actually pin.
fn gen_txtail_round(rng: &mut ChaCha20Rng) -> algo_types::TxTailRound {
    let n = rng.gen_range(0..=5);
    let txn_ids: Vec<serde_bytes::ByteBuf> = (0..n)
        .map(|_| serde_bytes::ByteBuf::from(gen_bytes32(rng).to_vec()))
        .collect();
    let last_valid: Vec<u64> = (0..n).map(|_| rng.gen()).collect();
    let lease_count = rng.gen_range(0..=3);
    let leases: Vec<algo_types::TxTailRoundLease> = (0..lease_count)
        .map(|_| gen_txtail_round_lease(rng))
        .collect();

    let hdr = BlockHeader {
        round: rng.gen::<u64>().into(),
        timestamp: rng.gen(),
        txn_counter: rng.gen(),
        ..BlockHeader::default()
    };

    algo_types::TxTailRound {
        txn_ids,
        last_valid,
        leases,
        hdr,
    }
}

#[test]
fn txtail_round_randomized_roundtrip() {
    assert_randomized_roundtrip(
        0x7a11_2020,
        gen_txtail_round,
        |v: &algo_types::TxTailRound| canonical_encode_txtail_round(v),
        |data| rmp_serde::from_slice(data).expect("decode randomized txtailround via rmp_serde"),
    );
}

fn decode_state_proof_verification_context_value(
    data: &[u8],
) -> Result<StateProofVerificationContext, String> {
    let val: rmpv::Value =
        rmpv::decode::read_value(&mut &data[..]).map_err(|e| format!("rmpv decode: {e}"))?;
    let pairs = match val {
        rmpv::Value::Map(m) => m,
        other => return Err(format!("expected msgpack map, got {other:?}")),
    };
    let mut c = StateProofVerificationContext::default();
    for (k, v) in pairs {
        let key = k.as_str().ok_or_else(|| format!("non-string key: {k:?}"))?;
        match key {
            "pw" => c.online_total_weight = as_u64(&v),
            "spround" => c.last_attested_round = as_u64(&v),
            "v" => c.version = as_str(&v)?,
            "vc" => c.voters_commitment = as_bytes(&v)?,
            other => {
                return Err(format!(
                    "unexpected StateProofVerificationContext tag {other:?}"
                ))
            }
        }
    }
    Ok(c)
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
