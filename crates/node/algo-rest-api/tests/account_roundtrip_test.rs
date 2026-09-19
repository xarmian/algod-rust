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

//! Roundtrip conformance of account REST responses vs go-algorand (TASK-254).
//!
//! For each fixture, go-algorand v4.6.0-stable produced references from a
//! `basics.AccountData` (see `fixtures/account_roundtrip/`):
//!
//! - `<name>.account.json` — `model.Account` via `AccountDataToAccount` +
//!   `JSONStrictHandle` (the JSON endpoint body).
//! - `<name>.accountdata.msgpack` — the raw `AccountData` via `CodecHandle` (the
//!   msgpack endpoint body).
//! - `<name>.meta.json` — address, round, amount-without-pending-rewards.
//!
//! The Rust side constructs the *same* `AccountData`, builds the response with
//! `account_data_to_response`, and asserts: JSON equality (field-for-field,
//! order-independent) and msgpack equality (byte-for-byte canonical).

use std::collections::BTreeMap;

use rand::Rng;

use algo_codec::canonical_encode_account_data;
use algo_rest_api::models::account_data_to_response;
use algo_rest_api::node::AccountLookup;
use algo_types::consensus::{consensus_params_for_version, CONSENSUS_V41};
use algo_types::{
    AccountData, AccountStatus, Address, AppLocalState, AppParams, AssetHolding, AssetParams,
    StateSchema, TealValue,
};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/account_roundtrip"
);

/// `[b, 0, …, 0, b ^ 0xff]` — mirrors the Go generator's `addr(b)`.
fn addr(b: u8) -> Address {
    let mut a = [0u8; 32];
    a[0] = b;
    a[31] = b ^ 0xff;
    Address(a)
}

fn d32(b: u8) -> [u8; 32] {
    let mut d = [0u8; 32];
    d[0] = b;
    d
}

fn d64(b: u8) -> [u8; 64] {
    let mut d = [0u8; 64];
    d[0] = b;
    d
}

struct Fixture {
    name: &'static str,
    addr: Address,
    round: u64,
    awpr: u64,
    data: AccountData,
}

fn fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            name: "offline_minimal",
            addr: addr(0x11),
            round: 100,
            awpr: 1_000_000,
            data: AccountData {
                micro_algos: 1_000_000,
                status: AccountStatus::Offline,
                ..Default::default()
            },
        },
        Fixture {
            name: "online_participation",
            addr: addr(0x22),
            round: 5000,
            awpr: 4_999_000,
            data: AccountData {
                micro_algos: 5_000_000,
                status: AccountStatus::Online,
                rewarded_micro_algos: 1234,
                rewards_base: 7,
                vote_id: Some(d32(0x01)),
                selection_id: Some(d32(0x02)),
                state_proof_id: Some(d64(0x03)),
                vote_first_valid: 1,
                vote_last_valid: 10000,
                vote_key_dilution: 100,
                incentive_eligible: true,
                ..Default::default()
            },
        },
        Fixture {
            name: "with_assets",
            addr: addr(0x33),
            round: 200,
            awpr: 2_000_000,
            data: AccountData {
                micro_algos: 2_000_000,
                status: AccountStatus::Offline,
                auth_addr: Some(addr(0x99)),
                total_assets_opted_in: 2,
                total_created_assets: 1,
                assets: BTreeMap::from([
                    (
                        10,
                        AssetHolding {
                            amount: 500,
                            frozen: true,
                        },
                    ),
                    (
                        2,
                        AssetHolding {
                            amount: 9,
                            frozen: false,
                        },
                    ),
                ]),
                asset_params: BTreeMap::from([(
                    7,
                    AssetParams {
                        total: 1_000_000,
                        decimals: 6,
                        unit_name: "TST".into(),
                        asset_name: "Test Asset".into(),
                        url: "https://x.io".into(),
                        metadata_hash: Some(d32(0xAB)),
                        manager: Some(addr(0x33)),
                        reserve: Some(addr(0x44)),
                        freeze: Some(addr(0x55)),
                        clawback: Some(addr(0x66)),
                        default_frozen: true,
                    },
                )]),
                ..Default::default()
            },
        },
        Fixture {
            name: "with_apps",
            addr: addr(0x44),
            round: 300,
            awpr: 3_000_000,
            data: AccountData {
                micro_algos: 3_000_000,
                status: AccountStatus::Offline,
                total_apps_opted_in: 1,
                total_created_apps: 1,
                total_extra_app_pages: 1,
                total_app_schema: StateSchema {
                    num_uint: 3,
                    num_byte_slice: 2,
                },
                app_local_states: BTreeMap::from([(
                    5,
                    AppLocalState {
                        schema: StateSchema {
                            num_uint: 1,
                            num_byte_slice: 0,
                        },
                        key_value: BTreeMap::from([
                            (b"k".to_vec(), TealValue::Uint(9)),
                            (b"b".to_vec(), TealValue::Bytes(b"v".to_vec())),
                        ]),
                    },
                )]),
                app_params: BTreeMap::from([(
                    8,
                    AppParams {
                        creator: addr(0x44),
                        approval_program: vec![0x06, 0x81, 0x01],
                        clear_state_program: vec![0x06, 0x81, 0x01],
                        global_state: BTreeMap::from([(b"g".to_vec(), TealValue::Uint(7))]),
                        local_state_schema: StateSchema {
                            num_uint: 1,
                            num_byte_slice: 0,
                        },
                        global_state_schema: StateSchema {
                            num_uint: 0,
                            num_byte_slice: 1,
                        },
                        extra_program_pages: 1,
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            },
        },
    ]
}

fn lookup_for(f: &Fixture) -> AccountLookup {
    AccountLookup {
        account_data: f.data.clone(),
        last_round: f.round,
        amount_without_pending_rewards: f.awpr,
        assets: f.data.assets.clone(),
        created_assets: f.data.asset_params.clone(),
        app_local_states: f.data.app_local_states.clone(),
        created_apps: f.data.app_params.clone(),
    }
}

fn read(name: &str) -> String {
    std::fs::read_to_string(format!("{DIR}/{name}")).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

#[test]
fn account_json_matches_go_field_for_field() {
    let consensus = consensus_params_for_version(CONSENSUS_V41).expect("v41 consensus");
    for f in fixtures() {
        let lookup = lookup_for(&f);
        let resp = account_data_to_response(&lookup, &f.addr, "none", false, false, &consensus);
        let got: serde_json::Value = serde_json::to_value(&resp).unwrap();
        let want: serde_json::Value =
            serde_json::from_str(&read(&format!("{}.account.json", f.name))).unwrap();
        assert_eq!(
            got, want,
            "{}: account JSON must match go-algorand field-for-field\n--- got ---\n{}\n--- want ---\n{}",
            f.name,
            serde_json::to_string_pretty(&got).unwrap(),
            serde_json::to_string_pretty(&want).unwrap(),
        );
    }
}

#[test]
fn account_msgpack_matches_go_canonical() {
    for f in fixtures() {
        let got = canonical_encode_account_data(&f.data);
        let want = std::fs::read(format!("{DIR}/{}.accountdata.msgpack", f.name))
            .unwrap_or_else(|e| panic!("read msgpack {}: {e}", f.name));
        assert_eq!(
            got, want,
            "{}: canonical AccountData msgpack must match go-algorand byte-for-byte",
            f.name
        );
    }
}

/// The standalone `GET /v2/assets/{id}` response (`model.Asset`) built by
/// `asset_params_to_api` must match go's `AssetParamsToAsset`.
#[test]
fn standalone_asset_json_matches_go() {
    use algo_rest_api::models::asset_params_to_api;
    let creator = addr(0x33);
    let params = AssetParams {
        total: 1_000_000,
        decimals: 6,
        unit_name: "TST".into(),
        asset_name: "Test Asset".into(),
        url: "https://x.io".into(),
        metadata_hash: Some(d32(0xAB)),
        manager: Some(addr(0x33)),
        reserve: Some(addr(0x44)),
        freeze: Some(addr(0x55)),
        clawback: Some(addr(0x66)),
        default_frozen: true,
    };
    let got = serde_json::to_value(asset_params_to_api(
        7,
        &creator.to_algorand_string(),
        &params,
    ))
    .unwrap();
    let want: serde_json::Value = serde_json::from_str(&read("asset.json")).unwrap();
    assert_eq!(
        got, want,
        "standalone asset JSON must match go field-for-field"
    );
}

/// The standalone `GET /v2/applications/{id}` response (`model.Application`)
/// built by `app_params_to_api` must match go's `AppParamsToApplication`.
#[test]
fn standalone_application_json_matches_go() {
    use algo_rest_api::models::app_params_to_api;
    let creator = addr(0x44);
    let params = AppParams {
        creator,
        approval_program: vec![0x06, 0x81, 0x01],
        clear_state_program: vec![0x06, 0x81, 0x01],
        global_state: BTreeMap::from([(b"g".to_vec(), TealValue::Uint(7))]),
        local_state_schema: StateSchema {
            num_uint: 1,
            num_byte_slice: 0,
        },
        global_state_schema: StateSchema {
            num_uint: 0,
            num_byte_slice: 1,
        },
        extra_program_pages: 1,
        ..Default::default()
    };
    let got =
        serde_json::to_value(app_params_to_api(8, &creator.to_algorand_string(), &params)).unwrap();
    let want: serde_json::Value = serde_json::from_str(&read("application.json")).unwrap();
    assert_eq!(
        got, want,
        "standalone application JSON must match go field-for-field"
    );
}

/// go's `model.ApplicationParams.ForeignBoxReads`/`FamilyBoxAccess` are
/// `*bool` `omitempty` fields (added in `v5.0.0-beta`, issue #1048): present
/// as `true` when the app opted in via `app_params_set`, and absent
/// (never `false`) otherwise.
#[test]
fn application_json_surfaces_box_access_flags_when_true() {
    use algo_rest_api::models::app_params_to_api;
    let creator = addr(0x44);
    let params = AppParams {
        creator,
        approval_program: vec![0x06, 0x81, 0x01],
        clear_state_program: vec![0x06, 0x81, 0x01],
        foreign_box_reads: true,
        family_box_access: true,
        ..Default::default()
    };
    let got =
        serde_json::to_value(app_params_to_api(9, &creator.to_algorand_string(), &params)).unwrap();
    assert_eq!(
        got["params"]["foreign-box-reads"],
        serde_json::json!(true),
        "foreign-box-reads must be surfaced as true in the JSON model"
    );
    assert_eq!(
        got["params"]["family-box-access"],
        serde_json::json!(true),
        "family-box-access must be surfaced as true in the JSON model"
    );
}

/// The false/default case must omit both fields entirely, matching go's
/// `*bool` `omitempty` semantics (a `false` value is never serialized).
#[test]
fn application_json_omits_box_access_flags_when_false() {
    use algo_rest_api::models::app_params_to_api;
    let creator = addr(0x44);
    let params = AppParams {
        creator,
        approval_program: vec![0x06, 0x81, 0x01],
        clear_state_program: vec![0x06, 0x81, 0x01],
        ..Default::default()
    };
    let got =
        serde_json::to_value(app_params_to_api(9, &creator.to_algorand_string(), &params)).unwrap();
    assert!(
        got["params"].get("foreign-box-reads").is_none(),
        "foreign-box-reads must be omitted when false"
    );
    assert!(
        got["params"].get("family-box-access").is_none(),
        "family-box-access must be omitted when false"
    );
}

/// `exclude=all` omits resource lists but keeps the counts (go's
/// `basicAccountInformation`).
#[test]
fn account_json_exclude_all_omits_resources() {
    let consensus = consensus_params_for_version(CONSENSUS_V41).expect("v41 consensus");
    let f = fixtures()
        .into_iter()
        .find(|f| f.name == "with_assets")
        .unwrap();
    let lookup = lookup_for(&f);
    let resp = account_data_to_response(&lookup, &f.addr, "all", false, false, &consensus);
    let v: serde_json::Value = serde_json::to_value(&resp).unwrap();
    assert!(v.get("assets").is_none(), "exclude=all must omit assets");
    assert!(
        v.get("created-assets").is_none(),
        "exclude=all must omit created-assets"
    );
    // Counts are still present.
    assert_eq!(v["total-assets-opted-in"], 2);
    assert_eq!(v["total-created-assets"], 1);
}

// ---------------------------------------------------------------------------
// Randomized forward-conversion fuzzing (Phase 17: parity_daemon_node.md's
// TestAccountRandomRoundTrip row).
//
// go's `TestAccountRandomRoundTrip` (account_test.go) round-trips
// `ledgertesting.RandomAccounts(20, simple)` through
// `AccountDataToAccount` -> `AccountToAccountData` and asserts the
// reconstructed `AccountData` equals the original. algod-rust has no
// `AccountToAccountData` reverse-conversion function (not needed -- this is
// a server, not a client that needs to reconstruct `AccountData` from an API
// response), so the round-trip half has no equivalent to test at all.
//
// This covers the other half of go's test that *does* have a Rust
// counterpart: exercising the forward conversion
// (`account_data_to_response`, go's `AccountDataToAccount`) over many
// randomly generated accounts rather than only the small set of fixed
// fixtures above, and -- mirroring go's own `IsDeterministic` sub-test --
// asserting the conversion is a pure, deterministic function of its inputs.
// ---------------------------------------------------------------------------

/// A minimal, self-contained account/resource randomizer -- deliberately not
/// a full port of go's `ledgertesting.RandomAccounts` (which also produces
/// harness-internal bookkeeping this crate has no use for), just enough
/// entropy to fuzz every field `account_data_to_response` reads.
fn random_account_data(rng: &mut impl Rng) -> AccountData {
    let status = match rng.gen_range(0..3) {
        0 => AccountStatus::Offline,
        1 => AccountStatus::Online,
        _ => AccountStatus::NotParticipating,
    };

    let has_participation = status == AccountStatus::Online && rng.gen_bool(0.7);
    let (vote_id, selection_id, state_proof_id) = if has_participation {
        (
            Some(random_32(rng)),
            Some(random_32(rng)),
            if rng.gen_bool(0.5) {
                Some(random_64(rng))
            } else {
                None
            },
        )
    } else {
        (None, None, None)
    };

    let num_assets = rng.gen_range(0..4usize);
    let mut assets = BTreeMap::new();
    for i in 0..num_assets {
        assets.insert(
            100 + i as u64,
            AssetHolding {
                amount: rng.gen_range(0..1_000_000_000u64),
                frozen: rng.gen_bool(0.3),
            },
        );
    }

    let num_created_assets = rng.gen_range(0..3usize);
    let mut asset_params = BTreeMap::new();
    for i in 0..num_created_assets {
        asset_params.insert(
            200 + i as u64,
            AssetParams {
                total: rng.gen_range(1..1_000_000_000u64),
                decimals: rng.gen_range(0..19u32),
                unit_name: format!("U{i}"),
                asset_name: format!("Asset {i}"),
                url: format!("https://example.com/{i}"),
                metadata_hash: if rng.gen_bool(0.5) {
                    Some(random_32(rng))
                } else {
                    None
                },
                manager: if rng.gen_bool(0.7) {
                    Some(random_address(rng))
                } else {
                    None
                },
                reserve: None,
                freeze: None,
                clawback: None,
                default_frozen: rng.gen_bool(0.2),
            },
        );
    }

    let num_apps = rng.gen_range(0..3usize);
    let mut app_local_states = BTreeMap::new();
    for i in 0..num_apps {
        let mut key_value = BTreeMap::new();
        key_value.insert(vec![b'k', i as u8], TealValue::Uint(rng.gen()));
        app_local_states.insert(
            300 + i as u64,
            AppLocalState {
                schema: StateSchema {
                    num_uint: 1,
                    num_byte_slice: 0,
                },
                key_value,
            },
        );
    }

    let num_created_apps = rng.gen_range(0..3usize);
    let mut app_params = BTreeMap::new();
    for i in 0..num_created_apps {
        app_params.insert(
            400 + i as u64,
            AppParams {
                creator: random_address(rng),
                approval_program: vec![0x06, 0x81, 0x01],
                clear_state_program: vec![0x06, 0x81, 0x01],
                global_state: BTreeMap::new(),
                local_state_schema: StateSchema::default(),
                global_state_schema: StateSchema::default(),
                extra_program_pages: rng.gen_range(0..3u32),
                ..Default::default()
            },
        );
    }

    AccountData {
        micro_algos: rng.gen_range(0..100_000_000_000u64),
        rewards_base: rng.gen_range(0..1000u64),
        rewarded_micro_algos: rng.gen_range(0..1_000_000u64),
        status,
        vote_id,
        selection_id,
        state_proof_id,
        vote_first_valid: rng.gen_range(0..1_000_000u64),
        vote_last_valid: rng.gen_range(0..2_000_000u64),
        vote_key_dilution: rng.gen_range(1..1000u64),
        auth_addr: if rng.gen_bool(0.2) {
            Some(random_address(rng))
        } else {
            None
        },
        total_assets_opted_in: assets.len() as u64,
        total_created_assets: asset_params.len() as u64,
        total_apps_opted_in: app_local_states.len() as u64,
        total_created_apps: app_params.len() as u64,
        incentive_eligible: rng.gen_bool(0.3),
        assets,
        asset_params,
        app_local_states,
        app_params,
        ..Default::default()
    }
}

fn random_32(rng: &mut impl Rng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill(&mut b);
    b
}

fn random_64(rng: &mut impl Rng) -> [u8; 64] {
    let mut b = [0u8; 64];
    rng.fill(&mut b);
    b
}

fn random_address(rng: &mut impl Rng) -> Address {
    Address(random_32(rng))
}

/// Fuzzes `account_data_to_response` over many randomly generated accounts
/// (mirroring go's `RandomAccounts(20, simple)` loop, run twice -- once
/// "simple", once "full" resource-bearing, matching go's `simple` bool
/// sweep in spirit) with a fixed seed for reproducibility. For every
/// generated account: the conversion must not panic, must be a pure
/// deterministic function of its inputs (go's `IsDeterministic` sub-test),
/// and several structural invariants that would hold for *any* valid
/// `AccountData` must survive the conversion (address preserved, resource
/// counts match the maps that produced them, participation presence tracks
/// `vote_id`).
#[test]
fn account_data_to_response_random_fuzz_is_deterministic_and_consistent() {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let consensus = consensus_params_for_version(CONSENSUS_V41).expect("v41 consensus");
    let mut rng = StdRng::seed_from_u64(0xACC0_5EED);

    for _ in 0..40 {
        let data = random_account_data(&mut rng);
        let addr = random_address(&mut rng);
        let lookup = AccountLookup {
            account_data: data.clone(),
            last_round: rng.gen_range(1..10_000_000u64),
            amount_without_pending_rewards: data.micro_algos,
            assets: data.assets.clone(),
            created_assets: data.asset_params.clone(),
            app_local_states: data.app_local_states.clone(),
            created_apps: data.app_params.clone(),
        };

        let resp = account_data_to_response(&lookup, &addr, "none", false, false, &consensus);

        // Determinism: converting the same inputs again yields byte-for-byte
        // identical JSON (go's `IsDeterministic` sub-test).
        let resp2 = account_data_to_response(&lookup, &addr, "none", false, false, &consensus);
        assert_eq!(
            serde_json::to_string(&resp).unwrap(),
            serde_json::to_string(&resp2).unwrap(),
            "account_data_to_response must be a pure function of its inputs"
        );

        // Structural invariants.
        assert_eq!(resp.address, addr.to_algorand_string());
        assert_eq!(resp.amount, data.micro_algos);
        assert_eq!(
            resp.assets.as_ref().map(|a| a.len()).unwrap_or(0),
            data.assets.len(),
            "asset count must be preserved"
        );
        assert_eq!(
            resp.created_assets.as_ref().map(|a| a.len()).unwrap_or(0),
            data.asset_params.len(),
            "created-asset count must be preserved"
        );
        assert_eq!(
            resp.apps_local_state.as_ref().map(|a| a.len()).unwrap_or(0),
            data.app_local_states.len(),
            "app-local-state count must be preserved"
        );
        assert_eq!(
            resp.created_apps.as_ref().map(|a| a.len()).unwrap_or(0),
            data.app_params.len(),
            "created-app count must be preserved"
        );
        // Participation is present iff a non-zero vote_id was set.
        let has_real_vote_id = data.vote_id.map(|v| v != [0u8; 32]).unwrap_or(false);
        assert_eq!(
            resp.participation.is_some(),
            has_real_vote_id,
            "participation must be present iff vote_id is non-zero"
        );
    }
}
