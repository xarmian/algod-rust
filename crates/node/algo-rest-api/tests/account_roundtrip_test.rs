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
        let resp = account_data_to_response(&lookup, &f.addr, "none", &consensus);
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
    };
    let got =
        serde_json::to_value(app_params_to_api(8, &creator.to_algorand_string(), &params)).unwrap();
    let want: serde_json::Value = serde_json::from_str(&read("application.json")).unwrap();
    assert_eq!(
        got, want,
        "standalone application JSON must match go field-for-field"
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
    let resp = account_data_to_response(&lookup, &f.addr, "all", &consensus);
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
