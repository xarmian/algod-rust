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

//! Msgpack self-roundtrip coverage for REST response models that
//! go-algorand exercises via its `msgp`-generated
//! `TestMarshalUnmarshal*`/`TestRandomizedEncoding*` tests (Phase 17,
//! issue #827 theme 5).
//!
//! go-algorand generates, per model, a `MarshalMsg`/`UnmarshalMsg` pair
//! plus a test that: encodes a zero-value instance, decodes it back,
//! and asserts there are zero leftover bytes
//! (`daemon/algod/api/spec/v2/msgp_gen_test.go`:
//! `TestMarshalUnmarshalAccountApplicationModel`,
//! `TestMarshalUnmarshalAccountAssetModel`), plus a randomized-field
//! variant (`TestRandomizedEncodingAccountApplicationModel`,
//! `TestRandomizedEncodingAccountAssetModel`).
//!
//! algod-rust doesn't generate a bespoke msgp codec — `AccountAssetResponse`
//! and `AccountApplicationResponse` (`crates/node/algo-rest-api/src/models.rs`)
//! derive `serde`, driven through `rmp_serde` the same way the REST handlers
//! encode `?format=msgpack` responses (see `account_asset_msgpack_uses_protocol_codec_tags`
//! / `account_app_msgpack_uses_protocol_codec_tags` in `tests/integration.rs`
//! for wire-shape coverage of the *handler* path). What's missing is
//! coverage of the *model type itself* round-tripping cleanly through
//! msgpack in isolation — the zero-value case (all-`None` optional fields)
//! and a spread of populated-field variants — which is what this file adds.
//!
//! Since these types don't derive `PartialEq` (adding it purely for test
//! convenience would be scope creep beyond what issue #827 asks for), each
//! roundtrip is verified by re-encoding the decoded value and asserting the
//! resulting bytes are identical to the original encoding — proving no data
//! is silently dropped or corrupted, which is the same guarantee Go's
//! generated-codec test provides (no leftover/lost bytes).

use algo_rest_api::models::{
    AccountApplicationResponse, AccountAssetResponse, ApiApplicationLocalState,
    ApiApplicationParams, ApiApplicationStateSchema, ApiAssetHolding, ApiAssetParams,
};

/// Encode `value`, decode it back into `T`, re-encode the decoded value, and
/// assert the two byte strings match — a value that survives msgpack
/// round-tripping without loss or corruption.
fn assert_msgpack_roundtrips<T>(value: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let encoded = rmp_serde::to_vec_named(value).expect("encode");
    let decoded: T = rmp_serde::from_slice(&encoded).expect("decode");
    let re_encoded = rmp_serde::to_vec_named(&decoded).expect("re-encode");
    assert_eq!(
        encoded, re_encoded,
        "msgpack roundtrip must be byte-stable (no data loss)"
    );
}

// ---------------------------------------------------------------------------
// AccountAssetResponse (~ go's AccountAssetModel)
// ---------------------------------------------------------------------------

#[test]
fn account_asset_response_zero_value_roundtrips() {
    // Mirrors TestMarshalUnmarshalAccountAssetModel: the "empty" case with
    // no holding and no created-asset params — both optional fields absent.
    let v = AccountAssetResponse {
        asset_holding: None,
        created_asset: None,
        round: 0,
    };
    assert_msgpack_roundtrips(&v);
}

#[test]
fn account_asset_response_holding_only_roundtrips() {
    let v = AccountAssetResponse {
        asset_holding: Some(ApiAssetHolding {
            amount: u64::MAX,
            asset_id: 42,
            is_frozen: true,
        }),
        created_asset: None,
        round: 1000,
    };
    assert_msgpack_roundtrips(&v);
}

#[test]
fn account_asset_response_created_asset_only_roundtrips() {
    let v = AccountAssetResponse {
        asset_holding: None,
        created_asset: Some(ApiAssetParams {
            clawback: Some("CLAWBACKADDR".to_string()),
            creator: "CREATORADDR".to_string(),
            decimals: 6,
            default_frozen: Some(false),
            freeze: None,
            manager: Some("MANAGERADDR".to_string()),
            metadata_hash: Some(vec![0xAB; 32]),
            name: Some("Test Asset".to_string()),
            name_b64: Some(b"Test Asset".to_vec()),
            reserve: None,
            total: 1_000_000_000,
            unit_name: Some("TST".to_string()),
            unit_name_b64: Some(b"TST".to_vec()),
            url: Some("https://example.com".to_string()),
            url_b64: Some(b"https://example.com".to_vec()),
        }),
        round: 12345,
    };
    assert_msgpack_roundtrips(&v);
}

#[test]
fn account_asset_response_both_fields_populated_roundtrips() {
    let v = AccountAssetResponse {
        asset_holding: Some(ApiAssetHolding {
            amount: 0,
            asset_id: 1,
            is_frozen: false,
        }),
        created_asset: Some(ApiAssetParams {
            clawback: None,
            creator: String::new(),
            decimals: 0,
            default_frozen: None,
            freeze: None,
            manager: None,
            metadata_hash: None,
            name: None,
            name_b64: None,
            reserve: None,
            total: 0,
            unit_name: None,
            unit_name_b64: None,
            url: None,
            url_b64: None,
        }),
        round: 1,
    };
    assert_msgpack_roundtrips(&v);
}

// ---------------------------------------------------------------------------
// AccountApplicationResponse (~ go's AccountApplicationModel)
// ---------------------------------------------------------------------------

#[test]
fn account_application_response_zero_value_roundtrips() {
    // Mirrors TestMarshalUnmarshalAccountApplicationModel.
    let v = AccountApplicationResponse {
        app_local_state: None,
        created_app: None,
        round: 0,
    };
    assert_msgpack_roundtrips(&v);
}

#[test]
fn account_application_response_local_state_only_roundtrips() {
    let v = AccountApplicationResponse {
        app_local_state: Some(ApiApplicationLocalState {
            id: 100,
            schema: ApiApplicationStateSchema {
                num_uint: 3,
                num_byte_slice: 2,
            },
            key_value: None,
        }),
        created_app: None,
        round: 999,
    };
    assert_msgpack_roundtrips(&v);
}

#[test]
fn account_application_response_created_app_only_roundtrips() {
    let v = AccountApplicationResponse {
        app_local_state: None,
        created_app: Some(ApiApplicationParams {
            approval_program: vec![0x06, 0x81, 0x01],
            clear_state_program: vec![0x06, 0x81, 0x01],
            creator: "CREATORADDR".to_string(),
            extra_program_pages: Some(1),
            global_state: None,
            global_state_schema: Some(ApiApplicationStateSchema {
                num_uint: 5,
                num_byte_slice: 0,
            }),
            local_state_schema: Some(ApiApplicationStateSchema {
                num_uint: 0,
                num_byte_slice: 0,
            }),
            size_sponsor: Some("SPONSORADDR".to_string()),
            version: Some(3),
        }),
        round: 54321,
    };
    assert_msgpack_roundtrips(&v);
}

#[test]
fn account_application_response_both_fields_populated_roundtrips() {
    let v = AccountApplicationResponse {
        app_local_state: Some(ApiApplicationLocalState {
            id: 0,
            schema: ApiApplicationStateSchema {
                num_uint: 0,
                num_byte_slice: 0,
            },
            key_value: None,
        }),
        created_app: Some(ApiApplicationParams {
            approval_program: vec![],
            clear_state_program: vec![],
            creator: String::new(),
            extra_program_pages: None,
            global_state: None,
            global_state_schema: None,
            local_state_schema: None,
            size_sponsor: None,
            version: None,
        }),
        round: 1,
    };
    assert_msgpack_roundtrips(&v);
}

// ---------------------------------------------------------------------------
// Randomized field-combination sweep (~ go's TestRandomizedEncoding*)
// ---------------------------------------------------------------------------

#[test]
fn account_asset_response_randomized_field_combinations_roundtrip() {
    // Deterministic pseudo-randomization (LCG) over field presence/values,
    // matching the spirit of go-algorand's protocol.RunEncodingTest fuzz —
    // many struct-shape combinations must all survive msgpack round-tripping.
    let mut state: u64 = 0x1234_5678_9abc_def0;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state
    };

    for i in 0..64u64 {
        let r = next();
        let v = AccountAssetResponse {
            asset_holding: if r & 1 == 0 {
                None
            } else {
                Some(ApiAssetHolding {
                    amount: r,
                    asset_id: i,
                    is_frozen: r & 2 == 0,
                })
            },
            created_asset: if r & 4 == 0 {
                None
            } else {
                Some(ApiAssetParams {
                    clawback: if r & 8 == 0 {
                        None
                    } else {
                        Some(format!("ADDR{r}"))
                    },
                    creator: format!("CREATOR{i}"),
                    decimals: r % 20,
                    default_frozen: Some(r & 16 == 0),
                    freeze: None,
                    manager: if r & 32 == 0 {
                        None
                    } else {
                        Some(format!("MGR{r}"))
                    },
                    metadata_hash: if r & 64 == 0 {
                        None
                    } else {
                        Some(vec![(r % 256) as u8; 32])
                    },
                    name: Some(format!("Asset {i}")),
                    name_b64: Some(format!("Asset {i}").into_bytes()),
                    reserve: None,
                    total: r,
                    unit_name: Some("U".to_string()),
                    unit_name_b64: Some(b"U".to_vec()),
                    url: None,
                    url_b64: None,
                })
            },
            round: r,
        };
        assert_msgpack_roundtrips(&v);
    }
}

#[test]
fn account_application_response_randomized_field_combinations_roundtrip() {
    let mut state: u64 = 0x0fed_cba9_8765_4321;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state
    };

    for i in 0..64u64 {
        let r = next();
        let v = AccountApplicationResponse {
            app_local_state: if r & 1 == 0 {
                None
            } else {
                Some(ApiApplicationLocalState {
                    id: i,
                    schema: ApiApplicationStateSchema {
                        num_uint: r % 10,
                        num_byte_slice: (r >> 4) % 10,
                    },
                    key_value: None,
                })
            },
            created_app: if r & 2 == 0 {
                None
            } else {
                Some(ApiApplicationParams {
                    approval_program: vec![(r % 256) as u8; (r % 8) as usize],
                    clear_state_program: vec![(r % 128) as u8; (r % 4) as usize],
                    creator: format!("CREATOR{i}"),
                    extra_program_pages: if r & 4 == 0 { None } else { Some(r % 3) },
                    global_state: None,
                    global_state_schema: if r & 8 == 0 {
                        None
                    } else {
                        Some(ApiApplicationStateSchema {
                            num_uint: r % 5,
                            num_byte_slice: 0,
                        })
                    },
                    local_state_schema: None,
                    size_sponsor: if r & 16 == 0 {
                        None
                    } else {
                        Some(format!("SPONSOR{r}"))
                    },
                    version: Some(r % 100),
                })
            },
            round: r,
        };
        assert_msgpack_roundtrips(&v);
    }
}
