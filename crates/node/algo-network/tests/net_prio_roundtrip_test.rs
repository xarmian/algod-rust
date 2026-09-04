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

//! Msgpack self-roundtrip coverage for [`algo_network::net_prio`]'s
//! `NetPrioResponse`/`NetPrioResponseSigned` (Phase 17, issue #961) — the
//! algod-rust analogue of go-algorand's
//! `TestMarshalUnmarshalnetPrioResponse`/`netPrioResponseSigned` and their
//! randomized-encoding variants (`node/msgp_gen_test.go`).
//!
//! Follows the byte-stability pattern established in
//! `crates/node/algo-rest-api/tests/msgpack_model_roundtrip_test.rs`: encode,
//! decode, re-encode, and assert the bytes are identical — proving no field
//! is silently dropped or corrupted.

use algo_network::block_cert::OneTimeSignature;
use algo_network::net_prio::{NetPrioResponse, NetPrioResponseSigned};
use algo_types::{Address, Round};
use serde_bytes::ByteBuf;

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

fn sample_ots(seed: u8) -> OneTimeSignature {
    OneTimeSignature {
        sig: ByteBuf::from(vec![seed; 64]),
        pk: ByteBuf::from(vec![seed.wrapping_add(1); 32]),
        pk_sig_old: ByteBuf::from(vec![0u8; 64]),
        pk2: ByteBuf::from(vec![seed.wrapping_add(2); 32]),
        pk1_sig: ByteBuf::from(vec![seed.wrapping_add(3); 64]),
        pk2_sig: ByteBuf::from(vec![seed.wrapping_add(4); 64]),
    }
}

// ---------------------------------------------------------------------------
// NetPrioResponse (~ go's netPrioResponse)
// ---------------------------------------------------------------------------

#[test]
fn net_prio_response_zero_value_roundtrips() {
    let v = NetPrioResponse::default();
    assert_msgpack_roundtrips(&v);
}

#[test]
fn net_prio_response_populated_roundtrips() {
    let v = NetPrioResponse {
        nonce: "cGFzc3BocmFzZQ==".to_string(),
    };
    assert_msgpack_roundtrips(&v);
}

// ---------------------------------------------------------------------------
// NetPrioResponseSigned (~ go's netPrioResponseSigned)
// ---------------------------------------------------------------------------

#[test]
fn net_prio_response_signed_zero_value_roundtrips() {
    let v = NetPrioResponseSigned::default();
    assert_msgpack_roundtrips(&v);
}

#[test]
fn net_prio_response_signed_populated_roundtrips() {
    let v = NetPrioResponseSigned {
        response: NetPrioResponse {
            nonce: "Y2hhbGxlbmdlLW5vbmNl".to_string(),
        },
        round: Round(123_456),
        sender: Address([7u8; 32]),
        sig: sample_ots(0x42),
    };
    assert_msgpack_roundtrips(&v);
}

#[test]
fn net_prio_response_signed_partial_fields_roundtrip() {
    // Only the round populated, everything else at its zero value —
    // exercises independent omitempty behavior per field.
    let v = NetPrioResponseSigned {
        response: NetPrioResponse::default(),
        round: Round(9),
        sender: Address::default(),
        sig: OneTimeSignature::default(),
    };
    assert_msgpack_roundtrips(&v);
}

// ---------------------------------------------------------------------------
// Randomized field-combination sweep (~ go's TestRandomizedEncoding*)
// ---------------------------------------------------------------------------

#[test]
fn net_prio_response_signed_randomized_field_combinations_roundtrip() {
    // Deterministic pseudo-randomization (LCG) over field presence/values,
    // matching the spirit of go-algorand's protocol.RunEncodingTest fuzz.
    let mut state: u64 = 0xABCD_EF01_2345_6789;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state
    };

    for i in 0..64u64 {
        let r = next();
        let v = NetPrioResponseSigned {
            response: if r & 1 == 0 {
                NetPrioResponse::default()
            } else {
                NetPrioResponse {
                    nonce: format!("nonce-{r}"),
                }
            },
            round: Round(r % 1_000_000),
            sender: if r & 2 == 0 {
                Address::default()
            } else {
                Address([(r % 256) as u8; 32])
            },
            sig: if r & 4 == 0 {
                OneTimeSignature::default()
            } else {
                sample_ots((r % 256) as u8)
            },
        };
        assert_msgpack_roundtrips(&v);
        // Also confirm decoded content is exactly what was encoded (not
        // just byte-stable under re-encoding).
        let encoded = rmp_serde::to_vec_named(&v).expect("encode");
        let decoded: NetPrioResponseSigned = rmp_serde::from_slice(&encoded).expect("decode");
        assert_eq!(v, decoded, "round {i}: seed r={r:#x}");
    }
}
