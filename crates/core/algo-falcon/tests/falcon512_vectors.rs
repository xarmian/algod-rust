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

//! Falcon-512 (det512) against go-algorand's own output (issue #2546): every
//! row of `fixtures/falcon/vectors512.jsonl`, written by
//! `tools/falcon-vector-capture` from `crypto.GenerateFalcon512Signer` /
//! `SignBytes` / `VerifyBytes` (falcon v0.2.0), must be reproduced byte for
//! byte: the key from its seed, the deterministic signature of each message,
//! and the verify verdicts.

use std::collections::HashMap;

const VECTORS: &str = include_str!("fixtures/falcon/vectors512.jsonl");

#[test]
fn falcon512_matches_go_on_every_vector() {
    let mut keys: HashMap<String, (Vec<u8>, Vec<u8>)> = HashMap::new();
    let mut sigs = 0;
    for line in VECTORS.lines().filter(|l| !l.trim().is_empty()) {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        match row["kind"].as_str().unwrap() {
            "key" => {
                let seed = hex::decode(row["seed"].as_str().unwrap()).unwrap();
                let (pk, sk) = algo_falcon::falcon512_keygen(&seed).unwrap();
                assert_eq!(hex::encode(&pk), row["pubkey"].as_str().unwrap(), "{line}");
                assert_eq!(pk.len(), algo_falcon::FALCON_DET512_PUBKEY_SIZE);
                keys.insert(row["name"].as_str().unwrap().to_string(), (pk, sk));
            }
            "sig" => {
                let (pk, sk) = &keys[row["key"].as_str().unwrap()];
                let msg = hex::decode(row["msg_hex"].as_str().unwrap()).unwrap();
                let want = hex::decode(row["sig"].as_str().unwrap()).unwrap();
                let got = algo_falcon::falcon512_sign(sk, &msg).unwrap();
                assert_eq!(got, want, "{}/{}", row["key"], row["msg"]);
                assert!(want.len() <= algo_falcon::FALCON_DET512_SIG_COMPRESSED_MAXSIZE);
                let ok = algo_falcon::falcon512_verify_code(pk, &want, &msg).unwrap() == 0;
                assert_eq!(ok, row["verifies"].as_bool().unwrap());
                let mut appended = msg.clone();
                appended.push(1);
                let ok = algo_falcon::falcon512_verify_code(pk, &want, &appended).unwrap() == 0;
                assert_eq!(ok, row["verifies_with_appended_byte"].as_bool().unwrap());
                sigs += 1;
            }
            other => panic!("unknown row kind {other}"),
        }
    }
    assert_eq!(keys.len(), 12);
    assert_eq!(sigs, 72);
}

#[test]
fn falcon512_rejects_wrong_sized_inputs_like_go() {
    let (pk, sk) = algo_falcon::falcon512_keygen(&[3u8; 32]).unwrap();
    assert!(algo_falcon::falcon512_verify_code(&pk[1..], &[0, 0], b"m").is_err());
    assert!(algo_falcon::falcon512_sign(&sk[1..], b"m").is_err());
    // A signature outside 2..=max is a BADSIG code, not an error (as for 1024).
    assert_eq!(
        algo_falcon::falcon512_verify_code(&pk, &[0xB9], b"m").unwrap(),
        algo_falcon::FALCON_ERR_BADSIG
    );
}
