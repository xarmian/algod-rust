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

//! Integration tests for the crypto envelope against Go-generated
//! fixtures.
//!
//! The fixture in `tests/fixtures/kmd_crypto_vectors.json` is produced
//! by `tools/kmd-crypto-vector-capture/main.go`, which reimplements the
//! algorithm from
//! `../go-algorand/daemon/kmd/wallet/driver/sqlite_crypto.go`
//! (v4.6.0-stable) using the same public crypto + go-codec primitives.
//! Regenerate via:
//!
//! ```text
//! cd tools/kmd-crypto-vector-capture
//! go run . > ../../crates/node/algo-kmd/tests/fixtures/kmd_crypto_vectors.json
//! ```
//!
//! Each vector locks in two independent guarantees:
//! 1. `decrypt_blob_with_password` of the Go-produced blob recovers the
//!    expected plaintext (Rust reads what Go writes).
//! 2. `encrypt_blob_with_nonce_and_salt` with the same deterministic
//!    inputs produces a byte-identical blob (Rust writes what Go reads).

use algo_kmd::{
    config::ScryptParams, decrypt_blob_with_password, encrypt_blob_with_nonce_and_salt,
    PlaintextType, NONCE_LEN, SALT_LEN,
};

const FIXTURE_JSON: &str = include_str!("fixtures/kmd_crypto_vectors.json");

#[derive(serde::Deserialize)]
struct Fixture {
    scrypt: Vector,
    raw_key: Vector,
}

#[derive(serde::Deserialize)]
struct Vector {
    password_hex: String,
    plaintext_hex: String,
    plaintext_type: String,
    nonce_hex: String,
    salt_hex: String,
    scrypt_n: u64,
    scrypt_r: u64,
    scrypt_p: u64,
    blob_hex: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE_JSON).expect("fixture parses")
}

fn pt_type(name: &str) -> PlaintextType {
    match name {
        "master_key" => PlaintextType::MasterKey,
        "secret_key" => PlaintextType::SecretKey,
        "master_derivation_key" => PlaintextType::MasterDerivationKey,
        "max_key_idx" => PlaintextType::MaxKeyIdx,
        other => panic!("unknown plaintext_type {other}"),
    }
}

fn nonce_array(hex_str: &str) -> [u8; NONCE_LEN] {
    let bytes = hex::decode(hex_str).unwrap();
    assert_eq!(bytes.len(), NONCE_LEN, "nonce must be {NONCE_LEN} bytes");
    let mut out = [0u8; NONCE_LEN];
    out.copy_from_slice(&bytes);
    out
}

fn salt_array(hex_str: &str) -> [u8; SALT_LEN] {
    let mut out = [0u8; SALT_LEN];
    if hex_str.is_empty() {
        return out;
    }
    let bytes = hex::decode(hex_str).unwrap();
    assert_eq!(bytes.len(), SALT_LEN, "salt must be {SALT_LEN} bytes");
    out.copy_from_slice(&bytes);
    out
}

#[test]
fn decrypts_go_scrypt_blob() {
    let v = fixture().scrypt;
    let blob = hex::decode(&v.blob_hex).unwrap();
    let pw = hex::decode(&v.password_hex).unwrap();
    let plaintext =
        decrypt_blob_with_password(&blob, pt_type(&v.plaintext_type), &pw).expect("decrypt");
    assert_eq!(plaintext, hex::decode(&v.plaintext_hex).unwrap());
}

#[test]
fn decrypts_go_raw_key_blob() {
    let v = fixture().raw_key;
    let blob = hex::decode(&v.blob_hex).unwrap();
    let key = hex::decode(&v.password_hex).unwrap();
    let plaintext =
        decrypt_blob_with_password(&blob, pt_type(&v.plaintext_type), &key).expect("decrypt");
    assert_eq!(plaintext, hex::decode(&v.plaintext_hex).unwrap());
}

#[test]
fn reencrypts_byte_equal_to_go_scrypt_blob() {
    let v = fixture().scrypt;
    let pw = hex::decode(&v.password_hex).unwrap();
    let plaintext = hex::decode(&v.plaintext_hex).unwrap();
    let cfg = ScryptParams {
        scrypt_n: i64::try_from(v.scrypt_n).unwrap(),
        scrypt_r: i64::try_from(v.scrypt_r).unwrap(),
        scrypt_p: i64::try_from(v.scrypt_p).unwrap(),
    };
    let nonce = nonce_array(&v.nonce_hex);
    let salt = salt_array(&v.salt_hex);

    let blob = encrypt_blob_with_nonce_and_salt(
        &plaintext,
        pt_type(&v.plaintext_type),
        &pw,
        algo_kmd::Kdf::Scrypt(&cfg),
        &nonce,
        &salt,
    )
    .unwrap();
    assert_eq!(
        hex::encode(&blob),
        v.blob_hex,
        "Rust encryption must produce byte-identical output to Go"
    );
}

#[test]
fn reencrypts_byte_equal_to_go_raw_key_blob() {
    let v = fixture().raw_key;
    let key = hex::decode(&v.password_hex).unwrap();
    let plaintext = hex::decode(&v.plaintext_hex).unwrap();
    let nonce = nonce_array(&v.nonce_hex);
    let salt = salt_array(&v.salt_hex); // zeros for raw-key path

    let blob = encrypt_blob_with_nonce_and_salt(
        &plaintext,
        pt_type(&v.plaintext_type),
        &key,
        algo_kmd::Kdf::RawKey,
        &nonce,
        &salt,
    )
    .unwrap();
    assert_eq!(
        hex::encode(&blob),
        v.blob_hex,
        "Rust raw-key encryption must produce byte-identical output to Go"
    );
}
