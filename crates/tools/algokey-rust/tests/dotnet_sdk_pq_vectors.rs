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

//! Bit-identical interop with the .NET SDK's post-quantum test vectors
//! (issue #2014): `tests/fixtures/dotnet-sdk/` holds the files of
//! `scholtz/dotnet-algorand-sdk/test/TestData` (`algokey-pq-accounts.json`,
//! `algokey-pq-signed-{1,2,3}.stxn`), produced with go-algorand's
//! `algokey pq`. Falcon-1024 det1024 signing is deterministic, so
//!
//! * the same 24-word mnemonic must give the byte-identical address, salt,
//!   public key and private key (`algokey pq import`), and
//! * signing the same transaction must give the byte-identical signed
//!   transaction (`algokey pq sign`), whose signature must verify.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;

const ALGOKEY: &str = env!("CARGO_BIN_EXE_algokey-rust");

/// The mnemonic `algokey pq generate` printed for the key that signed
/// `algokey-pq-signed-*.stxn` (golden values from the SDK's PQSignatureTests.cs,
/// with the public key and canonical-salt-0 address algokey printed).
const GOLDEN_MNEMONIC: &str = "office route parade much super sphere wheel morning spawn true wire already siren unveil planet damage basket depend undo deer acquire popular what about clay";
const GOLDEN_PUBLIC_KEY_B64: &str = "Cox97DWtqVQ6jWcSV8NFhiWnZwYjAHE6+AJfUtuwcVhyOpBtDq7iZyDD8FW0F8D8IiQQ5TEUL9B/ub76F7cXBAi5fvfQZYRXDDDBAwhwO4g5daZetFuaihTgJhBNZD54a9clUC4n0/MHL4+K2Aa7TI2MyGrKHI7qrM1Dc4oqeb9FTkqx7wmzVEhqnsSDd6aeK0ZFrHyNGXQhEFMo9TblX6brEcEnEv7G4ogcH2MXZJabahsE0lBUuXKYdYwqD2r0s5NOF7+qnhNVi4N9btmb2hAfkp8u6EvAldOlUEQYVcWsO9nbERFpAFIwoZK22Gh7QC+CcdI3orDv4gJBn0Nx64BeKNEFoDWogO+sWGh2YLLioy/ARfR8yv8JHcYXQEbKYvZ7kVfTdZtRXHZ3xX2YISu5BCCtH7UuJnTjCSKl1fhADH6FTq5otoxEj4BjKQYdfUm0R5gkrl1tmLcFN4EWvLSJEbvDt0ZhR+JpVvNFBN8LekVmeyx2gMIpijhMVkn+DeW/bae6+Kn4BaxV99fFUzym07k123ZYpGFYnSUAK1Xj2KNZtCKOsmFqboQkDkAkWZF5YuLMZy6nAHXp+7VLjrAmcFMLtt16t2IwRUEZBQYgkoImFA0zJp8Y/lQxDPCuJxwexZwmbeaiXJ9F+FLIldA/n22wkIfhtpIQSeLXp+pBgSBhtutaOjT2EC+tclh+XbrFGMhTQv5L00h0JCBtgpjfgXZsWAZKl9hTyppIcJVWGkCvWOTAez3cB0VM09FVcGar9GqVVUDDpoCpxG/R+9tr4t4u0GvCpyH6YbruZdtZeTbVZFC/HwxzEvs3j57pl53fS4JU42WgEsjRGDJPeIk2icX7Y7QBaYUYsDD0vUlRa6q1GkUwny/xLrB+Zx6hb1tYPyf+6so3HFC38B4aZB4JUcDR5LtccRe1RBKrEG/bUl3RR2EsdwjuonMwN4Z7FcdZpUCTVaJXMOTj2T/RkldgpOC5Eb4bpYwTY65lngKjwzpBxLiBLtW4WxtnVam6hE0qMnR+YQpGHCO4nyPnrlSDoiX7vxRNCiILt5rZ0ZaNNWFIktJhPchBRBtWPFqk1DYM+rXgK8Hj3A4yQPBAPd8mJSbzYIDdSohuE4nnb3KK3hFRMd0Nq5q+eE3NKAa85sti1pGrGMyFzWYPJ1JttD6CY1Bl8Eh+aP8LNW+U/FukVbgCoMIvQS04i5CLUFtwSenoVgu2nRnUmkiljjLKi9YxGpVoRfzR44OwkCTGZp9W5JA6ulSGga2sdKtHLawBgwQql+0iwFSo24LRysS22Us1gEVolDB2W3na4r48NhZ1Apd4WnxDfRmFr9GHFxjhNXwF2eBXqes2PO5oE27AEC3v1KDm9j+VbJVpLwKlth0plFJtebD6IbvUKGwRGGRiLTsspJgxEIS+U207hdYYBGou7sJeAmhFDAwVH5DQSP3rYj1lJRM4SdgDJYkR6RcGo2Y0MtWsOXtEiXV1QXj31Haq0riJ2+yjC7gcyCtTbDjErIgoWDBtSqklYVMAFGxr1rnMLwWpVVfnbg8C4L5rH+7IOJD296+V8noJE7c80Fxu4IGHFR3KOxGJYmEpc4jadhlVqOAJtqjjogSqdnjtsrZfFIkZ4xXIySYfCY0X5Gc0RX5ORHXpOVJkU1JzQYN5ZWCCtM8VfpCRNqJSxVMmT4mdIsQ80FJxnWu6cmEpkslmOQ4+Mnc9zFNmVXUG9utLuF3s9x2U6X/9yPKRwlCkkWhGqVwfPQqqY8ueSo00VsvlRXVqwJJFm8QtRt2b42/f9bP+z7TyB1eGkqBpQEAWoU5A2hhchIgZberthUVU1mUZkuT7Ftbh4ZFJ716UBom4lTU7Sc2xiFckomEl5yzSb4Q0S3vyFf8V9ITmUYAsc0LddjLf0z7FUCsGJ1o6WKgRGAq5MjSjxP6t2hfZJgaO1iGTSm4aTsNctVVZpGbOUE5QTCcMzSqjrPEj12R8PVqP4i1uWYMduWcopmmBKXjUBcl6nh1gmytLclBsS+DDzL4efT967NPqRhzqeglGFQa6hgkrQHcQ2LRjd4a6GwgyqGCaCJKVimKtj4GvHbFkjwGLcJ3ipCtMnAa24xFrz++bemnwCg4Lbo28Vj2GahOswmYeAC08eAAgfWbPGUJ4aFcYP38xN/lOQ1wGDHpS8pxuKeobivTdNCKEIBZrl/aKxCO3JazqiKBsoicY0gOQMCsLRaU6fWKUEw2HivJygrrgPhLqhVCFqR5OBLVoPp1YRoETEZZo95EVhyWpxUQFbQUIW5FmRJ2HeZGrFg2i6ZjMEEw//RpKXtsiXI3TJ9tq9kn9OSlDZjC6lfd5zK3dcMAp2dNmrBrA8IsaSXJ7yqiX7cgAllhuwEvR22A5NPu+4XQ=";
const GOLDEN_ADDRESS: &str = "HTKQVJJ3KYQDTRBAV2ZBHAHXCJKP2OXZXHJ4KQZFYDORVBOR676MY4NLQE";

/// Both Falcon backends must reproduce the vectors (DIV-001: the pure-Rust
/// port is the default, the vendored C stays selectable).
fn backends() -> Vec<&'static str> {
    let mut b = vec!["rust"];
    if cfg!(feature = "falcon-c-backend") {
        b.push("c");
    }
    b
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/dotnet-sdk")
        .join(name)
}

#[derive(Deserialize)]
struct Account {
    mnemonic: String,
    address: String,
    salt: u8,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "privateKey")]
    private_key: String,
}

fn accounts() -> Vec<Account> {
    let text = std::fs::read_to_string(fixture("algokey-pq-accounts.json")).expect("accounts");
    serde_json::from_str(&text).expect("accounts json")
}

/// The on-disk key file `algokey pq import` writes (go's `pqSigningMaterial`).
#[derive(Deserialize)]
struct KeyFile {
    #[serde(rename = "private-key", with = "serde_bytes")]
    private_key: Vec<u8>,
    public: KeyFilePublic,
}

#[derive(Deserialize)]
struct KeyFilePublic {
    #[serde(rename = "public-key", with = "serde_bytes")]
    public_key: Vec<u8>,
    salt: u8,
    #[serde(with = "serde_bytes")]
    scheme: Vec<u8>,
}

/// Runs `algokey pq import` for `mnemonic`; returns the written key file and
/// the printed `PQ address:` line.
fn import(dir: &Path, backend: &str, mnemonic: &str) -> (KeyFile, String) {
    let keyfile = dir.join("key");
    let _ = std::fs::remove_file(&keyfile);
    let out = Command::new(ALGOKEY)
        .args(["--falcon-backend", backend, "pq", "import", "-m", mnemonic, "-k"])
        .arg(&keyfile)
        .output()
        .expect("run algokey-rust");
    assert!(out.status.success(), "import failed: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let address = stdout
        .lines()
        .find_map(|l| l.strip_prefix("PQ address: "))
        .unwrap_or_else(|| panic!("no 'PQ address:' line in: {stdout}"))
        .trim()
        .to_string();
    let bytes = std::fs::read(&keyfile).expect("key file");
    (rmp_serde::from_slice(&bytes).expect("key file msgpack"), address)
}

#[test]
fn the_vectors_have_the_expected_shape() {
    let accounts = accounts();
    assert_eq!(accounts.len(), 50);
    for a in &accounts {
        assert_eq!(a.mnemonic.split_whitespace().count(), 25, "24 words + checksum word");
        assert_eq!(STANDARD.decode(&a.public_key).unwrap().len(), 1793, "{}", a.address);
        assert_eq!(STANDARD.decode(&a.private_key).unwrap().len(), 2305, "{}", a.address);
    }
}

#[test]
fn all_50_mnemonics_derive_bit_identical_keys_salt_and_address() {
    let dir = tempfile::tempdir().unwrap();
    for backend in backends() {
        for (i, a) in accounts().iter().enumerate() {
            let (kf, address) = import(dir.path(), backend, &a.mnemonic);
            assert_eq!(kf.public.scheme, b"f1", "{backend} account {i}");
            assert_eq!(kf.public.salt, a.salt, "{backend} account {i}: salt");
            assert_eq!(
                STANDARD.encode(&kf.public.public_key),
                a.public_key,
                "{backend} account {i}: public key"
            );
            assert_eq!(
                STANDARD.encode(&kf.private_key),
                a.private_key,
                "{backend} account {i}: private key"
            );
            assert_eq!(address, a.address, "{backend} account {i}: address");
        }
    }
}

#[test]
fn the_golden_mnemonic_derives_the_public_key_salt_and_address_algokey_printed() {
    let dir = tempfile::tempdir().unwrap();
    for backend in backends() {
        let (kf, address) = import(dir.path(), backend, GOLDEN_MNEMONIC);
        assert_eq!(kf.public.salt, 0, "{backend}");
        assert_eq!(STANDARD.encode(&kf.public.public_key), GOLDEN_PUBLIC_KEY_B64, "{backend}");
        assert_eq!(address, GOLDEN_ADDRESS, "{backend}");
    }
}

/// The unsigned transaction a signed fixture carries: its `txn` map,
/// re-encoded (the fixture's map is already canonical, key-sorted msgpack).
fn unsigned_txn_of(stxn: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let value = rmpv::decode::read_value(&mut &stxn[..]).expect("stxn msgpack");
    let rmpv::Value::Map(entries) = value else { panic!("stxn is not a map") };
    let mut txn = None;
    let mut pk = None;
    for (k, v) in entries {
        match k.as_str() {
            Some("txn") => txn = Some(v),
            Some("pqsig") => {
                let rmpv::Value::Map(sig) = v else { panic!("pqsig is not a map") };
                for (sk, sv) in sig {
                    if sk.as_str() == Some("pk") {
                        pk = sv.as_slice().map(<[u8]>::to_vec);
                    }
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &txn.expect("txn field")).unwrap();
    (out, pk.expect("pqsig.pk"))
}

fn sign_and_compare(n: usize) {
    let expected = std::fs::read(fixture(&format!("algokey-pq-signed-{n}.stxn"))).unwrap();
    let (unsigned, pk) = unsigned_txn_of(&expected);

    // all three were signed with the golden key
    assert_eq!(STANDARD.encode(&pk), GOLDEN_PUBLIC_KEY_B64, "signed-{n}: embedded public key");

    let dir = tempfile::tempdir().unwrap();
    let txfile = dir.path().join("tx.unsigned");
    let outfile = dir.path().join("tx.signed");
    for backend in backends() {
        sign_with(backend, n, &unsigned, &txfile, &outfile, &expected);
    }

    // and the vector's own signature verifies against its public key over "TX"||txn
    verify_vector(n, &expected, &unsigned, &pk);
}

fn sign_with(backend: &str, n: usize, unsigned: &[u8], txfile: &Path, outfile: &Path, expected: &[u8]) {
    // `algokey pq sign` reads a SignedTransaction file that holds only `txn`
    // (what `goal clerk send --outfile` writes unsigned)
    let mut envelope = Vec::new();
    rmp::encode::write_map_len(&mut envelope, 1).unwrap();
    rmp::encode::write_str(&mut envelope, "txn").unwrap();
    envelope.extend_from_slice(unsigned);
    std::fs::write(txfile, &envelope).unwrap();
    let _ = std::fs::remove_file(outfile);
    let out = Command::new(ALGOKEY)
        .args(["--falcon-backend", backend, "pq", "sign", "-m", GOLDEN_MNEMONIC, "-t"])
        .arg(txfile)
        .arg("-o")
        .arg(outfile)
        .output()
        .expect("run algokey-rust");
    assert!(out.status.success(), "sign failed: {}", String::from_utf8_lossy(&out.stderr));

    let signed = std::fs::read(outfile).unwrap();
    assert_eq!(
        signed.len(),
        expected.len(),
        "{backend} signed-{n}: length differs from the vector"
    );
    assert_eq!(signed, expected, "{backend} signed-{n}: signed transaction is not bit-identical");
}

fn verify_vector(n: usize, expected: &[u8], unsigned: &[u8], pk: &[u8]) {
    let value = rmpv::decode::read_value(&mut &expected[..]).unwrap();
    let rmpv::Value::Map(entries) = value else { unreachable!() };
    let sig = entries
        .into_iter()
        .find(|(k, _)| k.as_str() == Some("pqsig"))
        .map(|(_, v)| v)
        .unwrap();
    let rmpv::Value::Map(sig) = sig else { unreachable!() };
    let sig_bytes = sig
        .into_iter()
        .find(|(k, _)| k.as_str() == Some("sig"))
        .and_then(|(_, v)| v.as_slice().map(<[u8]>::to_vec))
        .unwrap();
    let mut message = b"TX".to_vec();
    message.extend_from_slice(unsigned);
    assert!(
        algo_falcon::falcon_verify(pk, &sig_bytes, &message).unwrap(),
        "signed-{n}: the vector's signature does not verify"
    );
}

#[test]
fn signed_vector_1_is_reproduced_bit_identically() {
    sign_and_compare(1);
}

#[test]
fn signed_vector_2_is_reproduced_bit_identically() {
    sign_and_compare(2);
}

#[test]
fn signed_vector_3_is_reproduced_bit_identically() {
    sign_and_compare(3);
}
