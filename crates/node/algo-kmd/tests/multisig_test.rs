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

//! Integration tests for multisig operations (TASK-206).
//!
//! Two layers:
//! 1. In-Rust round-trip — import / lookup / list / delete.
//! 2. Cross-implementation interop against
//!    `tests/fixtures/go_wallet_multisig/`, a wallet with multiple
//!    multisig preimages produced by go-algorand's kmd. Rust must
//!    list the same addresses and recover the same `(version,
//!    threshold, pks)` triples Go's `LookupMultisigPreimage` returns.

use std::path::PathBuf;

use algo_kmd::{
    config::ScryptParams, Error, MultisigPreimage, WalletDriver, WalletDriverConfig, ADDRESS_LEN,
};
use tempfile::TempDir;

fn weak_cfg(dir: &std::path::Path) -> WalletDriverConfig {
    WalletDriverConfig {
        wallets_dir: dir.to_path_buf(),
        scrypt_params: ScryptParams {
            scrypt_n: 1024,
            scrypt_r: 1,
            scrypt_p: 1,
        },
        allow_unsafe_scrypt: true,
    }
}

fn fixed_pks(count: usize, offset: u8) -> Vec<[u8; ADDRESS_LEN]> {
    (0..count)
        .map(|i| {
            let mut pk = [0u8; ADDRESS_LEN];
            for (j, b) in pk.iter_mut().enumerate() {
                *b = offset.wrapping_add((i * 32 + j) as u8);
            }
            pk
        })
        .collect()
}

#[test]
fn import_lookup_list_delete_round_trip() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver.create_wallet(b"m", b"id-m", b"pw", None).unwrap();
    let w = driver.fetch_wallet(b"id-m").unwrap();

    let pks_a = fixed_pks(3, 0x10);
    let pks_b = fixed_pks(2, 0x40);

    let addr_a = w.import_multisig(1, 2, &pks_a).unwrap();
    let addr_b = w.import_multisig(1, 1, &pks_b).unwrap();

    let listed = w.list_multisig().unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.contains(&addr_a));
    assert!(listed.contains(&addr_b));

    let pre_a = w.lookup_multisig(&addr_a).unwrap();
    assert_eq!(
        pre_a,
        MultisigPreimage {
            version: 1,
            threshold: 2,
            pks: pks_a.clone(),
        }
    );

    // Looking up an unknown address returns MultisigNotFound.
    assert!(matches!(
        w.lookup_multisig(&[0u8; ADDRESS_LEN]),
        Err(Error::MultisigNotFound)
    ));

    // Delete needs password.
    assert!(matches!(
        w.delete_multisig(&addr_a, b"wrong"),
        Err(Error::Decrypt)
    ));
    w.delete_multisig(&addr_a, b"pw").unwrap();
    assert_eq!(w.list_multisig().unwrap(), vec![addr_b]);
    // Re-deleting is silent (Go behavior).
    w.delete_multisig(&addr_a, b"pw").unwrap();
}

#[test]
fn import_rejects_invalid_preimage() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver.create_wallet(b"i", b"id-i", b"pw", None).unwrap();
    let w = driver.fetch_wallet(b"id-i").unwrap();

    // version != 1
    assert!(matches!(
        w.import_multisig(2, 1, &fixed_pks(2, 0)),
        Err(Error::MultisigInvalid)
    ));
    // threshold > len(pks)
    assert!(matches!(
        w.import_multisig(1, 5, &fixed_pks(2, 0)),
        Err(Error::MultisigInvalid)
    ));
    // threshold = 0
    assert!(matches!(
        w.import_multisig(1, 0, &fixed_pks(2, 0)),
        Err(Error::MultisigInvalid)
    ));
    // empty pks
    assert!(matches!(
        w.import_multisig(1, 1, &[]),
        Err(Error::MultisigInvalid)
    ));
}

#[test]
fn duplicate_import_is_rejected() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver.create_wallet(b"d", b"id-d", b"pw", None).unwrap();
    let w = driver.fetch_wallet(b"id-d").unwrap();

    let pks = fixed_pks(3, 0x10);
    w.import_multisig(1, 2, &pks).unwrap();
    // UNIQUE on msig_addrs.address (PRIMARY KEY) surfaces as KeyExists.
    let err = w.import_multisig(1, 2, &pks).unwrap_err();
    assert!(matches!(err, Error::KeyExists), "got {err:?}");
}

// -----------------------------------------------------------------------------
// Cross-implementation interop: a Go-produced wallet with several
// multisig entries opens under Rust; list / lookup recover the same
// (version, threshold, pks) triples Go stored.

#[derive(serde::Deserialize)]
struct MsigEntry {
    address_hex: String,
    version: u8,
    threshold: u8,
    pks_hex: Vec<String>,
}

#[derive(serde::Deserialize)]
struct GoMsigFixtureManifest {
    db_relpath: String,
    wallet_id: String,
    password: String,
    scrypt_n: i64,
    scrypt_r: i64,
    scrypt_p: i64,
    multisig: Vec<MsigEntry>,
}

const GO_MSIG_MANIFEST: &str = include_str!("fixtures/go_wallet_multisig/manifest.json");

fn msig_fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go_wallet_multisig")
}

#[test]
fn opens_go_wallet_and_round_trips_multisig() {
    let manifest: GoMsigFixtureManifest =
        serde_json::from_str(GO_MSIG_MANIFEST).expect("manifest parses");
    assert!(
        manifest.multisig.len() >= 2,
        "fixture must include multiple multisig entries"
    );

    // Copy the fixture into a temp work dir.
    let work = TempDir::new().unwrap();
    let dst_walletsdir = work.path().join("sqlite_wallets");
    std::fs::create_dir_all(&dst_walletsdir).unwrap();
    let src_db = msig_fixture_root().join(&manifest.db_relpath);
    let dst_db = dst_walletsdir.join(src_db.file_name().unwrap());
    std::fs::copy(&src_db, &dst_db).unwrap();

    let driver = WalletDriver::new(WalletDriverConfig {
        wallets_dir: dst_walletsdir,
        scrypt_params: ScryptParams {
            scrypt_n: manifest.scrypt_n,
            scrypt_r: manifest.scrypt_r,
            scrypt_p: manifest.scrypt_p,
        },
        allow_unsafe_scrypt: true,
    })
    .unwrap();

    let w = driver.fetch_wallet(manifest.wallet_id.as_bytes()).unwrap();

    // Rust must list every address Go imported, and lookup must return
    // the same (version, threshold, pks) triple.
    let listed = w.list_multisig().unwrap();
    assert_eq!(listed.len(), manifest.multisig.len());

    for entry in &manifest.multisig {
        let addr_bytes = hex::decode(&entry.address_hex).unwrap();
        let mut addr = [0u8; ADDRESS_LEN];
        addr.copy_from_slice(&addr_bytes);
        assert!(
            listed.contains(&addr),
            "expected addr {} in list_multisig",
            entry.address_hex
        );

        let pre = w.lookup_multisig(&addr).unwrap();
        assert_eq!(pre.version, entry.version);
        assert_eq!(pre.threshold, entry.threshold);
        assert_eq!(pre.pks.len(), entry.pks_hex.len());
        for (got, want_hex) in pre.pks.iter().zip(&entry.pks_hex) {
            let want = hex::decode(want_hex).unwrap();
            assert_eq!(got.as_slice(), want.as_slice());
        }
    }

    // Delete one entry on the Rust side and confirm list_multisig
    // shrinks — proves DELETE wiring is consistent with Go.
    let first_addr_bytes = hex::decode(&manifest.multisig[0].address_hex).unwrap();
    let mut first_addr = [0u8; ADDRESS_LEN];
    first_addr.copy_from_slice(&first_addr_bytes);
    // Need an unlocked wallet for password check on delete.
    let mut w = driver.fetch_wallet(manifest.wallet_id.as_bytes()).unwrap();
    w.init(manifest.password.as_bytes()).unwrap();
    w.delete_multisig(&first_addr, manifest.password.as_bytes())
        .unwrap();
    let after = w.list_multisig().unwrap();
    assert_eq!(after.len(), manifest.multisig.len() - 1);
    assert!(!after.contains(&first_addr));
}
