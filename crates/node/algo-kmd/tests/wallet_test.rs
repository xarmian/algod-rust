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

//! Integration tests for the wallet driver (TASK-204).
//!
//! Covers both the in-Rust round trip (create → list → fetch → init →
//! export-MDK → rename) and the cross-implementation interop test
//! against a wallet produced by go-algorand's own kmd driver. The
//! fixture lives in `tests/fixtures/go_wallet/` and is regenerated via
//! `tools/kmd-wallet-fixture-capture`:
//!
//! ```text
//! cd tools/kmd-wallet-fixture-capture && \
//!   go run . ../../crates/node/algo-kmd/tests/fixtures/go_wallet
//! ```

use std::path::PathBuf;

use algo_kmd::{
    config::{SQLiteWalletDriverConfig, ScryptParams},
    Error, WalletDriver, WalletDriverConfig,
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

#[test]
fn create_list_fetch_export_round_trip() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();

    driver
        .create_wallet(b"alpha", b"id-1", b"hunter2", None)
        .unwrap();

    let metas = driver.list_wallet_metadatas().unwrap();
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].name, b"alpha");
    assert_eq!(metas[0].id, b"id-1");

    let mut wallet = driver.fetch_wallet(b"id-1").unwrap();
    wallet.init(b"hunter2").unwrap();

    // export-MDK with the same password succeeds and returns 32 bytes.
    let mdk = wallet.export_master_derivation_key(b"hunter2").unwrap();
    assert_eq!(mdk.len(), 32);

    // Repeated export returns the same bytes — the MDK is cached.
    let mdk2 = wallet.export_master_derivation_key(b"hunter2").unwrap();
    assert_eq!(mdk, mdk2);

    // Wrong password is rejected (typed error, no panic).
    let err = wallet.export_master_derivation_key(b"wrong").unwrap_err();
    assert!(matches!(err, Error::Decrypt), "got {err:?}");
}

#[test]
fn create_with_fixed_mdk_round_trips() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    let mdk_in: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);

    driver
        .create_wallet(b"fixed-mdk", b"id-fixed", b"pw", Some(mdk_in))
        .unwrap();

    let mut wallet = driver.fetch_wallet(b"id-fixed").unwrap();
    wallet.init(b"pw").unwrap();
    let exported = wallet.export_master_derivation_key(b"pw").unwrap();
    assert_eq!(
        exported, mdk_in,
        "exporting a wallet created with a known MDK must return that MDK"
    );
}

#[test]
fn create_rejects_duplicate_name_or_id() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver.create_wallet(b"dup", b"id-a", b"pw", None).unwrap();

    // Same name, different id → SameName
    let err = driver
        .create_wallet(b"dup", b"id-b", b"pw", None)
        .unwrap_err();
    assert!(matches!(err, Error::SameName), "got {err:?}");

    // Different name, same id → SameId
    let err = driver
        .create_wallet(b"dup2", b"id-a", b"pw", None)
        .unwrap_err();
    assert!(matches!(err, Error::SameId), "got {err:?}");
}

#[test]
fn failed_create_does_not_poison_claimed_registry() {
    // Regression for Codex PR #348 round 1: claim() used to append to
    // the in-memory list before checking on-disk dup state. A failed
    // CreateWallet (on-disk conflict) would leave a stale entry that
    // rejected a legitimate retry after the conflict was cleared.
    //
    // Go's claimWalletNameID (sqlite.go:382–409) appends only after
    // every check passes, so we must do the same.
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();

    // Stage 1: a *different* driver instance creates the on-disk
    // conflict. This way the in-memory registry of `driver` starts
    // empty, so any stale entry it ends up with must have come from
    // the failed claim path.
    {
        let driver_a = WalletDriver::new(weak_cfg(dir.path())).unwrap();
        driver_a
            .create_wallet(b"shared", b"id-existing", b"pw", None)
            .unwrap();
    }

    // Stage 2: `driver` (empty claim list) attempts to create a
    // wallet whose name collides with what's on disk. Must fail with
    // SameName (on-disk path).
    let err = driver
        .create_wallet(b"shared", b"id-new", b"pw", None)
        .unwrap_err();
    assert!(matches!(err, Error::SameName), "got {err:?}");

    // Stage 3: clear the on-disk conflict.
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }

    // Stage 4: retry on the *same* `driver`. With the bug
    // (pre-emptive append), the failed Stage 2 left "shared" in the
    // registry and this retry would fail with SameName even though
    // the disk is clean. With the fix, the registry stayed empty
    // and the retry succeeds.
    driver
        .create_wallet(b"shared", b"id-new", b"pw", None)
        .expect("retry must succeed after disk conflict is cleared");
}

#[test]
fn create_rejects_oversized_name_and_id() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();

    let too_long = vec![b'a'; 65];
    assert!(matches!(
        driver.create_wallet(&too_long, b"id", b"pw", None),
        Err(Error::NameTooLong)
    ));
    assert!(matches!(
        driver.create_wallet(b"ok", &too_long, b"pw", None),
        Err(Error::IdTooLong)
    ));
}

#[test]
fn rename_wallet_persists_and_requires_password() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver
        .create_wallet(b"original", b"id-r", b"pw", None)
        .unwrap();

    // Wrong password rejected.
    let err = driver
        .rename_wallet(b"id-r", b"newname", b"wrong")
        .unwrap_err();
    assert!(matches!(err, Error::Decrypt), "got {err:?}");

    // Correct password renames; metadata reflects the new name.
    driver.rename_wallet(b"id-r", b"newname", b"pw").unwrap();
    let metas = driver.list_wallet_metadatas().unwrap();
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].name, b"newname");
}

#[test]
fn rename_rejects_duplicate_name() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver.create_wallet(b"a", b"id-a", b"pw", None).unwrap();
    driver.create_wallet(b"b", b"id-b", b"pw", None).unwrap();

    let err = driver.rename_wallet(b"id-a", b"b", b"pw").unwrap_err();
    assert!(matches!(err, Error::SameName), "got {err:?}");
}

#[test]
fn fetch_missing_wallet_returns_not_found() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    assert!(matches!(
        driver.fetch_wallet(b"nope"),
        Err(Error::WalletNotFound)
    ));
}

#[test]
fn driver_new_creates_missing_parent_directories() {
    // Regression for Codex PR #348 round 2: previously used
    // std::fs::create_dir, which errors if any parent component
    // doesn't exist. WalletDriver::new now uses create_dir_all so a
    // fresh install on a deep path succeeds.
    let dir = TempDir::new().unwrap();
    let deep = dir.path().join("a").join("b").join("c").join("wallets");
    let driver = WalletDriver::new(WalletDriverConfig {
        wallets_dir: deep.clone(),
        scrypt_params: ScryptParams {
            scrypt_n: 1024,
            scrypt_r: 1,
            scrypt_p: 1,
        },
        allow_unsafe_scrypt: true,
    })
    .expect("deep path must be created");
    assert!(deep.exists(), "deep wallets_dir must exist after new()");
    // And the driver remains usable end-to-end on the fresh path.
    driver
        .create_wallet(b"deep", b"id-deep", b"pw", None)
        .unwrap();
}

#[test]
fn from_kmd_config_substitutes_default_subdir() {
    let dir = TempDir::new().unwrap();
    let sqlite_cfg = SQLiteWalletDriverConfig {
        wallets_dir: String::new(),
        unsafe_scrypt: true,
        scrypt_params: ScryptParams {
            scrypt_n: 1024,
            scrypt_r: 1,
            scrypt_p: 1,
        },
    };
    let driver = WalletDriver::from_kmd_config(dir.path(), &sqlite_cfg).unwrap();
    assert_eq!(
        driver.wallets_dir(),
        dir.path().join("sqlite_wallets"),
        "empty wallets_dir must resolve to <data_dir>/sqlite_wallets per sqlite.go:321"
    );
    assert!(
        driver.wallets_dir().exists(),
        "the wallets directory must be created by new()"
    );
}

#[test]
fn check_password_after_init_uses_cached_hash() {
    // We can't observe whether scrypt ran the slow path or the cached
    // fast-hash path without timing, but we can at least assert the
    // cached path is functionally correct: CheckPassword after Init
    // accepts the same password and rejects a different one with a
    // typed error.
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver
        .create_wallet(b"cache", b"id-cache", b"pw", None)
        .unwrap();
    let mut wallet = driver.fetch_wallet(b"id-cache").unwrap();
    wallet.init(b"pw").unwrap();

    wallet.check_password(b"pw").unwrap();
    assert!(matches!(
        wallet.check_password(b"nope"),
        Err(Error::Decrypt)
    ));
}

// -----------------------------------------------------------------------------
// Cross-implementation interop: open a wallet produced by go-algorand's
// own kmd driver and export the MDK.

#[derive(serde::Deserialize)]
struct GoFixtureManifest {
    db_relpath: String,
    wallet_id: String,
    password: String,
    mdk_hex: String,
    scrypt_n: i64,
    scrypt_r: i64,
    scrypt_p: i64,
}

const GO_FIXTURE_DIR: &str = "tests/fixtures/go_wallet";
const GO_FIXTURE_MANIFEST: &str = include_str!("fixtures/go_wallet/manifest.json");

fn fixture_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/node/algo-kmd.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(GO_FIXTURE_DIR)
}

#[test]
fn opens_go_wallet_and_exports_known_mdk() {
    let manifest: GoFixtureManifest =
        serde_json::from_str(GO_FIXTURE_MANIFEST).expect("manifest parses");
    let expected_mdk = hex::decode(&manifest.mdk_hex).expect("mdk hex parses");
    assert_eq!(expected_mdk.len(), 32);

    // Copy the read-only fixture into a temp dir so the test doesn't
    // mutate the committed file (sqlite may take WAL/SHM locks).
    let work = TempDir::new().unwrap();
    let src_db = fixture_root().join(&manifest.db_relpath);
    let dst_walletsdir = work.path().join("sqlite_wallets");
    std::fs::create_dir_all(&dst_walletsdir).unwrap();
    let dst_db = dst_walletsdir.join(src_db.file_name().unwrap());
    std::fs::copy(&src_db, &dst_db).expect("copy fixture wallet.db");

    let driver = WalletDriver::new(WalletDriverConfig {
        wallets_dir: dst_walletsdir.clone(),
        scrypt_params: ScryptParams {
            scrypt_n: manifest.scrypt_n,
            scrypt_r: manifest.scrypt_r,
            scrypt_p: manifest.scrypt_p,
        },
        allow_unsafe_scrypt: true,
    })
    .unwrap();

    // List sees the Go-produced wallet.
    let metas = driver.list_wallet_metadatas().unwrap();
    assert!(
        metas.iter().any(|m| m.id == manifest.wallet_id.as_bytes()),
        "expected to see Go-produced wallet in list; got {:?}",
        metas
            .iter()
            .map(|m| String::from_utf8_lossy(&m.id))
            .collect::<Vec<_>>()
    );

    // Open it, unlock with the manifested password, export MDK.
    let mut wallet = driver.fetch_wallet(manifest.wallet_id.as_bytes()).unwrap();
    wallet.init(manifest.password.as_bytes()).unwrap();
    let exported = wallet
        .export_master_derivation_key(manifest.password.as_bytes())
        .unwrap();
    assert_eq!(
        exported.as_slice(),
        expected_mdk.as_slice(),
        "Rust must export the same MDK the Go fixture was created with"
    );

    // Wrong password is rejected, no panic.
    let err = wallet
        .export_master_derivation_key(b"definitely wrong")
        .unwrap_err();
    assert!(matches!(err, Error::Decrypt), "got {err:?}");
}
