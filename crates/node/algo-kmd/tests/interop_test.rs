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

//! MIXED_CLUSTER=1 end-to-end interop tests (TASK-207).
//!
//! These tests are *gated* — they run only when the environment
//! variable `MIXED_CLUSTER` is set to `1`. They exercise full
//! bidirectional schema interop between `algo-kmd` and go-algorand's
//! actual kmd driver:
//!
//! - `go_writes_rust_reads`: shells out to
//!   `tools/kmd-wallet-interop write <tmpdir>` which uses
//!   `driver.SQLiteWalletDriver.CreateWallet` + `GenerateKey` +
//!   `ImportKey` + `ImportMultisigAddr` to build a wallet. Rust then
//!   opens that wallet, reads every entry, and asserts the bytes match
//!   what Go recorded in the manifest.
//!
//! - `rust_writes_go_reads`: builds a wallet under `algo-kmd` with the
//!   same workload (same MDK, same imported seeds, same multisig
//!   inputs) and writes a manifest, then shells out to
//!   `tools/kmd-wallet-interop verify` which uses go-algorand's kmd to
//!   open the wallet and assert each manifest entry matches the bytes
//!   it reads back.
//!
//! Skipped by default because:
//! - they require the `go` toolchain
//! - they require the `../go-algorand` source tree to be present
//!   (the Go tool's go.mod uses `replace github.com/algorand/go-algorand
//!   => ../../../go-algorand`)
//! - they run real scrypt (weak params, but still ~100ms each)
//!
//! Run with `MIXED_CLUSTER=1 cargo test -p algo-kmd --test interop_test`.

use std::path::PathBuf;
use std::process::Command;

use algo_kmd::{
    config::ScryptParams, WalletDriver, WalletDriverConfig, ADDRESS_LEN, SECRET_KEY_LEN,
};
use tempfile::TempDir;

// ---- Shared workload definition --------------------------------------------
// These values must match the constants in
// tools/kmd-wallet-interop/main.go exactly. Any drift breaks the
// `rust_writes_go_reads` direction silently — both tests assert against
// each other.

const WALLET_NAME: &[u8] = b"interop";
const WALLET_ID: &[u8] = b"interop-id";
const PASSWORD: &[u8] = b"interop-pw";
const NUM_DERIVED: usize = 2;
const NUM_IMPORTED: usize = 2;
const SCRYPT_N: i64 = 1024;
const SCRYPT_R: i64 = 1;
const SCRYPT_P: i64 = 1;

fn fixed_mdk() -> [u8; 32] {
    let mut mdk = [0u8; 32];
    for (i, b) in mdk.iter_mut().enumerate() {
        *b = 0xA0u8.wrapping_add(i as u8);
    }
    mdk
}

fn imported_seeds() -> Vec<[u8; 32]> {
    (0..NUM_IMPORTED)
        .map(|i| {
            let mut s = [0u8; 32];
            for (j, b) in s.iter_mut().enumerate() {
                *b = 0xC0u8.wrapping_add((i * 32 + j) as u8);
            }
            s
        })
        .collect()
}

struct MsigDef {
    version: u8,
    threshold: u8,
    pk_offset: u8,
    pk_count: usize,
}

fn msig_inputs() -> Vec<MsigDef> {
    vec![
        MsigDef {
            version: 1,
            threshold: 2,
            pk_offset: 0x10,
            pk_count: 3,
        },
        MsigDef {
            version: 1,
            threshold: 1,
            pk_offset: 0x40,
            pk_count: 2,
        },
    ]
}

fn make_pks(count: usize, offset: u8) -> Vec<[u8; ADDRESS_LEN]> {
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

fn weak_driver_cfg(wallets_dir: PathBuf) -> WalletDriverConfig {
    WalletDriverConfig {
        wallets_dir,
        scrypt_params: ScryptParams {
            scrypt_n: SCRYPT_N,
            scrypt_r: SCRYPT_R,
            scrypt_p: SCRYPT_P,
        },
        allow_unsafe_scrypt: true,
    }
}

fn mixed_cluster_enabled() -> bool {
    std::env::var("MIXED_CLUSTER").as_deref() == Ok("1")
}

/// `tools/kmd-wallet-interop/` relative to the algod-rust workspace root.
fn interop_tool_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/node/algo-kmd. Workspace root is ../../..
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("tools/kmd-wallet-interop")
        .canonicalize()
        .expect("interop tool dir resolves")
}

fn run_go_tool(args: &[&str]) {
    let dir = interop_tool_dir();
    let mut cmd = Command::new("go");
    cmd.arg("run").arg(".").args(args).current_dir(&dir);
    let output = cmd.output().expect("invoke go run");
    if !output.status.success() {
        panic!(
            "go run {:?} failed (status {:?})\nstdout: {}\nstderr: {}",
            args,
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

// ---- Manifest types (shared with the Go tool's JSON output) ----------------

#[derive(serde::Serialize, serde::Deserialize)]
struct KeyEntry {
    address_hex: String,
    secret_key_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_idx: Option<u64>,
    source: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MsigEntry {
    address_hex: String,
    version: u8,
    threshold: u8,
    pks_hex: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Manifest {
    db_relpath: String,
    wallet_id: String,
    wallet_name: String,
    password: String,
    mdk_hex: String,
    scrypt_n: i64,
    scrypt_r: i64,
    scrypt_p: i64,
    keys: Vec<KeyEntry>,
    multisig: Vec<MsigEntry>,
}

// ---- Direction A: Go writes, Rust reads ------------------------------------

#[test]
fn go_writes_rust_reads() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "skipping go_writes_rust_reads: set MIXED_CLUSTER=1 to enable \
             (requires `go` and ../go-algorand)"
        );
        return;
    }

    let work = TempDir::new().unwrap();
    let out = work.path().to_path_buf();

    // 1. Go: write a wallet + manifest.
    run_go_tool(&["write", out.to_str().unwrap()]);

    let manifest_path = out.join("manifest.json");
    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();

    let wallets_dir = out.join("sqlite_wallets");
    let driver = WalletDriver::new(weak_driver_cfg(wallets_dir)).unwrap();

    // 2. Rust: open the Go-produced wallet.
    let mut wallet = driver.fetch_wallet(manifest.wallet_id.as_bytes()).unwrap();
    wallet.init(manifest.password.as_bytes()).unwrap();

    // MDK matches.
    let exported_mdk = wallet
        .export_master_derivation_key(manifest.password.as_bytes())
        .unwrap();
    assert_eq!(
        hex::encode(exported_mdk),
        manifest.mdk_hex,
        "Rust must export the same MDK Go's kmd stored"
    );

    // Every key listed by Go is found by Rust, and the SK matches.
    let listed = wallet.list_keys().unwrap();
    assert_eq!(listed.len(), manifest.keys.len());
    for k in &manifest.keys {
        let addr = hex_to_addr(&k.address_hex);
        assert!(
            listed.contains(&addr),
            "address {} from Go manifest not in Rust list_keys",
            k.address_hex
        );
        assert!(wallet.lookup_key(&addr).unwrap());
        let exported = wallet
            .export_key(&addr, manifest.password.as_bytes())
            .unwrap();
        assert_eq!(
            hex::encode(exported),
            k.secret_key_hex,
            "SK mismatch for {} (source={})",
            k.address_hex,
            k.source
        );
    }

    // Every multisig entry listed by Go is found by Rust.
    let listed_msig = wallet.list_multisig().unwrap();
    assert_eq!(listed_msig.len(), manifest.multisig.len());
    for m in &manifest.multisig {
        let addr = hex_to_addr(&m.address_hex);
        assert!(listed_msig.contains(&addr));
        let pre = wallet.lookup_multisig(&addr).unwrap();
        assert_eq!(pre.version, m.version);
        assert_eq!(pre.threshold, m.threshold);
        assert_eq!(pre.pks.len(), m.pks_hex.len());
        for (got, want) in pre.pks.iter().zip(&m.pks_hex) {
            assert_eq!(hex::encode(got), *want);
        }
    }
}

// ---- Direction B: Rust writes, Go reads ------------------------------------

#[test]
fn rust_writes_go_reads() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "skipping rust_writes_go_reads: set MIXED_CLUSTER=1 to enable \
             (requires `go` and ../go-algorand)"
        );
        return;
    }

    let work = TempDir::new().unwrap();
    let wallets_dir = work.path().join("sqlite_wallets");
    std::fs::create_dir_all(&wallets_dir).unwrap();

    let driver = WalletDriver::new(weak_driver_cfg(wallets_dir.clone())).unwrap();
    let mdk = fixed_mdk();
    driver
        .create_wallet(WALLET_NAME, WALLET_ID, PASSWORD, Some(mdk))
        .unwrap();
    let mut wallet = driver.fetch_wallet(WALLET_ID).unwrap();
    wallet.init(PASSWORD).unwrap();

    let mut manifest = Manifest {
        db_relpath: format!(
            "sqlite_wallets/{}.{}.db",
            std::str::from_utf8(WALLET_NAME).unwrap(),
            std::str::from_utf8(WALLET_ID).unwrap(),
        ),
        wallet_id: String::from_utf8(WALLET_ID.to_vec()).unwrap(),
        wallet_name: String::from_utf8(WALLET_NAME.to_vec()).unwrap(),
        password: String::from_utf8(PASSWORD.to_vec()).unwrap(),
        mdk_hex: hex::encode(mdk),
        scrypt_n: SCRYPT_N,
        scrypt_r: SCRYPT_R,
        scrypt_p: SCRYPT_P,
        keys: Vec::new(),
        multisig: Vec::new(),
    };

    // Generate N derived keys.
    for i in 0..NUM_DERIVED {
        let addr = wallet.generate_key().unwrap();
        let sk = wallet.export_key(&addr, PASSWORD).unwrap();
        manifest.keys.push(KeyEntry {
            address_hex: hex::encode(addr),
            secret_key_hex: hex::encode(sk),
            key_idx: Some(i as u64 + 1),
            source: "derived".into(),
        });
    }

    // Import N keys with deterministic seeds.
    for seed in imported_seeds() {
        let mut sk_input = [0u8; SECRET_KEY_LEN];
        sk_input[..32].copy_from_slice(&seed);
        // pubkey half is re-derived; left zero here.
        let addr = wallet.import_key(&sk_input).unwrap();
        let sk_full = wallet.export_key(&addr, PASSWORD).unwrap();
        manifest.keys.push(KeyEntry {
            address_hex: hex::encode(addr),
            secret_key_hex: hex::encode(sk_full),
            key_idx: None,
            source: "imported".into(),
        });
    }

    // Import multisig entries.
    for m in msig_inputs() {
        let pks = make_pks(m.pk_count, m.pk_offset);
        let addr = wallet
            .import_multisig(m.version, m.threshold, &pks)
            .unwrap();
        manifest.multisig.push(MsigEntry {
            address_hex: hex::encode(addr),
            version: m.version,
            threshold: m.threshold,
            pks_hex: pks.iter().map(hex::encode).collect(),
        });
    }

    // Write the manifest where the Go tool expects it.
    let manifest_path = work.path().join("manifest.json");
    let json = serde_json::to_vec_pretty(&manifest).unwrap();
    std::fs::write(&manifest_path, json).unwrap();

    // Hand off to Go: open the Rust-written wallet and assert every entry.
    let work_str = work.path().to_str().unwrap();
    let mfp_str = manifest_path.to_str().unwrap();
    run_go_tool(&["verify", work_str, mfp_str]);
}

fn hex_to_addr(s: &str) -> [u8; ADDRESS_LEN] {
    let bytes = hex::decode(s).unwrap();
    assert_eq!(bytes.len(), ADDRESS_LEN);
    let mut addr = [0u8; ADDRESS_LEN];
    addr.copy_from_slice(&bytes);
    addr
}

#[test]
fn interop_tests_are_skipped_when_env_not_set() {
    // Sanity: when MIXED_CLUSTER is unset (CI default), the gating
    // function returns false so the two tests above no-op. This test
    // documents that behavior and runs unconditionally.
    if std::env::var("MIXED_CLUSTER").is_ok() {
        // When the gate IS set we don't have a strong assertion to
        // make here; just succeed.
        return;
    }
    assert!(!mixed_cluster_enabled());
}
