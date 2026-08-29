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

//! End-to-end happy path: spawn `kmd-rust serve` against a fresh
//! data dir and drive the wallet workflow (create → init → rename
//! → release) through [`KmdClient`].
//!
//! Mirrors the spawn-server / wait-for-port / SIGTERM-on-drop pattern
//! from `crates/node/algo-kmd/tests/rest_interop_test.rs` so the
//! same operational invariants apply (Unix-only, requires a writable
//! tmpdir, picks an ephemeral port via kmd-rust's auto-bind).
//!
//! No `MIXED_CLUSTER` gate — this exercises pure Rust↔Rust and is
//! cheap enough to keep in the default test run.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use algo_codec::canonical_encode_transaction;
use algo_kmd_client::{KmdClient, KmdError};
use algo_types::{Address, SignedTransaction, Transaction, TxnType};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn kmd_rust_binary() -> PathBuf {
    let root = workspace_root();
    let status = Command::new("cargo")
        .args(["build", "-p", "kmd-rust"])
        .current_dir(&root)
        .status()
        .expect("invoke cargo build");
    assert!(status.success(), "cargo build -p kmd-rust failed");
    for c in ["debug/kmd-rust", "release/kmd-rust"] {
        let p = root.join("target").join(c);
        if p.exists() {
            return p;
        }
    }
    panic!("kmd-rust binary not found under {}/target", root.display());
}

fn write_minimal_config(data_dir: &Path) {
    // Match the config used by algo-kmd's rest_interop_test.rs — the
    // insecure scrypt params keep create/init under a second, and
    // `allow_unsafe_scrypt: true` is required for N=1024.
    let cfg = serde_json::json!({
        "drivers": {
            "sqlite": {
                "scrypt": {"scrypt_n": 1024, "scrypt_r": 1, "scrypt_p": 1},
                "allow_unsafe_scrypt": true,
            },
        },
        "session_lifetime_secs": 60,
    });
    std::fs::write(
        data_dir.join("kmd_config.json"),
        serde_json::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
}

fn poll_for_listening(data_dir: &Path, timeout: Duration) -> Result<(String, String), String> {
    let net_path = data_dir.join("kmd.net");
    let token_path = data_dir.join("kmd.token");
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let (Ok(net), Ok(tok)) = (
            std::fs::read_to_string(&net_path),
            std::fs::read_to_string(&token_path),
        ) {
            let net = net.trim().to_string();
            let tok = tok.trim().to_string();
            if !net.is_empty() && !tok.is_empty() {
                return Ok((net, tok));
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "kmd.net / kmd.token never appeared at {}",
        data_dir.display()
    ))
}

fn send_sigterm(pid: u32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe {
        kill(pid as i32, 15);
    }
}

/// RAII guard that SIGTERMs the spawned kmd-rust process when dropped
/// so test failures don't leak child processes.
struct KmdGuard(Child);

impl Drop for KmdGuard {
    fn drop(&mut self) {
        send_sigterm(self.0.id());
        let _ = self.0.wait();
    }
}

fn spawn_kmd(data_dir: &Path) -> (KmdGuard, String, String) {
    write_minimal_config(data_dir);
    let bin = kmd_rust_binary();
    let child = Command::new(&bin)
        .args(["serve", "--data-dir"])
        .arg(data_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kmd-rust");
    let guard = KmdGuard(child);
    let (net, tok) = poll_for_listening(data_dir, Duration::from_secs(20))
        .expect("kmd-rust failed to start within 20s");
    (guard, net, tok)
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

#[test]
fn create_init_rename_release_happy_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_guard, net, tok) = spawn_kmd(tmp.path());
    let client = KmdClient::new(&net, &tok).expect("client");

    rt().block_on(async {
        // versions: unauthenticated GET — sanity check the spawn.
        let v = client.versions().await.expect("versions");
        assert!(
            !v.versions.is_empty(),
            "versions returned at least one entry"
        );

        // create wallet
        let create = client
            .create_wallet("integ-wallet", "sqlite", "secret123", [0u8; 32])
            .await
            .expect("create");
        let wallet_id = create.wallet.id.clone();
        assert!(!wallet_id.is_empty(), "create returned a wallet id");
        assert_eq!(create.wallet.name, "integ-wallet");

        // list_wallets sees the new wallet
        let listed = client.list_wallets().await.expect("list");
        assert!(
            listed.wallets.iter().any(|w| w.id == wallet_id),
            "list_wallets must include the created wallet id {wallet_id}; got {:?}",
            listed.wallets,
        );

        // init wallet → handle
        let init = client
            .init_wallet(&wallet_id, "secret123")
            .await
            .expect("init");
        let handle = init.wallet_handle_token.clone();
        assert!(!handle.is_empty(), "init returned a handle");

        // wallet_info round-trips
        let info = client.wallet_info(&handle).await.expect("info");
        assert_eq!(info.wallet_handle.wallet.id, wallet_id);

        // rename
        client
            .rename_wallet(&wallet_id, "renamed", "secret123")
            .await
            .expect("rename");
        let listed = client.list_wallets().await.expect("list after rename");
        let found = listed
            .wallets
            .iter()
            .find(|w| w.id == wallet_id)
            .expect("wallet still present after rename");
        assert_eq!(found.name, "renamed");

        // release handle
        client
            .release_wallet_handle(&handle)
            .await
            .expect("release");

        // Using the released handle should now produce an Api error
        // with a non-empty server-side message.
        let after = client.wallet_info(&handle).await;
        match after {
            Err(KmdError::Api { message, .. }) => {
                assert!(
                    !message.is_empty(),
                    "released handle must produce a non-empty error message"
                );
            }
            other => panic!("expected KmdError::Api after release, got {other:?}"),
        }
    });
}

#[test]
fn invalid_token_surfaces_api_error_message() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_guard, net, _real_tok) = spawn_kmd(tmp.path());
    let client = KmdClient::new(&net, "wrong-token-not-the-real-one").expect("client");

    rt().block_on(async {
        let err = client
            .list_wallets()
            .await
            .expect_err("must reject bad token");
        // kmd's auth middleware sends back an envelope with the
        // wrong-token message rather than a bare HTTP 401, so we
        // surface it as KmdError::Api. (If the middleware ever
        // changes to plain text, this would become KmdError::Status —
        // either signals the failure correctly.)
        match err {
            KmdError::Api { message, .. } => {
                assert!(
                    !message.is_empty(),
                    "wrong-token error must carry a message"
                );
            }
            KmdError::Status { status, .. } => {
                assert!(
                    status == 401 || status == 403,
                    "expected 401/403, got {status}",
                );
            }
            other => panic!("expected Api or Status error for wrong token, got {other:?}"),
        }
    });
}

#[test]
fn unknown_driver_surfaces_api_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_guard, net, tok) = spawn_kmd(tmp.path());
    let client = KmdClient::new(&net, &tok).expect("client");

    rt().block_on(async {
        let err = client
            .create_wallet("foo", "definitely-not-a-driver", "pw", [0u8; 32])
            .await
            .expect_err("unknown driver must fail");
        match err {
            KmdError::Api { message, .. } => {
                assert!(!message.is_empty(), "unknown driver must carry a message");
            }
            other => panic!("expected KmdError::Api for unknown driver, got {other:?}"),
        }
    });
}

// ---------- TASK-233 (B1) coverage: key + multisig + sign + renew ---------

/// Helper: open a wallet and return (wallet_id, handle).
async fn create_and_init(client: &KmdClient, name: &str, pw: &str) -> (String, String) {
    let create = client
        .create_wallet(name, "sqlite", pw, [0u8; 32])
        .await
        .expect("create");
    let init = client
        .init_wallet(&create.wallet.id, pw)
        .await
        .expect("init");
    (create.wallet.id, init.wallet_handle_token)
}

#[test]
fn generate_key_list_keys_round_trip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_g, net, tok) = spawn_kmd(tmp.path());
    let client = KmdClient::new(&net, &tok).expect("client");

    rt().block_on(async {
        let (_id, handle) = create_and_init(&client, "key-rt", "pw").await;

        // Empty wallet → no keys.
        let initial = client.list_keys(&handle).await.expect("list_keys empty");
        assert!(initial.addresses.is_empty(), "fresh wallet has no keys");

        // generate_key returns a non-empty base32 address.
        let g = client.generate_key(&handle).await.expect("generate_key");
        assert!(!g.address.is_empty(), "generate_key returns an address");
        // Parses as a real Algorand address.
        let parsed = Address::from_algorand_string(&g.address)
            .expect("generated address is a valid Algorand base32 string");
        assert!(!parsed.is_zero(), "generated pubkey is non-zero");

        // list_keys now contains it.
        let after = client
            .list_keys(&handle)
            .await
            .expect("list_keys after gen");
        assert!(
            after.addresses.contains(&g.address),
            "list_keys must contain the freshly generated address {} (got {:?})",
            g.address,
            after.addresses,
        );
    });
}

#[test]
fn sign_transaction_returns_valid_ed25519_signature() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_g, net, tok) = spawn_kmd(tmp.path());
    let client = KmdClient::new(&net, &tok).expect("client");

    rt().block_on(async {
        let (_id, handle) = create_and_init(&client, "sign-rt", "pw").await;
        let signer_addr_str = client
            .generate_key(&handle)
            .await
            .expect("generate_key")
            .address;
        let signer_addr = Address::from_algorand_string(&signer_addr_str).expect("addr parse");

        // Build a synthetic pay txn with the freshly generated key as
        // sender (so kmd will agree to sign it). Only the fields that
        // affect canonical encoding matter for the signature check; the
        // rest stay default. Mirrors the shape of a real `goal clerk
        // send` payment but with a localnet-style genesis hash.
        let mut txn = Transaction {
            txn_type: TxnType::Pay,
            sender: signer_addr,
            fee: 1000,
            first_valid: 1.into(),
            last_valid: 1000.into(),
            amount: 0,
            receiver: signer_addr,
            ..Default::default()
        };
        txn.genesis_id = "kmd-client-test".to_string();
        txn.genesis_hash = [7u8; 32];

        let txn_bytes = canonical_encode_transaction(&txn);

        // Sign — pass [0u8;32] for `signer` to mirror Go's "infer from
        // txn.snd" behavior; the server resolves the key from the txn
        // sender.
        let resp = client
            .sign_transaction(&handle, "pw", txn_bytes.clone(), [0u8; 32])
            .await
            .expect("sign_transaction");
        assert!(!resp.signed_transaction.is_empty(), "got signed bytes");

        // Decode the returned SignedTransaction msgpack and pull out
        // the sig.
        let signed = SignedTransaction::decode_from_bytes(&resp.signed_transaction)
            .expect("decode SignedTransaction");
        assert_eq!(signed.txn.sender, signer_addr, "sender preserved");
        assert_ne!(signed.sig, [0u8; 64], "sig field populated");

        // Verify: ed25519(pubkey).verify("TX" || canonical_encode(txn))
        // Matches go-algorand's `crypto.HashRep` rule for transaction
        // signing (protocol/hash.go: "TX").
        let mut msg = Vec::with_capacity(2 + txn_bytes.len());
        msg.extend_from_slice(b"TX");
        msg.extend_from_slice(&txn_bytes);
        let vk = VerifyingKey::from_bytes(&signer_addr.0).expect("pubkey parses");
        let sig = Signature::from_bytes(&signed.sig);
        vk.verify(&msg, &sig)
            .expect("ed25519 sig must verify under TX-tagged canonical txn");
    });
}

#[test]
fn multisig_round_trip_import_list_export_delete() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_g, net, tok) = spawn_kmd(tmp.path());
    let client = KmdClient::new(&net, &tok).expect("client");

    rt().block_on(async {
        let (_id, handle) = create_and_init(&client, "msig-rt", "pw").await;

        // Mint two component keys.
        let a_addr = client.generate_key(&handle).await.expect("genA").address;
        let b_addr = client.generate_key(&handle).await.expect("genB").address;
        let a_pk = Address::from_algorand_string(&a_addr).expect("a parse").0;
        let b_pk = Address::from_algorand_string(&b_addr).expect("b parse").0;

        // Import a 1-of-2 multisig.
        let imp = client
            .import_multisig(&handle, 1, 1, vec![a_pk, b_pk])
            .await
            .expect("import_multisig");
        let msig_addr = imp.address;
        assert!(!msig_addr.is_empty(), "import returned an address");

        // list_multisig_addrs sees it.
        let listed = client
            .list_multisig_addrs(&handle)
            .await
            .expect("list_multisig");
        assert!(
            listed.addresses.contains(&msig_addr),
            "list_multisig must include the new msig addr {msig_addr} (got {:?})",
            listed.addresses,
        );

        // export_multisig returns the same preimage.
        let exp = client
            .export_multisig(&handle, &msig_addr)
            .await
            .expect("export_multisig");
        assert_eq!(exp.version, 1, "version preserved");
        assert_eq!(exp.threshold, 1, "threshold preserved");
        assert_eq!(exp.pks, vec![a_pk, b_pk], "pks preserved in order");

        // Re-export after delete should fail with an API error.
        client
            .delete_multisig(&handle, "pw", &msig_addr)
            .await
            .expect("delete_multisig");
        let after = client.export_multisig(&handle, &msig_addr).await;
        match after {
            Err(KmdError::Api { message, .. }) => {
                assert!(
                    !message.is_empty(),
                    "post-delete export must carry a message"
                );
            }
            other => panic!("expected KmdError::Api after delete, got {other:?}"),
        }
    });
}

#[test]
fn delete_key_wrong_password_surfaces_api_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_g, net, tok) = spawn_kmd(tmp.path());
    let client = KmdClient::new(&net, &tok).expect("client");

    rt().block_on(async {
        let (_id, handle) = create_and_init(&client, "del-bad-pw", "right-pw").await;
        let addr = client
            .generate_key(&handle)
            .await
            .expect("generate_key")
            .address;

        let err = client
            .delete_key(&handle, "wrong-pw", &addr)
            .await
            .expect_err("wrong password must surface as error");
        match err {
            KmdError::Api { message, .. } => {
                assert!(
                    !message.is_empty(),
                    "wrong-password delete must carry a server message"
                );
            }
            other => panic!("expected KmdError::Api for wrong password, got {other:?}"),
        }

        // The key is still there.
        let after = client.list_keys(&handle).await.expect("list_keys");
        assert!(
            after.addresses.contains(&addr),
            "key must still be present after failed delete"
        );
    });
}

#[test]
fn renew_wallet_handle_extends_existing_handle() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_g, net, tok) = spawn_kmd(tmp.path());
    let client = KmdClient::new(&net, &tok).expect("client");

    rt().block_on(async {
        let (_id, handle) = create_and_init(&client, "renew-rt", "pw").await;

        // Renew should succeed and keep the handle usable.
        let renewed = client
            .renew_wallet_handle(&handle)
            .await
            .expect("renew_wallet_handle");
        // The renewed envelope embeds the same handle's wallet metadata.
        assert_eq!(
            renewed.wallet_handle.wallet.id,
            client
                .wallet_info(&handle)
                .await
                .expect("wallet_info after renew")
                .wallet_handle
                .wallet
                .id,
            "renew must report the same wallet id as wallet_info",
        );
    });
}

#[test]
fn master_key_export_returns_thirty_two_bytes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_g, net, tok) = spawn_kmd(tmp.path());
    let client = KmdClient::new(&net, &tok).expect("client");

    rt().block_on(async {
        let (_id, handle) = create_and_init(&client, "mdk-rt", "pw").await;

        let mdk = client
            .master_key_export(&handle, "pw")
            .await
            .expect("master_key_export");
        // MDK is a fixed-size 32-byte key (common::APIV1MasterDerivationKey);
        // the kmd server generates it randomly per wallet, so any non-zero
        // value confirms the field deserialized correctly.
        assert_ne!(
            mdk.master_derivation_key, [0u8; 32],
            "MDK must be a non-zero random key",
        );
    });
}
