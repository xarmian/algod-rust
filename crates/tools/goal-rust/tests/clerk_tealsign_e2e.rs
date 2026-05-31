//! `goal-rust clerk tealsign` parity test (TASK-290, `cmd/goal/tealsign.go`).
//!
//! Signs a fixed payload with a fixed ed25519 seed and asserts the printed
//! base64 signature byte-for-byte matches the reference produced by
//! go-algorand v4.5.1-stable's `crypto.SignatureSecrets.Sign(logic.Msg{...})`
//! (i.e. ed25519 over `"ProgData" || HashProgram(program) || data`).
//!
//! This runs offline (no node / kmd) — it only invokes the `goal-rust` binary —
//! so it's part of the default `cargo test` run.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

/// The contract address (program hash) of `#pragma version 2; int 1`, from
/// `logic.HashProgram` — the same program the localnet logicsig e2e uses.
const CONTRACT_ADDR: &str = "YOE6C22GHCTKAN3HU4SE5PGIPN5UKXAJTXCQUPJ3KKF5HOAH646MKKCPDA";

/// Reference signature for seed=[1,2,..,32], data=0xDEADBEEF, signed against the
/// above contract's program hash. Captured from `sec.Sign(logic.Msg{...})` in
/// go-algorand v4.5.1-stable.
const GO_REF_SIG_B64: &str =
    "PinXFNDIA1tNSR8nYDCn39tCMdtnztoiRJXFTDtImauk+rb8P9sJhktkxR8lIX0WnSRyj4g1Rv8c/Se0I63eAA==";

fn goal_rust(args: &[&str]) -> std::process::Output {
    Command::new(GOAL_RUST_BIN)
        .args(args)
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust")
}

#[test]
fn tealsign_contract_addr_data_b64_matches_go() {
    let dir = tempfile::tempdir().expect("tempdir");
    // algokey keyfile = raw 32-byte ed25519 seed (cmd/algokey writePrivateKey).
    let seed: Vec<u8> = (1u8..=32).collect();
    let keyfile = dir.path().join("key.bin");
    std::fs::write(&keyfile, &seed).unwrap();

    let out = goal_rust(&[
        "clerk",
        "tealsign",
        "--keyfile",
        keyfile.to_str().unwrap(),
        "--contract-addr",
        CONTRACT_ADDR,
        "--data-b64",
        "3q2+7w==", // 0xDEADBEEF
    ]);
    assert!(
        out.status.success(),
        "tealsign failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let sig_line = stdout
        .lines()
        .find_map(|l| l.strip_prefix("Signature: "))
        .unwrap_or_else(|| panic!("no Signature line in:\n{stdout}"));
    assert_eq!(
        sig_line.trim(),
        GO_REF_SIG_B64,
        "tealsign signature must match go-algorand's logic.Msg signing"
    );
}

#[test]
fn tealsign_set_lsig_arg_idx_rewrites_file_and_appends_signature() {
    // Build a SignedTxn file carrying an `int 1` LogicSig, then tealsign with
    // --sign-txid + --set-lsig-arg-idx to store the signature as lsig arg 0.
    let dir = tempfile::tempdir().expect("tempdir");
    let seed: Vec<u8> = (1u8..=32).collect();
    let keyfile = dir.path().join("key.bin");
    std::fs::write(&keyfile, &seed).unwrap();

    let lsig_txn = dir.path().join("lsig.tx");
    write_int1_lsig_payment(&lsig_txn);
    let before = std::fs::read(&lsig_txn).unwrap();

    let out = goal_rust(&[
        "clerk",
        "tealsign",
        "--keyfile",
        keyfile.to_str().unwrap(),
        "--lsig-txn",
        lsig_txn.to_str().unwrap(),
        "--sign-txid",
        "--set-lsig-arg-idx",
        "0",
    ]);
    assert!(
        out.status.success(),
        "tealsign --set-lsig-arg-idx failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Updated lsig arg 0"),
        "should report the in-place arg update; got:\n{stdout}"
    );
    assert!(
        stdout.contains("Signature: "),
        "should still print the base64 signature; got:\n{stdout}"
    );
    let after = std::fs::read(&lsig_txn).unwrap();
    assert_ne!(before, after, "lsig-txn file must be rewritten in place");

    // The rewritten file must decode with a 64-byte arg at index 0.
    let decoded = algo_codec::decode_signed_txn_stream(&after).expect("decode rewritten file");
    assert_eq!(decoded.len(), 1);
    let args = decoded[0]
        .lsig
        .as_ref()
        .expect("lsig present")
        .args
        .as_ref()
        .expect("args present");
    assert_eq!(args.len(), 1, "exactly one arg stored");
    assert_eq!(args[0].len(), 64, "arg 0 is a 64-byte ed25519 signature");
}

/// Write a single payment SignedTxn carrying the `int 1` LogicSig (no
/// delegated sig — a contract-account escrow spend) to `path`.
fn write_int1_lsig_payment(path: &Path) {
    use algo_types::{Address, LogicSig, SignedTransaction, Transaction, TxnType};
    use serde_bytes::ByteBuf;

    // Assembled bytes of `#pragma version 2; int 1` (0x0220010122).
    let program = vec![0x02u8, 0x20, 0x01, 0x01, 0x22];
    let txn = Transaction {
        txn_type: TxnType::Pay,
        sender: Address([7u8; 32]),
        fee: 1000,
        first_valid: 1.into(),
        last_valid: 1001.into(),
        genesis_hash: [9u8; 32],
        amount: 1,
        receiver: Address([8u8; 32]),
        ..Transaction::default()
    };
    let stxn = SignedTransaction {
        txn,
        lsig: Some(LogicSig {
            logic: ByteBuf::from(program),
            ..LogicSig::default()
        }),
        ..SignedTransaction::default()
    };
    let encoded = algo_codec::canonical_encode_signed_transaction(&stxn);
    std::fs::write(path, &encoded).unwrap();
}
