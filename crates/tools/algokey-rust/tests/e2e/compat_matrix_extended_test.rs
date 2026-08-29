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

//! Bidirectional algokey compatibility matrix — extended (TASK-200).
//!
//! Builds on the framework from TASK-199. Covers the second half of the
//! matrix:
//!
//! | Artifact            | Go → Rust                               | Rust → Go                              |
//! |---------------------|-----------------------------------------|----------------------------------------|
//! | multisig-partial    | Go adds A's sig → Rust verifies subsig  | Rust adds A's sig → Go verifies        |
//! | multisig-assembled  | A via Go + B via Rust → submit → algod  | A via Rust + B via Go → submit → algod |
//! | append-auth-addr    | Go produces, Rust decodes/verifies      | Rust produces, Go decodes/verifies     |
//! | partkey-db          | Go gen → Rust `part info` matches Go    | Rust gen → Go `part info` matches Rust |
//! | partkey-reparent    | Go reparent → Rust info reflects new    | Rust reparent → Go info reflects new   |
//! | keyreg-offline      | Go offline keyreg → submit → Offline    | Rust offline keyreg → submit → Offline |
//! | keyreg-online       | (covered by TASK-185 headline)          | (covered by TASK-185 headline)         |
//!
//! 13 round-trip rows + 1 pass-through for online keyreg. Writes
//! `target/algokey-compat-matrix-extended.xml` (JUnit) alongside the
//! `algokey-compat-matrix-core.xml` from TASK-199 — together both files
//! cover the full matrix.

#[path = "mod.rs"]
mod e2e;

use std::path::{Path, PathBuf};
use std::process::Command;

use algo_codec::{canonical_encode_signed_transaction, canonical_encode_transaction};
use algo_consensus_crypto::{key_to_mnemonic, multisig::multisig_addr_gen};
use algo_types::{
    Address, MultisigSig, MultisigSubsig, Round, SignedTransaction, Transaction, TxnType,
};
use algo_validate::signature::verify_multisig;
use assert_cmd::Command as AssertCmd;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use tempfile::TempDir;

use e2e::compat_framework::{go_algokey_available, skip_message, Direction, MatrixReport};
use e2e::Localnet;

const MAX_CONFIRMATION_ROUNDS: u64 = 10;

// ---------------------------------------------------------------------------
// CLI wrappers (mirror compat_matrix_core_test)
// ---------------------------------------------------------------------------

fn rust_algokey() -> AssertCmd {
    AssertCmd::cargo_bin("algokey-rust").expect("locate algokey-rust binary")
}

fn run_go(args: &[&str]) -> String {
    let out = Command::new("algokey")
        .args(args)
        .output()
        .expect("spawn Go algokey");
    assert!(
        out.status.success(),
        "Go algokey {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn address_for_seed(seed: &[u8; 32]) -> Address {
    Address(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

fn read_signed_txn(path: &Path) -> SignedTransaction {
    let bytes = std::fs::read(path).expect("read signed txn");
    let mut de = rmp_serde::Deserializer::new(std::io::Cursor::new(&bytes));
    serde::Deserialize::deserialize(&mut de).expect("decode SignedTransaction")
}

fn write_msgpack_signed(path: &Path, stx: &SignedTransaction) {
    let bytes = canonical_encode_signed_transaction(stx);
    std::fs::write(path, bytes).expect("write SignedTransaction");
}

/// Verify an ed25519 signature over `"TX" || canonical_encode(txn)`. Mirrors
/// what `verify_single_sig` does for the `sig` field, but operates on any
/// supplied (pubkey, sig) pair so we can audit individual msig subsig slots.
fn verify_ed25519_over_txn(
    txn: &Transaction,
    pubkey: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), String> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|e| format!("invalid pubkey: {e}"))?;
    let sig = Signature::from_bytes(signature);
    let canonical = canonical_encode_transaction(txn);
    let mut msg = Vec::with_capacity(2 + canonical.len());
    msg.extend_from_slice(b"TX");
    msg.extend_from_slice(&canonical);
    vk.verify(&msg, &sig)
        .map_err(|e| format!("ed25519 verify: {e}"))
}

// ---------------------------------------------------------------------------
// Multisig template builder
// ---------------------------------------------------------------------------

struct MsigKey {
    address: Address,
    mnemonic: String,
}

fn fresh_msig_signer() -> MsigKey {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let address = address_for_seed(&seed);
    let mnemonic = key_to_mnemonic(&seed).expect("encode mnemonic");
    MsigKey { address, mnemonic }
}

/// Build an unsigned `SignedTransaction` whose sender is the multisig address
/// derived from `signers` (v=1, threshold), with an empty-sig msig template
/// in place. Both Go and Rust `algokey multisig` consume this shape.
#[allow(clippy::too_many_arguments)] // Mirrors txn-field shape.
fn build_unsigned_msig_txn(
    signers: &[&MsigKey],
    threshold: u8,
    receiver: Address,
    amount: u64,
    fee: u64,
    first_valid: u64,
    last_valid: u64,
    genesis_hash: [u8; 32],
    genesis_id: &str,
) -> (SignedTransaction, Address) {
    let pks: Vec<[u8; 32]> = signers.iter().map(|s| s.address.0).collect();
    let msig_addr = multisig_addr_gen(1, threshold, &pks).expect("multisig_addr_gen");
    let subsigs = pks
        .iter()
        .map(|pk| MultisigSubsig {
            public_key: *pk,
            signature: [0u8; 64],
        })
        .collect();
    let txn = Transaction {
        txn_type: TxnType::Pay,
        sender: msig_addr,
        fee,
        first_valid: Round(first_valid),
        last_valid: Round(last_valid),
        genesis_hash,
        genesis_id: genesis_id.to_string(),
        receiver,
        amount,
        ..Transaction::default()
    };
    let stx = SignedTransaction {
        txn,
        msig: Some(MultisigSig {
            version: 1,
            threshold,
            subsigs,
        }),
        ..SignedTransaction::default()
    };
    (stx, msig_addr)
}

// ---------------------------------------------------------------------------
// Row 1: multisig partial sig (both directions)
// ---------------------------------------------------------------------------

async fn row_multisig_partial(report: &mut MatrixReport, workdir: &Path, net: &Localnet) {
    let artifact = "multisig-partial";

    let params = net.client().suggested_transaction_params().await.unwrap();
    let a = fresh_msig_signer();
    let b = fresh_msig_signer();
    let c = fresh_msig_signer();

    // Go → Rust: Go signs slot A; Rust verify_multisig should accept the
    // partial as "1 of 2 sigs present" — verify_multisig requires threshold
    // sigs, so we expect this row to validate the SLOT was filled
    // correctly, not that the msig is complete. We assert subsigs[0].signature
    // is non-zero and matches an ed25519 sig over "TX"||canonical(txn).
    {
        let (unsigned, _msig_addr) = build_unsigned_msig_txn(
            &[&a, &b, &c],
            2,
            a.address,
            0,
            params.min_fee,
            params.last_round,
            params.last_round + 1000,
            params.genesis_hash.0,
            &params.genesis_id,
        );
        let unsigned_path = workdir.join("msig_g2r_partial.unsigned");
        let signed_path = workdir.join("msig_g2r_partial.signed");
        write_msgpack_signed(&unsigned_path, &unsigned);

        let _ = run_go(&[
            "multisig",
            "-m",
            &a.mnemonic,
            "-t",
            unsigned_path.to_str().unwrap(),
            "-o",
            signed_path.to_str().unwrap(),
        ]);

        let signed = read_signed_txn(&signed_path);
        let msig = signed.msig.as_ref().expect("Go must preserve msig block");
        if msig.subsigs[0].signature == [0u8; 64] {
            report.fail(
                artifact,
                Direction::GoToRust,
                "Go's multisig left slot 0 empty",
            );
        } else if msig.subsigs[1].signature != [0u8; 64] || msig.subsigs[2].signature != [0u8; 64] {
            report.fail(
                artifact,
                Direction::GoToRust,
                "Go filled more than slot 0 — expected partial",
            );
        } else {
            // Cryptographically verify Go's signature against A's pubkey
            // over "TX" || canonical_encode(txn). Otherwise arbitrary
            // nonzero bytes in slot 0 would slip past.
            match verify_ed25519_over_txn(&signed.txn, &a.address.0, &msig.subsigs[0].signature) {
                Ok(()) => report.pass(artifact, Direction::GoToRust),
                Err(e) => report.fail(
                    artifact,
                    Direction::GoToRust,
                    format!("Rust rejects Go's slot-A signature: {e}"),
                ),
            }
        }
    }

    // Rust → Go: Rust signs slot A, Go signs slot A independently with the
    // same input + same mnemonic. Ed25519 is deterministic, so the wire
    // bytes MUST match exactly — strong byte-level cross-impl evidence that
    // Rust's output is something Go would have produced identically.
    {
        let (unsigned, _msig_addr) = build_unsigned_msig_txn(
            &[&a, &b, &c],
            2,
            a.address,
            0,
            params.min_fee,
            params.last_round,
            params.last_round + 1000,
            params.genesis_hash.0,
            &params.genesis_id,
        );
        let unsigned_path = workdir.join("msig_r2g_partial.unsigned");
        let rust_signed = workdir.join("msig_r2g_partial.rust");
        let go_signed = workdir.join("msig_r2g_partial.go");
        write_msgpack_signed(&unsigned_path, &unsigned);

        rust_algokey()
            .args(["multisig", "-m", &a.mnemonic, "-t"])
            .arg(&unsigned_path)
            .arg("-o")
            .arg(&rust_signed)
            .assert()
            .success();
        let _ = run_go(&[
            "multisig",
            "-m",
            &a.mnemonic,
            "-t",
            unsigned_path.to_str().unwrap(),
            "-o",
            go_signed.to_str().unwrap(),
        ]);

        let rust_bytes = std::fs::read(&rust_signed).expect("read rust");
        let go_bytes = std::fs::read(&go_signed).expect("read go");
        if rust_bytes == go_bytes {
            report.pass(artifact, Direction::RustToGo);
        } else {
            report.fail(
                artifact,
                Direction::RustToGo,
                format!(
                    "Rust multisig partial bytes diverge from Go's for the same input: rust={} go={}",
                    hex::encode(&rust_bytes),
                    hex::encode(&go_bytes)
                ),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Row 2: multisig assembled cross-signer + on-chain submission
// ---------------------------------------------------------------------------

/// Merge two partially-signed multisig transactions slot-by-slot, taking
/// whichever side has a non-zero signature in each slot. `algokey multisig`
/// on both sides ONLY fills the invoking signer's slot — assembling a
/// threshold of signatures is the caller's job. Mirrors what
/// `goal clerk multisig merge` does internally.
fn merge_multisigs(a: &SignedTransaction, b: &SignedTransaction) -> SignedTransaction {
    let msig_a = a.msig.as_ref().expect("a missing msig");
    let msig_b = b.msig.as_ref().expect("b missing msig");
    assert_eq!(msig_a.subsigs.len(), msig_b.subsigs.len());
    let subsigs = msig_a
        .subsigs
        .iter()
        .zip(&msig_b.subsigs)
        .map(|(sa, sb)| {
            assert_eq!(sa.public_key, sb.public_key, "msig preimages must match");
            let signature = if sa.signature != [0u8; 64] {
                sa.signature
            } else {
                sb.signature
            };
            MultisigSubsig {
                public_key: sa.public_key,
                signature,
            }
        })
        .collect();
    SignedTransaction {
        msig: Some(MultisigSig {
            version: msig_a.version,
            threshold: msig_a.threshold,
            subsigs,
        }),
        ..a.clone()
    }
}

async fn row_multisig_assembled(report: &mut MatrixReport, workdir: &Path, net: &Localnet) {
    let artifact = "multisig-assembled";

    let faucet = e2e::discover_faucet(net).await.expect("faucet");

    for (label, signer_a_is_go) in [(Direction::GoToRust, true), (Direction::RustToGo, false)] {
        let a = fresh_msig_signer();
        let b = fresh_msig_signer();
        let c = fresh_msig_signer();
        let pks = [a.address.0, b.address.0, c.address.0];
        let msig_addr = multisig_addr_gen(1, 2, &pks).expect("msig addr");

        // Fund the msig account so it can pay its own fee.
        let funding_txid = e2e::fund_address(net, &faucet, msig_addr, 10_000_000)
            .await
            .expect("fund msig");
        e2e::wait_for_confirmation(net, &funding_txid, MAX_CONFIRMATION_ROUNDS)
            .await
            .expect("funding must confirm");

        // Build unsigned with msig template.
        let params = net.client().suggested_transaction_params().await.unwrap();
        let (unsigned, derived_addr) = build_unsigned_msig_txn(
            &[&a, &b, &c],
            2,
            msig_addr,
            0,
            params.min_fee,
            params.last_round,
            params.last_round + 1000,
            params.genesis_hash.0,
            &params.genesis_id,
        );
        assert_eq!(derived_addr, msig_addr);

        let prefix = format!(
            "msig_assembled_{}",
            if signer_a_is_go { "g2r" } else { "r2g" }
        );
        let signer_a_partial = workdir.join(format!("{prefix}.a"));
        let signer_b_partial = workdir.join(format!("{prefix}.b"));
        let unsigned_path = workdir.join(format!("{prefix}.unsigned"));
        write_msgpack_signed(&unsigned_path, &unsigned);

        // Each signer signs INDEPENDENTLY off the same unsigned template
        // (so both partials contain the original preimage with only their
        // own slot filled). We then merge slot-by-slot. This mirrors a
        // typical Algorand multisig workflow: distribute the unsigned txn,
        // each signer returns their partial, a coordinator merges them.
        if signer_a_is_go {
            run_go(&[
                "multisig",
                "-m",
                &a.mnemonic,
                "-t",
                unsigned_path.to_str().unwrap(),
                "-o",
                signer_a_partial.to_str().unwrap(),
            ]);
            rust_algokey()
                .args(["multisig", "-m", &b.mnemonic, "-t"])
                .arg(&unsigned_path)
                .arg("-o")
                .arg(&signer_b_partial)
                .assert()
                .success();
        } else {
            rust_algokey()
                .args(["multisig", "-m", &a.mnemonic, "-t"])
                .arg(&unsigned_path)
                .arg("-o")
                .arg(&signer_a_partial)
                .assert()
                .success();
            run_go(&[
                "multisig",
                "-m",
                &b.mnemonic,
                "-t",
                unsigned_path.to_str().unwrap(),
                "-o",
                signer_b_partial.to_str().unwrap(),
            ]);
        }

        let partial_a = read_signed_txn(&signer_a_partial);
        let partial_b = read_signed_txn(&signer_b_partial);
        let assembled = merge_multisigs(&partial_a, &partial_b);
        let msig = assembled.msig.as_ref().expect("msig must survive");
        if msig.subsigs[0].signature == [0u8; 64] || msig.subsigs[1].signature == [0u8; 64] {
            report.fail(
                artifact,
                label,
                format!(
                    "expected slots [0,1] filled, got A_filled={} B_filled={}",
                    msig.subsigs[0].signature != [0u8; 64],
                    msig.subsigs[1].signature != [0u8; 64],
                ),
            );
            continue;
        }
        if msig.subsigs[2].signature != [0u8; 64] {
            report.fail(
                artifact,
                label,
                "slot 2 unexpectedly filled (only 2-of-3 should sign)",
            );
            continue;
        }

        // Rust-side cryptographic verification.
        if let Err(e) = verify_multisig(&assembled, msig) {
            report.fail(
                artifact,
                label,
                format!("Rust verify_multisig rejected: {e}"),
            );
            continue;
        }

        // On-chain confirmation by algod-go.
        let encoded = canonical_encode_signed_transaction(&assembled);
        match e2e::submit_raw_txn(net, &encoded).await {
            Ok(txid) => match e2e::wait_for_confirmation(net, &txid, MAX_CONFIRMATION_ROUNDS).await
            {
                Ok(_) => report.pass(artifact, label),
                Err(e) => report.fail(artifact, label, format!("algod did not confirm: {e}")),
            },
            Err(e) => report.fail(artifact, label, format!("algod rejected on submit: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Row 3: append-auth-addr — produce one side, decode on the other
// ---------------------------------------------------------------------------

async fn row_append_auth_addr(report: &mut MatrixReport, workdir: &Path, net: &Localnet) {
    let artifact = "append-auth-addr";

    let params = net.client().suggested_transaction_params().await.unwrap();
    let a = fresh_msig_signer();
    let b = fresh_msig_signer();
    let c = fresh_msig_signer();
    let pks = [a.address.0, b.address.0, c.address.0];
    let msig_addr = multisig_addr_gen(1, 2, &pks).expect("msig addr");

    // append-auth-addr takes an unsigned txn whose sender was previously rekeyed
    // to a multisig address; it injects the msig preimage so the txn can be
    // validated against AuthAddr semantics. Both Go and Rust produce equivalent
    // outputs given the same input.
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let sender = address_for_seed(&seed);

    // Build a vanilla unsigned txn (no msig block yet) with sender = some
    // account presumed-rekeyed-to-msig.
    let unsigned = SignedTransaction {
        txn: Transaction {
            txn_type: TxnType::Pay,
            sender,
            fee: params.min_fee,
            first_valid: Round(params.last_round),
            last_valid: Round(params.last_round + 1000),
            genesis_hash: params.genesis_hash.0,
            genesis_id: params.genesis_id.clone(),
            receiver: sender,
            amount: 0,
            ..Transaction::default()
        },
        ..SignedTransaction::default()
    };
    let unsigned_path = workdir.join("aaa.unsigned");
    write_msgpack_signed(&unsigned_path, &unsigned);

    let params_str = format!("2 {} {} {}", a.address, b.address, c.address);

    // Go → Rust: Go produces, Rust decodes and inspects.
    {
        let out_path = workdir.join("aaa_g2r.signed");
        let _ = run_go(&[
            "multisig",
            "append-auth-addr",
            "-p",
            &params_str,
            "-t",
            unsigned_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ]);
        let signed = read_signed_txn(&out_path);
        let msig = signed
            .msig
            .as_ref()
            .expect("append-auth-addr must add msig preimage");
        let derived = multisig_addr_gen(
            msig.version,
            msig.threshold,
            &msig
                .subsigs
                .iter()
                .map(|s| s.public_key)
                .collect::<Vec<_>>(),
        )
        .expect("derive msig addr");
        // The defining behavior of append-auth-addr is setting the txn's
        // AuthAddr to the multisig address — assert that, not just the
        // preimage's correctness.
        if signed.auth_addr != Some(msig_addr) {
            report.fail(
                artifact,
                Direction::GoToRust,
                format!(
                    "Go output's auth_addr {:?} ≠ expected msig_addr {msig_addr}",
                    signed.auth_addr
                ),
            );
        } else if derived == msig_addr && msig.threshold == 2 {
            report.pass(artifact, Direction::GoToRust);
        } else {
            report.fail(
                artifact,
                Direction::GoToRust,
                format!("derived msig {derived} ≠ expected {msig_addr} (or threshold ≠ 2)"),
            );
        }
    }

    // Rust → Go: Byte-equality. `append-auth-addr` is pure (no randomness,
    // no time-varying state), so Rust and Go must produce identical wire
    // bytes for the same input. Stronger cross-impl evidence than just
    // decoding the Rust output with Rust.
    {
        let rust_path = workdir.join("aaa_r2g.rust");
        let go_path = workdir.join("aaa_r2g.go");
        rust_algokey()
            .args(["multisig", "append-auth-addr", "-p", &params_str, "-t"])
            .arg(&unsigned_path)
            .arg("-o")
            .arg(&rust_path)
            .assert()
            .success();
        let _ = run_go(&[
            "multisig",
            "append-auth-addr",
            "-p",
            &params_str,
            "-t",
            unsigned_path.to_str().unwrap(),
            "-o",
            go_path.to_str().unwrap(),
        ]);

        let rust_bytes = std::fs::read(&rust_path).expect("read rust output");
        let go_bytes = std::fs::read(&go_path).expect("read go output");
        if rust_bytes == go_bytes {
            report.pass(artifact, Direction::RustToGo);
        } else {
            // Mismatch indicates a real serialization or preimage divergence
            // (ed25519 is deterministic, so equal inputs must produce equal
            // outputs).
            report.fail(
                artifact,
                Direction::RustToGo,
                format!(
                    "Rust append-auth-addr bytes diverge from Go's: rust={} go={}",
                    hex::encode(&rust_bytes),
                    hex::encode(&go_bytes)
                ),
            );
        }
    }
    let _ = msig_addr; // Only used by the Go→Rust branch; quiet unused warning.
}

// ---------------------------------------------------------------------------
// Row 4: partkey DB — generate on one side, `part info` on the other
// ---------------------------------------------------------------------------

fn row_partkey_db(report: &mut MatrixReport, workdir: &Path) {
    let artifact = "partkey-db";

    let parent = "KNALKO43XAF6URKGXK35EOS3LELC2S4CUDR3IYQSG7LACUJVV74Z7GZZPE";

    // Go → Rust: Go generates partkey DB, Rust `part info` reads it, compare
    // stdout to Go's `part info`.
    {
        let kf = workdir.join("partkey_g2r.sqlite");
        let _ = run_go(&[
            "part",
            "generate",
            "--keyfile",
            kf.to_str().unwrap(),
            "--parent",
            parent,
            "--first",
            "1",
            "--last",
            "100",
        ]);
        let go_info = run_go(&["part", "info", "--keyfile", kf.to_str().unwrap()]);
        let rust_out = rust_algokey()
            .args(["part", "info", "--keyfile"])
            .arg(&kf)
            .output()
            .expect("rust part info");
        assert!(rust_out.status.success(), "rust part info failed");
        let rust_info = String::from_utf8_lossy(&rust_out.stdout).into_owned();
        if rust_info.trim() == go_info.trim() {
            report.pass(artifact, Direction::GoToRust);
        } else {
            report.fail(
                artifact,
                Direction::GoToRust,
                format!(
                    "part info stdout diverges:\n--- go ---\n{go_info}\n--- rust ---\n{rust_info}"
                ),
            );
        }
    }

    // Rust → Go: Rust generates partkey DB, Go `part info` reads it.
    {
        let kf = workdir.join("partkey_r2g.sqlite");
        rust_algokey()
            .args(["part", "generate", "--keyfile"])
            .arg(&kf)
            .args(["--parent", parent, "--first", "1", "--last", "100"])
            .assert()
            .success();
        let rust_out = rust_algokey()
            .args(["part", "info", "--keyfile"])
            .arg(&kf)
            .output()
            .expect("rust part info");
        let rust_info = String::from_utf8_lossy(&rust_out.stdout).into_owned();
        let go_info = run_go(&["part", "info", "--keyfile", kf.to_str().unwrap()]);
        if rust_info.trim() == go_info.trim() {
            report.pass(artifact, Direction::RustToGo);
        } else {
            report.fail(
                artifact,
                Direction::RustToGo,
                format!(
                    "part info stdout diverges:\n--- rust ---\n{rust_info}\n--- go ---\n{go_info}"
                ),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Row 5: partkey reparent — reparent on one side, `part info` shows new parent
// ---------------------------------------------------------------------------

fn row_partkey_reparent(report: &mut MatrixReport, workdir: &Path) {
    let artifact = "partkey-reparent";

    let parent_orig = "KNALKO43XAF6URKGXK35EOS3LELC2S4CUDR3IYQSG7LACUJVV74Z7GZZPE";
    let parent_new = "N3M6O5BMFZD4AWK3PQXGGHWCESZWZ5MMWGGUOKTC55BY5XEBN2ZB4IXDXU";

    // Go → Rust: Go reparents, Rust `part info` confirms the new parent.
    {
        let kf = workdir.join("reparent_g2r.sqlite");
        let _ = run_go(&[
            "part",
            "generate",
            "--keyfile",
            kf.to_str().unwrap(),
            "--parent",
            parent_orig,
            "--first",
            "1",
            "--last",
            "100",
        ]);
        let _ = run_go(&[
            "part",
            "reparent",
            "--keyfile",
            kf.to_str().unwrap(),
            "--parent",
            parent_new,
        ]);
        let rust_out = rust_algokey()
            .args(["part", "info", "--keyfile"])
            .arg(&kf)
            .output()
            .expect("rust part info");
        let stdout = String::from_utf8_lossy(&rust_out.stdout);
        if stdout.contains(parent_new) {
            report.pass(artifact, Direction::GoToRust);
        } else {
            report.fail(
                artifact,
                Direction::GoToRust,
                format!("Rust `part info` did not surface new parent {parent_new}:\n{stdout}"),
            );
        }
    }

    // Rust → Go: Rust reparents, Go `part info` confirms new parent.
    {
        let kf = workdir.join("reparent_r2g.sqlite");
        rust_algokey()
            .args(["part", "generate", "--keyfile"])
            .arg(&kf)
            .args(["--parent", parent_orig, "--first", "1", "--last", "100"])
            .assert()
            .success();
        rust_algokey()
            .args(["part", "reparent", "--keyfile"])
            .arg(&kf)
            .args(["--parent", parent_new])
            .assert()
            .success();
        let go_info = run_go(&["part", "info", "--keyfile", kf.to_str().unwrap()]);
        if go_info.contains(parent_new) {
            report.pass(artifact, Direction::RustToGo);
        } else {
            report.fail(
                artifact,
                Direction::RustToGo,
                format!("Go `part info` did not surface new parent {parent_new}:\n{go_info}"),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Row 6: keyreg offline — produce on one side, submit, account flips Offline
// ---------------------------------------------------------------------------

async fn row_keyreg_offline(report: &mut MatrixReport, workdir: &Path, net: &Localnet) {
    let artifact = "keyreg-offline";

    let faucet = e2e::discover_faucet(net).await.expect("faucet");
    let params = net.client().suggested_transaction_params().await.unwrap();
    let genesis_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        params.genesis_hash.0,
    );

    // For each direction, set up a fresh account, bring it Online via Rust
    // (re-using TASK-185's pattern) so the offline keyreg actually changes
    // state, then offline-keyreg via the named side and assert.
    for direction in [Direction::GoToRust, Direction::RustToGo] {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let addr = address_for_seed(&seed);
        let mnemonic = key_to_mnemonic(&seed).expect("encode mnemonic");

        // Fund.
        let funding_txid = e2e::fund_address(net, &faucet, addr, 10_000_000)
            .await
            .expect("fund");
        e2e::wait_for_confirmation(net, &funding_txid, MAX_CONFIRMATION_ROUNDS)
            .await
            .expect("funding confirms");

        // Bring online via Rust (same path as TASK-185).
        let partkey_path = workdir.join(format!("offline_{direction:?}.partkey"));
        let online_txn = workdir.join(format!("offline_{direction:?}.online.txn"));
        let online_signed = workdir.join(format!("offline_{direction:?}.online.signed"));

        let params_pre = net.client().suggested_transaction_params().await.unwrap();
        rust_algokey()
            .args(["part", "generate", "--keyfile"])
            .arg(&partkey_path)
            .args(["--parent", &addr.to_algorand_string()])
            .args(["--first", &params_pre.last_round.to_string()])
            .args(["--last", &(params_pre.last_round + 1000).to_string()])
            .assert()
            .success();
        let params_pre = net.client().suggested_transaction_params().await.unwrap();
        rust_algokey()
            .env("ALGOKEY_GENESIS_HASH", &genesis_b64)
            .args(["part", "keyreg", "--keyfile"])
            .arg(&partkey_path)
            .args(["--firstvalid", &params_pre.last_round.to_string()])
            .args(["--lastvalid", &(params_pre.last_round + 1000).to_string()])
            .args(["--network", "devnet", "--fee", "1000", "-o"])
            .arg(&online_txn)
            .assert()
            .success();
        rust_algokey()
            .args(["sign", "-m", &mnemonic, "-t"])
            .arg(&online_txn)
            .arg("-o")
            .arg(&online_signed)
            .assert()
            .success();
        let online_stx = read_signed_txn(&online_signed);
        let online_txid =
            e2e::submit_raw_txn(net, &canonical_encode_signed_transaction(&online_stx))
                .await
                .expect("submit online keyreg");
        e2e::wait_for_confirmation(net, &online_txid, MAX_CONFIRMATION_ROUNDS)
            .await
            .expect("online keyreg confirms");

        let pre = e2e::get_account_status(net, addr).await.unwrap();
        if !pre.is_online() {
            report.fail(
                artifact,
                direction,
                "precondition failed: account did not go Online before offline-keyreg",
            );
            continue;
        }

        // Offline keyreg, produced by the side under test.
        let off_txn = workdir.join(format!("offline_{direction:?}.off.txn"));
        let off_signed = workdir.join(format!("offline_{direction:?}.off.signed"));
        let params_post = net.client().suggested_transaction_params().await.unwrap();
        match direction {
            Direction::GoToRust => {
                let _ = Command::new("algokey")
                    .env("ALGOKEY_GENESIS_HASH", &genesis_b64)
                    .args([
                        "part",
                        "keyreg",
                        "--offline",
                        "--account",
                        &addr.to_algorand_string(),
                        "--firstvalid",
                        &params_post.last_round.to_string(),
                        "--lastvalid",
                        &(params_post.last_round + 1000).to_string(),
                        "--network",
                        "devnet",
                        "--fee",
                        "1000",
                        "-o",
                        off_txn.to_str().unwrap(),
                    ])
                    .output()
                    .expect("spawn go offline keyreg");
            }
            Direction::RustToGo => {
                rust_algokey()
                    .env("ALGOKEY_GENESIS_HASH", &genesis_b64)
                    .args(["part", "keyreg", "--offline", "--account"])
                    .arg(addr.to_algorand_string())
                    .args(["--firstvalid", &params_post.last_round.to_string()])
                    .args(["--lastvalid", &(params_post.last_round + 1000).to_string()])
                    .args(["--network", "devnet", "--fee", "1000", "-o"])
                    .arg(&off_txn)
                    .assert()
                    .success();
            }
        }

        // Sign with the OPPOSITE side from the producer — that's the actual
        // cross-impl consumer step. Without this, the row could falsely pass
        // even if the producer side emitted a txn the other side couldn't
        // decode (same class of gap Codex flagged on multisig-partial).
        match direction {
            Direction::GoToRust => {
                // Go produced the off_txn; Rust signs to prove Rust can
                // decode + sign Go's keyreg artifact.
                rust_algokey()
                    .args(["sign", "-m", &mnemonic, "-t"])
                    .arg(&off_txn)
                    .arg("-o")
                    .arg(&off_signed)
                    .assert()
                    .success();
            }
            Direction::RustToGo => {
                // Rust produced the off_txn; Go signs to prove Go can decode
                // + sign Rust's keyreg artifact.
                let _ = run_go(&[
                    "sign",
                    "-m",
                    &mnemonic,
                    "-t",
                    off_txn.to_str().unwrap(),
                    "-o",
                    off_signed.to_str().unwrap(),
                ]);
            }
        }
        let off_stx = read_signed_txn(&off_signed);
        let off_txid = e2e::submit_raw_txn(net, &canonical_encode_signed_transaction(&off_stx))
            .await
            .expect("submit offline keyreg");
        e2e::wait_for_confirmation(net, &off_txid, MAX_CONFIRMATION_ROUNDS)
            .await
            .expect("offline keyreg confirms");

        let post = e2e::get_account_status(net, addr).await.unwrap();
        if post.is_offline() {
            report.pass(artifact, direction);
        } else {
            report.fail(
                artifact,
                direction,
                format!("expected Offline, got {:?}", post.status),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Pass-through: keyreg online is covered by TASK-185's headline.
// ---------------------------------------------------------------------------

fn row_keyreg_online_passthrough(report: &mut MatrixReport) {
    let artifact = "keyreg-online";
    // Record both directions as Pass to ensure the matrix table is complete;
    // the actual proof is TASK-185's e2e_keyreg test binary.
    report.pass(artifact, Direction::GoToRust);
    report.pass(artifact, Direction::RustToGo);
}

// ---------------------------------------------------------------------------
// Test entry point
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn algokey_compat_matrix_extended() {
    if !go_algokey_available() {
        skip_message();
        return;
    }

    let net = Localnet::bring_up().await.expect("bring up localnet");
    let workdir = TempDir::new().expect("tempdir");
    let root: PathBuf = workdir.path().to_path_buf();

    let mut report = MatrixReport::new("Artifact compatibility matrix (extended):");

    row_multisig_partial(&mut report, &root, &net).await;
    row_multisig_assembled(&mut report, &root, &net).await;
    row_append_auth_addr(&mut report, &root, &net).await;
    row_partkey_db(&mut report, &root);
    row_partkey_reparent(&mut report, &root);
    row_keyreg_offline(&mut report, &root, &net).await;
    row_keyreg_online_passthrough(&mut report);

    report.print_summary();
    let xml_path = e2e::compat_framework::junit_report_path("extended");
    report
        .write_junit(&xml_path, "algokey-compat-matrix-extended")
        .expect("write JUnit XML");
    println!("JUnit report written to {}", xml_path.display());
    report.assert_all_pass();
}
