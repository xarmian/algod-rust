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

//! `algokey pq sign` — mirrors `runPQSignWithOptions` (`pq.go:256-309`):
//! read a `SignedTxn` msgpack stream, fill each record's `PQsig` field
//! (setting `AuthAddr` when the signer differs from the sender), and write
//! the re-encoded stream back.

use std::io::Write;
use std::process::ExitCode;

use algo_codec::{canonical_encode_signed_transaction, canonical_encode_transaction};
use algo_types::SignedTransaction;

use crate::cli::PqSignArgs;
use crate::commands::sign::decode_one_signed_txn;
use crate::common::write_with_mode_0600;

use super::context::{resolve_pq_signing_context, sign_pq};

/// Domain separator prepended to canonical transaction bytes before
/// PQ-signing — identical to ed25519's `"TX"` prefix (Go: `PQsig.Verify`
/// signs the same message ed25519 does, just under a different scheme).
const TX_PREFIX: &[u8] = b"TX";

/// Mirrors `SignedTxn.HasSignature()` (`data/transactions/signedtxn.go:115-117`).
fn has_signature(stxn: &SignedTransaction) -> bool {
    stxn.sig != [0u8; 64] || stxn.msig.is_some() || stxn.lsig.is_some() || stxn.pqsig.is_some()
}

/// Mirrors `clearSignedTxnAuthorization` (`pq.go:431-437`).
fn clear_signed_txn_authorization(stxn: &mut SignedTransaction) {
    stxn.sig = [0u8; 64];
    stxn.msig = None;
    stxn.lsig = None;
    stxn.pqsig = None;
    stxn.auth_addr = None;
}

pub fn run(args: PqSignArgs) -> ExitCode {
    run_with_io(args, &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run_with_io<O: Write, E: Write>(
    args: PqSignArgs,
    _stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    let ctx = match resolve_pq_signing_context(
        args.keyfile.as_deref(),
        args.mnemonic.as_deref(),
        &args.scheme,
    ) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            return ExitCode::from(1);
        }
    };
    let public = ctx.signing.public.clone();

    let txdata = match std::fs::read(&args.txfile) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                stderr,
                "cannot read transactions from {}: {e}",
                args.txfile.display()
            );
            return ExitCode::from(1);
        }
    };

    let mut out_bytes: Vec<u8> = Vec::with_capacity(txdata.len() + 256);
    let mut pos: usize = 0;
    let mut decoded_txns: usize = 0;
    while pos < txdata.len() {
        let (mut stxn, advance) = match decode_one_signed_txn(&txdata[pos..]) {
            Ok(p) => p,
            Err(e) => {
                let _ = writeln!(stderr, "cannot decode transaction: {e}");
                return ExitCode::from(1);
            }
        };
        decoded_txns += 1;

        if has_signature(&stxn) {
            if !args.overwrite {
                let _ = writeln!(stderr, "transaction already has a signature");
                return ExitCode::from(1);
            }
            clear_signed_txn_authorization(&mut stxn);
        }

        let canonical = canonical_encode_transaction(&stxn.txn);
        let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
        msg.extend_from_slice(TX_PREFIX);
        msg.extend_from_slice(&canonical);

        let pqsig = match sign_pq(&ctx, &msg) {
            Ok(s) => s,
            Err(e) => {
                let _ = writeln!(stderr, "cannot sign transaction: {e}");
                return ExitCode::from(1);
            }
        };
        stxn.pqsig = Some(pqsig);
        if stxn.txn.sender != public.address() {
            stxn.auth_addr = Some(public.address());
        }

        out_bytes.extend_from_slice(&canonical_encode_signed_transaction(&stxn));
        pos += advance;
    }

    if decoded_txns == 0 {
        let _ = writeln!(stderr, "no transactions found in {}", args.txfile.display());
        return ExitCode::from(1);
    }

    if let Err(e) = write_with_mode_0600(&args.outfile, &out_bytes) {
        let _ = writeln!(
            stderr,
            "cannot write signed transactions to {}: {e}",
            args.outfile.display()
        );
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::pq::scheme::generate_pq_signing_material;
    use algo_types::{Address, Round, Transaction, TxnType, PQ_SCHEME_FALCON1024};

    fn build_unsigned_txn(sender: Address) -> SignedTransaction {
        SignedTransaction {
            txn: Transaction {
                txn_type: TxnType::Pay,
                sender,
                fee: 1000,
                first_valid: Round(1),
                last_valid: Round(1000),
                receiver: Address([0x11u8; 32]),
                amount: 12345,
                genesis_hash: [9u8; 32],
                ..Transaction::default()
            },
            ..SignedTransaction::default()
        }
    }

    #[test]
    fn sign_populates_pqsig_and_verifies() {
        let (_, signing) = generate_pq_signing_material(PQ_SCHEME_FALCON1024).unwrap();
        let sender = signing.public.address();
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("k");
        super::super::key::write_pq_private_key_file(&kf, &signing).unwrap();

        let txfile = dir.path().join("in.tx");
        let outfile = dir.path().join("out.tx");
        let unsigned = build_unsigned_txn(sender);
        std::fs::write(&txfile, canonical_encode_signed_transaction(&unsigned)).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            PqSignArgs {
                keyfile: Some(kf),
                mnemonic: None,
                scheme: "falcon-1024".to_string(),
                txfile,
                outfile: outfile.clone(),
                overwrite: false,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "stderr: {}",
            String::from_utf8_lossy(&err)
        );

        let produced = std::fs::read(&outfile).unwrap();
        let (signed, _) = decode_one_signed_txn(&produced).unwrap();
        let pqsig = signed.pqsig.expect("pqsig must be set");
        assert_eq!(
            pqsig.public_key.as_slice(),
            signing.public.public_key.as_slice()
        );
        assert!(
            signed.auth_addr.is_none(),
            "sender==signer, no rekey needed"
        );

        let canonical = canonical_encode_transaction(&signed.txn);
        let mut msg = Vec::with_capacity(2 + canonical.len());
        msg.extend_from_slice(b"TX");
        msg.extend_from_slice(&canonical);
        assert!(algo_falcon::falcon_verify(&pqsig.public_key, &pqsig.signature, &msg).unwrap());
    }

    #[test]
    fn sign_sets_auth_addr_when_sender_differs_from_signer() {
        let (_, signing) = generate_pq_signing_material(PQ_SCHEME_FALCON1024).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("k");
        super::super::key::write_pq_private_key_file(&kf, &signing).unwrap();

        let sender = Address([0x77u8; 32]); // different from the PQ signer's own address
        let txfile = dir.path().join("in.tx");
        let outfile = dir.path().join("out.tx");
        std::fs::write(
            &txfile,
            canonical_encode_signed_transaction(&build_unsigned_txn(sender)),
        )
        .unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            PqSignArgs {
                keyfile: Some(kf),
                mnemonic: None,
                scheme: "falcon-1024".to_string(),
                txfile,
                outfile: outfile.clone(),
                overwrite: false,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let produced = std::fs::read(&outfile).unwrap();
        let (signed, _) = decode_one_signed_txn(&produced).unwrap();
        assert_eq!(signed.auth_addr, Some(signing.public.address()));
    }

    #[test]
    fn sign_rejects_already_signed_txn_without_overwrite() {
        let (_, signing) = generate_pq_signing_material(PQ_SCHEME_FALCON1024).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("k");
        super::super::key::write_pq_private_key_file(&kf, &signing).unwrap();

        let mut stxn = build_unsigned_txn(signing.public.address());
        stxn.sig = [9u8; 64]; // pretend it already carries an ed25519 sig
        let txfile = dir.path().join("in.tx");
        let outfile = dir.path().join("out.tx");
        std::fs::write(&txfile, canonical_encode_signed_transaction(&stxn)).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            PqSignArgs {
                keyfile: Some(kf),
                mnemonic: None,
                scheme: "falcon-1024".to_string(),
                txfile,
                outfile,
                overwrite: false,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("already has a signature"));
    }

    #[test]
    fn sign_with_overwrite_replaces_existing_signature() {
        let (_, signing) = generate_pq_signing_material(PQ_SCHEME_FALCON1024).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("k");
        super::super::key::write_pq_private_key_file(&kf, &signing).unwrap();

        let mut stxn = build_unsigned_txn(signing.public.address());
        stxn.sig = [9u8; 64];
        let txfile = dir.path().join("in.tx");
        let outfile = dir.path().join("out.tx");
        std::fs::write(&txfile, canonical_encode_signed_transaction(&stxn)).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            PqSignArgs {
                keyfile: Some(kf),
                mnemonic: None,
                scheme: "falcon-1024".to_string(),
                txfile,
                outfile: outfile.clone(),
                overwrite: true,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let produced = std::fs::read(&outfile).unwrap();
        let (signed, _) = decode_one_signed_txn(&produced).unwrap();
        assert_eq!(signed.sig, [0u8; 64], "old ed25519 sig must be cleared");
        assert!(signed.pqsig.is_some());
    }

    #[test]
    fn sign_rejects_empty_txfile() {
        let (_, signing) = generate_pq_signing_material(PQ_SCHEME_FALCON1024).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("k");
        super::super::key::write_pq_private_key_file(&kf, &signing).unwrap();

        let txfile = dir.path().join("in.tx");
        std::fs::write(&txfile, b"").unwrap();
        let outfile = dir.path().join("out.tx");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            PqSignArgs {
                keyfile: Some(kf),
                mnemonic: None,
                scheme: "falcon-1024".to_string(),
                txfile,
                outfile,
                overwrite: false,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("no transactions found"));
    }
}
