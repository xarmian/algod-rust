//! `algokey multisig` — for each SignedTxn in the input stream, extract
//! the existing multisig preimage (version/threshold/pks), produce this
//! signer's subsig, and replace `stxn.Msig` with the result.
//!
//! Mirrors `../go-algorand/cmd/algokey/multisig.go:60-109`.
//!
//! Stream IO + key-loader patterns are shared with [`super::super::sign`]
//! (`commands/sign.rs`): we read all SignedTxn records, sign each one,
//! and write the re-encoded stream to `-o` at mode 0600.

use std::io::Write;
use std::process::ExitCode;

use algo_codec::canonical_encode_signed_transaction;
use algo_consensus_crypto::multisig::{multisig_addr_gen, multisig_sign};
use ed25519_dalek::SigningKey;

use crate::cli::MultisigCli;
use crate::commands::sign::{decode_one_signed_txn, load_keyfile_or_mnemonic, TX_PREFIX};
use crate::common::write_with_mode_0600;

pub fn run(args: MultisigCli) -> ExitCode {
    run_with_io(args, &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run_with_io<O: Write, E: Write>(
    args: MultisigCli,
    _stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    // `multisig` without a subcommand requires --txfile and --outfile.
    // clap's `subcommand_negates_reqs` makes them required for the bare
    // form; if we get here `args.command.is_none()` so they must be Some.
    let Some(txfile) = args.txfile.as_ref() else {
        let _ = writeln!(stderr, "missing --txfile");
        return ExitCode::from(2);
    };
    let Some(outfile) = args.outfile.as_ref() else {
        let _ = writeln!(stderr, "missing --outfile");
        return ExitCode::from(2);
    };

    let seed = match load_keyfile_or_mnemonic(args.keyfile.as_deref(), args.mnemonic.as_deref()) {
        Ok(s) => s,
        Err(msg) => {
            let _ = writeln!(stderr, "{msg}");
            return ExitCode::from(1);
        }
    };

    let txdata = match std::fs::read(txfile) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                stderr,
                "Cannot read transactions from {}: {e}",
                txfile.display()
            );
            return ExitCode::from(1);
        }
    };

    let signing_key = SigningKey::from_bytes(&seed);

    let mut out_bytes: Vec<u8> = Vec::with_capacity(txdata.len() + 256);
    let mut pos: usize = 0;
    while pos < txdata.len() {
        let (mut stxn, advance) = match decode_one_signed_txn(&txdata[pos..]) {
            Ok(p) => p,
            Err(e) => {
                let _ = writeln!(stderr, "Cannot decode transaction: {e}");
                return ExitCode::from(1);
            }
        };

        // Mirrors multisig.go:87-98: extract the existing msig preimage
        // (version, threshold, pks) and derive the msig address. If the
        // input lacks an Msig field, fail with Go's wording.
        let Some(existing_msig) = stxn.msig.as_ref() else {
            let _ = writeln!(
                stderr,
                "Cannot generate multisig addr: input txn has no Msig preimage"
            );
            return ExitCode::from(1);
        };
        let version = existing_msig.version;
        let threshold = existing_msig.threshold;
        let pks: Vec<[u8; 32]> = existing_msig.subsigs.iter().map(|s| s.public_key).collect();

        // Validate (matches multisig.go:88-92 via MultisigAddrGen check
        // wrapped in MultisigSign).
        if let Err(e) = multisig_addr_gen(version, threshold, &pks) {
            let _ = writeln!(stderr, "Cannot generate multisig addr: {e}");
            return ExitCode::from(1);
        }

        // Compose the signed message: TX_PREFIX || canonical_encode(txn).
        let canonical = algo_codec::canonical_encode_transaction(&stxn.txn);
        let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
        msg.extend_from_slice(TX_PREFIX);
        msg.extend_from_slice(&canonical);

        // Single-signer subsig — fills only the slots whose pubkey
        // matches the signer.
        let new_msig = match multisig_sign(&msg, version, threshold, &pks, &signing_key) {
            Ok(m) => m,
            Err(e) => {
                let _ = writeln!(stderr, "Cannot add multisig signature: {e}");
                return ExitCode::from(1);
            }
        };
        stxn.msig = Some(new_msig);
        // Multisig sign does NOT populate stxn.Sig (Go leaves it zero
        // too — only the Msig field changes).

        let encoded = canonical_encode_signed_transaction(&stxn);
        out_bytes.extend_from_slice(&encoded);
        pos += advance;
    }

    if let Err(e) = write_with_mode_0600(outfile, &out_bytes) {
        let _ = writeln!(
            stderr,
            "Cannot write signed transactions to {}: {e}",
            outfile.display()
        );
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::MultisigCli;
    use algo_consensus_crypto::multisig::{multisig_addr_gen, multisig_preimage_from_pks};
    use algo_types::{Address, Round, SignedTransaction, Transaction, TxnType};
    use tempfile::tempdir;

    fn build_keypair_at_index(seed_byte: u8) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed_byte; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    /// Build an unsigned SignedTxn with an empty 2-of-3 msig preimage.
    fn build_unsigned_with_preimage(threshold: u8, pks: &[[u8; 32]]) -> SignedTransaction {
        let msig = multisig_preimage_from_pks(1, threshold, pks);
        let msig_addr = multisig_addr_gen(1, threshold, pks).expect("addr");
        SignedTransaction {
            txn: Transaction {
                txn_type: TxnType::Pay,
                sender: msig_addr,
                fee: 1000,
                first_valid: Round(1),
                last_valid: Round(1000),
                receiver: Address([0x99u8; 32]),
                amount: 50_000,
                genesis_hash: [3u8; 32],
                ..Transaction::default()
            },
            msig: Some(msig),
            ..SignedTransaction::default()
        }
    }

    /// Signer A produces a 2-of-3 partial; only slot 0 has a sig.
    #[test]
    fn fills_signers_subsig_only() {
        let (sk_a, pk_a) = build_keypair_at_index(1);
        let (_, pk_b) = build_keypair_at_index(2);
        let (_, pk_c) = build_keypair_at_index(3);
        let pks = [pk_a, pk_b, pk_c];
        let stxn = build_unsigned_with_preimage(2, &pks);

        let dir = tempdir().unwrap();
        let kf = dir.path().join("k");
        std::fs::write(&kf, sk_a.to_bytes()).unwrap();
        let txfile = dir.path().join("in.tx");
        let outfile = dir.path().join("out.tx");
        std::fs::write(&txfile, canonical_encode_signed_transaction(&stxn)).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            MultisigCli {
                keyfile: Some(kf),
                mnemonic: None,
                txfile: Some(txfile),
                outfile: Some(outfile.clone()),
                command: None,
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
        let msig = signed.msig.expect("msig present");
        assert_eq!(msig.subsigs.len(), 3);
        assert_ne!(msig.subsigs[0].signature, [0u8; 64], "signer A slot filled");
        assert_eq!(msig.subsigs[1].signature, [0u8; 64], "slot 1 blank");
        assert_eq!(msig.subsigs[2].signature, [0u8; 64], "slot 2 blank");
    }

    /// Missing Msig field on input → Go-compatible error.
    #[test]
    fn missing_msig_preimage_errors() {
        let (sk_a, _) = build_keypair_at_index(5);
        let stxn = SignedTransaction {
            txn: Transaction {
                txn_type: TxnType::Pay,
                sender: Address([0x42u8; 32]),
                fee: 1000,
                first_valid: Round(1),
                last_valid: Round(2),
                genesis_hash: [0x55u8; 32],
                ..Transaction::default()
            },
            msig: None,
            ..SignedTransaction::default()
        };
        let dir = tempdir().unwrap();
        let kf = dir.path().join("k");
        std::fs::write(&kf, sk_a.to_bytes()).unwrap();
        let txfile = dir.path().join("in.tx");
        let outfile = dir.path().join("out.tx");
        std::fs::write(&txfile, canonical_encode_signed_transaction(&stxn)).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            MultisigCli {
                keyfile: Some(kf),
                mnemonic: None,
                txfile: Some(txfile),
                outfile: Some(outfile),
                command: None,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.contains("Cannot generate multisig addr"),
            "stderr: {stderr}"
        );
    }
}
