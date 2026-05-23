//! `algokey sign` — read a SignedTxn stream, fill the ed25519 `Sig`
//! field on each record, set `AuthAddr` for rekey'd senders, and write
//! the re-encoded stream back.
//!
//! Mirrors `../go-algorand/cmd/algokey/sign.go:46-86` exactly:
//! - Loop over msgpack records until EOF
//! - For each: sign `Txn` with the loaded key (`"TX" ||
//!   canonical_encode(txn)`); populate `stxn.Sig`
//! - If `stxn.Txn.Sender != Address(verifier)` set
//!   `stxn.AuthAddr = Address(verifier)` (rekey case)
//! - Concatenate per-record msgpack bytes; write to `-o <path>` at
//!   mode 0600
//!
//! Key loader: `loadKeyfileOrMnemonic` from
//! `../go-algorand/cmd/algokey/common.go:33-51`. Mutual exclusion +
//! error wording match Go exactly.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use algo_codec::canonical_encode_signed_transaction;
use algo_consensus_crypto::mnemonic_to_key;
use algo_types::{Address, SignedTransaction};
use ed25519_dalek::{Signer, SigningKey};

use crate::cli::SignArgs;
use crate::common::{write_with_mode_0600, Seed};

/// Domain separator prepended to canonical transaction bytes before
/// ed25519-signing. Matches Go's `protocol.HashID("TX")` for
/// `transactions.Transaction` (used by `crypto.SignatureSecrets.Sign`).
pub(crate) const TX_PREFIX: &[u8] = b"TX";

pub fn run(args: SignArgs) -> ExitCode {
    run_with_io(args, &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run_with_io<O: Write, E: Write>(
    args: SignArgs,
    _stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    // Mutual-exclusion + presence check (common.go:34-49).
    let seed = match load_keyfile_or_mnemonic(args.keyfile.as_deref(), args.mnemonic.as_deref()) {
        Ok(s) => s,
        Err(msg) => {
            let _ = writeln!(stderr, "{msg}");
            return ExitCode::from(1);
        }
    };

    // Read the txfile.
    let txdata = match std::fs::read(&args.txfile) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                stderr,
                "Cannot read transactions from {}: {e}",
                args.txfile.display()
            );
            return ExitCode::from(1);
        }
    };

    // Decode the SignedTxn stream until EOF (sign.go:62-71).
    let signing_key = SigningKey::from_bytes(&seed);
    let verifier: [u8; 32] = signing_key.verifying_key().to_bytes();
    let verifier_addr = Address(verifier);

    let mut out_bytes: Vec<u8> = Vec::with_capacity(txdata.len() + 256);
    let mut pos: usize = 0;
    while pos < txdata.len() {
        let (stxn, advance) = match decode_one_signed_txn(&txdata[pos..]) {
            Ok(p) => p,
            Err(e) => {
                let _ = writeln!(stderr, "Cannot decode transaction: {e}");
                return ExitCode::from(1);
            }
        };
        let signed = sign_one(stxn, &signing_key, verifier_addr);
        let encoded = canonical_encode_signed_transaction(&signed);
        out_bytes.extend_from_slice(&encoded);
        pos += advance;
    }

    // Write output at mode 0600 (sign.go:80).
    if let Err(e) = write_with_mode_0600(&args.outfile, &out_bytes) {
        let _ = writeln!(
            stderr,
            "Cannot write signed transactions to {}: {e}",
            args.outfile.display()
        );
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// Sign one SignedTransaction in place. Mirrors sign.go:73-77.
fn sign_one(
    mut stxn: SignedTransaction,
    signing_key: &SigningKey,
    verifier_addr: Address,
) -> SignedTransaction {
    let canonical = algo_codec::canonical_encode_transaction(&stxn.txn);
    let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
    msg.extend_from_slice(TX_PREFIX);
    msg.extend_from_slice(&canonical);
    let signature = signing_key.sign(&msg).to_bytes();
    stxn.sig = signature;

    // Rekey case: if the sender isn't the signer, populate AuthAddr so
    // a relay can verify the txn against the signing key.
    if stxn.txn.sender != verifier_addr {
        stxn.auth_addr = Some(verifier_addr);
    }
    stxn
}

/// Decode one SignedTransaction from the front of `buf`, returning the
/// decoded value plus how many input bytes it consumed. Uses a Cursor
/// so we can observe the post-decode position (rmp_serde's bare
/// `Deserializer<&[u8]>` doesn't expose one).
pub(crate) fn decode_one_signed_txn(buf: &[u8]) -> Result<(SignedTransaction, usize), String> {
    let cursor = std::io::Cursor::new(buf);
    let mut de = rmp_serde::Deserializer::new(cursor);
    let stxn: SignedTransaction =
        serde::Deserialize::deserialize(&mut de).map_err(|e| e.to_string())?;
    let pos = de.get_ref().position() as usize;
    Ok((stxn, pos))
}

/// Mirrors `loadKeyfileOrMnemonic` (common.go:33-51): exactly one of
/// `keyfile` / `mnemonic` must be given; both → error, neither → error.
pub(crate) fn load_keyfile_or_mnemonic(
    keyfile: Option<&Path>,
    mnemonic: Option<&str>,
) -> Result<Seed, &'static str> {
    match (keyfile, mnemonic) {
        (Some(_), Some(_)) => Err("Cannot specify both keyfile and mnemonic"),
        (Some(path), None) => {
            // Mirror Go's loadKeyfile (common.go:65-75): read whatever
            // bytes exist, then `copy(seed[:], bytes)` — which zero-
            // pads short reads and truncates long ones. Matches
            // existing `algokey export` loader behavior in this repo.
            let bytes = std::fs::read(path).map_err(|_| "Cannot read key seed from keyfile")?;
            let mut seed = [0u8; 32];
            let n = bytes.len().min(32);
            seed[..n].copy_from_slice(&bytes[..n]);
            Ok(seed)
        }
        (None, Some(m)) => mnemonic_to_key(m).map_err(|_| "Cannot recover key seed from mnemonic"),
        (None, None) => Err("Must specify one of keyfile or mnemonic"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{Round, Transaction, TxnType};
    use ed25519_dalek::{Verifier, VerifyingKey};
    use tempfile::tempdir;

    fn build_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

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

    /// Round-trip: write an unsigned stxn → sign → decode → verify the
    /// ed25519 sig over "TX"||canonical_encode(txn). Tests that the
    /// signature populates and the bytes serialize correctly.
    #[test]
    fn sign_one_produces_valid_ed25519_sig() {
        let sk = build_signing_key();
        let pk_bytes = sk.verifying_key().to_bytes();
        let sender = Address(pk_bytes);
        let unsigned = build_unsigned_txn(sender);
        let signed = sign_one(unsigned, &sk, sender);
        assert_ne!(signed.sig, [0u8; 64], "sig must be populated");
        let sig_bytes = signed.sig;

        // Reconstruct the signed message and verify.
        let canonical = algo_codec::canonical_encode_transaction(&signed.txn);
        let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
        msg.extend_from_slice(TX_PREFIX);
        msg.extend_from_slice(&canonical);
        let vk = VerifyingKey::from_bytes(&pk_bytes).expect("vk");
        vk.verify(&msg, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .expect("signature must verify");
    }

    /// AuthAddr is populated when sender != signing key (rekey case).
    #[test]
    fn rekey_case_populates_auth_addr() {
        let sk = build_signing_key();
        let signer_pk = Address(sk.verifying_key().to_bytes());
        let sender = Address([0xAAu8; 32]); // different from signer
        let unsigned = build_unsigned_txn(sender);
        let signed = sign_one(unsigned, &sk, signer_pk);
        assert_eq!(signed.auth_addr, Some(signer_pk));
    }

    /// AuthAddr stays None when sender IS the signing key.
    #[test]
    fn non_rekey_case_leaves_auth_addr_none() {
        let sk = build_signing_key();
        let signer_pk = Address(sk.verifying_key().to_bytes());
        let unsigned = build_unsigned_txn(signer_pk);
        let signed = sign_one(unsigned, &sk, signer_pk);
        assert_eq!(signed.auth_addr, None);
    }

    /// End-to-end: write a small SignedTxn stream to a file, invoke
    /// `run_with_io`, parse the output, verify every sig.
    #[test]
    fn full_pipeline_signs_multi_txn_stream() {
        let sk = build_signing_key();
        let signer_pk = Address(sk.verifying_key().to_bytes());

        let dir = tempdir().unwrap();
        let kf = dir.path().join("k");
        std::fs::write(&kf, [7u8; 32]).unwrap();
        let txfile = dir.path().join("in.tx");
        let outfile = dir.path().join("out.tx");

        // Pre-canned stream of 3 unsigned txns.
        let mut stream = Vec::new();
        for i in 0..3u64 {
            let mut stxn = build_unsigned_txn(signer_pk);
            stxn.txn.first_valid = Round(i + 1);
            stream.extend_from_slice(&canonical_encode_signed_transaction(&stxn));
        }
        std::fs::write(&txfile, &stream).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            SignArgs {
                keyfile: Some(kf),
                mnemonic: None,
                txfile,
                outfile: outfile.clone(),
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

        // Parse the output and verify each sig.
        let mut produced = std::fs::read(&outfile).unwrap();
        let mut count = 0;
        let mut cur: &[u8] = &produced;
        while !cur.is_empty() {
            let (stxn, advance) = decode_one_signed_txn(cur).expect("decode");
            assert_ne!(stxn.sig, [0u8; 64], "txn {count} missing sig");
            count += 1;
            cur = &cur[advance..];
        }
        assert_eq!(count, 3, "expected 3 signed txns, got {count}");

        // Confirm output file is mode 0600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&outfile).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600);
        }
        let _ = produced.pop();
    }

    /// Error wording for keyfile+mnemonic conflict matches Go's
    /// `common.go:35`.
    #[test]
    fn both_keyfile_and_mnemonic_errors_with_go_wording() {
        let dir = tempdir().unwrap();
        let kf = dir.path().join("k");
        std::fs::write(&kf, [0u8; 32]).unwrap();
        let txfile = dir.path().join("in.tx");
        std::fs::write(&txfile, b"").unwrap();
        let outfile = dir.path().join("out.tx");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            SignArgs {
                keyfile: Some(kf),
                mnemonic: Some("anything".into()),
                txfile,
                outfile,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.contains("Cannot specify both keyfile and mnemonic"),
            "stderr: {stderr}"
        );
    }

    /// Error wording when neither is provided.
    #[test]
    fn neither_keyfile_nor_mnemonic_errors_with_go_wording() {
        let dir = tempdir().unwrap();
        let txfile = dir.path().join("in.tx");
        std::fs::write(&txfile, b"").unwrap();
        let outfile = dir.path().join("out.tx");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            SignArgs {
                keyfile: None,
                mnemonic: None,
                txfile,
                outfile,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.contains("Must specify one of keyfile or mnemonic"),
            "stderr: {stderr}"
        );
    }
}
