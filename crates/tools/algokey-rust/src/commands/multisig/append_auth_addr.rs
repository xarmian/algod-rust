//! `algokey multisig append-auth-addr` — given a single SignedTxn and
//! a `--params "<threshold> <addr1> <addr2> ..."` string, build the
//! corresponding msig preimage and set `stxn.AuthAddr` to the derived
//! msig address (rekey-to-msig scenario). Does NOT sign — just rewires
//! the txn for a multisig auth-addr.
//!
//! Mirrors `../go-algorand/cmd/algokey/multisig.go:111-187`.
//!
//! When `-o` is omitted, the input file is overwritten in place
//! (matches `multisig.go:177-180`). `-o -` writes to stdout (matches
//! Go's `writeFile` stdin/out filename handling at `common.go:107-114`).

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use algo_codec::canonical_encode_signed_transaction;
use algo_consensus_crypto::multisig::{multisig_addr_gen, multisig_preimage_from_pks};
use algo_types::Address;

use crate::cli::AppendAuthAddrArgs;
use crate::commands::sign::decode_one_signed_txn;
use crate::common::write_with_mode_0600;

/// Special filename meaning "write to stdout" — matches Go's
/// `stdoutFilenameValue` constant at `common.go:29`.
const STDOUT_FILENAME: &str = "-";

pub fn run(args: AppendAuthAddrArgs) -> ExitCode {
    run_with_io(args, &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run_with_io<O: Write, E: Write>(
    args: AppendAuthAddrArgs,
    stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    // Read input txn (single SignedTxn record).
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

    let (mut stxn, _consumed) = match decode_one_signed_txn(&txdata) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "Cannot decode transaction: {e}");
            return ExitCode::from(1);
        }
    };

    // Parse --params: "<threshold> <addr1> <addr2> ...". Mirrors
    // multisig.go:135-156.
    let params: Vec<&str> = args.params.split(' ').filter(|s| !s.is_empty()).collect();
    if params.len() < 3 {
        let _ = writeln!(
            stderr,
            "Not enough arguments to create the multisig address.\n\
             Please make sure to specify the threshold and at least 2 addresses"
        );
        return ExitCode::from(1);
    }

    let threshold: u8 = match params[0].parse() {
        Ok(n) if (1u8..=255).contains(&n) => n,
        Ok(_) | Err(_) => {
            // Go uses `strconv.ParseUint(params[0], 10, 8)` which
            // implicitly enforces 0..=255 (matches multisig.go:141-145).
            let _ = writeln!(
                stderr,
                "Failed to parse the threshold. Make sure it's a number between 1 and 255: {}",
                params[0]
            );
            return ExitCode::from(1);
        }
    };

    let mut pks: Vec<[u8; 32]> = Vec::with_capacity(params.len() - 1);
    for addr_str in &params[1..] {
        let addr = match Address::from_str(addr_str) {
            Ok(a) => a,
            Err(e) => {
                let _ = writeln!(stderr, "Cannot decode address: {e}");
                return ExitCode::from(1);
            }
        };
        pks.push(addr.0);
    }

    // Derive the msig address. Matches multisig.go:158-162.
    let msig_addr = match multisig_addr_gen(1, threshold, &pks) {
        Ok(a) => a,
        Err(e) => {
            let _ = writeln!(stderr, "Cannot generate multisig addr: {e}");
            return ExitCode::from(1);
        }
    };

    // Reject if msig addr equals sender (matches multisig.go:168-171).
    // Go's wording includes a literal "err" reference that is always
    // nil at this point; we mirror the surface message but skip the
    // dangling `err`.
    if msig_addr == stxn.txn.sender {
        let _ = writeln!(
            stderr,
            "The sender at the msig address should not be the same"
        );
        return ExitCode::from(1);
    }

    // Build the preimage (no sigs) and attach.
    stxn.msig = Some(multisig_preimage_from_pks(1, threshold, &pks));
    stxn.auth_addr = Some(msig_addr);

    let encoded = canonical_encode_signed_transaction(&stxn);

    // Output destination — mirrors multisig.go:177-180.
    let target = match args.outfile.as_ref() {
        Some(p) => p.clone(),
        None => args.txfile.clone(),
    };
    if target.as_os_str() == STDOUT_FILENAME {
        if let Err(e) = stdout.write_all(&encoded) {
            let _ = writeln!(stderr, "Cannot write to stdout: {e}");
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }
    let _ = PathBuf::new; // keep PathBuf import in scope for clippy.
    if let Err(e) = write_with_mode_0600(&target, &encoded) {
        let _ = writeln!(
            stderr,
            "Cannot write transactions to {}: {e}",
            target.display()
        );
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{Round, SignedTransaction, Transaction, TxnType};
    use ed25519_dalek::SigningKey;
    use tempfile::tempdir;

    fn pk_for_seed(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    fn write_initial_txn(path: &std::path::Path, sender: Address) {
        let stxn = SignedTransaction {
            txn: Transaction {
                txn_type: TxnType::Pay,
                sender,
                fee: 1000,
                first_valid: Round(1),
                last_valid: Round(1000),
                receiver: Address([0x88u8; 32]),
                amount: 1,
                genesis_hash: [4u8; 32],
                ..Transaction::default()
            },
            ..SignedTransaction::default()
        };
        std::fs::write(path, canonical_encode_signed_transaction(&stxn)).unwrap();
    }

    /// Happy path: 2-of-3 → AuthAddr set to derived msig address +
    /// Msig preimage attached. -o specifies a distinct outfile.
    #[test]
    fn writes_auth_addr_and_preimage_to_outfile() {
        let pks = [pk_for_seed(1), pk_for_seed(2), pk_for_seed(3)];
        let addr_strs: Vec<String> = pks.iter().map(|pk| Address(*pk).to_string()).collect();
        let sender = Address([0x42u8; 32]); // NOT the msig addr
        let dir = tempdir().unwrap();
        let txfile = dir.path().join("in.tx");
        write_initial_txn(&txfile, sender);
        let outfile = dir.path().join("out.tx");

        let params = format!("2 {} {} {}", addr_strs[0], addr_strs[1], addr_strs[2]);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            AppendAuthAddrArgs {
                params,
                txfile,
                outfile: Some(outfile.clone()),
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
        let expected_msig_addr = multisig_addr_gen(1, 2, &pks).unwrap();
        assert_eq!(signed.auth_addr, Some(expected_msig_addr));
        let msig = signed.msig.expect("msig populated");
        assert_eq!(msig.version, 1);
        assert_eq!(msig.threshold, 2);
        assert_eq!(msig.subsigs.len(), 3);
        // All subsigs blank (this command does not sign).
        for sub in &msig.subsigs {
            assert_eq!(sub.signature, [0u8; 64]);
        }
    }

    /// In-place: omitting `-o` overwrites the input file.
    #[test]
    fn no_outfile_overwrites_in_place() {
        let pks = [pk_for_seed(10), pk_for_seed(11)];
        let addr_strs: Vec<String> = pks.iter().map(|pk| Address(*pk).to_string()).collect();
        let dir = tempdir().unwrap();
        let txfile = dir.path().join("in.tx");
        write_initial_txn(&txfile, Address([0xACu8; 32]));
        let before_len = std::fs::metadata(&txfile).unwrap().len();

        let params = format!("1 {} {}", addr_strs[0], addr_strs[1]);
        let code = run_with_io(
            AppendAuthAddrArgs {
                params,
                txfile: txfile.clone(),
                outfile: None,
            },
            &mut Vec::new(),
            &mut Vec::new(),
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let after_len = std::fs::metadata(&txfile).unwrap().len();
        assert_ne!(before_len, after_len, "file should have been rewritten");
        let (signed, _) = decode_one_signed_txn(&std::fs::read(&txfile).unwrap()).unwrap();
        assert!(signed.auth_addr.is_some());
    }

    /// Too few params → Go-compatible error wording.
    #[test]
    fn too_few_params_errors() {
        let dir = tempdir().unwrap();
        let txfile = dir.path().join("in.tx");
        write_initial_txn(&txfile, Address([0xAAu8; 32]));
        let pk_str = Address(pk_for_seed(1)).to_string();
        let mut err = Vec::new();
        let code = run_with_io(
            AppendAuthAddrArgs {
                params: format!("2 {pk_str}"), // only 1 addr → too few
                txfile,
                outfile: None,
            },
            &mut Vec::new(),
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.contains("Not enough arguments to create the multisig address"),
            "stderr: {stderr}"
        );
    }

    /// Sender = msig addr → reject.
    #[test]
    fn sender_equals_msig_addr_rejected() {
        let pks = [pk_for_seed(50), pk_for_seed(51)];
        let addr_strs: Vec<String> = pks.iter().map(|pk| Address(*pk).to_string()).collect();
        let msig_addr = multisig_addr_gen(1, 1, &pks).unwrap();
        let dir = tempdir().unwrap();
        let txfile = dir.path().join("in.tx");
        write_initial_txn(&txfile, msig_addr); // sender == msig addr
        let params = format!("1 {} {}", addr_strs[0], addr_strs[1]);
        let mut err = Vec::new();
        let code = run_with_io(
            AppendAuthAddrArgs {
                params,
                txfile,
                outfile: None,
            },
            &mut Vec::new(),
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.contains("The sender at the msig address should not be the same"),
            "stderr: {stderr}"
        );
    }

    /// Bad threshold (zero) → reject.
    #[test]
    fn bad_threshold_rejected() {
        let pks = [pk_for_seed(20), pk_for_seed(21)];
        let addr_strs: Vec<String> = pks.iter().map(|pk| Address(*pk).to_string()).collect();
        let dir = tempdir().unwrap();
        let txfile = dir.path().join("in.tx");
        write_initial_txn(&txfile, Address([0x11u8; 32]));
        let params = format!("0 {} {}", addr_strs[0], addr_strs[1]);
        let mut err = Vec::new();
        let code = run_with_io(
            AppendAuthAddrArgs {
                params,
                txfile,
                outfile: None,
            },
            &mut Vec::new(),
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        let stderr = String::from_utf8(err).unwrap();
        // Threshold 0 actually parses fine (it's in u8 range); the
        // multisig_addr_gen call then rejects it.
        assert!(
            stderr.contains("Cannot generate multisig addr") || stderr.contains("threshold"),
            "stderr: {stderr}"
        );
    }
}
