//! `algokey keyreg` — build a key-registration (online or offline)
//! transaction. Wraps the registration-txn builder from TASK-166 and
//! the genesis-hash resolver from TASK-163. Mirrors
//! `../go-algorand/cmd/algokey/keyreg.go:134-259` exactly.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::str::FromStr;

use algo_codec::canonical_encode_signed_transaction;
use algo_ledger::erasable_db::ErasableDb;
use algo_ledger::participation::{generate_registration_transaction, restore_participation};
use algo_types::{resolve_genesis_hash, Address, Round, SignedTransaction, Transaction, TxnType};

use crate::cli::KeyregArgs;
use crate::common::write_with_mode_0600;

/// Maximum validity span. Mirrors Go's `txnLife` constant at
/// `keyreg.go:54`.
const TXN_LIFE: u64 = 1000;
/// Minimum acceptable fee. Mirrors `minFee` at `keyreg.go:55`.
const MIN_FEE: u64 = 1000;
/// Output filename meaning "write to stdout". Same literal as Go.
const STDOUT_FILENAME: &str = "-";

pub fn run(args: KeyregArgs) -> ExitCode {
    run_with_io(args, &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run_with_io<O: Write, E: Write>(
    mut args: KeyregArgs,
    stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    // Implicit last_valid = first_valid + txnLife (matches keyreg.go:137).
    if args.lastvalid == 0 {
        args.lastvalid = args.firstvalid + TXN_LIFE;
    }

    if args.fee < MIN_FEE {
        let _ = writeln!(
            stderr,
            "the provided transaction fee ({}) is too low, the minimum fee is {}",
            args.fee, MIN_FEE
        );
        return ExitCode::from(1);
    }

    // Mutual-exclusion checks (keyreg.go:144-158).
    if args.offline {
        if args.account.is_none() {
            let _ = writeln!(
                stderr,
                "must provide --account when bringing an account offline"
            );
            return ExitCode::from(1);
        }
        if args.keyfile.is_some() {
            let _ = writeln!(
                stderr,
                "do not provide --keyfile when bringing an account offline"
            );
            return ExitCode::from(1);
        }
    } else {
        if args.keyfile.is_none() {
            let _ = writeln!(
                stderr,
                "must provide --keyfile when registering participation keys"
            );
            return ExitCode::from(1);
        }
        if args.account.is_some() {
            let _ = writeln!(
                stderr,
                "do not provide --account when registering participation keys"
            );
            return ExitCode::from(1);
        }
    }

    // Account address (offline mode only). keyreg.go:160-167.
    let account_address: Option<Address> = match args.account.as_deref() {
        Some(s) => match Address::from_str(s) {
            Ok(a) => Some(a),
            Err(e) => {
                let _ = writeln!(stderr, "unable to parse --account: {e}");
                return ExitCode::from(1);
            }
        },
        None => None,
    };

    // Keyfile existence check. keyreg.go:169-171.
    if let Some(p) = args.keyfile.as_ref() {
        if !p.exists() {
            let _ = writeln!(stderr, "cannot access keyfile '{}'", p.display());
            return ExitCode::from(1);
        }
    }

    // Default outputFile = <keyfile>.tx (keyreg.go:173-175).
    if args.output_file.is_none() {
        if let Some(p) = args.keyfile.as_ref() {
            args.output_file = Some(format!("{}.tx", p.display()));
        }
    }

    let output_file = args.output_file.clone().unwrap_or_default();
    let write_to_stdout = output_file == STDOUT_FILENAME;

    // File-exists guard (keyreg.go:177-179) — but only when writing to
    // a real file, not stdout.
    if !write_to_stdout && Path::new(&output_file).exists() {
        let _ = writeln!(stderr, "outputFile '{output_file}' already exists");
        return ExitCode::from(1);
    }

    // Build the inner Transaction depending on offline/online mode.
    let txn: Transaction = if args.offline {
        // Offline form: bare Header with sender + fee + rounds; no
        // keyreg fields. Matches keyreg.go:217-225.
        Transaction {
            txn_type: TxnType::Keyreg,
            sender: account_address.expect("checked above"),
            fee: args.fee,
            first_valid: Round(args.firstvalid),
            last_valid: Round(args.lastvalid),
            ..Transaction::default()
        }
    } else {
        // Online form: load partkey, validate first_valid >= part's,
        // then use the registration_txn builder.
        let keyfile = args.keyfile.as_ref().expect("checked above");
        let db = match ErasableDb::open_read_only(keyfile) {
            Ok(db) => db,
            Err(e) => {
                let _ = writeln!(stderr, "cannot open keyfile {}: {e}", keyfile.display());
                return ExitCode::from(1);
            }
        };
        let part = match restore_participation(&db) {
            Ok(p) => p,
            Err(e) => {
                let _ = writeln!(stderr, "cannot load keyfile {}: {e}", keyfile.display());
                return ExitCode::from(1);
            }
        };
        if args.firstvalid < part.first_valid.0 {
            let _ = writeln!(
                stderr,
                "the transaction's firstvalid round ({}) field should be set greater than or \
                 equal to the participation key's first valid round ({}). The network will \
                 reject key registration transactions that are set to take effect before the \
                 participation key's first valid round",
                args.firstvalid, part.first_valid.0
            );
            return ExitCode::from(1);
        }
        let include_state_proof = part.state_proof_secrets.is_some();
        generate_registration_transaction(
            &part,
            args.fee,
            Round(args.firstvalid),
            Round(args.lastvalid),
            [0u8; 32],
            include_state_proof,
        )
    };

    // Explicit `lv >= fv` check. Go relies on uint64 underflow wrapping
    // here (keyreg.go:202: `validRange := params.lastValid - params.
    // firstValid`) so a lastvalid < firstvalid produces a giant number
    // that fails the txnLife check anyway. We surface that as an
    // explicit error so operators see a clear message instead of the
    // confusing "validity range > 1000" wording.
    if args.lastvalid < args.firstvalid {
        let _ = writeln!(
            stderr,
            "the transaction's lastvalid round ({}) must be \
             greater than or equal to firstvalid ({})",
            args.lastvalid, args.firstvalid
        );
        return ExitCode::from(1);
    }
    // Validity-range check (keyreg.go:202-205). Safe to subtract now.
    let valid_range = args.lastvalid - args.firstvalid;
    if valid_range > TXN_LIFE {
        let _ = writeln!(
            stderr,
            "the transaction's specified validity range must be less than or equal to {} rounds \
             due to security constraints. Please enter a first valid round ({}) and last valid \
             round ({}) whose difference is no more than {} rounds",
            TXN_LIFE, args.firstvalid, args.lastvalid, TXN_LIFE
        );
        return ExitCode::from(1);
    }

    // Resolve and inject genesis hash.
    let mut txn = txn;
    txn.genesis_hash = match resolve_genesis_hash(&args.network) {
        Ok(d) => d.0,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            return ExitCode::from(1);
        }
    };

    // Wrap in a SignedTxn with empty Sig/Msig — matches Go's
    // `AssembleSignedTxn(txn, empty_sig, empty_msig)` at keyreg.go:236.
    let stxn = SignedTransaction {
        txn,
        ..SignedTransaction::default()
    };
    let data = canonical_encode_signed_transaction(&stxn);

    // Output.
    if write_to_stdout {
        if let Err(e) = stdout.write_all(&data) {
            let _ = writeln!(stderr, "failed to write transaction to stdout: {e}");
            return ExitCode::from(1);
        }
    } else if let Err(e) = write_with_mode_0600(Path::new(&output_file), &data) {
        let _ = writeln!(
            stderr,
            "failed to write transaction to '{output_file}': {e}"
        );
        return ExitCode::from(1);
    }

    // Summary line. When the txn bytes were piped to stdout (`-o -`)
    // we route the summary to stderr to avoid corrupting the binary
    // payload — Go has the same code path write to stdout too, which
    // is a Go-side footgun for any pipe consumer. We diverge here on
    // operational grounds; the consensus-critical byte stream (the
    // signed txn) is unchanged.
    let summary = if args.offline {
        format!("Account key go offline transaction written to '{output_file}'.")
    } else {
        format!("Key registration transaction written to '{output_file}'.")
    };
    if write_to_stdout {
        let _ = writeln!(stderr, "{summary}");
    } else {
        let _ = writeln!(stdout, "{summary}");
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::sign::decode_one_signed_txn;
    use tempfile::tempdir;

    /// Path to the committed Go-produced partkey fixture (small DB
    /// from TASK-165). Used here for the online-mode test.
    fn partkey_fixture() -> std::path::PathBuf {
        // Walk up from `crates/tools/algokey-rust` to the workspace
        // root, then into the algo-ledger fixtures directory.
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest
            .join("../../core/algo-ledger/tests/fixtures/partkey/small.sqlite")
            .canonicalize()
            .expect("partkey fixture present")
    }

    fn base_args() -> KeyregArgs {
        KeyregArgs {
            fee: 1000,
            firstvalid: 1,
            lastvalid: 0,
            network: "mainnet".into(),
            offline: false,
            output_file: None,
            keyfile: None,
            account: None,
        }
    }

    /// Offline txn carries the right type, sender, rounds, fee, and
    /// genesis hash from the network name. Holds the env lock to keep
    /// the no-override path stable against parallel env-mutating tests.
    #[test]
    fn offline_txn_has_expected_fields() {
        let _guard = EnvGuard::clear("ALGOKEY_GENESIS_HASH");
        let dir = tempdir().unwrap();
        let outfile = dir.path().join("offline.tx");
        let acct = "HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI".to_string();
        let mut args = base_args();
        args.offline = true;
        args.account = Some(acct.clone());
        args.network = "testnet".into();
        args.output_file = Some(outfile.to_string_lossy().into_owned());
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(args, &mut out, &mut err);
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "stderr: {}",
            String::from_utf8_lossy(&err)
        );

        let produced = std::fs::read(&outfile).unwrap();
        let (signed, _) = decode_one_signed_txn(&produced).unwrap();
        assert_eq!(signed.txn.txn_type, TxnType::Keyreg);
        assert_eq!(signed.txn.sender.to_string(), acct);
        assert_eq!(signed.txn.fee, 1000);
        assert_eq!(signed.txn.first_valid.0, 1);
        assert_eq!(signed.txn.last_valid.0, 1001);
        assert_eq!(
            signed.txn.genesis_hash,
            resolve_genesis_hash("testnet").unwrap().0
        );
        assert!(signed.txn.vote_pk.is_none() || signed.txn.vote_pk == Some([0u8; 32]));
    }

    /// Online txn (read partkey) populates vote_pk + selection_pk +
    /// state_proof_pk + vote_first/last/dilution. Env-guarded.
    #[test]
    fn online_txn_uses_partkey_fields() {
        let _guard = EnvGuard::clear("ALGOKEY_GENESIS_HASH");
        let dir = tempdir().unwrap();
        let outfile = dir.path().join("online.tx");
        let mut args = base_args();
        args.keyfile = Some(partkey_fixture());
        args.network = "mainnet".into();
        args.output_file = Some(outfile.to_string_lossy().into_owned());
        // Partkey is valid for [1, 100]; pick first_valid=50, lastvalid=100.
        args.firstvalid = 50;
        args.lastvalid = 100;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(args, &mut out, &mut err);
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "stderr: {}",
            String::from_utf8_lossy(&err)
        );
        let (signed, _) = decode_one_signed_txn(&std::fs::read(&outfile).unwrap()).unwrap();
        assert_eq!(signed.txn.txn_type, TxnType::Keyreg);
        assert!(signed.txn.vote_pk.is_some(), "vote_pk populated");
        assert!(signed.txn.selection_pk.is_some(), "selection_pk populated");
        assert!(
            signed.txn.state_proof_pk.is_some(),
            "state_proof_pk populated"
        );
        assert_eq!(signed.txn.vote_first, 1);
        assert_eq!(signed.txn.vote_last, 100);
        assert_eq!(signed.txn.vote_key_dilution, 10);
        assert_eq!(
            signed.txn.genesis_hash,
            resolve_genesis_hash("mainnet").unwrap().0
        );
    }

    /// Fee below 1000 → reject with Go's exact wording.
    #[test]
    fn low_fee_rejected() {
        let mut args = base_args();
        args.fee = 999;
        args.offline = true;
        args.account = Some("ABC".into()); // mutual-exclusion path
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(args, &mut out, &mut err);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.contains("the provided transaction fee (999) is too low"),
            "stderr: {stderr}"
        );
    }

    /// Validity range > 1000 → reject.
    #[test]
    fn validity_range_too_large_rejected() {
        let mut args = base_args();
        args.firstvalid = 1;
        args.lastvalid = 2000;
        args.offline = true;
        args.account = Some("HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI".into());
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(args, &mut out, &mut err);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.contains("validity range must be less than or equal to 1000 rounds"),
            "stderr: {stderr}"
        );
    }

    /// Online mode without --keyfile → reject.
    #[test]
    fn online_without_keyfile_rejected() {
        let args = base_args();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(args, &mut out, &mut err);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.contains("must provide --keyfile when registering participation keys"),
            "stderr: {stderr}"
        );
    }

    /// Offline mode with --keyfile present → reject.
    #[test]
    fn offline_with_keyfile_rejected() {
        let mut args = base_args();
        args.offline = true;
        args.account = Some("HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI".into());
        args.keyfile = Some(partkey_fixture());
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(args, &mut out, &mut err);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.contains("do not provide --keyfile when bringing an account offline"),
            "stderr: {stderr}"
        );
    }

    /// Process-wide lock for tests that mutate `ALGOKEY_GENESIS_HASH`.
    /// Without this, parallel test threads observe each other's env
    /// mutations — Codex caught this in round 1.
    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// Scoped env-var guard: serializes against `env_lock` and restores
    /// the prior value on drop. Mirrors the pattern in
    /// algo-types::networks tests.
    struct EnvGuard<'a> {
        key: &'a str,
        prev: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl<'a> EnvGuard<'a> {
        fn set(key: &'a str, value: &str) -> Self {
            let _lock = env_lock().lock().unwrap_or_else(|p| p.into_inner());
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prev, _lock }
        }
        fn clear(key: &'a str) -> Self {
            let _lock = env_lock().lock().unwrap_or_else(|p| p.into_inner());
            let prev = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, prev, _lock }
        }
    }

    impl Drop for EnvGuard<'_> {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    /// ALGOKEY_GENESIS_HASH env override flows through resolve_genesis_hash.
    #[test]
    fn genesis_hash_env_override_propagates() {
        let dir = tempdir().unwrap();
        let outfile = dir.path().join("env_override.tx");
        use data_encoding::BASE64;
        let custom = [0xAAu8; 32];
        let custom_b64 = BASE64.encode(&custom);
        let _guard = EnvGuard::set("ALGOKEY_GENESIS_HASH", &custom_b64);
        let mut args = base_args();
        args.offline = true;
        args.account = Some("HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI".into());
        args.output_file = Some(outfile.to_string_lossy().into_owned());
        let code = run_with_io(args, &mut Vec::new(), &mut Vec::new());
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let (signed, _) = decode_one_signed_txn(&std::fs::read(&outfile).unwrap()).unwrap();
        assert_eq!(signed.txn.genesis_hash, custom);
    }

    /// lv < fv → explicit reject (no underflow path through validity-
    /// range check). Codex round 1.
    #[test]
    fn lastvalid_below_firstvalid_rejected() {
        let mut args = base_args();
        args.firstvalid = 100;
        args.lastvalid = 50;
        args.offline = true;
        args.account = Some("HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI".into());
        let mut err = Vec::new();
        let code = run_with_io(args, &mut Vec::new(), &mut err);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("lastvalid round (50)"), "stderr: {stderr}");
    }
}
