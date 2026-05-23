//! `algokey import` — decode a 25-word mnemonic into a key.
//!
//! Mirrors `../go-algorand/cmd/algokey/import.go:37-54` plus
//! `common.go::loadMnemonic`. Stdout format matches `generate` exactly
//! (`Private key mnemonic:` + `Public key:` lines); `-f <path>` writes
//! the raw 32-byte seed at mode 0600.
//!
//! Error wording on invalid mnemonics matches Go's `common.go:56`:
//! `"Cannot recover key seed from mnemonic: <err>"`.

use std::io::Write;
use std::process::ExitCode;

use algo_consensus_crypto::mnemonic_to_key;

use crate::cli::ImportArgs;
use crate::common::{address_for_seed, write_private_key};

/// Run `algokey import`.
pub fn run(args: ImportArgs) -> ExitCode {
    run_with_io(args, &mut std::io::stdout(), &mut std::io::stderr())
}

/// Inner entry — sinks injected for tests.
pub fn run_with_io<O: Write, E: Write>(
    args: ImportArgs,
    stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    let seed = match mnemonic_to_key(&args.mnemonic) {
        Ok(s) => s,
        Err(e) => {
            // Error wording mirrors common.go:56 exactly so operator
            // scripts that grep stderr keep working.
            let _ = writeln!(stderr, "Cannot recover key seed from mnemonic: {e}");
            return ExitCode::from(1);
        }
    };
    let address = address_for_seed(&seed);

    // Stdout format matches import.go:47-48 — note the mnemonic line
    // echoes the user-supplied mnemonic verbatim (NOT the canonical
    // re-encoding from the seed). This matches Go, which prints
    // `mnemonic` (the variable holding the CLI input).
    if let Err(e) = writeln!(stdout, "Private key mnemonic: {}", args.mnemonic) {
        let _ = writeln!(stderr, "Cannot write to stdout: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writeln!(stdout, "Public key: {address}") {
        let _ = writeln!(stderr, "Cannot write to stdout: {e}");
        return ExitCode::from(1);
    }

    if let Some(path) = &args.keyfile {
        if let Err(e) = write_private_key(path, &seed) {
            let _ = writeln!(stderr, "Cannot write key to {}: {e}", path.display());
            return ExitCode::from(1);
        }
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";
    const ZERO_ADDR: &str = "HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI";

    #[test]
    fn zero_mnemonic_stdout_matches_go() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            ImportArgs {
                mnemonic: ZERO_MNEMONIC.to_string(),
                keyfile: None,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let stdout = String::from_utf8(out).unwrap();
        let want = format!(
            "Private key mnemonic: {ZERO_MNEMONIC}\n\
             Public key: {ZERO_ADDR}\n"
        );
        assert_eq!(stdout, want);
        assert!(err.is_empty());
    }

    #[test]
    fn import_writes_keyfile_at_mode_0600() {
        let dir = tempdir().unwrap();
        let kf = dir.path().join("k");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            ImportArgs {
                mnemonic: ZERO_MNEMONIC.to_string(),
                keyfile: Some(kf.clone()),
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        assert_eq!(std::fs::read(&kf).unwrap(), [0u8; 32]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&kf).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600);
        }
    }

    #[test]
    fn bad_mnemonic_prints_go_compatible_error_and_exits_1() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            ImportArgs {
                mnemonic: "bad words here".to_string(),
                keyfile: None,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.starts_with("Cannot recover key seed from mnemonic:"),
            "stderr should match Go's wording, got: {stderr}"
        );
        assert!(
            out.is_empty(),
            "stdout should not have been written on error"
        );
    }
}
