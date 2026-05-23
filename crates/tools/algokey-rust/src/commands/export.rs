//! `algokey export` — read a keyfile, print mnemonic + address.
//!
//! Mirrors `../go-algorand/cmd/algokey/export.go:37-55` plus
//! `common.go::loadKeyfile`. Stdout format is identical to
//! `generate`/`import`. `-p <path>` writes `"<addr>\n"` at mode 0666.
//!
//! Error wording on read failures matches `common.go:68`:
//! `"Cannot read key seed from <path>: <err>"`.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use algo_consensus_crypto::key_to_mnemonic;

use crate::cli::ExportArgs;
use crate::common::{address_for_seed, write_public_key, Seed};

/// Run `algokey export`.
pub fn run(args: ExportArgs) -> ExitCode {
    run_with_io(args, &mut std::io::stdout(), &mut std::io::stderr())
}

/// Inner entry — sinks injected for tests.
pub fn run_with_io<O: Write, E: Write>(
    args: ExportArgs,
    stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    let seed = match load_keyfile(&args.keyfile) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(
                stderr,
                "Cannot read key seed from {}: {e}",
                args.keyfile.display()
            );
            return ExitCode::from(1);
        }
    };

    let mnemonic = match key_to_mnemonic(&seed) {
        Ok(m) => m,
        Err(e) => {
            let _ = writeln!(stderr, "Cannot generate key mnemonic: {e}");
            return ExitCode::from(1);
        }
    };
    let address = address_for_seed(&seed);

    // Stdout format matches export.go:48-49.
    if let Err(e) = writeln!(stdout, "Private key mnemonic: {mnemonic}") {
        let _ = writeln!(stderr, "Cannot write to stdout: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writeln!(stdout, "Public key: {address}") {
        let _ = writeln!(stderr, "Cannot write to stdout: {e}");
        return ExitCode::from(1);
    }

    if let Some(path) = &args.pubkeyfile {
        if let Err(e) = write_public_key(path, &address) {
            let _ = writeln!(stderr, "Cannot write public key to {}: {e}", path.display());
            return ExitCode::from(1);
        }
    }

    ExitCode::SUCCESS
}

/// Read a 32-byte seed from a file. Mirrors Go's `loadKeyfile`
/// (`common.go:65-75`): `os.ReadFile` then `copy(seed[:], bytes)`. Go
/// silently truncates a longer-than-32-byte file because of `copy(dst,
/// src)` semantics; the task description calls out that "longer files
/// trigger an error matching Go's wording" — but the Go source does NOT
/// error on length mismatch (only on read failure). To stay byte-identical
/// to Go we replicate the `copy(dst, src)` behaviour: take the first 32
/// bytes when the file is at least 32 bytes long, and zero-pad shorter
/// reads (Go's `copy` does the same — uninitialised `seed` is already
/// zeroed). Files exactly 32 bytes round-trip cleanly with TASK-157.
fn load_keyfile(path: &Path) -> std::io::Result<Seed> {
    let bytes = std::fs::read(path)?;
    let mut seed = [0u8; 32];
    let n = bytes.len().min(32);
    seed[..n].copy_from_slice(&bytes[..n]);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";
    const ZERO_ADDR: &str = "HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI";

    #[test]
    fn export_zero_keyfile_matches_go() {
        let dir = tempdir().unwrap();
        let kf = dir.path().join("k");
        std::fs::write(&kf, [0u8; 32]).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            ExportArgs {
                keyfile: kf,
                pubkeyfile: None,
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
    fn export_writes_pubkeyfile() {
        let dir = tempdir().unwrap();
        let kf = dir.path().join("k");
        let pf = dir.path().join("p");
        std::fs::write(&kf, [0xCDu8; 32]).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            ExportArgs {
                keyfile: kf,
                pubkeyfile: Some(pf.clone()),
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let pf_text = std::fs::read_to_string(&pf).unwrap();
        assert_eq!(pf_text.len(), 59);
        assert!(pf_text.ends_with('\n'));
    }

    /// Import → export round-trip: a keyfile written by `import` must be
    /// readable by `export` and yield the same mnemonic.
    #[test]
    fn import_export_round_trip() {
        use crate::cli::ImportArgs;
        use crate::commands::import;

        let dir = tempdir().unwrap();
        let kf = dir.path().join("k");

        // Write the keyfile via `import` (which uses write_private_key).
        let mut imp_out = Vec::new();
        let mut imp_err = Vec::new();
        let code = import::run_with_io(
            ImportArgs {
                mnemonic: ZERO_MNEMONIC.to_string(),
                keyfile: Some(kf.clone()),
            },
            &mut imp_out,
            &mut imp_err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

        // Read it back via `export` and confirm the mnemonic.
        let mut exp_out = Vec::new();
        let mut exp_err = Vec::new();
        let code = run_with_io(
            ExportArgs {
                keyfile: kf,
                pubkeyfile: None,
            },
            &mut exp_out,
            &mut exp_err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let stdout = String::from_utf8(exp_out).unwrap();
        assert!(
            stdout.contains(&format!("Private key mnemonic: {ZERO_MNEMONIC}\n")),
            "round-trip mnemonic divergence: {stdout}"
        );
    }

    #[test]
    fn missing_keyfile_exits_1_with_go_wording() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            ExportArgs {
                keyfile: "/nonexistent/path/algokey-rust-export-test".into(),
                pubkeyfile: None,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.starts_with("Cannot read key seed from "),
            "stderr should match Go's wording, got: {stderr}"
        );
    }
}
