//! `algokey generate` — generate a fresh key pair + mnemonic.
//!
//! Mirrors `../go-algorand/cmd/algokey/generate.go:36-60` byte-for-byte
//! for stdout and file contents:
//!
//! ```text
//! Private key mnemonic: <25 words>
//! Public key: <58-char checksummed address>
//! ```
//!
//! `-f <path>` writes the raw 32-byte seed (mode 0600); `-p <path>`
//! writes `"<addr>\n"` (mode 0666).

use std::io::Write;
use std::process::ExitCode;

use algo_consensus_crypto::key_to_mnemonic;
use rand::RngCore;

use crate::cli::GenerateArgs;
use crate::common::{address_for_seed, write_private_key, write_public_key, Seed};

/// Run `algokey generate`. Returns the process exit code (0 on success,
/// 1 on file write failure — matches Go's `os.Exit(1)` in
/// `writePrivateKey`/`writePublicKey`).
pub fn run(args: GenerateArgs) -> ExitCode {
    let seed = fresh_seed();
    run_with_seed(args, seed, &mut std::io::stdout(), &mut std::io::stderr())
}

/// Cryptographic seed source — `OsRng::fill_bytes` matches Go's
/// `crypto/rand.Read` semantics (cryptographic randomness on every call).
fn fresh_seed() -> Seed {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

/// Inner entry that takes an explicit seed + sinks. Factored out so
/// integration tests can drive `generate` with a deterministic seed and
/// capture stdout — required for byte-equal-to-Go parity fixtures.
pub fn run_with_seed<O: Write, E: Write>(
    args: GenerateArgs,
    seed: Seed,
    stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    let mnemonic = match key_to_mnemonic(&seed) {
        Ok(m) => m,
        Err(e) => {
            let _ = writeln!(stderr, "Cannot generate key mnemonic: {e}");
            return ExitCode::from(1);
        }
    };
    let address = address_for_seed(&seed);

    // Stdout format matches generate.go:49-50 exactly.
    if let Err(e) = writeln!(stdout, "Private key mnemonic: {mnemonic}") {
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

    if let Some(path) = &args.pubkeyfile {
        if let Err(e) = write_public_key(path, &address) {
            let _ = writeln!(stderr, "Cannot write public key to {}: {e}", path.display());
            return ExitCode::from(1);
        }
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Zero-vector fixture: with `seed = [0u8; 32]` the mnemonic line is
    /// the known "abandon ... invest" string, and the address is the
    /// fixed all-zeros pubkey + sha512_256 checksum. This locks
    /// byte-equal-to-Go parity (matches generate.go's behaviour when
    /// rand returns all zeros).
    #[test]
    fn zero_seed_stdout_matches_expected() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_seed(
            GenerateArgs {
                keyfile: None,
                pubkeyfile: None,
            },
            [0u8; 32],
            &mut out,
            &mut err,
        );
        // ExitCode doesn't expose its numeric value, but we can compare
        // its Debug form for the success / failure distinction.
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let stdout = String::from_utf8(out).unwrap();
        let mnem = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";
        // Address captured from go-algorand v4.5.1-stable using
        // `crypto.GenerateSignatureSecrets({0...}).SignatureVerifier`
        // formatted via `basics.Address.String()`.
        let want = format!(
            "Private key mnemonic: {mnem}\n\
             Public key: HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI\n"
        );
        assert_eq!(stdout, want);
        assert!(err.is_empty(), "stderr should be empty: {err:?}");
    }

    /// Both `-f` and `-p` write expected file shapes (length + content).
    #[test]
    fn writes_keyfile_and_pubkeyfile() {
        let dir = tempdir().unwrap();
        let kf = dir.path().join("k");
        let pf = dir.path().join("p");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let seed = [0xABu8; 32];
        let code = run_with_seed(
            GenerateArgs {
                keyfile: Some(kf.clone()),
                pubkeyfile: Some(pf.clone()),
            },
            seed,
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        // Keyfile = raw 32 bytes.
        let kf_bytes = std::fs::read(&kf).unwrap();
        assert_eq!(kf_bytes, seed);
        // Pubkeyfile = "<addr>\n" — 59 chars total.
        let pf_text = std::fs::read_to_string(&pf).unwrap();
        assert_eq!(pf_text.len(), 59);
        assert!(pf_text.ends_with('\n'));
    }
}
