//! End-to-end smoke tests for `algokey-rust generate`.
//!
//! These exercise the actual binary (random seed each run) and assert the
//! shape of stdout + files. Byte-equal-to-Go parity for fixed-seed cases
//! is covered by unit tests in `src/commands/generate.rs` (the random
//! source isn't injectable from the CLI).

use std::process::Command;

fn algokey() -> Command {
    Command::new(env!("CARGO_BIN_EXE_algokey-rust"))
}

#[test]
fn generate_emits_two_lines_to_stdout() {
    let out = algokey().arg("generate").output().expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "expected 2 lines, got {}: {stdout}",
        lines.len()
    );
    assert!(
        lines[0].starts_with("Private key mnemonic: "),
        "line 0: {}",
        lines[0]
    );
    assert!(lines[1].starts_with("Public key: "), "line 1: {}", lines[1]);
    // The address is 58 base32 chars (32-byte pubkey + 4-byte checksum).
    let addr = lines[1].trim_start_matches("Public key: ");
    assert_eq!(addr.len(), 58, "address should be 58 chars, got {addr:?}");
    // Mnemonic is exactly 25 space-separated words.
    let mnemonic = lines[0].trim_start_matches("Private key mnemonic: ");
    assert_eq!(
        mnemonic.split(' ').count(),
        25,
        "expected 25 words, got: {mnemonic}"
    );
}

#[test]
fn generate_with_files_round_trips_addr() {
    let dir = tempfile::tempdir().unwrap();
    let kf = dir.path().join("k");
    let pf = dir.path().join("p");
    let out = algokey()
        .args(["generate", "-f"])
        .arg(&kf)
        .arg("-p")
        .arg(&pf)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Keyfile = 32 raw bytes.
    let key_bytes = std::fs::read(&kf).unwrap();
    assert_eq!(key_bytes.len(), 32, "keyfile must be exactly 32 bytes");

    // Pubkeyfile = "<addr>\n" — 59 bytes, trailing newline.
    let pub_text = std::fs::read_to_string(&pf).unwrap();
    assert_eq!(pub_text.len(), 59);
    assert!(pub_text.ends_with('\n'));
    let addr_in_file = pub_text.trim_end();
    assert_eq!(addr_in_file.len(), 58);

    // Stdout's "Public key:" must equal the pubkeyfile address.
    let stdout = String::from_utf8(out.stdout).unwrap();
    let pub_line = stdout
        .lines()
        .find(|l| l.starts_with("Public key: "))
        .unwrap();
    let stdout_addr = pub_line.trim_start_matches("Public key: ");
    assert_eq!(
        stdout_addr, addr_in_file,
        "address divergence between stdout and pubkeyfile"
    );

    // Unix file mode check on the keyfile.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(&kf).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o600, "keyfile must be mode 0600, got {m:o}");
    }
}
