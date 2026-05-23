//! Byte-equal parity for Phase B subcommands (`sign`, `multisig`,
//! `keyreg --offline`) vs go-algorand v4.5.1-stable.
//!
//! Fixtures under `tests/fixtures/algokey/{sign,multisig,keyreg}/`
//! were captured by linking against the Go algokey crypto stack
//! directly (not the CLI) so we have deterministic seeded inputs.
//! See `scripts/build_phase_b_fixtures.go` for the recipe.

use std::path::{Path, PathBuf};
use std::process::Command;

fn algokey_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_algokey-rust"))
}

fn fix(sub: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/algokey")
        .join(sub)
}

fn run_ok(cmd: &mut Command) -> Vec<u8> {
    let out = cmd.output().expect("spawn algokey-rust");
    assert!(
        out.status.success(),
        "non-zero exit {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// `algokey-rust sign` on the committed unsigned-pay fixture produces
/// the same bytes Go's `crypto.SignatureSecrets.Sign` emits.
#[test]
fn sign_output_matches_go() {
    let dir = tempfile::tempdir().unwrap();
    let outfile = dir.path().join("rust-signed.tx");
    run_ok(
        algokey_bin()
            .args(["sign", "-k"])
            .arg(fix("sign/keyfile"))
            .arg("-t")
            .arg(fix("sign/unsigned.tx"))
            .arg("-o")
            .arg(&outfile),
    );
    let got = std::fs::read(&outfile).expect("read Rust output");
    let want = std::fs::read(fix("sign/go-signed.tx")).expect("read Go fixture");
    assert_eq!(got, want, "sign output diverges from Go");
}

/// `algokey-rust multisig` produces the same partial Go's
/// `crypto.MultisigSign(... skA)` emits for the same preimage+input.
#[test]
fn multisig_partial_matches_go() {
    let dir = tempfile::tempdir().unwrap();
    let outfile = dir.path().join("rust-msig.tx");
    run_ok(
        algokey_bin()
            .args(["multisig", "-k"])
            .arg(fix("multisig/keyfile-a"))
            .arg("-t")
            .arg(fix("multisig/unsigned.tx"))
            .arg("-o")
            .arg(&outfile),
    );
    let got = std::fs::read(&outfile).expect("read Rust output");
    let want = std::fs::read(fix("multisig/go-signed-by-a.tx")).expect("read Go fixture");
    assert_eq!(got, want, "multisig output diverges from Go");
}

/// `algokey-rust part keyreg --offline` produces the same bytes Go's
/// keyreg offline form emits for the same (account, fee, rounds,
/// network) inputs.
#[test]
fn keyreg_offline_output_matches_go() {
    let dir = tempfile::tempdir().unwrap();
    let outfile = dir.path().join("rust-offline.tx");
    let account =
        std::fs::read_to_string(fix("keyreg/offline-account.txt")).expect("read offline account");
    let account = account.trim();
    run_ok(
        algokey_bin()
            .args(["part", "keyreg", "--offline", "--account"])
            .arg(account)
            .arg("--firstvalid")
            .arg("1")
            .arg("--lastvalid")
            .arg("1001")
            .arg("--network")
            .arg("testnet")
            .arg("-o")
            .arg(&outfile),
    );
    let got = std::fs::read(&outfile).expect("read Rust output");
    let want = std::fs::read(fix("keyreg/offline-testnet.tx")).expect("read Go fixture");
    assert_eq!(got, want, "keyreg offline output diverges from Go");
}

// ---------------------------------------------------------------------------
// Cross-impl: when Go `algokey` is on PATH, push Rust output back through
// Go and confirm the SignedTxn structure decodes cleanly (Go's
// `protocol.Decode` is strict enough to reject malformed bytes).
// ---------------------------------------------------------------------------

fn locate_go_algokey() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ALGOKEY") {
        let path = PathBuf::from(&p);
        if path.is_file() {
            return Some(path);
        }
    }
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let cand = dir.join("algokey");
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

fn run_go_algokey(go: &Path, args: &[&str]) -> std::process::Output {
    Command::new(go)
        .args(args)
        .output()
        .expect("run Go algokey")
}

/// Cross-impl: Go-signed txn ↔ Rust-signed txn for the sign fixture.
/// Round-trips both ways:
///  1. Rust signs the unsigned fixture → bytes match Go's pre-signed
///  2. Go signs the unsigned fixture via `algokey sign` → bytes match
///     Rust's output
///
/// Skipped when Go algokey isn't on PATH.
#[test]
fn cross_impl_sign_round_trip() {
    let Some(go) = locate_go_algokey() else {
        println!("skipping cross_impl_sign_round_trip: Go algokey not on PATH");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let go_out = dir.path().join("go-out.tx");
    let st = run_go_algokey(
        &go,
        &[
            "sign",
            "-k",
            fix("sign/keyfile").to_str().unwrap(),
            "-t",
            fix("sign/unsigned.tx").to_str().unwrap(),
            "-o",
            go_out.to_str().unwrap(),
        ],
    );
    assert!(
        st.status.success(),
        "Go algokey sign failed: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let go_bytes = std::fs::read(&go_out).unwrap();
    let want_bytes = std::fs::read(fix("sign/go-signed.tx")).unwrap();
    assert_eq!(
        go_bytes, want_bytes,
        "Go algokey CLI diverges from build-time fixture"
    );

    let rust_out = dir.path().join("rust-out.tx");
    run_ok(
        algokey_bin()
            .args(["sign", "-k"])
            .arg(fix("sign/keyfile"))
            .arg("-t")
            .arg(fix("sign/unsigned.tx"))
            .arg("-o")
            .arg(&rust_out),
    );
    let rust_bytes = std::fs::read(&rust_out).unwrap();
    assert_eq!(rust_bytes, go_bytes, "Rust ≠ Go for sign fixture");
}
