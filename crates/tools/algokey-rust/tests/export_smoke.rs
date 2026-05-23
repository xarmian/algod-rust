//! End-to-end smoke for `algokey-rust export`.

use std::process::Command;

fn algokey() -> Command {
    Command::new(env!("CARGO_BIN_EXE_algokey-rust"))
}

const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";
const ZERO_ADDR: &str = "HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI";

#[test]
fn export_zero_keyfile_matches_go_output() {
    let dir = tempfile::tempdir().unwrap();
    let kf = dir.path().join("k");
    std::fs::write(&kf, [0u8; 32]).unwrap();

    let out = algokey()
        .args(["export", "-f"])
        .arg(&kf)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let expected = format!(
        "Private key mnemonic: {ZERO_MNEMONIC}\n\
         Public key: {ZERO_ADDR}\n"
    );
    assert_eq!(stdout, expected);
}

#[test]
fn export_missing_keyfile_exits_1() {
    let out = algokey()
        .args(["export", "-f", "/no/such/file/algokey-rust-export-test"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.starts_with("Cannot read key seed from "),
        "stderr: {stderr}"
    );
}

#[test]
fn import_then_export_round_trips_mnemonic() {
    let dir = tempfile::tempdir().unwrap();
    let kf = dir.path().join("k");

    let imp = algokey()
        .args(["import", "-m"])
        .arg(ZERO_MNEMONIC)
        .arg("-f")
        .arg(&kf)
        .output()
        .expect("run");
    assert!(imp.status.success());

    let exp = algokey()
        .args(["export", "-f"])
        .arg(&kf)
        .output()
        .expect("run");
    assert!(exp.status.success());
    let stdout = String::from_utf8(exp.stdout).unwrap();
    assert!(stdout.contains(&format!("Private key mnemonic: {ZERO_MNEMONIC}\n")));
    assert!(stdout.contains(&format!("Public key: {ZERO_ADDR}\n")));
}
