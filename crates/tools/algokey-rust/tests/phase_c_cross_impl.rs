//! Cross-impl Phase C tests: drive both `algokey-rust` and Go's
//! `algokey` against the same DB and assert structural-field round-trips.
//!
//! Skipped (not failed) when no Go `algokey` binary is reachable —
//! either via the `ALGOKEY` environment variable (preferred for CI
//! pinning) or `which algokey` on `PATH`. The acceptance contract in
//! the Phase C plan is "must pass when algokey is available; skipped
//! otherwise."

use std::path::{Path, PathBuf};
use std::process::Command;

fn rust_algokey() -> Command {
    Command::new(env!("CARGO_BIN_EXE_algokey-rust"))
}

fn go_algokey() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("ALGOKEY") {
        let p = PathBuf::from(path);
        if p.is_file() {
            return Some(p);
        }
    }
    // Fallback: `which algokey`.
    let out = Command::new("sh")
        .args(["-c", "command -v algokey"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if stdout.is_empty() {
        None
    } else {
        Some(PathBuf::from(stdout))
    }
}

fn tmp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "algod-rust-crossimpl-{}-{}.sqlite",
        name,
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn parse_field(stdout: &str, label: &str) -> Option<String> {
    stdout
        .lines()
        .find(|l| l.starts_with(label))
        .map(|l| l[label.len()..].trim().to_string())
}

fn run_part_info(bin: &Command, path: &Path) -> String {
    let bin_path = bin.get_program().to_owned();
    let out = Command::new(&bin_path)
        .args(["part", "info", "--keyfile"])
        .arg(path)
        .output()
        .expect("spawn part info");
    assert!(
        out.status.success(),
        "part info failed for {}\nstderr: {}",
        bin_path.to_string_lossy(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

/// Assert the labelled-field projection of two `part info` stdouts agree
/// on every field except optionally `skip_label`. Returns the parsed
/// fields for additional caller-side asserts.
fn assert_field_parity(
    rust: &str,
    go: &str,
    skip_label: Option<&str>,
) -> std::collections::BTreeMap<String, String> {
    use std::collections::BTreeMap;
    const LABELS: &[&str] = &[
        "Parent address:",
        "VRF public key:",
        "Voting public key:",
        "State proof key:",
        "State proof key lifetime:",
        "First round:",
        "Last round:",
        "Key dilution:",
        "First batch:",
        "First offset:",
    ];
    let mut rust_fields = BTreeMap::new();
    for label in LABELS {
        if Some(*label) == skip_label {
            continue;
        }
        let rust_val = parse_field(rust, label);
        let go_val = parse_field(go, label);
        assert_eq!(
            rust_val, go_val,
            "label `{label}` diverged: rust={rust_val:?} go={go_val:?}\n--- rust ---\n{rust}\n--- go ---\n{go}",
        );
        if let Some(v) = rust_val {
            rust_fields.insert((*label).to_string(), v);
        }
    }
    rust_fields
}

#[test]
fn rust_generated_db_readable_by_go_with_identical_info() {
    let Some(algokey_go) = go_algokey() else {
        eprintln!("skipping: no Go algokey binary (set ALGOKEY=… or install algokey)");
        return;
    };

    let path = tmp_path("rust-gen");
    let parent = "7777777777777777777777777777777777777777777777777774MSJUVU";

    // 1. Generate via Rust.
    let gen = rust_algokey()
        .args(["part", "generate", "--keyfile"])
        .arg(&path)
        .args([
            "--first",
            "1",
            "--last",
            "512",
            "--dilution",
            "100",
            "--parent",
            parent,
        ])
        .output()
        .expect("rust generate");
    assert!(
        gen.status.success(),
        "rust generate failed: {}",
        String::from_utf8_lossy(&gen.stderr)
    );

    // 2. Run BOTH part info binaries against the resulting DB.
    let rust_info = run_part_info(&rust_algokey(), &path);
    let go_info = run_part_info(&Command::new(&algokey_go), &path);

    // Every printed field must agree byte-for-byte.
    let fields = assert_field_parity(&rust_info, &go_info, None);
    assert_eq!(
        fields.get("Parent address:").map(String::as_str),
        Some(parent)
    );
    assert_eq!(fields.get("First round:").map(String::as_str), Some("1"));
    assert_eq!(fields.get("Last round:").map(String::as_str), Some("512"));
    assert_eq!(fields.get("Key dilution:").map(String::as_str), Some("100"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn go_generated_db_readable_by_rust_with_identical_info() {
    let Some(algokey_go) = go_algokey() else {
        eprintln!("skipping: no Go algokey binary");
        return;
    };

    let path = tmp_path("go-gen");
    let parent = "7777777777777777777777777777777777777777777777777774MSJUVU";

    // 1. Generate via Go.
    let gen = Command::new(&algokey_go)
        .args(["part", "generate", "--keyfile"])
        .arg(&path)
        .args([
            "--first",
            "1",
            "--last",
            "512",
            "--dilution",
            "100",
            "--parent",
            parent,
        ])
        .output()
        .expect("go generate");
    assert!(
        gen.status.success(),
        "go generate failed: {}",
        String::from_utf8_lossy(&gen.stderr)
    );

    // 2. Run BOTH binaries; expect identical info output.
    let rust_info = run_part_info(&rust_algokey(), &path);
    let go_info = run_part_info(&Command::new(&algokey_go), &path);
    let fields = assert_field_parity(&rust_info, &go_info, None);
    assert_eq!(
        fields.get("Parent address:").map(String::as_str),
        Some(parent)
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn rust_reparented_db_readable_by_go_with_new_parent() {
    let Some(algokey_go) = go_algokey() else {
        eprintln!("skipping: no Go algokey binary");
        return;
    };

    let path = tmp_path("rust-reparent");
    let original = "7777777777777777777777777777777777777777777777777774MSJUVU";
    // Valid checksummed Algorand address produced by `algokey generate`.
    let new_parent = "I5AODWQLNPKQF2Y4HDVWVRNSFYB3F3E5NIYSMT62UYCLKYSKU3A4YC4WTM";

    // Generate via Rust, reparent via Rust.
    assert!(rust_algokey()
        .args(["part", "generate", "--keyfile"])
        .arg(&path)
        .args([
            "--first",
            "1",
            "--last",
            "512",
            "--dilution",
            "100",
            "--parent",
            original,
        ])
        .status()
        .unwrap()
        .success());

    assert!(rust_algokey()
        .args(["part", "reparent", "--keyfile"])
        .arg(&path)
        .args(["--parent", new_parent])
        .status()
        .unwrap()
        .success());

    // Go must observe the new parent.
    let go_info = run_part_info(&Command::new(&algokey_go), &path);
    let parsed = parse_field(&go_info, "Parent address:");
    assert_eq!(parsed.as_deref(), Some(new_parent), "go info: {go_info}");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn go_reparented_db_readable_by_rust_with_new_parent() {
    let Some(algokey_go) = go_algokey() else {
        eprintln!("skipping: no Go algokey binary");
        return;
    };

    let path = tmp_path("go-reparent");
    let original = "7777777777777777777777777777777777777777777777777774MSJUVU";
    // Valid checksummed Algorand address (produced by `algokey generate`).
    let new_parent = "I5AODWQLNPKQF2Y4HDVWVRNSFYB3F3E5NIYSMT62UYCLKYSKU3A4YC4WTM";

    assert!(Command::new(&algokey_go)
        .args(["part", "generate", "--keyfile"])
        .arg(&path)
        .args([
            "--first",
            "1",
            "--last",
            "512",
            "--dilution",
            "100",
            "--parent",
            original,
        ])
        .status()
        .unwrap()
        .success());

    assert!(Command::new(&algokey_go)
        .args(["part", "reparent", "--keyfile"])
        .arg(&path)
        .args(["--parent", new_parent])
        .status()
        .unwrap()
        .success());

    let rust_info = run_part_info(&rust_algokey(), &path);
    let parsed = parse_field(&rust_info, "Parent address:");
    assert_eq!(
        parsed.as_deref(),
        Some(new_parent),
        "rust info: {rust_info}"
    );

    let _ = std::fs::remove_file(&path);
}
