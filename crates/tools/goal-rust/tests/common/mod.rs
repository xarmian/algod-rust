//! Shared parity-fixture harness used across the per-leaf
//! `tests/*.rs` files.
//!
//! Acts as a thin wrapper around the committed fixtures under
//! `tests/fixtures/parity/` so the per-leaf tests don't reinvent
//! file-reading / diff-printing on their own.
//!
//! All fixtures are byte-exact snapshots of Go's `goal` output —
//! see `tests/fixtures/parity/README.md` for the refresh workflow.

#![allow(dead_code)] // utilities are picked up per-test-binary

use std::path::PathBuf;

/// Absolute path of `tests/fixtures/parity/<name>.txt`.
pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("parity")
        .join(format!("{name}.txt"))
}

/// Read the committed fixture; panics with a helpful message if it's
/// missing so a typo doesn't silently turn into a passing test.
pub fn load_fixture(name: &str) -> String {
    let p = fixture_path(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "missing parity fixture {} ({e}); see {}",
            p.display(),
            "crates/tools/goal-rust/tests/fixtures/parity/README.md",
        )
    })
}

/// Diff-clean assertion: panics with the standard
/// `assert_eq!`-style message but also emits the fixture path and a
/// hint about `UPDATE_FIXTURES=1` so a Go-side wording change has
/// an obvious next step.
pub fn assert_matches_fixture(name: &str, actual: &str) {
    let expected = load_fixture(name);
    if expected == actual {
        return;
    }
    if update_requested() {
        // Honour the refresh contract documented in the fixtures
        // README — let `UPDATE_FIXTURES=1` rewrite the file instead
        // of failing, so a CI run can bake in the new snapshot.
        std::fs::write(fixture_path(name), actual).expect("write fixture");
        return;
    }
    panic!(
        "parity fixture mismatch: {}\n  expected ({} bytes):\n{}\n  actual ({} bytes):\n{}\n\
         (re-run with UPDATE_FIXTURES=1 to refresh after a deliberate Go-side change)",
        fixture_path(name).display(),
        expected.len(),
        expected,
        actual.len(),
        actual,
    );
}

/// True when `UPDATE_FIXTURES=1` is in the env. Gated by Go-binary
/// availability for the live-capture path; the harness itself just
/// uses it as a "write expected, don't fail" toggle.
pub fn update_requested() -> bool {
    matches!(std::env::var("UPDATE_FIXTURES").as_deref(), Ok("1"))
}
