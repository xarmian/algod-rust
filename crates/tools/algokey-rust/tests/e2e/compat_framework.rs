//! Bidirectional Go↔Rust algokey compatibility matrix framework (TASK-199).
//!
//! Tests record one [`MatrixRow`] per artifact-and-direction combination via
//! [`MatrixReport::record`]. At end of test, [`MatrixReport::finish`] prints
//! a human-readable summary and asserts every row passed.
//!
//! TASK-200 extends this with multisig / partkey / keyreg rows plus a JUnit
//! emitter that aggregates BOTH halves of the matrix.

use std::fmt;
use std::process::Command;

/// Which side produced the artifact and which side is consuming it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Go `algokey` produces, `algokey-rust` (or Rust libraries) consumes.
    GoToRust,
    /// `algokey-rust` produces, Go `algokey` (or live algod) consumes.
    RustToGo,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::GoToRust => f.write_str("Go → Rust"),
            Direction::RustToGo => f.write_str("Rust → Go"),
        }
    }
}

/// A single matrix-row verdict. `Fail` carries the human-readable detail
/// that gets surfaced on test failure AND in JUnit XML output (TASK-200).
#[derive(Debug, Clone)]
pub enum Verdict {
    Pass,
    Fail { detail: String },
}

/// One artifact × direction outcome.
#[derive(Debug, Clone)]
pub struct MatrixRow {
    pub artifact: &'static str,
    pub direction: Direction,
    pub verdict: Verdict,
}

/// Accumulates rows across the test, prints a summary at end, panics if any
/// row failed.
pub struct MatrixReport {
    title: &'static str,
    rows: Vec<MatrixRow>,
}

impl MatrixReport {
    pub fn new(title: &'static str) -> Self {
        Self {
            title,
            rows: Vec::new(),
        }
    }

    pub fn record(&mut self, artifact: &'static str, direction: Direction, verdict: Verdict) {
        self.rows.push(MatrixRow {
            artifact,
            direction,
            verdict,
        });
    }

    pub fn pass(&mut self, artifact: &'static str, direction: Direction) {
        self.record(artifact, direction, Verdict::Pass);
    }

    pub fn fail(
        &mut self,
        artifact: &'static str,
        direction: Direction,
        detail: impl Into<String>,
    ) {
        self.record(
            artifact,
            direction,
            Verdict::Fail {
                detail: detail.into(),
            },
        );
    }

    /// Borrowed view of all recorded rows (for JUnit emission etc.).
    pub fn rows(&self) -> &[MatrixRow] {
        &self.rows
    }

    /// Print the stdout summary table and panic if any row failed.
    pub fn finish(self) {
        // Group rows by artifact, with both directions side-by-side.
        use std::collections::BTreeMap;
        let mut by_artifact: BTreeMap<&'static str, [Option<&Verdict>; 2]> = BTreeMap::new();
        for r in &self.rows {
            let slot = match r.direction {
                Direction::GoToRust => 0,
                Direction::RustToGo => 1,
            };
            by_artifact.entry(r.artifact).or_insert([None, None])[slot] = Some(&r.verdict);
        }

        println!("\n{}", self.title);
        for (artifact, slots) in &by_artifact {
            let g2r = format_cell(slots[0]);
            let r2g = format_cell(slots[1]);
            println!("  {artifact:<22} Go → Rust  {g2r}    Rust → Go  {r2g}");
        }

        let total = self.rows.len();
        let passed = self
            .rows
            .iter()
            .filter(|r| matches!(r.verdict, Verdict::Pass))
            .count();
        let failed = total - passed;
        if failed == 0 {
            println!("All {total} round-trips passed.");
        } else {
            println!("{failed}/{total} round-trips FAILED. Details:");
            for r in &self.rows {
                if let Verdict::Fail { detail } = &r.verdict {
                    println!("  ✗ {} {}: {}", r.artifact, r.direction, detail);
                }
            }
            panic!("{failed}/{total} matrix round-trips failed; see stdout above");
        }
    }
}

fn format_cell(v: Option<&Verdict>) -> &'static str {
    match v {
        Some(Verdict::Pass) => "✓",
        Some(Verdict::Fail { .. }) => "✗",
        None => "—",
    }
}

/// Check whether the Go `algokey` binary is on `PATH`. Tests use this to
/// skip-with-notice rather than fail when the cross-impl tool isn't installed
/// (e.g. unattended CI without the go-algorand build step).
pub fn go_algokey_available() -> bool {
    Command::new("algokey")
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Standard skip message for tests when the Go `algokey` binary is absent.
/// Print this and return early from the test (exits success).
pub fn skip_message() {
    eprintln!(
        "SKIP: Go `algokey` binary not on PATH — install go-algorand@v4.5.1-stable \
         (e.g. `cd ../go-algorand && go build -o ~/.local/bin/algokey ./cmd/algokey`) \
         then re-run."
    );
}
