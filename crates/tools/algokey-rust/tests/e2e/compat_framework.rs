//! Bidirectional Go↔Rust algokey compatibility matrix framework (TASK-199).
//!
//! Tests record one [`MatrixRow`] per artifact-and-direction combination via
//! [`MatrixReport::record`]. At end of test, [`MatrixReport::finish`] prints
//! a human-readable summary and asserts every row passed.
//!
//! TASK-200 extends this with multisig / partkey / keyreg rows plus a JUnit
//! emitter that aggregates BOTH halves of the matrix.

use std::fmt;
use std::path::Path;
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

    /// Print the human-readable summary table to stdout. Doesn't fail —
    /// callers run [`Self::assert_all_pass`] after to enforce success.
    pub fn print_summary(&self) {
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
        let passed = self.passed();
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
        }
    }

    /// Write a JUnit-format XML report to `path`. The schema is the standard
    /// `<testsuite><testcase>` flavor consumable by GitHub Actions
    /// `test-reporter`, `junit-viewer`, IntelliJ, etc. Each row becomes one
    /// `<testcase>`; failed rows include a `<failure>` child carrying the
    /// detail string.
    pub fn write_junit(&self, path: &Path, suite_name: &str) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let total = self.rows.len();
        let failed = total - self.passed();
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str(&format!(
            "<testsuite name=\"{}\" tests=\"{total}\" failures=\"{failed}\" errors=\"0\">\n",
            xml_escape(suite_name),
        ));
        for r in &self.rows {
            let name = format!("{}/{}", r.artifact, r.direction);
            xml.push_str(&format!(
                "  <testcase name=\"{}\" classname=\"{}\">\n",
                xml_escape(&name),
                xml_escape(suite_name),
            ));
            if let Verdict::Fail { detail } = &r.verdict {
                xml.push_str(&format!(
                    "    <failure message=\"{}\">{}</failure>\n",
                    xml_escape(detail),
                    xml_escape(detail),
                ));
            }
            xml.push_str("  </testcase>\n");
        }
        xml.push_str("</testsuite>\n");
        std::fs::write(path, xml)
    }

    /// Panic with the full detail of every failed row if any row failed.
    pub fn assert_all_pass(self) {
        let total = self.rows.len();
        let failed = total - self.passed();
        if failed > 0 {
            panic!("{failed}/{total} matrix round-trips failed; see stdout above");
        }
    }

    fn passed(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| matches!(r.verdict, Verdict::Pass))
            .count()
    }
}

/// Minimal XML attribute/content escaper. Avoids pulling in a heavy XML crate
/// for the trivial test-report use case.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if (c as u32) < 0x20 && c != '\n' && c != '\r' && c != '\t' => {
                // Control characters aren't valid in XML 1.0; replace with U+FFFD.
                out.push('\u{FFFD}');
            }
            c => out.push(c),
        }
    }
    out
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

/// Workspace-root `target/algokey-compat-matrix-{half}.xml`. Cargo runs
/// integration tests with CWD = package dir, so we have to resolve up from
/// `CARGO_MANIFEST_DIR`. `half` is e.g. "core" or "extended".
pub fn junit_report_path(half: &str) -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest.join("../../..");
    workspace_root
        .join("target")
        .join(format!("algokey-compat-matrix-{half}.xml"))
}

/// Standard skip message for tests when the Go `algokey` binary is absent.
/// Print this and return early from the test (exits success).
pub fn skip_message() {
    eprintln!(
        "SKIP: Go `algokey` binary not on PATH — install go-algorand@v4.6.0-stable \
         (e.g. `cd ../go-algorand && go build -o ~/.local/bin/algokey ./cmd/algokey`) \
         then re-run."
    );
}
