// Copyright (c) 2026 Algod DAO
//
// SPDX-License-Identifier: MIT
// For the full license text, see LICENSE-MIT at the repository root.

//! `trie_bench_compare` — diff Rust↔Go `trie_replay` JSON outputs and
//! rewrite the results block in `docs/PERF_TRIE.md` (TASK-145 / PLAN-144).
//!
//! Inputs default to the conventional bench output paths:
//!
//! - Rust: `target/bench-results/trie_replay-rust.json`
//! - Go:   `tools/go-trie-replay-bench/bench-results/trie_replay-go.json`
//! - Doc:  `docs/PERF_TRIE.md`
//!
//! All three are overridable via CLI flag. Refusal modes:
//!
//! - Either JSON file missing → hard error with the missing path.
//! - `input_hash_hex` mismatch between Rust and Go → hard error (input
//!   sets are not the same; the ratios would be meaningless).
//! - `n_elements` mismatch → hard error (same reason).
//! - Phase set mismatch (Rust has "apply" but Go doesn't, etc.) → hard
//!   error listing the symmetric difference.
//!
//! Output is a markdown table to stdout AND written to the `docs/PERF_TRIE.md`
//! block delimited by:
//!
//! ```text
//! <!-- BEGIN BENCH RESULTS -->
//! ...
//! <!-- END BENCH RESULTS -->
//! ```
//!
//! The hand-written methodology section above the markers is preserved.

use std::path::{Path, PathBuf};

use algo_bench::trie_replay::{PhaseStats, TrieReplayResult};

/// Workspace root, computed from `CARGO_MANIFEST_DIR`. The crate lives at
/// `crates/tools/algo-bench/`, so three `..`s reach the workspace root.
fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("..").join("..").join("..")
}

fn default_rust_json() -> PathBuf {
    workspace_root().join("target/bench-results/trie_replay-rust.json")
}

fn default_go_json() -> PathBuf {
    workspace_root().join("tools/go-trie-replay-bench/bench-results/trie_replay-go.json")
}

fn default_doc_path() -> PathBuf {
    workspace_root().join("docs/PERF_TRIE.md")
}

const BEGIN_MARKER: &str = "<!-- BEGIN BENCH RESULTS -->";
const END_MARKER: &str = "<!-- END BENCH RESULTS -->";

struct Args {
    rust_json: PathBuf,
    go_json: PathBuf,
    doc_path: PathBuf,
    /// When true, do NOT rewrite `docs/PERF_TRIE.md` — print only.
    dry_run: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut rust_json = default_rust_json();
    let mut go_json = default_go_json();
    let mut doc_path = default_doc_path();
    let mut dry_run = false;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--rust-json" => {
                rust_json = it.next().ok_or("--rust-json: missing value")?.into();
            }
            "--go-json" => {
                go_json = it.next().ok_or("--go-json: missing value")?.into();
            }
            "--doc-path" => {
                doc_path = it.next().ok_or("--doc-path: missing value")?.into();
            }
            "--dry-run" => {
                dry_run = true;
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    Ok(Args {
        rust_json,
        go_json,
        doc_path,
        dry_run,
    })
}

fn print_help() {
    println!(
        "trie_bench_compare — diff Rust↔Go trie_replay bench results\n\
         \n\
         Usage: trie_bench_compare [OPTIONS]\n\
         \n\
         Options:\n\
           --rust-json <PATH>   Rust bench JSON  [default: {}]\n\
           --go-json   <PATH>   Go bench JSON    [default: {}]\n\
           --doc-path  <PATH>   Perf doc to update  [default: {}]\n\
           --dry-run            Print the report; do NOT update the doc\n\
           -h, --help           Print this help",
        default_rust_json().display(),
        default_go_json().display(),
        default_doc_path().display(),
    );
}

fn load(path: &Path) -> Result<TrieReplayResult, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))
}

/// Pair phases by name. Errors on symmetric difference so a missing phase
/// on either side never silently degrades the report.
fn pair_phases<'a>(
    rust: &'a TrieReplayResult,
    go: &'a TrieReplayResult,
) -> Result<Vec<(&'a PhaseStats, &'a PhaseStats)>, String> {
    use std::collections::BTreeSet;
    let r_names: BTreeSet<&str> = rust.phases.iter().map(|p| p.phase.as_str()).collect();
    let g_names: BTreeSet<&str> = go.phases.iter().map(|p| p.phase.as_str()).collect();

    let only_rust: Vec<&&str> = r_names.difference(&g_names).collect();
    let only_go: Vec<&&str> = g_names.difference(&r_names).collect();
    if !only_rust.is_empty() || !only_go.is_empty() {
        return Err(format!(
            "phase mismatch: only-in-rust={only_rust:?} only-in-go={only_go:?}"
        ));
    }

    // Stable order: by phase name.
    let mut paired: Vec<(&PhaseStats, &PhaseStats)> = Vec::new();
    for name in r_names {
        let r = rust.phases.iter().find(|p| p.phase == name).unwrap();
        let g = go.phases.iter().find(|p| p.phase == name).unwrap();
        paired.push((r, g));
    }
    Ok(paired)
}

/// Format `rust_ns / go_ns` as a "Nx" ratio (Rust wall-clock relative to
/// Go). `<1` means Rust is faster, `>1` means Rust is slower. Zero-Go
/// guarded to avoid div-by-zero on degenerate bench output.
fn ratio(rust_ns: u64, go_ns: u64) -> f64 {
    if go_ns == 0 {
        f64::NAN
    } else {
        rust_ns as f64 / go_ns as f64
    }
}

fn render_markdown(
    rust: &TrieReplayResult,
    go: &TrieReplayResult,
    paired: &[(&PhaseStats, &PhaseStats)],
) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "_Generated by `cargo run -p algo-bench --bin trie_bench_compare`._\n\n\
         **Working set:** {} elements (36 bytes each).  \n\
         **Input hash:** `{}` (Rust = Go).\n\n",
        rust.n_elements, rust.input_hash_hex
    ));
    s.push_str(
        "| Phase | Rust median (ns) | Go median (ns) | Rust/Go median | Rust p99 (ns) | Go p99 (ns) | Rust/Go p99 |\n\
         |-------|-----------------:|---------------:|---------------:|--------------:|------------:|------------:|\n",
    );
    for (r, g) in paired {
        s.push_str(&format!(
            "| `{}` | {:>15} | {:>14} | {:>13.2}× | {:>13} | {:>11} | {:>10.2}× |\n",
            r.phase,
            r.median_ns,
            g.median_ns,
            ratio(r.median_ns, g.median_ns),
            r.p99_ns,
            g.p99_ns,
            ratio(r.p99_ns, g.p99_ns),
        ));
    }
    s.push_str(&format!(
        "\nRust samples per phase: {}. Go samples per phase: {}.\n",
        rust.phases.first().map(|p| p.n_samples).unwrap_or(0),
        go.phases.first().map(|p| p.n_samples).unwrap_or(0),
    ));
    s
}

fn render_terminal(paired: &[(&PhaseStats, &PhaseStats)]) -> String {
    let mut s = String::new();
    s.push_str("phase       rust_med_ns   go_med_ns   ratio   rust_p99_ns   go_p99_ns   ratio\n");
    for (r, g) in paired {
        s.push_str(&format!(
            "{:<10}  {:>11}  {:>10}  {:>5.2}x  {:>11}  {:>10}  {:>5.2}x\n",
            r.phase,
            r.median_ns,
            g.median_ns,
            ratio(r.median_ns, g.median_ns),
            r.p99_ns,
            g.p99_ns,
            ratio(r.p99_ns, g.p99_ns),
        ));
    }
    s
}

/// Replace the content between BEGIN/END markers in `doc_path` with
/// `block`. Errors if either marker is missing — the doc must be
/// initialized with both markers before the comparator can update it.
fn rewrite_doc_block(doc_path: &Path, block: &str) -> Result<(), String> {
    let existing = std::fs::read_to_string(doc_path)
        .map_err(|e| format!("read {}: {e}", doc_path.display()))?;
    let begin_idx = existing.find(BEGIN_MARKER).ok_or_else(|| {
        format!(
            "missing `{BEGIN_MARKER}` in {} — initialize the doc with both markers first",
            doc_path.display()
        )
    })?;
    let end_idx = existing.find(END_MARKER).ok_or_else(|| {
        format!(
            "missing `{END_MARKER}` in {} — initialize the doc with both markers first",
            doc_path.display()
        )
    })?;
    if end_idx < begin_idx {
        return Err(format!(
            "`{END_MARKER}` appears before `{BEGIN_MARKER}` in {}",
            doc_path.display()
        ));
    }

    let before = &existing[..begin_idx + BEGIN_MARKER.len()];
    let after = &existing[end_idx..];
    let new_contents = format!("{before}\n\n{block}\n{after}");
    std::fs::write(doc_path, new_contents).map_err(|e| format!("write {}: {e}", doc_path.display()))
}

fn run() -> Result<(), String> {
    let args = parse_args()?;

    let rust = load(&args.rust_json)?;
    let go = load(&args.go_json)?;

    if rust.input_hash_hex != go.input_hash_hex {
        return Err(format!(
            "input set mismatch: rust input_hash={} go input_hash={} — both implementations \
             must generate byte-identical inputs",
            rust.input_hash_hex, go.input_hash_hex
        ));
    }
    if rust.n_elements != go.n_elements {
        return Err(format!(
            "n_elements mismatch: rust={} go={}",
            rust.n_elements, go.n_elements
        ));
    }

    let paired = pair_phases(&rust, &go)?;

    print!("{}", render_terminal(&paired));

    if !args.dry_run {
        let md = render_markdown(&rust, &go, &paired);
        rewrite_doc_block(&args.doc_path, &md)?;
        eprintln!("updated {}", args.doc_path.display());
    } else {
        eprintln!("dry-run: skipped doc update");
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("trie_bench_compare: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_bench::trie_replay::PhaseStats;

    fn ps(phase: &str, med: u64, p99: u64) -> PhaseStats {
        PhaseStats {
            phase: phase.to_string(),
            median_ns: med,
            p99_ns: p99,
            mean_ns: med,
            total_ms: 0.0,
            n_samples: 20,
            n_elements: 1000,
        }
    }

    fn result(impl_name: &str, phases: Vec<PhaseStats>) -> TrieReplayResult {
        TrieReplayResult {
            implementation: impl_name.to_string(),
            n_elements: 1000,
            input_hash_hex: "deadbeef".to_string(),
            phases,
        }
    }

    #[test]
    fn pair_phases_aligns_by_name() {
        let r = result("rust", vec![ps("apply", 100, 110), ps("commit", 200, 220)]);
        let g = result("go", vec![ps("commit", 300, 330), ps("apply", 150, 160)]);
        let paired = pair_phases(&r, &g).unwrap();
        // Sorted by name: apply, commit.
        assert_eq!(paired[0].0.phase, "apply");
        assert_eq!(paired[0].1.phase, "apply");
        assert_eq!(paired[1].0.phase, "commit");
        assert_eq!(paired[1].1.phase, "commit");
    }

    #[test]
    fn pair_phases_errors_on_mismatch() {
        let r = result("rust", vec![ps("apply", 100, 110)]);
        let g = result("go", vec![ps("commit", 300, 330)]);
        let err = pair_phases(&r, &g).unwrap_err();
        assert!(err.contains("apply"), "msg: {err}");
        assert!(err.contains("commit"), "msg: {err}");
    }

    #[test]
    fn ratio_handles_zero_go() {
        assert!(ratio(100, 0).is_nan());
    }

    #[test]
    fn rewrite_doc_block_replaces_between_markers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.md");
        std::fs::write(
            &path,
            "# Header\n\nMethodology stays.\n\n<!-- BEGIN BENCH RESULTS -->\nOLD\n<!-- END BENCH RESULTS -->\n\nFooter.\n",
        )
        .unwrap();
        rewrite_doc_block(&path, "NEW BLOCK").unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("Methodology stays."));
        assert!(after.contains("NEW BLOCK"));
        assert!(after.contains("Footer."));
        assert!(!after.contains("OLD"));
    }

    #[test]
    fn rewrite_doc_block_errors_without_markers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.md");
        std::fs::write(&path, "# No markers here").unwrap();
        let err = rewrite_doc_block(&path, "X").unwrap_err();
        assert!(err.contains("missing"), "{err}");
    }
}
