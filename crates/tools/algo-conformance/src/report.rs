use std::path::Path;

use algo_error::Result;
use serde::Serialize;

use crate::compare::{ComparisonResult, ComparisonStatus};

/// Summary report of a conformance validation run.
#[derive(Debug, Clone, Serialize)]
pub struct ConformanceReport {
    pub total_rounds: usize,
    pub passed: usize,
    pub failed: usize,
    pub started_at: String,
    pub finished_at: String,
    pub results: Vec<ComparisonResult>,
}

impl ConformanceReport {
    pub fn new(results: Vec<ComparisonResult>, started_at: String, finished_at: String) -> Self {
        let passed = results
            .iter()
            .filter(|r| r.status == ComparisonStatus::Pass)
            .count();
        let failed = results.len() - passed;
        Self {
            total_rounds: results.len(),
            passed,
            failed,
            started_at,
            finished_at,
            results,
        }
    }
}

/// Write a conformance report to a JSON file.
pub fn write_report(report: &ConformanceReport, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(report).map_err(|e| algo_error::AlgoError::Codec {
        source: Box::new(e),
        context: "serializing conformance report".into(),
    })?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Print a human-readable summary to stdout.
pub fn print_summary(report: &ConformanceReport) {
    println!("=== Conformance Report ===");
    println!(
        "Rounds: {} total, {} passed, {} failed",
        report.total_rounds, report.passed, report.failed
    );
    println!("Time: {} -> {}", report.started_at, report.finished_at);

    if report.failed > 0 {
        println!("\nFailed rounds:");
        for result in &report.results {
            if result.status == ComparisonStatus::Fail {
                println!(
                    "  Round {}: {} mismatches",
                    result.round,
                    result.mismatches.len()
                );
                for m in &result.mismatches {
                    println!("    - {:?}", m);
                }
            }
        }
    } else {
        println!("\nAll rounds passed!");
    }
}
