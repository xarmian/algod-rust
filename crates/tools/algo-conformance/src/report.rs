// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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
