// Copyright (c) 2026 Algod DAO
//
// SPDX-License-Identifier: MIT
// For the full license text, see LICENSE-MIT at the repository root.

use crate::metrics::BenchMetrics;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::Path;

/// Which implementation produced the benchmark result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Implementation {
    Rust,
    Go,
}

impl std::fmt::Display for Implementation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Implementation::Rust => write!(f, "Rust"),
            Implementation::Go => write!(f, "Go"),
        }
    }
}

/// Configuration parameters for a benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchConfig {
    /// Block range as a string, e.g. "1000-2000".
    pub block_range: Option<String>,
    /// Total number of blocks processed.
    pub block_count: Option<u64>,
    /// Duration limit in seconds (if time-bounded).
    pub duration_secs: Option<f64>,
    /// Arbitrary extra configuration parameters.
    #[serde(default)]
    pub custom: HashMap<String, String>,
}

/// A single benchmark run result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchRun {
    /// Name of the benchmark scenario.
    pub scenario: String,
    /// Which implementation was benchmarked.
    pub implementation: Implementation,
    /// Collected resource metrics.
    pub metrics: BenchMetrics,
    /// ISO 8601 timestamp of when the run completed.
    pub timestamp: String,
    /// Git SHA at the time of the run.
    pub git_sha: String,
    /// Configuration used for the run.
    pub config: BenchConfig,
}

/// Side-by-side comparison of a Rust run vs. a Go run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchComparison {
    /// Name of the benchmark scenario.
    pub scenario: String,
    /// The Rust benchmark run.
    pub rust_run: BenchRun,
    /// The Go benchmark run.
    pub go_run: BenchRun,
    /// Wall-clock speedup: go_time / rust_time (>1 means Rust is faster).
    pub speedup: f64,
    /// Memory ratio: go_rss / rust_rss (>1 means Rust uses less memory).
    pub memory_ratio: f64,
    /// CPU ratio: go_cpu / rust_cpu (>1 means Rust uses less CPU).
    pub cpu_ratio: f64,
}

impl BenchComparison {
    /// Build a comparison from a Rust run and a Go run.
    ///
    /// Ratios are computed as go / rust, so values > 1 mean Rust is
    /// better on that metric.
    pub fn from_runs(rust: BenchRun, go: BenchRun) -> Self {
        let speedup = if rust.metrics.wall_clock_secs > 0.0 {
            go.metrics.wall_clock_secs / rust.metrics.wall_clock_secs
        } else {
            0.0
        };

        let memory_ratio = if rust.metrics.peak_rss_bytes > 0 {
            go.metrics.peak_rss_bytes as f64 / rust.metrics.peak_rss_bytes as f64
        } else {
            0.0
        };

        let cpu_ratio = if rust.metrics.avg_cpu_pct > 0.0 {
            go.metrics.avg_cpu_pct / rust.metrics.avg_cpu_pct
        } else {
            0.0
        };

        let scenario = rust.scenario.clone();

        Self {
            scenario,
            rust_run: rust,
            go_run: go,
            speedup,
            memory_ratio,
            cpu_ratio,
        }
    }
}

/// Serialize a `BenchRun` to JSON and write it to `path`.
pub fn save_run(run: &BenchRun, path: &Path) -> io::Result<()> {
    let json = serde_json::to_string_pretty(run)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

/// Read a `BenchRun` from a JSON file at `path`.
pub fn load_run(path: &Path) -> io::Result<BenchRun> {
    let data = std::fs::read_to_string(path)?;
    serde_json::from_str(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Load a Rust run and a Go run from JSON files, returning a `BenchComparison`.
pub fn load_comparison(rust_path: &Path, go_path: &Path) -> io::Result<BenchComparison> {
    let rust_run = load_run(rust_path)?;
    let go_run = load_run(go_path)?;
    Ok(BenchComparison::from_runs(rust_run, go_run))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metrics() -> BenchMetrics {
        BenchMetrics {
            wall_clock_secs: 38.0,
            peak_rss_bytes: 210_000_000,
            avg_cpu_pct: 62.0,
            disk_io_bytes: None,
            blocks_per_sec: Some(263.0),
            txns_per_sec: Some(15_800.0),
        }
    }

    fn sample_config() -> BenchConfig {
        BenchConfig {
            block_range: Some("1-10000".to_string()),
            block_count: Some(10_000),
            duration_secs: None,
            custom: HashMap::new(),
        }
    }

    fn sample_rust_run() -> BenchRun {
        BenchRun {
            scenario: "block_replay".to_string(),
            implementation: Implementation::Rust,
            metrics: sample_metrics(),
            timestamp: "2026-03-14T12:00:00Z".to_string(),
            git_sha: "abc1234".to_string(),
            config: sample_config(),
        }
    }

    fn sample_go_run() -> BenchRun {
        BenchRun {
            scenario: "block_replay".to_string(),
            implementation: Implementation::Go,
            metrics: BenchMetrics {
                wall_clock_secs: 142.0,
                peak_rss_bytes: 1_800_000_000,
                avg_cpu_pct: 87.0,
                disk_io_bytes: None,
                blocks_per_sec: Some(70.0),
                txns_per_sec: Some(4_200.0),
            },
            timestamp: "2026-03-14T12:00:00Z".to_string(),
            git_sha: "def5678".to_string(),
            config: sample_config(),
        }
    }

    #[test]
    fn test_bench_run_serde_roundtrip() {
        let run = sample_rust_run();
        let json = serde_json::to_string_pretty(&run).unwrap();
        let run2: BenchRun = serde_json::from_str(&json).unwrap();
        assert_eq!(run2.scenario, "block_replay");
        assert_eq!(run2.implementation, Implementation::Rust);
        assert!((run2.metrics.wall_clock_secs - 38.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_comparison_ratios() {
        let comparison = BenchComparison::from_runs(sample_rust_run(), sample_go_run());
        // speedup = 142 / 38 ≈ 3.7368
        assert!((comparison.speedup - 142.0 / 38.0).abs() < 0.01);
        // memory_ratio = 1_800_000_000 / 210_000_000 ≈ 8.571
        assert!((comparison.memory_ratio - 1_800_000_000.0 / 210_000_000.0).abs() < 0.01);
        // cpu_ratio = 87 / 62 ≈ 1.403
        assert!((comparison.cpu_ratio - 87.0 / 62.0).abs() < 0.01);
    }

    #[test]
    fn test_save_and_load_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_run.json");

        let run = sample_rust_run();
        save_run(&run, &path).unwrap();
        let loaded = load_run(&path).unwrap();

        assert_eq!(loaded.scenario, run.scenario);
        assert_eq!(loaded.implementation, run.implementation);
        assert!(
            (loaded.metrics.wall_clock_secs - run.metrics.wall_clock_secs).abs() < f64::EPSILON
        );
    }

    #[test]
    fn test_load_comparison() {
        let dir = tempfile::tempdir().unwrap();

        let rust_path = dir.path().join("rust.json");
        let go_path = dir.path().join("go.json");

        save_run(&sample_rust_run(), &rust_path).unwrap();
        save_run(&sample_go_run(), &go_path).unwrap();

        let cmp = load_comparison(&rust_path, &go_path).unwrap();
        assert_eq!(cmp.scenario, "block_replay");
        assert!(cmp.speedup > 1.0);
        assert!(cmp.memory_ratio > 1.0);
    }

    #[test]
    fn test_implementation_display() {
        assert_eq!(format!("{}", Implementation::Rust), "Rust");
        assert_eq!(format!("{}", Implementation::Go), "Go");
    }

    #[test]
    fn test_bench_config_custom_fields() {
        let mut config = sample_config();
        config
            .custom
            .insert("network".to_string(), "mainnet".to_string());
        let json = serde_json::to_string(&config).unwrap();
        let config2: BenchConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config2.custom.get("network").unwrap(), "mainnet");
    }
}
