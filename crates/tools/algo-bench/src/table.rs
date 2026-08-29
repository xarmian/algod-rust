// Copyright (c) 2026 Algod DAO
//
// SPDX-License-Identifier: MIT
// For the full license text, see LICENSE-MIT at the repository root.

use crate::output::BenchComparison;

/// Format a byte count in human-readable form (B, KB, MB, GB, TB).
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1_024;
    const MB: u64 = 1_024 * KB;
    const GB: u64 = 1_024 * MB;
    const TB: u64 = 1_024 * GB;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format a ratio as a human-readable delta string.
///
/// - ratio > 1 => "X.Y\u{00d7} faster" (or "less" for memory/cpu)
/// - ratio < 1 => "X.Y\u{00d7} slower" (or "more")
/// - ratio == 1 => "same"
///
/// `kind` selects the wording: `"speed"` uses faster/slower,
/// `"resource"` uses less/more.
pub fn format_ratio(ratio: f64, kind: &str) -> String {
    if (ratio - 1.0).abs() < 0.01 {
        return "same".to_string();
    }

    match kind {
        "speed" => {
            if ratio > 1.0 {
                format!("{:.1}\u{00d7} faster", ratio)
            } else {
                format!("{:.1}\u{00d7} slower", 1.0 / ratio)
            }
        }
        "resource" => {
            if ratio > 1.0 {
                format!("{:.1}\u{00d7} less", ratio)
            } else {
                format!("{:.1}\u{00d7} more", 1.0 / ratio)
            }
        }
        "percent" => {
            if ratio > 1.0 {
                let pct = (ratio - 1.0) * 100.0;
                format!("{:.0}% less", pct)
            } else {
                let pct = (1.0 / ratio - 1.0) * 100.0;
                format!("{:.0}% more", pct)
            }
        }
        _ => format!("{:.1}\u{00d7}", ratio),
    }
}

/// Format a number with thousands separators (comma-separated).
fn format_number(n: f64) -> String {
    if n < 0.0 {
        return format!("-{}", format_number(-n));
    }
    let int_part = n as u64;
    let s = int_part.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

/// Render a comparison as an ASCII terminal table.
pub fn render_terminal(comparison: &BenchComparison) -> String {
    let mut lines = Vec::new();

    let go_ver = format!("Go ({})", comparison.go_run.git_sha);
    let rust_ver = format!("Rust ({})", comparison.rust_run.git_sha);

    lines.push(comparison.scenario.to_string());
    lines.push("\u{2500}".repeat(60));

    // Header
    lines.push(format!(
        "{:<20}{:>14}{:>16}{:>14}",
        "", go_ver, rust_ver, "\u{0394}"
    ));

    // Elapsed
    lines.push(format!(
        "{:<20}{:>14}{:>16}{:>14}",
        "Elapsed",
        format!("{:.1}s", comparison.go_run.metrics.wall_clock_secs),
        format!("{:.1}s", comparison.rust_run.metrics.wall_clock_secs),
        format_ratio(comparison.speedup, "speed"),
    ));

    // Peak RSS
    lines.push(format!(
        "{:<20}{:>14}{:>16}{:>14}",
        "Peak RSS",
        format_bytes(comparison.go_run.metrics.peak_rss_bytes),
        format_bytes(comparison.rust_run.metrics.peak_rss_bytes),
        format_ratio(comparison.memory_ratio, "resource"),
    ));

    // Avg CPU
    lines.push(format!(
        "{:<20}{:>14}{:>16}{:>14}",
        "Avg CPU",
        format!("{:.1}%", comparison.go_run.metrics.avg_cpu_pct),
        format!("{:.1}%", comparison.rust_run.metrics.avg_cpu_pct),
        format_ratio(comparison.cpu_ratio, "percent"),
    ));

    // Blocks/sec (if both have it)
    if let (Some(go_bps), Some(rust_bps)) = (
        comparison.go_run.metrics.blocks_per_sec,
        comparison.rust_run.metrics.blocks_per_sec,
    ) {
        let ratio = if go_bps > 0.0 { rust_bps / go_bps } else { 0.0 };
        lines.push(format!(
            "{:<20}{:>14}{:>16}{:>14}",
            "Blocks/sec",
            format_number(go_bps),
            format_number(rust_bps),
            format!("{:.1}\u{00d7}", ratio),
        ));
    }

    // Txns/sec (if both have it)
    if let (Some(go_tps), Some(rust_tps)) = (
        comparison.go_run.metrics.txns_per_sec,
        comparison.rust_run.metrics.txns_per_sec,
    ) {
        let ratio = if go_tps > 0.0 { rust_tps / go_tps } else { 0.0 };
        lines.push(format!(
            "{:<20}{:>14}{:>16}{:>14}",
            "Txns/sec",
            format_number(go_tps),
            format_number(rust_tps),
            format!("{:.1}\u{00d7}", ratio),
        ));
    }

    lines.join("\n")
}

/// Render a comparison as a Markdown table.
pub fn render_markdown(comparison: &BenchComparison) -> String {
    let mut lines = Vec::new();

    let go_ver = format!("Go ({})", comparison.go_run.git_sha);
    let rust_ver = format!("Rust ({})", comparison.rust_run.git_sha);

    lines.push(format!("### {}", comparison.scenario));
    lines.push(String::new());
    lines.push(format!("| Metric | {} | {} | \u{0394} |", go_ver, rust_ver));
    lines.push("| --- | ---: | ---: | ---: |".to_string());

    // Elapsed
    lines.push(format!(
        "| Elapsed | {:.1}s | {:.1}s | {} |",
        comparison.go_run.metrics.wall_clock_secs,
        comparison.rust_run.metrics.wall_clock_secs,
        format_ratio(comparison.speedup, "speed"),
    ));

    // Peak RSS
    lines.push(format!(
        "| Peak RSS | {} | {} | {} |",
        format_bytes(comparison.go_run.metrics.peak_rss_bytes),
        format_bytes(comparison.rust_run.metrics.peak_rss_bytes),
        format_ratio(comparison.memory_ratio, "resource"),
    ));

    // Avg CPU
    lines.push(format!(
        "| Avg CPU | {:.1}% | {:.1}% | {} |",
        comparison.go_run.metrics.avg_cpu_pct,
        comparison.rust_run.metrics.avg_cpu_pct,
        format_ratio(comparison.cpu_ratio, "percent"),
    ));

    // Blocks/sec
    if let (Some(go_bps), Some(rust_bps)) = (
        comparison.go_run.metrics.blocks_per_sec,
        comparison.rust_run.metrics.blocks_per_sec,
    ) {
        let ratio = if go_bps > 0.0 { rust_bps / go_bps } else { 0.0 };
        lines.push(format!(
            "| Blocks/sec | {} | {} | {:.1}\u{00d7} |",
            format_number(go_bps),
            format_number(rust_bps),
            ratio,
        ));
    }

    // Txns/sec
    if let (Some(go_tps), Some(rust_tps)) = (
        comparison.go_run.metrics.txns_per_sec,
        comparison.rust_run.metrics.txns_per_sec,
    ) {
        let ratio = if go_tps > 0.0 { rust_tps / go_tps } else { 0.0 };
        lines.push(format!(
            "| Txns/sec | {} | {} | {:.1}\u{00d7} |",
            format_number(go_tps),
            format_number(rust_tps),
            ratio,
        ));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::BenchMetrics;
    use crate::output::{BenchConfig, BenchRun, Implementation};
    use std::collections::HashMap;

    fn sample_comparison() -> BenchComparison {
        let rust_run = BenchRun {
            scenario: "Block Replay: 10,000 mainnet blocks".to_string(),
            implementation: Implementation::Rust,
            metrics: BenchMetrics {
                wall_clock_secs: 38.0,
                peak_rss_bytes: 210_000_000,
                avg_cpu_pct: 62.0,
                disk_io_bytes: None,
                blocks_per_sec: Some(263.0),
                txns_per_sec: Some(15_800.0),
            },
            timestamp: "2026-03-14T12:00:00Z".to_string(),
            git_sha: "0.1.0".to_string(),
            config: BenchConfig {
                block_range: Some("1-10000".to_string()),
                block_count: Some(10_000),
                duration_secs: None,
                custom: HashMap::new(),
            },
        };

        let go_run = BenchRun {
            scenario: "Block Replay: 10,000 mainnet blocks".to_string(),
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
            git_sha: "4.5.1".to_string(),
            config: BenchConfig {
                block_range: Some("1-10000".to_string()),
                block_count: Some(10_000),
                duration_secs: None,
                custom: HashMap::new(),
            },
        };

        BenchComparison::from_runs(rust_run, go_run)
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1_024), "1.0 KB");
        assert_eq!(format_bytes(1_500_000), "1.4 MB");
        assert_eq!(format_bytes(1_800_000_000), "1.7 GB");
        assert_eq!(format_bytes(2_000_000_000_000), "1.8 TB");
    }

    #[test]
    fn test_format_ratio_speed() {
        assert_eq!(format_ratio(3.7, "speed"), "3.7\u{00d7} faster");
        assert_eq!(format_ratio(0.5, "speed"), "2.0\u{00d7} slower");
        assert_eq!(format_ratio(1.0, "speed"), "same");
    }

    #[test]
    fn test_format_ratio_resource() {
        assert_eq!(format_ratio(8.6, "resource"), "8.6\u{00d7} less");
        assert_eq!(format_ratio(0.5, "resource"), "2.0\u{00d7} more");
    }

    #[test]
    fn test_format_ratio_percent() {
        assert_eq!(format_ratio(1.40, "percent"), "40% less");
        assert_eq!(format_ratio(0.5, "percent"), "100% more");
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0.0), "0");
        assert_eq!(format_number(999.0), "999");
        assert_eq!(format_number(1_000.0), "1,000");
        assert_eq!(format_number(15_800.0), "15,800");
        assert_eq!(format_number(1_000_000.0), "1,000,000");
    }

    #[test]
    fn test_render_terminal() {
        let cmp = sample_comparison();
        let table = render_terminal(&cmp);
        // Verify key content is present.
        assert!(table.contains("Block Replay"));
        assert!(table.contains("Elapsed"));
        assert!(table.contains("Peak RSS"));
        assert!(table.contains("Avg CPU"));
        assert!(table.contains("Blocks/sec"));
        assert!(table.contains("Txns/sec"));
        assert!(table.contains("faster"));
        assert!(table.contains("less"));
        // Print for visual inspection during development.
        println!("{table}");
    }

    #[test]
    fn test_render_markdown() {
        let cmp = sample_comparison();
        let md = render_markdown(&cmp);
        assert!(md.contains("### Block Replay"));
        assert!(md.contains("| Metric |"));
        assert!(md.contains("| Elapsed |"));
        assert!(md.contains("| Peak RSS |"));
        assert!(md.contains("faster"));
        println!("{md}");
    }

    #[test]
    fn test_render_terminal_no_throughput() {
        let rust_run = BenchRun {
            scenario: "Simple test".to_string(),
            implementation: Implementation::Rust,
            metrics: BenchMetrics {
                wall_clock_secs: 10.0,
                peak_rss_bytes: 100_000_000,
                avg_cpu_pct: 50.0,
                disk_io_bytes: None,
                blocks_per_sec: None,
                txns_per_sec: None,
            },
            timestamp: "2026-03-14T12:00:00Z".to_string(),
            git_sha: "abc".to_string(),
            config: BenchConfig {
                block_range: None,
                block_count: None,
                duration_secs: None,
                custom: HashMap::new(),
            },
        };

        let go_run = BenchRun {
            scenario: "Simple test".to_string(),
            implementation: Implementation::Go,
            metrics: BenchMetrics {
                wall_clock_secs: 30.0,
                peak_rss_bytes: 500_000_000,
                avg_cpu_pct: 90.0,
                disk_io_bytes: None,
                blocks_per_sec: None,
                txns_per_sec: None,
            },
            timestamp: "2026-03-14T12:00:00Z".to_string(),
            git_sha: "def".to_string(),
            config: BenchConfig {
                block_range: None,
                block_count: None,
                duration_secs: None,
                custom: HashMap::new(),
            },
        };

        let cmp = BenchComparison::from_runs(rust_run, go_run);
        let table = render_terminal(&cmp);
        // Should NOT contain Blocks/sec or Txns/sec lines when data is absent.
        assert!(!table.contains("Blocks/sec"));
        assert!(!table.contains("Txns/sec"));
    }
}
