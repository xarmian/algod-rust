// Copyright (c) 2026 Algod DAO
//
// SPDX-License-Identifier: MIT
// For the full license text, see LICENSE-MIT at the repository root.

//! `algo-bench` -- benchmark metrics collection, JSON output, and comparison
//! table rendering for algod-rust vs. go-algorand performance comparisons.

pub mod metrics;
pub mod output;
pub mod table;
pub mod trie_replay;

// Re-export key types for convenience.
pub use metrics::{BenchMetrics, MetricsCollector};
pub use output::{BenchComparison, BenchConfig, BenchRun, Implementation};
pub use table::{format_bytes, format_ratio, render_markdown, render_terminal};
