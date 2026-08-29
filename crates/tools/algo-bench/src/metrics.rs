// Copyright (c) 2026 Algod DAO
//
// SPDX-License-Identifier: MIT
// For the full license text, see LICENSE-MIT at the repository root.

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{Pid, System};

/// Resource metrics collected during a benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchMetrics {
    /// Wall-clock elapsed time in seconds.
    pub wall_clock_secs: f64,
    /// Peak resident set size in bytes.
    pub peak_rss_bytes: u64,
    /// Average CPU usage as a percentage (0-100+).
    pub avg_cpu_pct: f64,
    /// Total disk I/O bytes (if available).
    pub disk_io_bytes: Option<u64>,
    /// Blocks processed per second (if applicable).
    pub blocks_per_sec: Option<f64>,
    /// Transactions processed per second (if applicable).
    pub txns_per_sec: Option<f64>,
}

/// Collects resource metrics by sampling process stats in a background thread.
pub struct MetricsCollector {
    start: Instant,
    stop_flag: Arc<AtomicBool>,
    peak_rss: Arc<AtomicU64>,
    sample_handle: Option<thread::JoinHandle<()>>,
    pid: Pid,
}

impl MetricsCollector {
    /// Create a new `MetricsCollector` that samples at the default interval (100ms).
    pub fn new() -> Self {
        Self::with_interval(Duration::from_millis(100))
    }

    /// Create a new `MetricsCollector` with a custom sampling interval.
    pub fn with_interval(interval: Duration) -> Self {
        let pid = Pid::from_u32(std::process::id());
        let stop_flag = Arc::new(AtomicBool::new(false));
        let peak_rss = Arc::new(AtomicU64::new(0));

        let stop = Arc::clone(&stop_flag);
        let peak = Arc::clone(&peak_rss);
        let sample_pid = pid;

        // Take one synchronous sample before spawning the background thread
        // so that peak_rss is never zero.
        {
            let mut sys = System::new();
            sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
            if let Some(proc) = sys.process(pid) {
                peak_rss.fetch_max(proc.memory(), Ordering::Relaxed);
            }
        }

        let sample_handle = thread::spawn(move || {
            let mut sys = System::new();
            while !stop.load(Ordering::Relaxed) {
                sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[sample_pid]), true);
                if let Some(proc) = sys.process(sample_pid) {
                    let rss = proc.memory();
                    peak.fetch_max(rss, Ordering::Relaxed);
                }
                thread::sleep(interval);
            }
        });

        Self {
            start: Instant::now(),
            stop_flag,
            peak_rss,
            sample_handle: Some(sample_handle),
            pid,
        }
    }

    /// Stop sampling and return the collected metrics.
    ///
    /// `blocks_per_sec` and `txns_per_sec` are left as `None`;
    /// callers can fill them in based on workload-specific counters.
    pub fn finish(mut self) -> BenchMetrics {
        let wall_clock = self.start.elapsed();
        let wall_secs = wall_clock.as_secs_f64();

        // Signal the background thread to stop and wait for it.
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(h) = self.sample_handle.take() {
            let _ = h.join();
        }

        let peak_rss_bytes = self.peak_rss.load(Ordering::Relaxed);

        // Get CPU usage from process times.
        let avg_cpu_pct = {
            let mut sys = System::new();
            sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[self.pid]), true);
            if let Some(proc) = sys.process(self.pid) {
                // sysinfo reports cpu_usage as percentage (can exceed 100 on multicore).
                // We take a single snapshot; for a long-running benchmark this is
                // a reasonable approximation.
                proc.cpu_usage() as f64
            } else {
                0.0
            }
        };

        BenchMetrics {
            wall_clock_secs: wall_secs,
            peak_rss_bytes,
            avg_cpu_pct,
            disk_io_bytes: None,
            blocks_per_sec: None,
            txns_per_sec: None,
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot helper: return the current RSS of this process in bytes.
pub fn current_rss_bytes() -> u64 {
    let pid = Pid::from_u32(std::process::id());
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    sys.process(pid).map_or(0, |p| p.memory())
}

/// Return the short git SHA of HEAD, or `"unknown"` if git is unavailable.
pub fn git_sha() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_rss_bytes() {
        let rss = current_rss_bytes();
        // Process should have *some* memory allocated.
        assert!(rss > 0, "RSS should be > 0, got {rss}");
    }

    #[test]
    fn test_git_sha() {
        let sha = git_sha();
        assert!(!sha.is_empty());
        // In a git repo the SHA should be a hex string of 7-12 chars.
        // If not in a repo, we get "unknown".
        assert!(
            sha == "unknown" || sha.len() >= 7,
            "unexpected git sha: {sha}"
        );
    }

    #[test]
    fn test_metrics_collector_basic() {
        let collector = MetricsCollector::with_interval(Duration::from_millis(50));
        // Do a tiny bit of work so the sampler has something to observe.
        let mut v = Vec::new();
        for i in 0..10_000 {
            v.push(i);
        }
        drop(v);

        let metrics = collector.finish();
        assert!(metrics.wall_clock_secs >= 0.0);
        assert!(metrics.peak_rss_bytes > 0);
        // blocks_per_sec and txns_per_sec should be None by default.
        assert!(metrics.blocks_per_sec.is_none());
        assert!(metrics.txns_per_sec.is_none());
    }

    #[test]
    fn test_bench_metrics_serde_roundtrip() {
        let m = BenchMetrics {
            wall_clock_secs: 1.23,
            peak_rss_bytes: 1_000_000,
            avg_cpu_pct: 45.6,
            disk_io_bytes: Some(2048),
            blocks_per_sec: Some(100.0),
            txns_per_sec: Some(5000.0),
        };
        let json = serde_json::to_string(&m).unwrap();
        let m2: BenchMetrics = serde_json::from_str(&json).unwrap();
        assert!((m2.wall_clock_secs - 1.23).abs() < f64::EPSILON);
        assert_eq!(m2.peak_rss_bytes, 1_000_000);
        assert_eq!(m2.disk_io_bytes, Some(2048));
    }
}
