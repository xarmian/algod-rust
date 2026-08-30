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

//! Go-runtime-equivalent process counters and network-interface counters for
//! `GET /metrics` (issue #776).
//!
//! go-algorand gates two additional Prometheus registrations behind
//! `config.Local` flags (`daemon/algod/server.go:338-344`):
//!
//! * `EnableRuntimeMetrics` registers `metrics.NewRuntimeMetrics()`
//!   (`util/metrics/runtime.go`), which samples Go's `runtime/metrics`
//!   package: GC cycle counts, heap alloc/free byte and object counts, a
//!   fine-grained breakdown of `/memory/classes/*`, and the live goroutine
//!   count.
//! * `EnableNetDevMetrics` registers `metrics.NetDevMetrics`
//!   (`util/metrics/netdev_common.go` + per-OS `netdev_linux.go`/
//!   `netdev_darwin.go`), which reports cumulative bytes received/sent per
//!   network interface (from `/proc/net/dev`-equivalent OS accounting).
//!
//! ## Mapping decision (documented per issue #776's instruction)
//!
//! Rust has no garbage collector, so go's GC-cycle counters and the
//! fine-grained `/memory/classes/*` heap-allocator breakdown have **no**
//! meaningful Rust analogue — there is no allocator-internal accounting to
//! report that would mean the same thing. The closest defensible equivalent
//! is coarse OS-reported process health: resident and virtual memory size
//! (which upstream's own `/memory/classes/total:bytes` and
//! `/memory/classes/heap/objects:bytes` are trying to approximate at a
//! process level), CPU usage, process uptime, and — standing in for go's
//! `/sched/goroutines:goroutines` gauge — this process's live OS thread
//! count (algod-rust has no userspace green-thread scheduler the way the Go
//! runtime does; OS threads are the analogous "concurrently-schedulable unit
//! of work" primitive here).
//!
//! `EnableNetDevMetrics` has a direct, faithful Rust equivalent: `sysinfo`
//! (already a workspace dependency, used by `algo-bench`) exposes the exact
//! same cumulative per-interface received/transmitted byte counters that
//! go's `netdev_linux.go`/`netdev_darwin.go` read from the OS, and does so
//! portably (including on platforms upstream's `netdev_noop.go` gives up on,
//! such as Windows).
//!
//! Both snapshot types are hand-rendered to Prometheus text exposition
//! format, matching the existing convention in
//! `algo_agreement::metrics::ParticipationSnapshot` — no `prometheus` crate
//! dependency is introduced.

use sysinfo::{Networks, Pid, System};

// ---------------------------------------------------------------------------
// Runtime (process) metrics -- gated by `EnableRuntimeMetrics`
// ---------------------------------------------------------------------------

/// A point-in-time view of this process's Go-runtime-equivalent counters.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RuntimeMetricsSnapshot {
    /// Resident set size in bytes -- closest analogue to the sum of go's
    /// `/memory/classes/heap/*:bytes` series.
    pub resident_memory_bytes: u64,
    /// Virtual memory size in bytes -- closest analogue to go's
    /// `/memory/classes/total:bytes`.
    pub virtual_memory_bytes: u64,
    /// CPU usage as a percentage (0-100+ on multi-core), sampled the same
    /// way `algo_bench::metrics::MetricsCollector` does.
    pub cpu_usage_percent: f64,
    /// Seconds since this process started (go's runtime metrics carry no
    /// direct uptime series; included as a generally useful process-health
    /// gauge, matching `ParticipationSnapshot::uptime_ms`'s precedent).
    pub uptime_seconds: u64,
    /// Live OS thread count -- stand-in for go's
    /// `/sched/goroutines:goroutines` gauge (see module docs for why: no
    /// green-thread scheduler exists to report a native equivalent of).
    /// `0` where the platform cannot report this (see
    /// [`RuntimeMetricsSnapshot::capture`]).
    pub threads: u64,
}

impl RuntimeMetricsSnapshot {
    /// Sample the current process's counters via `sysinfo`.
    pub fn capture() -> Self {
        let pid = Pid::from_u32(std::process::id());
        let mut sys = System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
        match sys.process(pid) {
            Some(proc) => Self {
                resident_memory_bytes: proc.memory(),
                virtual_memory_bytes: proc.virtual_memory(),
                cpu_usage_percent: proc.cpu_usage() as f64,
                uptime_seconds: proc.run_time(),
                // `tasks()` (thread IDs) is only populated on Linux; other
                // platforms report `None` here rather than a fabricated
                // count, mirroring go's own `netdev_noop.go` "no data on
                // this platform" precedent rather than inventing a number.
                threads: proc.tasks().map(|t| t.len() as u64).unwrap_or(0),
            },
            None => Self::default(),
        }
    }

    /// Render as Prometheus text exposition format. Pure function of `self`
    /// so it can be unit-tested deterministically without sampling the live
    /// process.
    pub fn to_prometheus_text(&self) -> String {
        let mut out = String::with_capacity(512);
        for (name, help, value) in [
            (
                "algod_rust_runtime_resident_memory_bytes",
                "Resident set size of this process, in bytes (closest analogue to go's runtime.metrics heap byte counters).",
                self.resident_memory_bytes,
            ),
            (
                "algod_rust_runtime_virtual_memory_bytes",
                "Virtual memory size of this process, in bytes (closest analogue to go's /memory/classes/total:bytes).",
                self.virtual_memory_bytes,
            ),
            (
                "algod_rust_runtime_uptime_seconds",
                "Seconds since this process started.",
                self.uptime_seconds,
            ),
            (
                "algod_rust_runtime_threads",
                "Live OS thread count for this process (stand-in for go's /sched/goroutines:goroutines gauge; 0 where the platform cannot report it).",
                self.threads,
            ),
        ] {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"
            ));
        }
        out.push_str(
            "# HELP algod_rust_runtime_cpu_usage_percent CPU usage of this process as a percentage (may exceed 100 on multi-core hosts).\n\
             # TYPE algod_rust_runtime_cpu_usage_percent gauge\n",
        );
        out.push_str(&format!(
            "algod_rust_runtime_cpu_usage_percent {}\n",
            self.cpu_usage_percent
        ));
        out
    }
}

// ---------------------------------------------------------------------------
// Network-interface metrics -- gated by `EnableNetDevMetrics`
// ---------------------------------------------------------------------------

/// Cumulative byte counters for one network interface.
#[derive(Clone, Debug, PartialEq)]
pub struct NetDevInterface {
    /// OS-reported interface name (e.g. `eth0`, `lo`).
    pub name: String,
    /// Cumulative bytes received since the interface came up.
    pub bytes_received: u64,
    /// Cumulative bytes sent since the interface came up.
    pub bytes_sent: u64,
}

/// A point-in-time view of every network interface's cumulative byte
/// counters.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NetDevMetricsSnapshot {
    /// One entry per OS-reported network interface, in `sysinfo`'s
    /// iteration order.
    pub interfaces: Vec<NetDevInterface>,
}

impl NetDevMetricsSnapshot {
    /// Sample every network interface's cumulative counters via `sysinfo`.
    pub fn capture() -> Self {
        let networks = Networks::new_with_refreshed_list();
        let mut interfaces: Vec<NetDevInterface> = networks
            .iter()
            .map(|(name, data)| NetDevInterface {
                name: name.clone(),
                bytes_received: data.total_received(),
                bytes_sent: data.total_transmitted(),
            })
            .collect();
        // Deterministic ordering: `sysinfo`'s `Networks` is backed by a
        // `HashMap`, whose iteration order is not stable across samples —
        // sort so repeated scrapes render interfaces in the same order.
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        Self { interfaces }
    }

    /// Render as Prometheus text exposition format, matching go's
    /// `algod_netdev_received_bytes`/`algod_netdev_sent_bytes` metric names
    /// and per-interface `iface` label (`util/metrics/netdev_common.go`).
    pub fn to_prometheus_text(&self) -> String {
        let mut out = String::with_capacity(256 + self.interfaces.len() * 128);
        out.push_str(
            "# HELP algod_rust_netdev_received_bytes Cumulative bytes received on this network interface.\n\
             # TYPE algod_rust_netdev_received_bytes counter\n",
        );
        for iface in &self.interfaces {
            out.push_str(&format!(
                "algod_rust_netdev_received_bytes{{iface=\"{}\"}} {}\n",
                escape_label(&iface.name),
                iface.bytes_received
            ));
        }
        out.push_str(
            "# HELP algod_rust_netdev_sent_bytes Cumulative bytes sent on this network interface.\n\
             # TYPE algod_rust_netdev_sent_bytes counter\n",
        );
        for iface in &self.interfaces {
            out.push_str(&format!(
                "algod_rust_netdev_sent_bytes{{iface=\"{}\"}} {}\n",
                escape_label(&iface.name),
                iface.bytes_sent
            ));
        }
        out
    }
}

/// Escape a Prometheus label value (`\`, `"`, and newline) -- same rule as
/// `algo_agreement::metrics::escape_label`, duplicated here rather than
/// shared across a crate boundary for a two-line helper.
fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Pure rendering (deterministic) ──────────────────────────────────

    #[test]
    fn runtime_snapshot_renders_all_series_with_correct_types() {
        let snap = RuntimeMetricsSnapshot {
            resident_memory_bytes: 123_456,
            virtual_memory_bytes: 987_654,
            cpu_usage_percent: 12.5,
            uptime_seconds: 42,
            threads: 7,
        };
        let text = snap.to_prometheus_text();
        assert!(text.contains("algod_rust_runtime_resident_memory_bytes 123456"));
        assert!(text.contains("# TYPE algod_rust_runtime_resident_memory_bytes gauge"));
        assert!(text.contains("algod_rust_runtime_virtual_memory_bytes 987654"));
        assert!(text.contains("algod_rust_runtime_uptime_seconds 42"));
        assert!(text.contains("algod_rust_runtime_threads 7"));
        assert!(text.contains("algod_rust_runtime_cpu_usage_percent 12.5"));
    }

    #[test]
    fn runtime_snapshot_zero_values_still_render() {
        let snap = RuntimeMetricsSnapshot::default();
        let text = snap.to_prometheus_text();
        assert!(text.contains("algod_rust_runtime_resident_memory_bytes 0"));
        assert!(text.contains("algod_rust_runtime_threads 0"));
    }

    #[test]
    fn netdev_snapshot_renders_per_interface_series_with_labels() {
        let snap = NetDevMetricsSnapshot {
            interfaces: vec![
                NetDevInterface {
                    name: "eth0".to_string(),
                    bytes_received: 1000,
                    bytes_sent: 2000,
                },
                NetDevInterface {
                    name: "lo".to_string(),
                    bytes_received: 50,
                    bytes_sent: 50,
                },
            ],
        };
        let text = snap.to_prometheus_text();
        assert!(text.contains("# TYPE algod_rust_netdev_received_bytes counter"));
        assert!(text.contains("algod_rust_netdev_received_bytes{iface=\"eth0\"} 1000"));
        assert!(text.contains("algod_rust_netdev_sent_bytes{iface=\"eth0\"} 2000"));
        assert!(text.contains("algod_rust_netdev_received_bytes{iface=\"lo\"} 50"));
        assert!(text.contains("algod_rust_netdev_sent_bytes{iface=\"lo\"} 50"));
    }

    #[test]
    fn netdev_snapshot_no_interfaces_still_emits_headers_only() {
        let snap = NetDevMetricsSnapshot::default();
        let text = snap.to_prometheus_text();
        assert!(text.contains("# HELP algod_rust_netdev_received_bytes"));
        assert!(text.contains("# HELP algod_rust_netdev_sent_bytes"));
        assert!(!text.contains("iface="));
    }

    #[test]
    fn netdev_label_escaping_matches_agreement_metrics_convention() {
        let snap = NetDevMetricsSnapshot {
            interfaces: vec![NetDevInterface {
                name: "weird\"iface".to_string(),
                bytes_received: 1,
                bytes_sent: 1,
            }],
        };
        let text = snap.to_prometheus_text();
        assert!(text.contains("iface=\"weird\\\"iface\""));
    }

    // ── Live capture (non-deterministic values, but shape-checked) ──────

    #[test]
    fn runtime_snapshot_capture_reports_nonzero_memory_for_this_process() {
        let snap = RuntimeMetricsSnapshot::capture();
        assert!(
            snap.resident_memory_bytes > 0,
            "a running test process should have nonzero RSS"
        );
        let text = snap.to_prometheus_text();
        assert!(text.contains("algod_rust_runtime_resident_memory_bytes"));
    }

    #[test]
    fn netdev_snapshot_capture_produces_well_formed_text() {
        let snap = NetDevMetricsSnapshot::capture();
        // Interface presence/count is host-dependent (CI runners, sandboxes,
        // etc. may report zero interfaces), so this only checks the
        // exposition format stays well-formed either way.
        let text = snap.to_prometheus_text();
        assert!(text.starts_with("# HELP algod_rust_netdev_received_bytes"));
        for iface in &snap.interfaces {
            assert!(text.contains(&format!("iface=\"{}\"", iface.name)));
        }
    }
}
