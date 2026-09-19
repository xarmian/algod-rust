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

//! A small, reusable, registry-backed metrics primitive family, mirroring
//! go-algorand's `util/metrics` package (`Counter`, `Gauge`, `TagCounter`,
//! `Registry`, `DefaultRegistry`) — see `counter.go`, `gauge.go`,
//! `tagcounter.go`, `registry.go`, and their shared `couge.go` helper.
//!
//! Before this crate existed, every subsystem in algod-rust hand-rolled its
//! own concrete counter/gauge type (`algo_agreement::metrics`,
//! `algo_pool::metrics`, `algo_network`'s tag counters,
//! `algo_rest_api::process_metrics`). Those call sites are not migrated
//! wholesale here (see `docs/phase17/parity_util.md`'s notes on the closed
//! rows for why each one still exists as a concrete type), but this crate
//! gives new call sites — and, when useful, a future migration — a real
//! generic primitive instead of another bespoke counter.
//!
//! # Design notes vs. go-algorand
//!
//! * Go's `couge` (shared COUnter/gaUGE logic) uses a lock-free `AtomicUint64`
//!   fast path for the "no labels" case plus a mutex-guarded slice for
//!   labeled values, with a bespoke power-of-two label-set index. This crate
//!   keeps the same two-tier fast/slow-path shape (see [`Couge`] in
//!   `couge.rs`) because it is what several of the ported tests
//!   (`TestMetricCounterFastInts`, the "0 counters are still logged" case in
//!   `TestCounterWriteMetric`) actually pin, but replaces the label index
//!   with a plain sorted `Vec<(String, String)>` key — simpler, and
//!   order-independent lookups don't need go's bitmask trick in Rust.
//! * `Registry` here is an ordinary `struct` a caller constructs and shares
//!   via `Arc`, rather than a literal port of go's package-level
//!   `var defaultRegistry *Registry` + `init()`. [`default_registry()`]
//!   still provides the equivalent process-wide singleton for callers that
//!   want go's "just register it, nobody threads the registry through" flow.
//! * `TagCounter` keeps go's bounded/filtered tag-cardinality behavior
//!   (`allowed_tags` + optional `unknown_tag` bucket) so a caller can accept
//!   externally influenced tag values (e.g. a wire protocol tag) without an
//!   unbounded map.

mod couge;

pub mod counter;
pub mod gauge;
pub mod histogram;
pub mod registry;
pub mod tag_counter;

pub use counter::Counter;
pub use gauge::Gauge;
pub use histogram::Histogram;
pub use registry::{default_registry, Metric, Registry};
pub use tag_counter::TagCounter;

/// Ensures a metric name reported via [`Metric::add_metric`] doesn't contain
/// any non-alphanumeric characters (apart from `-` or `_`) and doesn't start
/// with a digit or a hyphen. Mirrors go's `sanitizeTelemetryName`
/// (`util/metrics/registryCommon.go`).
pub(crate) fn sanitize_telemetry_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for (i, c) in name.chars().enumerate() {
        let ok = if i == 0 {
            c.is_ascii_alphabetic() || c == '_'
        } else {
            c.is_ascii_alphanumeric() || c == '_' || c == '-'
        };
        out.push(if ok { c } else { '_' });
    }
    out
}

#[cfg(test)]
mod sanitize_tests {
    use super::sanitize_telemetry_name;

    #[test]
    fn sanitize_telemetry_name_replaces_invalid_leading_and_interior_characters() {
        assert_eq!(sanitize_telemetry_name("abc"), "abc");
        assert_eq!(sanitize_telemetry_name("1abc"), "_abc");
        assert_eq!(sanitize_telemetry_name("-abc"), "_abc");
        assert_eq!(sanitize_telemetry_name("a.b:c"), "a_b_c");
        assert_eq!(sanitize_telemetry_name("a-b_c"), "a-b_c");
    }
}
