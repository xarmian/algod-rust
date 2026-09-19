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

//! A generic, registry-backed gauge. Mirrors go-algorand's
//! `util/metrics.Gauge` (`gauge.go`).

use std::collections::HashMap;

use crate::couge::Couge;
use crate::registry::Metric;

/// A point-in-time value, optionally split by label set.
///
/// Like [`crate::Counter`], setting with no labels (`&[]`) is lock-free.
pub struct Gauge {
    couge: Couge,
}

impl Gauge {
    /// Creates a new, unregistered gauge with the given name and
    /// description.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Gauge {
            couge: Couge::new(name, description),
        }
    }

    /// Sets the gauge's unlabeled value to `x`.
    pub fn set(&self, x: u64) {
        self.couge.fast_set(x);
    }

    /// Sets the gauge's value for the given label set to `x`. An empty
    /// label slice is equivalent to [`Gauge::set`].
    pub fn set_with_labels(&self, x: u64, labels: &[(&str, &str)]) {
        if labels.is_empty() {
            self.couge.fast_set(x);
        } else {
            self.couge.set_labels(x, labels);
        }
    }

    /// Returns the value recorded for the given label set, or 0 if never
    /// set with those exact labels.
    pub fn value_for_labels(&self, labels: &[(&str, &str)]) -> u64 {
        self.couge.value_for_labels(labels)
    }
}

impl Metric for Gauge {
    fn write_metric(&self, buf: &mut String, parent_labels: &str) {
        self.couge.write_metric(buf, "gauge", parent_labels);
    }

    fn add_metric(&self, values: &mut HashMap<String, f64>) {
        self.couge.add_metric(values);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    /// Port of go's `TestGaugeLabels`.
    #[test]
    fn gauge_labels_render_independently() {
        let m = Gauge::new("testname", "testhelp");
        m.set_with_labels(1, &[("a", "b")]);
        m.set_with_labels(10, &[("c", "d")]);
        m.set_with_labels(2, &[("a", "b")]);
        m.set(5);

        assert_eq!(m.value_for_labels(&[("a", "b")]), 2);
        assert_eq!(m.value_for_labels(&[("c", "d")]), 10);

        let mut buf = String::new();
        m.write_metric(&mut buf, "");
        assert!(buf.contains(r#"testname{a="b"} 2"#));
        assert!(buf.contains(r#"testname{c="d"} 10"#));
        assert!(buf.contains("testname 5"));
        assert_eq!(buf.matches("# HELP testname testhelp").count(), 1);
        assert_eq!(buf.matches("# TYPE testname gauge").count(), 1);

        let mut buf = String::new();
        m.write_metric(&mut buf, r#"p1=v1,p2="v2""#);
        assert!(buf.contains(r#"testname{p1=v1,p2="v2",a="b"} 2"#));
        assert!(buf.contains(r#"testname{p1=v1,p2="v2",c="d"} 10"#));

        let m2 = Gauge::new("testname2", "testhelp2");
        m2.set(101);
        let mut buf = String::new();
        m2.write_metric(&mut buf, "");
        assert!(buf.contains("testname2 101"));
    }

    /// Port of go's `TestMetricGauge`: concurrent (interleaved) `Set` calls
    /// on distinct gauges each converge on the last-written value.
    #[test]
    fn concurrent_sets_on_distinct_gauges_converge_on_last_value() {
        let gauges: Vec<Arc<Gauge>> = (0..3)
            .map(|i| Arc::new(Gauge::new(format!("gauge_{i}"), "concurrency test")))
            .collect();

        let mut handles = Vec::new();
        for i in 0..9u64 {
            let gauge = Arc::clone(&gauges[(i as usize) % 3]);
            handles.push(thread::spawn(move || {
                gauge.set(i * 100 + i);
            }));
            // Join immediately so writes to the same gauge are ordered —
            // this test pins the value semantics, not raw concurrency
            // (that's covered by the counter test's concurrent increments).
            handles.pop().unwrap().join().unwrap();
        }

        // The unlabeled fast path is exposed through rendering (Prometheus
        // text / `add_metric`), not `value_for_labels` — mirrors go, where
        // `GetUint64ValueForLabels(nil)` reads the dummy no-labels
        // `cougeValues` entry rather than the fast-path `intValue`.
        let mut values = std::collections::HashMap::new();
        for (i, gauge) in gauges.iter().enumerate() {
            gauge.add_metric(&mut values);
            let expected = [606.0, 707.0, 808.0][i];
            assert_eq!(values.get(&format!("gauge_{i}")), Some(&expected));
        }
    }
}
