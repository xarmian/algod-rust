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

//! A generic, registry-backed counter. Mirrors go-algorand's
//! `util/metrics.Counter` (`counter.go`).

use std::collections::HashMap;

use crate::couge::Couge;
use crate::registry::Metric;

/// A monotonically-increasing counter, optionally split by label set.
///
/// Incrementing with no labels (`&[]`) is lock-free; incrementing with
/// labels takes a short-lived mutex to find or create the labeled entry
/// (mirrors go's `Counter.Inc`/`AddUint64` fast/slow-path split).
pub struct Counter {
    couge: Couge,
}

impl Counter {
    /// Creates a new, unregistered counter with the given name and
    /// description. Register it with a [`crate::Registry`] (or
    /// [`crate::default_registry`]) if it should be discoverable/renderable
    /// as a group.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Counter {
            couge: Couge::new(name, description),
        }
    }

    /// Increments the counter by 1.
    pub fn inc(&self) {
        self.couge.fast_add(1);
    }

    /// Increments the counter for the given label set by 1.
    pub fn inc_with_labels(&self, labels: &[(&str, &str)]) {
        self.add_with_labels(1, labels);
    }

    /// Increments the counter by `x`.
    pub fn add(&self, x: u64) {
        self.couge.fast_add(x);
    }

    /// Increments the counter for the given label set by `x`. An empty
    /// label slice is equivalent to [`Counter::add`] (both use the
    /// lock-free fast path, matching go's `len(labels) == 0` check).
    pub fn add_with_labels(&self, x: u64, labels: &[(&str, &str)]) {
        if labels.is_empty() {
            self.couge.fast_add(x);
        } else {
            self.couge.add_labels(x, labels);
        }
    }

    /// Returns the total value across the no-labels fast path.
    pub fn value(&self) -> u64 {
        self.couge.fast_value()
    }

    /// Returns the value recorded for the given label set, or 0 if never
    /// incremented with those exact labels.
    pub fn value_for_labels(&self, labels: &[(&str, &str)]) -> u64 {
        self.couge.value_for_labels(labels)
    }
}

impl Metric for Counter {
    fn write_metric(&self, buf: &mut String, parent_labels: &str) {
        self.couge.write_metric(buf, "counter", parent_labels);
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

    /// Port of go's `TestCounterWriteMetric`
    /// (`util/metrics/counter_test.go`): a freshly created counter still
    /// reports a `0` line (using the parent labels), and after an add the
    /// value is reflected.
    #[test]
    fn write_metric_reports_zero_before_any_increment() {
        let c = Counter::new("testname", "testhelp");
        let mut buf = String::new();
        c.write_metric(&mut buf, r#"host="myhost""#);
        assert_eq!(
            buf,
            "# HELP testname testhelp\n# TYPE testname counter\ntestname{host=\"myhost\"} 0\n"
        );

        c.add(2);
        let mut buf = String::new();
        c.write_metric(&mut buf, r#"host="myhost""#);
        assert_eq!(
            buf,
            "# HELP testname testhelp\n# TYPE testname counter\ntestname{host=\"myhost\"} 2\n"
        );
    }

    /// Port of go's `TestGetValue`.
    #[test]
    fn get_value_tracks_unlabeled_increments() {
        let c = Counter::new("testname", "testhelp");
        assert_eq!(c.value(), 0);
        c.inc();
        assert_eq!(c.value(), 1);
        c.inc();
        assert_eq!(c.value(), 2);
    }

    /// Port of go's `TestGetValueForLabels`.
    #[test]
    fn value_for_labels_is_independent_per_label_set() {
        let c = Counter::new("testname", "testhelp");
        let labels = [("a", "b")];
        assert_eq!(c.value_for_labels(&labels), 0);
        c.inc_with_labels(&labels);
        assert_eq!(c.value_for_labels(&labels), 1);
        c.inc_with_labels(&labels);
        assert_eq!(c.value_for_labels(&labels), 2);
        // Confirm the unlabeled fast path doesn't leak into labeled values.
        c.inc();
        assert_eq!(c.value_for_labels(&labels), 2);
        let labels2 = [("a", "c")];
        c.inc_with_labels(&labels2);
        assert_eq!(c.value_for_labels(&labels2), 1);
    }

    /// Port of go's `TestCounterLabels`.
    #[test]
    fn counter_labels_render_independently() {
        let m = Counter::new("testname", "testhelp");
        m.add_with_labels(1, &[("a", "b")]);
        m.add_with_labels(10, &[("c", "d")]);
        m.add_with_labels(1, &[("a", "b")]);
        m.add(5);

        assert_eq!(m.value_for_labels(&[("a", "b")]), 2);
        assert_eq!(m.value_for_labels(&[("c", "d")]), 10);

        let mut buf = String::new();
        m.write_metric(&mut buf, "");
        assert!(buf.contains(r#"testname{a="b"} 2"#));
        assert!(buf.contains(r#"testname{c="d"} 10"#));
        assert!(buf.contains("testname 5"));
        assert_eq!(buf.matches("# HELP testname testhelp").count(), 1);
        assert_eq!(buf.matches("# TYPE testname counter").count(), 1);

        let mut buf = String::new();
        m.write_metric(&mut buf, r#"p1=v1,p2="v2""#);
        assert!(buf.contains(r#"testname{p1=v1,p2="v2",a="b"} 2"#));
        assert!(buf.contains(r#"testname{p1=v1,p2="v2",c="d"} 10"#));

        let m2 = Counter::new("testname2", "testhelp2");
        m2.add(101);
        let mut buf = String::new();
        m2.write_metric(&mut buf, "");
        assert!(buf.contains("testname2 101"));
    }

    /// Port of go's `TestMetricCounterFastInts`: increments with no labels
    /// stay on the lock-free fast path and accumulate correctly.
    #[test]
    fn fast_path_increments_accumulate_without_labels() {
        let c = Counter::new("metric_test_name1", "fast path counter");
        for _ in 0..20 {
            c.inc();
        }
        c.add(2);
        assert_eq!(c.value(), 22);

        let mut values = HashMap::new();
        c.add_metric(&mut values);
        assert_eq!(values.len(), 1);
        assert_eq!(values.get("metric_test_name1"), Some(&22.0));
    }

    /// Port of go's `TestMetricCounter`: concurrent increments across a
    /// fixed label set are all accounted for.
    #[test]
    fn concurrent_labeled_increments_are_safe_across_threads() {
        let counter = Arc::new(Counter::new("metric_test_name1", "concurrency test"));
        let hosts = ["host0", "host1", "host2", "host3", "host4"];
        let mut handles = Vec::new();
        for i in 0..20 {
            let counter = Arc::clone(&counter);
            let host = hosts[i % 5];
            handles.push(thread::spawn(move || {
                counter.inc_with_labels(&[("pid", "123"), ("data_host", host)]);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        for host in hosts {
            assert_eq!(
                counter.value_for_labels(&[("pid", "123"), ("data_host", host)]),
                4,
                "host {host} should have been incremented 4 times"
            );
        }

        let mut buf = String::new();
        counter.write_metric(&mut buf, "");
        // 5 distinct label sets -> 5 rendered lines (plus HELP/TYPE header).
        assert_eq!(buf.matches("metric_test_name1{").count(), 5);
    }
}
