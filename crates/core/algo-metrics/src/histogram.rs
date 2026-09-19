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

//! A cumulative-bucket histogram, rendered as the standard Prometheus
//! `<name>_bucket`/`<name>_count`/`<name>_sum` triple.
//!
//! go-algorand has no generic `Histogram` metric type of its own — its
//! histogram coverage (`TestPrometheusHistogramMetrics`,
//! `util/metrics/prometheus_test.go`) comes entirely from wrapping the
//! third-party `prometheus.HistogramVec` through `prometheus.go`'s
//! `collectPrometheusMetrics`/`WriteMetric` adapter, since algod-rust has no
//! `prometheus` crate dependency to wrap (see `process_metrics.rs`'s module
//! doc). This type provides the same externally-observed shape — cumulative
//! `le="..."` buckets plus `_count`/`_sum` series, `_bucket`/`_count` typed
//! `counter` and `_sum` typed `gauge`, matching Prometheus's own histogram
//! convention — as a first-class primitive any subsystem can use directly.

use std::collections::HashMap;

use parking_lot::Mutex;

use crate::registry::Metric;
use crate::sanitize_telemetry_name;

struct Observations {
    /// Cumulative count per configured bucket boundary (ascending).
    bucket_counts: Vec<u64>,
    count: u64,
    sum: f64,
}

/// A histogram with a fixed, ascending set of bucket boundaries.
pub struct Histogram {
    name: String,
    description: String,
    buckets: Vec<f64>,
    series: Mutex<HashMap<Vec<(String, String)>, Observations>>,
}

fn canonicalize(labels: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = labels
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn format_labels(labels: &[(String, String)]) -> String {
    labels
        .iter()
        .map(|(k, v)| format!("{k}=\"{v}\""))
        .collect::<Vec<_>>()
        .join(",")
}

impl Histogram {
    /// Creates a histogram with the given ascending bucket boundaries
    /// (e.g. `&[1.0, 5.0, 10.0]`).
    pub fn new(name: impl Into<String>, description: impl Into<String>, buckets: &[f64]) -> Self {
        Histogram {
            name: name.into(),
            description: description.into(),
            buckets: buckets.to_vec(),
            series: Mutex::new(HashMap::new()),
        }
    }

    /// Records one observation of `value` for the given label set.
    pub fn observe(&self, value: f64, labels: &[(&str, &str)]) {
        let key = canonicalize(labels);
        let mut series = self.series.lock();
        let obs = series.entry(key).or_insert_with(|| Observations {
            bucket_counts: vec![0; self.buckets.len()],
            count: 0,
            sum: 0.0,
        });
        for (i, &boundary) in self.buckets.iter().enumerate() {
            if value <= boundary {
                obs.bucket_counts[i] += 1;
            }
        }
        obs.count += 1;
        obs.sum += value;
    }
}

impl Metric for Histogram {
    fn write_metric(&self, buf: &mut String, parent_labels: &str) {
        let series = self.series.lock();
        if series.is_empty() {
            return;
        }

        let bucket_name = format!("{}_bucket", self.name);
        let count_name = format!("{}_count", self.name);
        let sum_name = format!("{}_sum", self.name);

        let render_prefix = |buf: &mut String, labels: &str| {
            if !parent_labels.is_empty() || !labels.is_empty() {
                buf.push('{');
                if !parent_labels.is_empty() {
                    buf.push_str(parent_labels);
                    if !labels.is_empty() {
                        buf.push(',');
                    }
                }
                buf.push_str(labels);
                buf.push('}');
            }
        };

        for (key, obs) in series.iter() {
            let labels = format_labels(key);

            buf.push_str("# HELP ");
            buf.push_str(&bucket_name);
            buf.push(' ');
            buf.push_str(&self.description);
            buf.push_str("\n# TYPE ");
            buf.push_str(&bucket_name);
            buf.push_str(" counter\n");
            for (i, &boundary) in self.buckets.iter().enumerate() {
                buf.push_str(&bucket_name);
                let mut bucket_labels = labels.clone();
                if !bucket_labels.is_empty() {
                    bucket_labels.push(',');
                }
                bucket_labels.push_str(&format!(r#"le="{boundary}""#));
                render_prefix(buf, &bucket_labels);
                buf.push(' ');
                buf.push_str(&obs.bucket_counts[i].to_string());
                buf.push('\n');
            }
            buf.push_str(&bucket_name);
            let mut inf_labels = labels.clone();
            if !inf_labels.is_empty() {
                inf_labels.push(',');
            }
            inf_labels.push_str(r#"le="+Inf""#);
            render_prefix(buf, &inf_labels);
            buf.push(' ');
            buf.push_str(&obs.count.to_string());
            buf.push('\n');

            buf.push_str("# HELP ");
            buf.push_str(&count_name);
            buf.push(' ');
            buf.push_str(&self.description);
            buf.push_str("\n# TYPE ");
            buf.push_str(&count_name);
            buf.push_str(" counter\n");
            buf.push_str(&count_name);
            render_prefix(buf, &labels);
            buf.push(' ');
            buf.push_str(&obs.count.to_string());
            buf.push('\n');

            buf.push_str("# HELP ");
            buf.push_str(&sum_name);
            buf.push(' ');
            buf.push_str(&self.description);
            buf.push_str("\n# TYPE ");
            buf.push_str(&sum_name);
            buf.push_str(" gauge\n");
            buf.push_str(&sum_name);
            render_prefix(buf, &labels);
            buf.push(' ');
            buf.push_str(&obs.sum.to_string());
            buf.push('\n');
        }
    }

    fn add_metric(&self, values: &mut HashMap<String, f64>) {
        let series = self.series.lock();
        for (key, obs) in series.iter() {
            let labels = format_labels(key);
            let suffix = if labels.is_empty() {
                String::new()
            } else {
                format!(":{labels}")
            };
            values.insert(
                sanitize_telemetry_name(&format!("{}_count{suffix}", self.name)),
                obs.count as f64,
            );
            values.insert(
                sanitize_telemetry_name(&format!("{}_sum{suffix}", self.name)),
                obs.sum,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Port of go's `TestPrometheusHistogramMetrics`
    /// (`util/metrics/prometheus_test.go`): bucket/count/sum series render
    /// with the expected names, types, and cumulative bucket boundaries.
    #[test]
    fn histogram_renders_bucket_count_and_sum_series() {
        let hist = Histogram::new(
            "test_hist_metric_latency",
            "Latency histogram",
            &[1.0, 5.0, 10.0],
        );
        hist.observe(1.0, &[("dir", "inbound")]);
        hist.observe(7.0, &[("dir", "inbound")]);

        let mut buf = String::new();
        hist.write_metric(&mut buf, "");

        assert!(buf.contains("test_hist_metric_latency_bucket counter\n"));
        assert!(buf.contains(r#"dir="inbound""#));
        assert!(buf.contains(r#"le="1""#));
        assert!(buf.contains(r#"le="5""#));
        assert!(buf.contains(r#"le="10""#));
        assert!(buf.contains(r#"le="+Inf""#));

        assert!(buf.contains("test_hist_metric_latency_count counter\n"));
        assert!(buf.contains("test_hist_metric_latency_count{dir=\"inbound\"} 2\n"));

        assert!(buf.contains("test_hist_metric_latency_sum gauge\n"));
        assert!(buf.contains("test_hist_metric_latency_sum{dir=\"inbound\"} 8\n"));
    }

    #[test]
    fn empty_histogram_renders_nothing() {
        let hist = Histogram::new("h", "desc", &[1.0]);
        let mut buf = String::new();
        hist.write_metric(&mut buf, "");
        assert_eq!(buf, "");
    }
}
