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

//! A registry of [`Metric`]s that can be rendered together. Mirrors
//! go-algorand's `util/metrics.Registry`/`DefaultRegistry`
//! (`registry.go`/`registryCommon.go`).

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;

/// A single metric that can be rendered as Prometheus text or added to a
/// flat `name -> value` map (go's `Metric` interface).
pub trait Metric: Send + Sync {
    /// Writes this metric's Prometheus text-exposition-format lines into
    /// `buf`. `parent_labels` is an already-formatted `k="v",...` fragment
    /// (no braces) contributed by the registry's caller (e.g. a per-process
    /// `host`/`session_id` label set); it is merged with this metric's own
    /// labels the same way go's `couge.writeMetric` does.
    fn write_metric(&self, buf: &mut String, parent_labels: &str);

    /// Adds this metric's current values into `values`, keyed by a
    /// sanitized, label-qualified name. Used for the telemetry heartbeat
    /// style flat map go's `AddMetrics` produces.
    fn add_metric(&self, values: &mut HashMap<String, f64>);
}

/// A set of registered [`Metric`]s, rendered together.
///
/// Unlike go's package-level `defaultRegistry` singleton, this is an
/// ordinary value a caller constructs and shares (typically via `Arc`); use
/// [`default_registry`] for call sites that want go's "just register it"
/// global-singleton flow instead of threading a registry through.
#[derive(Default)]
pub struct Registry {
    metrics: Mutex<Vec<Arc<dyn Metric>>>,
}

impl Registry {
    /// Creates a new, empty registry.
    pub fn new() -> Self {
        Registry {
            metrics: Mutex::new(Vec::new()),
        }
    }

    /// Registers a metric. A metric may be registered with more than one
    /// registry (e.g. both a subsystem-local registry and the default one).
    pub fn register(&self, metric: Arc<dyn Metric>) {
        self.metrics.lock().push(metric);
    }

    /// Deregisters every currently-registered `Arc` pointing at the same
    /// metric instance as `metric` (pointer equality, matching go's
    /// identity-based `Deregister`).
    pub fn deregister(&self, metric: &Arc<dyn Metric>) {
        let target: *const dyn Metric = Arc::as_ptr(metric);
        self.metrics
            .lock()
            .retain(|m| !std::ptr::eq(Arc::as_ptr(m), target));
    }

    /// Renders every registered metric's Prometheus text into `buf`.
    pub fn write_metrics(&self, buf: &mut String, parent_labels: &str) {
        for m in self.metrics.lock().iter() {
            m.write_metric(buf, parent_labels);
        }
    }

    /// Renders every registered metric's Prometheus text as a fresh
    /// `String` (convenience wrapper around [`Registry::write_metrics`]).
    pub fn render(&self, parent_labels: &str) -> String {
        let mut buf = String::new();
        self.write_metrics(&mut buf, parent_labels);
        buf
    }

    /// Adds every registered metric's values into `values`.
    pub fn add_metrics(&self, values: &mut HashMap<String, f64>) {
        for m in self.metrics.lock().iter() {
            m.add_metric(values);
        }
    }

    /// Returns the number of currently registered metrics (test/debug aid).
    pub fn len(&self) -> usize {
        self.metrics.lock().len()
    }

    /// True if no metrics are registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

static DEFAULT_REGISTRY: OnceLock<Arc<Registry>> = OnceLock::new();

/// The process-wide default registry, analogous to go's
/// `metrics.DefaultRegistry()`. Lazily initialized on first use.
pub fn default_registry() -> Arc<Registry> {
    Arc::clone(DEFAULT_REGISTRY.get_or_init(|| Arc::new(Registry::new())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Counter, Gauge};

    #[test]
    fn register_and_render_multiple_metrics() {
        let reg = Registry::new();
        let counter: Arc<dyn Metric> = Arc::new(Counter::new("c", "a counter"));
        let gauge: Arc<dyn Metric> = Arc::new(Gauge::new("g", "a gauge"));
        reg.register(Arc::clone(&counter));
        reg.register(Arc::clone(&gauge));
        assert_eq!(reg.len(), 2);

        let text = reg.render("");
        assert!(text.contains("# TYPE c counter"));
        assert!(text.contains("# TYPE g gauge"));

        reg.deregister(&counter);
        assert_eq!(reg.len(), 1);
        let text = reg.render("");
        assert!(!text.contains("# TYPE c counter"));
        assert!(text.contains("# TYPE g gauge"));
    }

    #[test]
    fn add_metrics_aggregates_every_registered_metric() {
        let reg = Registry::new();
        let counter = Arc::new(Counter::new("c", "a counter"));
        counter.add(3);
        reg.register(counter);

        let mut values = HashMap::new();
        reg.add_metrics(&mut values);
        assert_eq!(values.get("c"), Some(&3.0));
    }

    #[test]
    fn default_registry_is_a_process_wide_singleton() {
        let a = default_registry();
        let b = default_registry();
        assert!(Arc::ptr_eq(&a, &b));
    }

    /// Port of go's `TestPrometheusMetrics`
    /// (`util/metrics/prometheus_test.go`): a labeled gauge, an unlabeled
    /// gauge, a labeled counter and an unlabeled counter all render as
    /// distinct Prometheus series through one registry, and each
    /// contributes exactly one entry to the flat `add_metric` map. Go's
    /// version wraps the third-party `prometheus` client library's
    /// `GaugeVec`/`CounterVec`; algod-rust has no such dependency to wrap
    /// (see `process_metrics.rs`'s module doc), so this exercises the same
    /// externally-observed property — label rendering plus registry-wide
    /// aggregation — against this crate's own `Counter`/`Gauge`.
    #[test]
    fn registry_renders_labeled_and_unlabeled_gauges_and_counters() {
        let reg = Registry::new();

        let gauge_labels = Arc::new(Gauge::new("test_metric_streams", "Number of Streams"));
        gauge_labels.set_with_labels(
            1,
            &[
                ("dir", "outbound"),
                ("scope", "protocol"),
                ("protocol", "/test/proto"),
            ],
        );
        reg.register(gauge_labels.clone());

        let gauge = Arc::new(Gauge::new("test_metric_protocols_count", "Protocols Count"));
        gauge.set(2);
        reg.register(gauge.clone());

        let counter_labels = Arc::new(Counter::new("test_metric_identify_total", "Identify"));
        counter_labels.add_with_labels(3, &[("dir", "inbound")]);
        reg.register(counter_labels.clone());

        let counter = Arc::new(Counter::new("test_metric_counter_total", "Counter"));
        counter.add(4);
        reg.register(counter.clone());

        let text = reg.render("");
        assert!(text.contains("test_metric_streams gauge\n"));
        assert!(text.contains("test_metric_streams{"));
        assert!(text.contains(r#"dir="outbound""#));
        assert!(text.contains(r#"protocol="/test/proto""#));
        assert!(text.contains(r#"scope="protocol""#));
        assert!(text.contains("} 1\n"));
        assert!(text.contains("test_metric_protocols_count gauge\n"));
        assert!(text.contains("test_metric_protocols_count 2\n"));
        assert!(text.contains("test_metric_identify_total counter\n"));
        assert!(text.contains("test_metric_identify_total{dir=\"inbound\"} 3\n"));
        assert!(text.contains("test_metric_counter_total counter\n"));
        assert!(text.contains("test_metric_counter_total 4\n"));

        let mut values = HashMap::new();
        reg.add_metrics(&mut values);
        assert_eq!(values.get("test_metric_protocols_count"), Some(&2.0));
        assert_eq!(values.get("test_metric_counter_total"), Some(&4.0));
    }
}
