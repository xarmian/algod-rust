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

//! Shared logic behind [`crate::Counter`] and [`crate::Gauge`], mirroring
//! go-algorand's `util/metrics/couge.go` ("common code for COUnters and
//! gaUGEs").

use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::sanitize_telemetry_name;

/// A single labeled value plus its pre-formatted `k="v",...` fragment.
struct LabeledValue {
    value: u64,
    labels: Vec<(String, String)>,
    formatted_labels: String,
}

fn format_labels(labels: &[(String, String)]) -> String {
    labels
        .iter()
        .map(|(k, v)| format!("{k}=\"{v}\""))
        .collect::<Vec<_>>()
        .join(",")
}

/// Sorts and dedupes a caller-provided label list into a canonical form so
/// lookups are independent of the order labels were passed in.
fn canonicalize(labels: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = labels
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

struct Inner {
    values: Vec<LabeledValue>,
}

/// Shared COUnter/gaUGE state: a lock-free fast path for the common
/// "no labels" case, plus a mutex-guarded set of labeled values.
pub(crate) struct Couge {
    pub(crate) name: String,
    pub(crate) description: String,
    fast_value: AtomicU64,
    inner: Mutex<Inner>,
}

impl Couge {
    pub(crate) fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Couge {
            name: name.into(),
            description: description.into(),
            fast_value: AtomicU64::new(0),
            inner: Mutex::new(Inner { values: Vec::new() }),
        }
    }

    /// Fast, lock-free add for the no-labels case (go's `fastAddUint64`).
    pub(crate) fn fast_add(&self, x: u64) {
        let prev = self.fast_value.fetch_add(x, Ordering::SeqCst);
        if prev == 0 && x != 0 {
            // First non-zero add: create the dummy no-labels entry so
            // `write_metric`/`add_metric` have something to iterate over.
            self.add_labels(0, &[]);
        }
    }

    /// Fast, lock-free set for the no-labels case (go's `Gauge.Set`).
    pub(crate) fn fast_set(&self, x: u64) {
        let prev = self.fast_value.swap(x, Ordering::SeqCst);
        if prev == 0 {
            self.set_labels(0, &[]);
        }
    }

    pub(crate) fn fast_value(&self) -> u64 {
        self.fast_value.load(Ordering::SeqCst)
    }

    fn find(&self, inner: &Inner, key: &[(String, String)]) -> Option<usize> {
        inner.values.iter().position(|v| v.labels == key)
    }

    /// Increments the labeled entry by `x` (creating it if absent).
    pub(crate) fn add_labels(&self, x: u64, labels: &[(&str, &str)]) {
        let key = canonicalize(labels);
        let mut inner = self.inner.lock();
        if let Some(idx) = self.find(&inner, &key) {
            inner.values[idx].value += x;
        } else {
            let formatted_labels = format_labels(&key);
            inner.values.push(LabeledValue {
                value: x,
                labels: key,
                formatted_labels,
            });
        }
    }

    /// Sets the labeled entry to `x` (creating it if absent).
    pub(crate) fn set_labels(&self, x: u64, labels: &[(&str, &str)]) {
        let key = canonicalize(labels);
        let mut inner = self.inner.lock();
        if let Some(idx) = self.find(&inner, &key) {
            inner.values[idx].value = x;
        } else {
            let formatted_labels = format_labels(&key);
            inner.values.push(LabeledValue {
                value: x,
                labels: key,
                formatted_labels,
            });
        }
    }

    pub(crate) fn value_for_labels(&self, labels: &[(&str, &str)]) -> u64 {
        let key = canonicalize(labels);
        let inner = self.inner.lock();
        self.find(&inner, &key)
            .map(|idx| inner.values[idx].value)
            .unwrap_or(0)
    }

    /// Renders this metric as Prometheus text exposition, mirroring go's
    /// `couge.writeMetric`.
    pub(crate) fn write_metric(&self, buf: &mut String, metric_type: &str, parent_labels: &str) {
        buf.push_str("# HELP ");
        buf.push_str(&self.name);
        buf.push(' ');
        buf.push_str(&self.description);
        buf.push_str("\n# TYPE ");
        buf.push_str(&self.name);
        buf.push(' ');
        buf.push_str(metric_type);
        buf.push('\n');

        let inner = self.inner.lock();
        if inner.values.is_empty() {
            // If the metric was never touched, still report 0 using the
            // parent labels only (no per-value tags exist yet).
            buf.push_str(&self.name);
            if !parent_labels.is_empty() {
                buf.push('{');
                buf.push_str(parent_labels);
                buf.push('}');
            }
            buf.push(' ');
            buf.push_str(&self.fast_value().to_string());
            buf.push('\n');
            return;
        }

        for v in &inner.values {
            buf.push_str(&self.name);
            if !parent_labels.is_empty() || !v.formatted_labels.is_empty() {
                buf.push('{');
                if !parent_labels.is_empty() {
                    buf.push_str(parent_labels);
                    if !v.formatted_labels.is_empty() {
                        buf.push(',');
                    }
                }
                buf.push_str(&v.formatted_labels);
                buf.push('}');
            }
            let mut value = v.value;
            if v.labels.is_empty() {
                value += self.fast_value();
            }
            buf.push(' ');
            buf.push_str(&value.to_string());
            buf.push('\n');
        }
    }

    /// Adds this metric's values into `values`, mirroring go's
    /// `couge.addMetric`.
    pub(crate) fn add_metric(&self, values: &mut std::collections::HashMap<String, f64>) {
        let inner = self.inner.lock();
        for v in &inner.values {
            let mut sum = v.value;
            if v.labels.is_empty() {
                sum += self.fast_value();
            }
            let key = if v.formatted_labels.is_empty() {
                self.name.clone()
            } else {
                format!("{}:{}", self.name, v.formatted_labels)
            };
            values.insert(sanitize_telemetry_name(&key), sum as f64);
        }
    }
}
