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

//! A set of counters keyed by an externally-influenced tag, with an
//! optional bounded/filtered tag cardinality. Mirrors go-algorand's
//! `util/metrics.TagCounter` (`tagcounter.go`).

use std::collections::{HashMap, HashSet};

use parking_lot::Mutex;

use crate::registry::Metric;
use crate::sanitize_telemetry_name;

/// A family of counters, one per distinct tag value seen so far.
///
/// `name` may contain the literal substring `"{TAG}"`, which is substituted
/// with the tag for each rendered series name; otherwise `"_{tag}"` is
/// appended (matching go's `NewTagCounter` doc comment).
///
/// When `allowed_tags` is set, any `add()` call for a tag outside that set
/// is redirected to `unknown_tag` (if any) or dropped — this is what keeps
/// an externally-influenced tag (e.g. a wire-protocol message tag) from
/// growing this counter's memory unboundedly.
pub struct TagCounter {
    name: String,
    description: String,
    allowed_tags: Option<HashSet<String>>,
    unknown_tag: Option<String>,
    tags: Mutex<HashMap<String, u64>>,
}

impl TagCounter {
    /// Creates an unfiltered tag counter, optionally pre-declaring a set of
    /// tags at zero so they're discoverable before their first increment
    /// (mirrors go's `NewTagCounter(rootName, desc, declaredTags...)`).
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        declared_tags: &[&str],
    ) -> Self {
        let tc = TagCounter {
            name: name.into(),
            description: description.into(),
            allowed_tags: None,
            unknown_tag: None,
            tags: Mutex::new(HashMap::new()),
        };
        for tag in declared_tags {
            tc.add(tag, 0);
        }
        tc
    }

    /// Creates a tag counter that only accepts tags in `allowed_tags`;
    /// anything else is counted under `unknown_tag` (if `Some`) or dropped
    /// (mirrors go's `NewTagCounterFiltered`).
    pub fn filtered(
        name: impl Into<String>,
        description: impl Into<String>,
        allowed_tags: &[&str],
        unknown_tag: Option<&str>,
    ) -> Self {
        TagCounter {
            name: name.into(),
            description: description.into(),
            allowed_tags: Some(allowed_tags.iter().map(|t| t.to_string()).collect()),
            unknown_tag: unknown_tag.map(|t| t.to_string()),
            tags: Mutex::new(HashMap::new()),
        }
    }

    /// `counters[tag] += val`. If `tag` isn't in `allowed_tags` (when set),
    /// it's redirected to `unknown_tag` or silently dropped.
    pub fn add(&self, tag: &str, val: u64) {
        let effective_tag: &str = match &self.allowed_tags {
            Some(allowed) if !allowed.contains(tag) => match &self.unknown_tag {
                Some(unk) => unk.as_str(),
                None => return,
            },
            _ => tag,
        };
        *self
            .tags
            .lock()
            .entry(effective_tag.to_string())
            .or_insert(0) += val;
    }

    /// Returns the current count for `tag` (post-filtering — pass
    /// `unknown_tag` to read the filtered bucket), or 0 if untouched.
    pub fn value(&self, tag: &str) -> u64 {
        self.tags.lock().get(tag).copied().unwrap_or(0)
    }

    fn series_name(&self, tag: &str) -> String {
        if self.name.contains("{TAG}") {
            self.name.replace("{TAG}", tag)
        } else {
            format!("{}_{}", self.name, tag)
        }
    }
}

impl Metric for TagCounter {
    fn write_metric(&self, buf: &mut String, parent_labels: &str) {
        let tags = self.tags.lock();
        for (tag, count) in tags.iter() {
            let name = self.series_name(tag);
            buf.push_str("# HELP ");
            buf.push_str(&name);
            buf.push(' ');
            buf.push_str(&self.description.replace("{TAG}", tag));
            buf.push_str("\n# TYPE ");
            buf.push_str(&name);
            buf.push_str(" counter\n");
            buf.push_str(&name);
            if !parent_labels.is_empty() {
                buf.push('{');
                buf.push_str(parent_labels);
                buf.push('}');
            }
            buf.push(' ');
            buf.push_str(&count.to_string());
            buf.push('\n');
        }
    }

    fn add_metric(&self, values: &mut HashMap<String, f64>) {
        let tags = self.tags.lock();
        for (tag, count) in tags.iter() {
            let name = self.series_name(tag);
            values.insert(sanitize_telemetry_name(&name), *count as f64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    /// Port of go's `TestTagCounter`: concurrent adds across many distinct
    /// tags are all accounted for, and an empty counter renders nothing.
    #[test]
    fn concurrent_adds_across_many_tags_are_accounted_for() {
        let tags: Vec<String> = (0..17u8)
            .map(|i| format!("A{}", (b'A' + i) as char))
            .collect();
        let counts: Vec<u64> = (0..17u64).map(|i| 10 * (i + 1)).collect();

        let tc = Arc::new(TagCounter::new("tc", "wat", &[]));

        let mut buf = String::new();
        tc.write_metric(&mut buf, "");
        assert_eq!(buf, "");
        let mut result = HashMap::new();
        tc.add_metric(&mut result);
        assert!(result.is_empty());

        let mut handles = Vec::new();
        for (tag, &count) in tags.iter().zip(counts.iter()) {
            let tc = Arc::clone(&tc);
            let tag = tag.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..count {
                    tc.add(&tag, 1);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        for (tag, &count) in tags.iter().zip(counts.iter()) {
            assert_eq!(tc.value(tag), count, "tag {tag}");
        }
    }

    /// Port of go's `TestTagCounterFilter`: tags outside `allowed_tags`
    /// bucket into `unknown_tag` instead of growing the map unboundedly.
    #[test]
    fn filtered_tags_outside_allowlist_bucket_into_unknown() {
        let tags: Vec<String> = (0..17u8)
            .map(|i| format!("A{}", (b'A' + i) as char))
            .collect();
        let counts: Vec<u64> = (0..17u64).map(|i| 10 * (i + 1)).collect();
        let good_tags: Vec<&str> = tags[..10].iter().map(|s| s.as_str()).collect();
        let bad_count: u64 = counts[10..].iter().sum();

        let tc = Arc::new(TagCounter::filtered("tc", "wat", &good_tags, Some("UNK")));

        let mut handles = Vec::new();
        for (tag, &count) in tags.iter().zip(counts.iter()) {
            let tc = Arc::clone(&tc);
            let tag = tag.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..count {
                    tc.add(&tag, 1);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        for (tag, &count) in tags[..10].iter().zip(counts[..10].iter()) {
            assert_eq!(tc.value(tag), count, "good tag {tag}");
        }
        for tag in &tags[10..] {
            assert_eq!(
                tc.value(tag),
                0,
                "bad tag {tag} must not be counted directly"
            );
        }
        assert_eq!(tc.value("UNK"), bad_count);
    }

    /// Port of go's `TestTagCounterWriteMetric`: `{TAG}` substitution in
    /// both the name and description, and pre-declared tags render at
    /// zero.
    #[test]
    fn write_metric_substitutes_tag_into_name_and_description() {
        let tc = TagCounter::new("count_msgs_{TAG}", "number of {TAG} messages", &[]);
        tc.add("TX", 100);
        tc.add("TX", 1);
        tc.add("RX", 0);

        let mut buf = String::new();
        tc.write_metric(&mut buf, r#"host="myhost""#);
        assert!(buf.contains("# HELP count_msgs_TX number of TX messages\n"));
        assert!(buf.contains("# TYPE count_msgs_TX counter\n"));
        assert!(buf.contains("count_msgs_TX{host=\"myhost\"} 101\n"));
        assert!(buf.contains("# HELP count_msgs_RX number of RX messages\n"));
        assert!(buf.contains("count_msgs_RX{host=\"myhost\"} 0\n"));

        let tc2 = TagCounter::new("declared", "number of {TAG}s", &["A", "B"]);
        let mut buf = String::new();
        tc2.write_metric(&mut buf, r#"host="h""#);
        assert!(buf.contains("declared_A{host=\"h\"} 0\n"));
        assert!(buf.contains("declared_B{host=\"h\"} 0\n"));
    }
}
