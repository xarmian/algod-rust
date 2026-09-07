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

//! Transaction-pool re-evaluation counter (issue #1134).
//!
//! go-algorand's `data/pools/errors.go` defines
//! `txPoolReevalCounter = metrics.NewTagCounter("algod_tx_pool_reeval_{TAG}",
//! "Number of transaction groups removed from pool during re-evaluation due
//! to {TAG}", TxPoolErrTags...)`, incremented once per transaction group that
//! `TransactionPool.recomputeBlockEvaluator` fails to re-admit while
//! rebuilding the pending block evaluator after a new block commits
//! (`data/pools/transactionPool.go`: `txPoolReevalCounter.Add(ClassifyTxPoolError(err), 1)`).
//!
//! algod-rust's [`crate::pool::TransactionPool::recompute_block_evaluator`]
//! is the exact structural analogue (re-feeds surviving pending groups
//! through a freshly started evaluator, called from `on_new_block`), and
//! already classifies re-evaluation failures with
//! [`crate::error::classify_pool_error`] for the status cache. This module
//! adds the matching per-tag counter, keyed by the same
//! [`crate::error::PoolErrorTag`] set the metric's `{TAG}` placeholder
//! ranges over in go.
//!
//! Hand-rolled Prometheus text rendering, matching the convention already
//! established by `algo_agreement::metrics::ParticipationSnapshot` and
//! `algo_p2p::metrics::GossipsubMetrics` — no `prometheus` crate dependency.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::PoolErrorTag;

/// Per-[`PoolErrorTag`] counters for transaction groups evicted during
/// pool re-evaluation, mirroring go's `txPoolReevalCounter`.
///
/// One fixed-size atomic slot per tag in [`PoolErrorTag::ALL`] — the tag set
/// is small and known at compile time, so a lock-free array indexed by
/// [`PoolErrorTag`] avoids the `Mutex<BTreeMap<..>>` pattern other
/// hand-rolled counters in this workspace use, without losing readability.
#[derive(Debug, Default)]
pub struct TxPoolReevalCounter {
    counts: [AtomicU64; PoolErrorTag::ALL.len()],
}

impl TxPoolReevalCounter {
    /// A fresh, all-zero counter set.
    pub fn new() -> Self {
        Self::default()
    }

    fn index_of(tag: PoolErrorTag) -> usize {
        PoolErrorTag::ALL
            .iter()
            .position(|t| *t == tag)
            .expect("PoolErrorTag::ALL is exhaustive over PoolErrorTag")
    }

    /// Record one transaction group evicted during re-evaluation, classified
    /// as `tag`. Go: `txPoolReevalCounter.Add(ClassifyTxPoolError(err), 1)`.
    pub fn record(&self, tag: PoolErrorTag) {
        self.counts[Self::index_of(tag)].fetch_add(1, Ordering::Relaxed);
    }

    /// Current count for `tag`. Zero for a tag nothing has been recorded
    /// for yet.
    pub fn count(&self, tag: PoolErrorTag) -> u64 {
        self.counts[Self::index_of(tag)].load(Ordering::Relaxed)
    }

    /// Render as Prometheus text exposition format: one
    /// `algod_tx_pool_reeval_{TAG}` series per [`PoolErrorTag`], substituting
    /// the literal tag into the metric name — not as a label — exactly as
    /// go's `metrics.TagCounter` does, so a scraper already configured for
    /// go-algorand's pool metrics recognizes the same series names from an
    /// algod-rust node. Zero-valued series are still emitted, matching go's
    /// `NewTagCounter` behavior of pre-registering every tag up front.
    pub fn to_prometheus_text(&self) -> String {
        let mut out = String::with_capacity(64 * PoolErrorTag::ALL.len());
        for tag in PoolErrorTag::ALL {
            let name = format!("algod_tx_pool_reeval_{}", tag.as_str());
            out.push_str(&format!(
                "# HELP {name} Number of transaction groups removed from pool during re-evaluation due to {}.\n# TYPE {name} counter\n{name} {}\n",
                tag.as_str(),
                self.count(*tag)
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_zero_for_every_tag() {
        let c = TxPoolReevalCounter::new();
        for tag in PoolErrorTag::ALL {
            assert_eq!(c.count(*tag), 0);
        }
    }

    #[test]
    fn record_increments_only_the_matching_tag() {
        let c = TxPoolReevalCounter::new();
        c.record(PoolErrorTag::Overspend);
        c.record(PoolErrorTag::Overspend);
        c.record(PoolErrorTag::Cap);

        assert_eq!(c.count(PoolErrorTag::Overspend), 2);
        assert_eq!(c.count(PoolErrorTag::Cap), 1);
        assert_eq!(c.count(PoolErrorTag::Fee), 0);
    }

    #[test]
    fn prometheus_text_includes_tag_in_series_name_not_as_label() {
        let c = TxPoolReevalCounter::new();
        c.record(PoolErrorTag::TealReject);
        let text = c.to_prometheus_text();

        assert!(text.contains("algod_tx_pool_reeval_teal_reject 1\n"));
        assert!(text.contains("# TYPE algod_tx_pool_reeval_teal_reject counter"));
        assert!(!text.contains("tag=\""));
    }

    #[test]
    fn prometheus_text_emits_zero_series_for_every_tag_up_front() {
        let c = TxPoolReevalCounter::new();
        let text = c.to_prometheus_text();
        for tag in PoolErrorTag::ALL {
            assert!(
                text.contains(&format!("algod_tx_pool_reeval_{} 0\n", tag.as_str())),
                "missing zero series for {tag:?}"
            );
        }
    }
}
