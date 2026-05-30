//! Per-transaction-group state-delta tracer.
//!
//! Mirrors go-algorand's `ledger/eval.TxnGroupDeltaTracer`
//! (`ledger/eval/txntracer.go`): during block apply it records the
//! [`StateDelta`] produced by each transaction group, indexed by every
//! transaction ID *and* the group ID within that group, keeping a rolling
//! `lookback`-round window. This backs the `GET /v2/deltas/txn/group/{id}` and
//! `GET /v2/deltas/{round}/txn/group` REST endpoints.
//!
//! Unlike go's incremental copy-on-write evaluator, the Rust apply path is
//! diff-based, so the per-group delta is captured by snapshotting the group's
//! touched accounts before the group and diffing after it (see
//! `apply_block_impl`). The captured fields (account deltas, txids, txleases)
//! match the scope of the per-round [`StateDelta`]; summed across a round's
//! groups they reconstruct that round's account deltas.

use std::collections::{BTreeMap, HashMap};

use algo_types::Digest;

use crate::state_delta::StateDelta;

/// A single group's state delta together with all IDs (txn IDs + group ID)
/// that resolve to it. Mirrors go's `TxnGroupDeltaWithIds`.
#[derive(Debug, Clone)]
pub struct TxnGroupDelta {
    /// All identifiers (each transaction's ID, plus the group ID when set)
    /// that map to this delta.
    pub ids: Vec<Digest>,
    /// The state delta produced by applying this group.
    pub delta: StateDelta,
}

#[derive(Debug, Default)]
struct RoundDeltas {
    /// One entry per transaction group in the round, in apply order.
    groups: Vec<TxnGroupDelta>,
    /// Maps each txn/group ID to the index of its group in `groups`.
    by_id: HashMap<Digest, usize>,
}

/// Collects per-transaction-group state deltas during block apply, retaining a
/// rolling window of the most recent `lookback` rounds.
#[derive(Debug)]
pub struct TxnGroupDeltaTracer {
    /// Number of rounds retained at any time.
    lookback: u64,
    /// Most recent round started via [`Self::before_block`].
    latest_round: u64,
    /// Per-round captured deltas.
    rounds: BTreeMap<u64, RoundDeltas>,
}

impl TxnGroupDeltaTracer {
    /// Create a tracer retaining `lookback` rounds of deltas.
    pub fn new(lookback: u64) -> Self {
        TxnGroupDeltaTracer {
            lookback,
            latest_round: 0,
            rounds: BTreeMap::new(),
        }
    }

    /// Advance the rolling window to `round`, evicting the round that has aged
    /// out of the `lookback` window, without retaining `round` itself. Called
    /// for *every* applied block (including those whose deltas are not captured)
    /// so stale deltas can never outlive the window.
    pub fn advance(&mut self, round: u64) {
        if let Some(expired) = round.checked_sub(self.lookback) {
            self.rounds.remove(&expired);
        }
        self.latest_round = round;
    }

    /// Begin capturing deltas for `round`: advance the window and retain an
    /// (initially empty) entry for `round`. Mirrors go's `BeforeBlock`.
    pub fn before_block(&mut self, round: u64) {
        self.advance(round);
        self.rounds.entry(round).or_default();
    }

    /// Record a group's `delta`, indexed by every `id` (each transaction's ID
    /// and the group ID when set). Mirrors go's `AfterTxnGroup`.
    pub fn record_group(&mut self, ids: Vec<Digest>, delta: StateDelta) {
        let round = self.latest_round;
        let entry = self.rounds.entry(round).or_default();
        let idx = entry.groups.len();
        for id in &ids {
            entry.by_id.insert(*id, idx);
        }
        entry.groups.push(TxnGroupDelta { ids, delta });
    }

    /// Look up the delta for a transaction ID or group ID across all retained
    /// rounds. Mirrors go's `GetDeltaForID`.
    pub fn get_delta_for_id(&self, id: &Digest) -> Option<&StateDelta> {
        self.rounds
            .values()
            .find_map(|rd| rd.by_id.get(id).map(|&i| &rd.groups[i].delta))
    }

    /// All per-group deltas captured for `round`, or `None` if the round is not
    /// retained. Mirrors go's `GetDeltasForRound`.
    pub fn get_deltas_for_round(&self, round: u64) -> Option<&[TxnGroupDelta]> {
        self.rounds.get(&round).map(|rd| rd.groups.as_slice())
    }

    /// Whether `round` is currently retained.
    pub fn has_round(&self, round: u64) -> bool {
        self.rounds.contains_key(&round)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(b: u8) -> Digest {
        let mut d = [0u8; 32];
        d[0] = b;
        Digest(d)
    }

    #[test]
    fn records_and_looks_up_by_txn_and_group_id() {
        let mut t = TxnGroupDeltaTracer::new(8);
        t.before_block(10);
        let mut delta = StateDelta::default();
        delta.txids.insert(
            digest(0xAA),
            crate::state_delta::IncludedTransactions {
                last_valid: algo_types::Round(1000),
                intra: 0,
            },
        );
        // group of two txns sharing a group id
        t.record_group(vec![digest(0xAA), digest(0xBB), digest(0x01)], delta);

        // every id resolves to the same delta
        assert!(t.get_delta_for_id(&digest(0xAA)).is_some());
        assert!(t.get_delta_for_id(&digest(0xBB)).is_some());
        assert!(t.get_delta_for_id(&digest(0x01)).is_some());
        assert!(t.get_delta_for_id(&digest(0xFF)).is_none());

        let round = t.get_deltas_for_round(10).unwrap();
        assert_eq!(round.len(), 1);
        assert_eq!(round[0].ids.len(), 3);
    }

    #[test]
    fn drops_rounds_outside_lookback_window() {
        let mut t = TxnGroupDeltaTracer::new(2);
        t.before_block(1);
        t.before_block(2);
        t.before_block(3); // round 1 (== 3 - 2) ages out
        assert!(!t.has_round(1));
        assert!(t.has_round(2));
        assert!(t.has_round(3));
    }

    /// `advance` evicts aged-out rounds even when no group is recorded, so a run
    /// of uncaptured (incomplete) blocks can't leave stale deltas behind.
    #[test]
    fn advance_evicts_without_recording() {
        let mut t = TxnGroupDeltaTracer::new(2);
        t.before_block(1);
        t.record_group(vec![digest(0xAA)], StateDelta::default());
        assert!(t.has_round(1));
        assert!(t.get_delta_for_id(&digest(0xAA)).is_some());

        // Incomplete blocks at rounds 2 and 3 — no recording, but the window
        // still advances and round 1 (== 3 - 2) is evicted.
        t.advance(2);
        t.advance(3);
        assert!(!t.has_round(1));
        assert!(t.get_delta_for_id(&digest(0xAA)).is_none());
    }
}
