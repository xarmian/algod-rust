//! Anti-equivocation tracking for consensus participation.
//!
//! Prevents an account from signing twice for the same (round, period, step)
//! tuple, which would be an equivocation violation in the Algorand agreement
//! protocol.
//!
//! Matches the anti-equivocation logic in go-algorand's `agreement/vote.go`
//! and `agreement/abstractions.go` (`KeyManager.Record()`).
//!
//! # Thread Safety
//!
//! `AntiEquivocationTracker` is **not** `Sync`. Callers must provide external
//! synchronization (e.g., wrap in `Mutex`) if shared across threads.

use std::collections::{HashMap, HashSet};

use algo_types::{Address, Round};

/// Key for the equivocation tracker: (round, period, step).
type SigningKey = (u64, u64, u64);

/// Tracks which accounts have already signed for a given (round, period, step)
/// to prevent equivocation (double-signing).
///
/// In Algorand's agreement protocol, an honest node must never sign two
/// different values for the same (round, period, step). This tracker
/// enforces that invariant locally.
#[derive(Debug, Default)]
pub struct AntiEquivocationTracker {
    /// Maps (round, period, step) -> set of accounts that have signed.
    signed: HashMap<SigningKey, HashSet<Address>>,
}

impl AntiEquivocationTracker {
    /// Create a new, empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if `addr` has NOT yet signed for this (round, period, step).
    ///
    /// Conservative: if in doubt, returns `false` to prevent double-signing.
    pub fn can_sign(&self, addr: &Address, round: Round, period: u64, step: u64) -> bool {
        let key = (round.0, period, step);
        match self.signed.get(&key) {
            None => true,
            Some(addrs) => !addrs.contains(addr),
        }
    }

    /// Record that `addr` signed for this (round, period, step).
    ///
    /// After this call, `can_sign` for the same parameters will return `false`.
    pub fn record_signing(&mut self, addr: &Address, round: Round, period: u64, step: u64) {
        let key = (round.0, period, step);
        self.signed.entry(key).or_default().insert(*addr);
    }

    /// Remove all entries for rounds strictly before `round`.
    ///
    /// This prevents unbounded memory growth as the node progresses through
    /// rounds. Old entries are no longer needed once the round has been
    /// finalized.
    pub fn cleanup_before(&mut self, round: Round) {
        self.signed.retain(|&(r, _, _), _| r >= round.0);
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address([byte; 32])
    }

    #[test]
    fn first_sign_attempt_succeeds() {
        let tracker = AntiEquivocationTracker::new();
        assert!(tracker.can_sign(&addr(1), Round(10), 0, 1));
    }

    #[test]
    fn second_sign_attempt_blocked() {
        let mut tracker = AntiEquivocationTracker::new();
        let a = addr(1);
        tracker.record_signing(&a, Round(10), 0, 1);
        assert!(!tracker.can_sign(&a, Round(10), 0, 1));
    }

    #[test]
    fn different_round_does_not_interfere() {
        let mut tracker = AntiEquivocationTracker::new();
        let a = addr(1);
        tracker.record_signing(&a, Round(10), 0, 1);
        // Same period and step, different round — should be allowed.
        assert!(tracker.can_sign(&a, Round(11), 0, 1));
    }

    #[test]
    fn different_period_does_not_interfere() {
        let mut tracker = AntiEquivocationTracker::new();
        let a = addr(1);
        tracker.record_signing(&a, Round(10), 0, 1);
        // Same round and step, different period — should be allowed.
        assert!(tracker.can_sign(&a, Round(10), 1, 1));
    }

    #[test]
    fn different_step_does_not_interfere() {
        let mut tracker = AntiEquivocationTracker::new();
        let a = addr(1);
        tracker.record_signing(&a, Round(10), 0, 1);
        // Same round and period, different step — should be allowed.
        assert!(tracker.can_sign(&a, Round(10), 0, 2));
    }

    #[test]
    fn multiple_accounts_tracked_independently() {
        let mut tracker = AntiEquivocationTracker::new();
        let a1 = addr(1);
        let a2 = addr(2);

        tracker.record_signing(&a1, Round(10), 0, 1);

        // a1 is blocked, a2 is not.
        assert!(!tracker.can_sign(&a1, Round(10), 0, 1));
        assert!(tracker.can_sign(&a2, Round(10), 0, 1));

        // Now a2 signs too.
        tracker.record_signing(&a2, Round(10), 0, 1);
        assert!(!tracker.can_sign(&a2, Round(10), 0, 1));
    }

    #[test]
    fn cleanup_removes_old_entries() {
        let mut tracker = AntiEquivocationTracker::new();
        let a = addr(1);

        tracker.record_signing(&a, Round(5), 0, 1);
        tracker.record_signing(&a, Round(10), 0, 1);
        tracker.record_signing(&a, Round(15), 0, 1);

        // Cleanup rounds before 10 — round 5 should be removed.
        tracker.cleanup_before(Round(10));

        // Round 5 entry gone — can sign again (though in practice this
        // would never happen since the round has passed).
        assert!(tracker.can_sign(&a, Round(5), 0, 1));

        // Rounds 10 and 15 still tracked.
        assert!(!tracker.can_sign(&a, Round(10), 0, 1));
        assert!(!tracker.can_sign(&a, Round(15), 0, 1));
    }

    #[test]
    fn cleanup_before_zero_is_noop() {
        let mut tracker = AntiEquivocationTracker::new();
        let a = addr(1);
        tracker.record_signing(&a, Round(0), 0, 1);
        tracker.cleanup_before(Round(0));
        // Round 0 is >= 0, so it should still be tracked.
        assert!(!tracker.can_sign(&a, Round(0), 0, 1));
    }

    #[test]
    fn empty_tracker_cleanup_is_noop() {
        let mut tracker = AntiEquivocationTracker::new();
        tracker.cleanup_before(Round(100));
        // No panic, no entries — still works.
        assert!(tracker.can_sign(&addr(1), Round(100), 0, 1));
    }
}
