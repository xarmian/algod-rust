// Agreement protocol types: timeouts, deadlines, freshness, and dynamic filter
// timeout.
//
// Mirrors go-algorand/agreement/types.go,
// go-algorand/agreement/dynamicFilterTimeoutParams.go, and
// go-algorand/agreement/credentialArrivalHistory.go.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use algo_types::{ConsensusParams, Round};

use crate::bundle::UnauthenticatedBundle;
use crate::step::{Period, Step, CERT, LATE, NEXT, SOFT};
use crate::vote::UnauthenticatedVote;

// ---------------------------------------------------------------------------
// TimeoutType
// ---------------------------------------------------------------------------

/// Defines the type of a `Deadline`, to distinguish between different timeouts
/// set by agreement.
///
/// Mirrors Go's `TimeoutType` in agreement/types.go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(i8)]
pub enum TimeoutType {
    /// Annotates timeout events in the agreement protocol (e.g., for receiving
    /// a block).
    #[default]
    Deadline = 0,
    /// Annotates the fast recovery timeout.
    FastRecovery = 1,
    /// Annotates the filter step timeout event.
    Filter = 2,
}

impl std::fmt::Display for TimeoutType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deadline => write!(f, "Deadline"),
            Self::FastRecovery => write!(f, "FastRecovery"),
            Self::Filter => write!(f, "Filter"),
        }
    }
}

// ---------------------------------------------------------------------------
// Deadline
// ---------------------------------------------------------------------------

/// Marks a timeout event that the player schedules to happen after `duration`
/// time.
///
/// Mirrors Go's `Deadline` struct in agreement/types.go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Deadline {
    /// How long until this deadline fires (relative to the start of the current
    /// period).
    #[serde(with = "duration_serde")]
    pub duration: Duration,
    /// The type of timeout this deadline represents.
    pub timeout_type: TimeoutType,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `BigLambda` — max time to wait for leader's proposal (time to propagate one
/// block). This is a protocol constant, not a consensus param.
///
/// Mirrors Go's `config.Protocol.BigLambda` (15s).
pub const BIG_LAMBDA: Duration = Duration::from_millis(15000);

/// `SmallLambda` — min time to wait for leader's credential (time to propagate
/// one credential). This is a protocol constant.
///
/// Mirrors Go's `config.Protocol.SmallLambda` (2s).
pub const SMALL_LAMBDA: Duration = Duration::from_millis(2000);

/// Default deadline timeout = BigLambda + SmallLambda.
///
/// Mirrors Go's `defaultDeadlineTimeout`.
pub const DEFAULT_DEADLINE_TIMEOUT: Duration =
    Duration::from_millis(BIG_LAMBDA.as_millis() as u64 + SMALL_LAMBDA.as_millis() as u64);

/// The step at which partition recovery begins.
///
/// Mirrors Go's `partitionStep = next + 3`.
pub const PARTITION_STEP: Step = Step(NEXT.0 + 3);

/// The extra timeout added during recovery steps.
///
/// Mirrors Go's `recoveryExtraTimeout = config.Protocol.SmallLambda`.
pub const RECOVERY_EXTRA_TIMEOUT: Duration = SMALL_LAMBDA;

// ---------------------------------------------------------------------------
// credentialRoundLag
// ---------------------------------------------------------------------------

/// The number of past credential arrivals measured to determine the next filter
/// timeout.
///
/// Mirrors Go's `dynamicFilterCredentialArrivalHistory`.
pub const DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY: usize = 40;

/// Minimal duration that the dynamic filter timeout must meet.
///
/// Mirrors Go's `dynamicFilterTimeoutLowerBound`.
pub const DYNAMIC_FILTER_TIMEOUT_LOWER_BOUND: Duration = Duration::from_millis(2500);

/// Which sample to use out of the sorted history array (95th percentile of
/// 40 samples = index 37).
///
/// Mirrors Go's `dynamicFilterTimeoutCredentialArrivalHistoryIdx`.
pub const DYNAMIC_FILTER_TIMEOUT_CREDENTIAL_ARRIVAL_HISTORY_IDX: usize = 37;

/// Additional time extension atop the one calculated based on credential
/// arrival history.
///
/// Mirrors Go's `dynamicFilterTimeoutGraceInterval`.
pub const DYNAMIC_FILTER_TIMEOUT_GRACE_INTERVAL: Duration = Duration::from_millis(50);

/// Minimum credential round lag (hardcoded to 8 in Go).
const MIN_CREDENTIAL_ROUND_LAG: u64 = 8;

/// The maximal number of rounds that could pass before a credential from an
/// honest party for an old round may arrive.
///
/// Mirrors Go's `credentialRoundLag` (computed in `init()`).
///
/// credential arrival time should be at most 2 * SmallLambda after it was sent.
/// credentialRoundLag = max(2 * SmallLambda / dynamicFilterTimeoutLowerBound, 8)
pub fn credential_round_lag() -> u64 {
    let two_small_lambda = 2 * SMALL_LAMBDA.as_millis() as u64;
    let lower_bound = DYNAMIC_FILTER_TIMEOUT_LOWER_BOUND.as_millis() as u64;

    let mut lag = two_small_lambda / lower_bound;
    lag = lag.max(MIN_CREDENTIAL_ROUND_LAG);

    // If the division was not exact, round up
    if lag * lower_bound < two_small_lambda {
        lag += 1;
    }

    lag
}

// ---------------------------------------------------------------------------
// Timeout duration functions
// ---------------------------------------------------------------------------

/// The duration of the first agreement step (filter timeout).
///
/// Mirrors Go's `FilterTimeout`.
pub fn filter_timeout(p: Period, params: &ConsensusParams) -> Duration {
    if p == Period(0) {
        params.agreement_filter_timeout_period0
    } else {
        params.agreement_filter_timeout
    }
}

/// The duration of the second agreement step (deadline timeout), varying based
/// on period and consensus version.
///
/// Mirrors Go's `DeadlineTimeout`.
pub fn deadline_timeout(p: Period, params: &ConsensusParams) -> Duration {
    if p == Period(0) {
        params.agreement_deadline_timeout_period0
    } else {
        DEFAULT_DEADLINE_TIMEOUT
    }
}

/// Returns the default deadline timeout (`BigLambda + SmallLambda`).
///
/// Mirrors Go's `DefaultDeadlineTimeout()`.
pub fn default_deadline_timeout() -> Duration {
    DEFAULT_DEADLINE_TIMEOUT
}

// ---------------------------------------------------------------------------
// Freshness functions
// ---------------------------------------------------------------------------

/// Determines whether a proposal satisfies freshness rules.
///
/// Mirrors Go's `proposalFresh` in agreement/proposalManager.go.
pub fn proposal_fresh(
    fresh_data: &FreshnessData,
    vote: &UnauthenticatedVote,
) -> Result<(), String> {
    let vote_round = vote.raw_vote.round;
    let vote_period = vote.raw_vote.period;

    if vote_round == fresh_data.player_round {
        if fresh_data.player_period != Period(0)
            && fresh_data.player_period.0.wrapping_sub(1) > vote_period.0
        {
            return Err(format!(
                "filtered stale proposal: period {} - 1 > {}",
                fresh_data.player_period, vote_period
            ));
        }
        if fresh_data.player_period.0 + 1 < vote_period.0 {
            return Err(format!(
                "filtered premature proposal: period {} + 1 < {}",
                fresh_data.player_period, vote_period
            ));
        }
    } else if vote_round == Round(fresh_data.player_round.0 + 1) {
        if vote_period != Period(0) {
            return Err(format!(
                "filtered premature proposal from next round: period {} > 0",
                vote_period
            ));
        }
    } else {
        return Err(format!(
            "filtered proposal from bad round: p.Round={}, vote.Round={}",
            fresh_data.player_round, vote_round
        ));
    }
    Ok(())
}

/// A helper function for vote relay rules. Votes from steps [soft, next] are
/// always propagated, as are votes from [s-1, s+1] where s is the
/// current/last concluding step.
///
/// Mirrors Go's `voteStepFresh` in agreement/voteAggregator.go.
pub fn vote_step_fresh(descr: &str, mine: Step, vote: Step) -> Result<(), String> {
    // Always propagate first recovery vote (steps <= next)
    if vote.0 <= NEXT.0 {
        return Ok(());
    }
    // Always propagate fast partition recovery votes (steps >= late)
    if vote.0 >= LATE.0 {
        return Ok(());
    }

    if mine.0 != 0 && mine.0.wrapping_sub(1) > vote.0 {
        return Err(format!(
            "filtered stale vote {descr}: step {} - 1 > {}",
            mine, vote
        ));
    }
    if mine.0 + 1 < vote.0 {
        return Err(format!(
            "filtered premature vote {descr}: step {} + 1 < {}",
            mine, vote
        ));
    }

    Ok(())
}

/// Determines whether a vote satisfies freshness rules.
///
/// Mirrors Go's `voteFresh` in agreement/voteAggregator.go.
pub fn vote_fresh(fresh_data: &FreshnessData, vote: &UnauthenticatedVote) -> Result<(), String> {
    let vote_round = vote.raw_vote.round;
    let vote_period = vote.raw_vote.period;
    let vote_step = vote.raw_vote.step;

    if fresh_data.player_round != vote_round && Round(fresh_data.player_round.0 + 1) != vote_round {
        return Err(format!(
            "filtered vote from bad round: player.Round={}; vote.Round={}",
            fresh_data.player_round, vote_round
        ));
    }

    if Round(fresh_data.player_round.0 + 1) == vote_round {
        if vote_period.0 > 0 {
            return Err(format!(
                "filtered future vote from bad period: player.Round={}; vote.(Round,Period,Step)=({},{},{})",
                fresh_data.player_round, vote_round, vote_period, vote_step
            ));
        }
        // Pipeline votes from next round period 0
        return vote_step_fresh("from next round", Step(0), vote_step);
    }

    // vote_round == fresh_data.player_round
    if vote_period.0 == fresh_data.player_period.0.wrapping_sub(1) {
        if fresh_data.player_period != Period(0) {
            return vote_step_fresh(
                "from previous period",
                fresh_data.player_last_concluding,
                vote_step,
            );
        }
    } else if vote_period == fresh_data.player_period {
        return vote_step_fresh("from period", fresh_data.player_step, vote_step);
    } else if vote_period.0 == fresh_data.player_period.0 + 1 {
        // Has the effect of rejecting all votes except for the ones from steps
        // which are always propagated
        return vote_step_fresh("from next period", SOFT, vote_step);
    }

    Err(format!(
        "filtered vote from bad period: p.Period={}, vote.Period={}",
        fresh_data.player_period, vote_period
    ))
}

/// Determines whether a bundle satisfies freshness rules.
///
/// Mirrors Go's `bundleFresh` in agreement/voteAggregator.go.
pub fn bundle_fresh(fresh_data: &FreshnessData, b: &UnauthenticatedBundle) -> Result<(), String> {
    if fresh_data.player_round != b.round {
        return Err(format!(
            "filtered bundle from different round: round {} != {}",
            fresh_data.player_round, b.round
        ));
    }

    if b.step == CERT {
        return Ok(());
    }

    if fresh_data.player_period != Period(0) && fresh_data.player_period.0 - 1 > b.period.0 {
        return Err(format!(
            "filtered stale bundle: period {} >= {}",
            fresh_data.player_period, b.period
        ));
    }

    Ok(())
}

/// Returns whether a proposal-vote for an old round may be useful for
/// credential arrival time tracking.
///
/// Mirrors Go's `proposalUsefulForCredentialHistory` in proposalManager.go.
pub fn proposal_useful_for_credential_history(
    cur_round: Round,
    vote: &UnauthenticatedVote,
) -> bool {
    let vote_round = vote.raw_vote.round;
    let cred_lag = credential_round_lag();

    if vote_round < cur_round
        && cur_round.0 <= vote_round.0 + cred_lag
        && vote.raw_vote.period == Period(0)
        && vote.raw_vote.step == Step(0)
    {
        // Continue processing old period 0 proposal votes for credential
        // arrival time tracking
        if DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY > 0 {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// FreshnessData (re-exported from events)
// ---------------------------------------------------------------------------

/// Re-export the canonical `FreshnessData` from `events.rs` so that the
/// freshness functions in this module and external callers can use the same
/// type without a conversion layer.
pub use crate::events::FreshnessData;

// ---------------------------------------------------------------------------
// CredentialArrivalHistory
// ---------------------------------------------------------------------------

/// Maintains a circular buffer of `Duration` samples for tracking credential
/// arrival times.
///
/// Mirrors Go's `credentialArrivalHistory` in
/// agreement/credentialArrivalHistory.go.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialArrivalHistory {
    /// The circular buffer of samples.
    #[serde(with = "duration_vec_serde")]
    history: Vec<Duration>,
    /// Current write position in the circular buffer.
    write_ptr: usize,
    /// Whether the buffer has been fully populated at least once.
    full: bool,
}

impl CredentialArrivalHistory {
    /// Create a new `CredentialArrivalHistory` with the given capacity.
    ///
    /// Mirrors Go's `makeCredentialArrivalHistory`.
    ///
    /// # Panics
    ///
    /// Panics if `size` is negative (which cannot happen with `usize`).
    pub fn new(size: usize) -> Self {
        let mut h = Self {
            history: vec![Duration::ZERO; size],
            write_ptr: 0,
            full: false,
        };
        h.reset();
        h
    }

    /// Saves a new sample into the circular buffer. If the buffer is full, it
    /// overwrites the oldest sample.
    ///
    /// Mirrors Go's `credentialArrivalHistory.store`.
    pub fn store(&mut self, sample: Duration) {
        if self.history.is_empty() {
            return;
        }

        self.history[self.write_ptr] = sample;
        self.write_ptr += 1;
        if self.write_ptr == self.history.len() {
            self.full = true;
            self.write_ptr = 0;
        }
    }

    /// Marks the history buffer as empty.
    ///
    /// Mirrors Go's `credentialArrivalHistory.reset`.
    pub fn reset(&mut self) {
        self.write_ptr = 0;
        self.full = false;
    }

    /// Checks if the circular buffer has been fully populated at least once.
    ///
    /// Mirrors Go's `credentialArrivalHistory.isFull`.
    pub fn is_full(&self) -> bool {
        self.full
    }

    /// Returns the `idx`-th duration in the sorted history array.
    ///
    /// Assumes the history is full and idx is within bounds.
    ///
    /// Mirrors Go's `credentialArrivalHistory.orderStatistics`.
    ///
    /// # Panics
    ///
    /// Panics if the history is not full or idx is out of bounds.
    pub fn order_statistics(&self, idx: usize) -> Duration {
        assert!(self.is_full(), "history not full");
        assert!(
            idx < self.history.len(),
            "index out of bounds: {} >= {}",
            idx,
            self.history.len()
        );

        let mut sorted = self.history.clone();
        sorted.sort();
        sorted[idx]
    }
}

impl Default for CredentialArrivalHistory {
    fn default() -> Self {
        Self::new(DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY)
    }
}

// ---------------------------------------------------------------------------
// Dynamic filter timeout
// ---------------------------------------------------------------------------

/// Computes the dynamic filter timeout based on the credential arrival history.
///
/// If the history is not yet full, or the feature is not enabled, returns
/// `None` and the caller should fall back to the static filter timeout.
///
/// The computation:
/// 1. Take the 95th percentile of the credential arrival history.
/// 2. Add the grace interval.
/// 3. Clamp to at least the lower bound.
///
/// This function always computes the timeout if the history is full, regardless
/// of whether dynamic filter timeout is enabled in consensus. The caller
/// decides whether to use the result based on `params.dynamic_filter_timeout`.
pub fn dynamic_filter_timeout(history: &CredentialArrivalHistory) -> Option<Duration> {
    if DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY == 0 {
        return None;
    }

    if !history.is_full() {
        return None;
    }

    let target = history.order_statistics(DYNAMIC_FILTER_TIMEOUT_CREDENTIAL_ARRIVAL_HISTORY_IDX);
    let timeout = target + DYNAMIC_FILTER_TIMEOUT_GRACE_INTERVAL;
    let timeout = timeout.max(DYNAMIC_FILTER_TIMEOUT_LOWER_BOUND);

    Some(timeout)
}

/// Serde helper for `Duration` — serializes as nanoseconds (u128).
///
/// Deserializes losslessly via u128 to avoid truncation that `Duration::from_nanos(u64)` would cause.
pub mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        d.as_nanos().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let nanos = u128::deserialize(d)?;
        Ok(Duration::new(
            (nanos / 1_000_000_000) as u64,
            (nanos % 1_000_000_000) as u32,
        ))
    }
}

/// Serde helper for `Vec<Duration>` — serializes each element as nanoseconds (u128).
///
/// Deserializes losslessly via u128 to avoid truncation.
mod duration_vec_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(v: &[Duration], s: S) -> Result<S::Ok, S::Error> {
        let nanos: Vec<u128> = v.iter().map(|d| d.as_nanos()).collect();
        nanos.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Duration>, D::Error> {
        let nanos: Vec<u128> = Vec::deserialize(d)?;
        Ok(nanos
            .into_iter()
            .map(|n| Duration::new((n / 1_000_000_000) as u64, (n % 1_000_000_000) as u32))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::UnauthenticatedCredential;
    use crate::vote::{ProposalValue, RawVote, BOTTOM};
    use algo_consensus_crypto::OneTimeSignature;
    use algo_types::{Address, Digest};

    // ---- TimeoutType tests ----

    #[test]
    fn timeout_type_default_is_deadline() {
        assert_eq!(TimeoutType::default(), TimeoutType::Deadline);
    }

    #[test]
    fn timeout_type_display() {
        assert_eq!(format!("{}", TimeoutType::Deadline), "Deadline");
        assert_eq!(format!("{}", TimeoutType::FastRecovery), "FastRecovery");
        assert_eq!(format!("{}", TimeoutType::Filter), "Filter");
    }

    // ---- Deadline tests ----

    #[test]
    fn deadline_default() {
        let d = Deadline::default();
        assert_eq!(d.duration, Duration::ZERO);
        assert_eq!(d.timeout_type, TimeoutType::Deadline);
    }

    // ---- Constants tests ----

    #[test]
    fn big_lambda_is_15s() {
        assert_eq!(BIG_LAMBDA, Duration::from_secs(15));
    }

    #[test]
    fn small_lambda_is_2s() {
        assert_eq!(SMALL_LAMBDA, Duration::from_secs(2));
    }

    #[test]
    fn default_deadline_timeout_is_big_plus_small() {
        assert_eq!(DEFAULT_DEADLINE_TIMEOUT, Duration::from_secs(17));
    }

    #[test]
    fn partition_step_is_next_plus_3() {
        assert_eq!(PARTITION_STEP, Step(NEXT.0 + 3));
    }

    // ---- credential_round_lag tests ----

    #[test]
    fn credential_round_lag_value() {
        let lag = credential_round_lag();
        // 2 * 2000ms / 2500ms = 1.6, floor = 1; max(1, 8) = 8
        // But then 8 * 2500 = 20000 >= 4000, so no increment.
        // Actually: 2 * 2000 = 4000; 4000 / 2500 = 1 (integer); max(1, 8) = 8;
        // 8 * 2500 = 20000 >= 4000, so lag stays 8.
        assert_eq!(lag, 8);
    }

    // ---- filter_timeout / deadline_timeout tests ----

    #[test]
    fn filter_timeout_period0() {
        let params = test_params();
        let ft = filter_timeout(Period(0), &params);
        assert_eq!(ft, params.agreement_filter_timeout_period0);
    }

    #[test]
    fn filter_timeout_period_nonzero() {
        let params = test_params();
        let ft = filter_timeout(Period(1), &params);
        assert_eq!(ft, params.agreement_filter_timeout);
    }

    #[test]
    fn deadline_timeout_period0() {
        let params = test_params();
        let dt = deadline_timeout(Period(0), &params);
        assert_eq!(dt, params.agreement_deadline_timeout_period0);
    }

    #[test]
    fn deadline_timeout_period_nonzero() {
        let dt = deadline_timeout(Period(1), &test_params());
        assert_eq!(dt, DEFAULT_DEADLINE_TIMEOUT);
    }

    // ---- CredentialArrivalHistory tests ----

    #[test]
    fn credential_arrival_history_empty() {
        let h = CredentialArrivalHistory::new(0);
        assert!(!h.is_full());
    }

    #[test]
    fn credential_arrival_history_store_and_full() {
        let mut h = CredentialArrivalHistory::new(3);
        assert!(!h.is_full());

        h.store(Duration::from_millis(100));
        h.store(Duration::from_millis(200));
        assert!(!h.is_full());

        h.store(Duration::from_millis(300));
        assert!(h.is_full());
    }

    #[test]
    fn credential_arrival_history_wraps_around() {
        let mut h = CredentialArrivalHistory::new(2);
        h.store(Duration::from_millis(100));
        h.store(Duration::from_millis(200));
        assert!(h.is_full());

        // This overwrites the first element
        h.store(Duration::from_millis(50));
        assert!(h.is_full());

        // order_statistics should return sorted values
        assert_eq!(h.order_statistics(0), Duration::from_millis(50));
        assert_eq!(h.order_statistics(1), Duration::from_millis(200));
    }

    #[test]
    fn credential_arrival_history_reset() {
        let mut h = CredentialArrivalHistory::new(2);
        h.store(Duration::from_millis(100));
        h.store(Duration::from_millis(200));
        assert!(h.is_full());

        h.reset();
        assert!(!h.is_full());
    }

    #[test]
    #[should_panic(expected = "history not full")]
    fn credential_arrival_history_order_statistics_not_full() {
        let h = CredentialArrivalHistory::new(3);
        h.order_statistics(0);
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn credential_arrival_history_order_statistics_out_of_bounds() {
        let mut h = CredentialArrivalHistory::new(2);
        h.store(Duration::from_millis(100));
        h.store(Duration::from_millis(200));
        h.order_statistics(2);
    }

    #[test]
    fn credential_arrival_history_order_statistics_sorted() {
        let mut h = CredentialArrivalHistory::new(5);
        h.store(Duration::from_millis(500));
        h.store(Duration::from_millis(100));
        h.store(Duration::from_millis(300));
        h.store(Duration::from_millis(200));
        h.store(Duration::from_millis(400));
        assert!(h.is_full());

        assert_eq!(h.order_statistics(0), Duration::from_millis(100));
        assert_eq!(h.order_statistics(1), Duration::from_millis(200));
        assert_eq!(h.order_statistics(2), Duration::from_millis(300));
        assert_eq!(h.order_statistics(3), Duration::from_millis(400));
        assert_eq!(h.order_statistics(4), Duration::from_millis(500));
    }

    // ---- Dynamic filter timeout tests ----

    #[test]
    fn dynamic_filter_timeout_not_full() {
        let h = CredentialArrivalHistory::new(DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY);
        assert_eq!(dynamic_filter_timeout(&h), None);
    }

    #[test]
    fn dynamic_filter_timeout_clamped_to_lower_bound() {
        let mut h = CredentialArrivalHistory::new(DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY);
        // Fill with very small values
        for _ in 0..DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY {
            h.store(Duration::from_millis(10));
        }
        let timeout = dynamic_filter_timeout(&h).unwrap();
        assert_eq!(timeout, DYNAMIC_FILTER_TIMEOUT_LOWER_BOUND);
    }

    #[test]
    fn dynamic_filter_timeout_uses_95th_percentile() {
        let mut h = CredentialArrivalHistory::new(DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY);
        // Fill with increasing values: 100ms, 200ms, ..., 4000ms
        for i in 0..DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY {
            h.store(Duration::from_millis((i as u64 + 1) * 100));
        }
        let timeout = dynamic_filter_timeout(&h).unwrap();
        // The 95th percentile (index 37) of [100, 200, ..., 4000] is 3800ms
        // 3800 + 50 grace = 3850ms, which is > 2500ms lower bound
        assert_eq!(timeout, Duration::from_millis(3850));
    }

    // ---- Freshness tests ----

    #[test]
    fn proposal_fresh_same_round() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(2),
            player_step: Step(1),
            player_last_concluding: Step(0),
        };
        let vote = make_uv(Round(10), Period(2), Step(0));
        assert!(proposal_fresh(&fd, &vote).is_ok());
    }

    #[test]
    fn proposal_fresh_stale() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(5),
            player_step: Step(1),
            player_last_concluding: Step(0),
        };
        let vote = make_uv(Round(10), Period(2), Step(0));
        assert!(proposal_fresh(&fd, &vote).is_err());
    }

    #[test]
    fn proposal_fresh_next_round_period0() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(0),
            player_step: Step(1),
            player_last_concluding: Step(0),
        };
        let vote = make_uv(Round(11), Period(0), Step(0));
        assert!(proposal_fresh(&fd, &vote).is_ok());
    }

    #[test]
    fn proposal_fresh_next_round_period_nonzero() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(0),
            player_step: Step(1),
            player_last_concluding: Step(0),
        };
        let vote = make_uv(Round(11), Period(1), Step(0));
        assert!(proposal_fresh(&fd, &vote).is_err());
    }

    #[test]
    fn proposal_fresh_bad_round() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(0),
            player_step: Step(1),
            player_last_concluding: Step(0),
        };
        let vote = make_uv(Round(8), Period(0), Step(0));
        assert!(proposal_fresh(&fd, &vote).is_err());
    }

    #[test]
    fn vote_fresh_same_round_same_period() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(2),
            player_step: SOFT,
            player_last_concluding: Step(0),
        };
        let vote = make_uv(Round(10), Period(2), SOFT);
        assert!(vote_fresh(&fd, &vote).is_ok());
    }

    #[test]
    fn vote_fresh_bad_round() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(0),
            player_step: SOFT,
            player_last_concluding: Step(0),
        };
        let vote = make_uv(Round(8), Period(0), SOFT);
        assert!(vote_fresh(&fd, &vote).is_err());
    }

    #[test]
    fn bundle_fresh_same_round() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(2),
            player_step: SOFT,
            player_last_concluding: Step(0),
        };
        let b = crate::bundle::UnauthenticatedBundle {
            round: Round(10),
            period: Period(2),
            step: CERT,
            proposal: BOTTOM,
            votes: vec![],
            equivocation_votes: vec![],
        };
        assert!(bundle_fresh(&fd, &b).is_ok());
    }

    #[test]
    fn bundle_fresh_different_round() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(2),
            player_step: SOFT,
            player_last_concluding: Step(0),
        };
        let b = crate::bundle::UnauthenticatedBundle {
            round: Round(11),
            period: Period(0),
            step: CERT,
            proposal: BOTTOM,
            votes: vec![],
            equivocation_votes: vec![],
        };
        assert!(bundle_fresh(&fd, &b).is_err());
    }

    #[test]
    fn vote_step_fresh_always_propagates_next() {
        // Steps <= next are always propagated
        assert!(vote_step_fresh("test", Step(5), NEXT).is_ok());
        assert!(vote_step_fresh("test", Step(5), SOFT).is_ok());
    }

    #[test]
    fn vote_step_fresh_always_propagates_late() {
        // Steps >= late are always propagated
        assert!(vote_step_fresh("test", Step(5), LATE).is_ok());
    }

    // ---- Dynamic filter timeout computation with full history ----

    #[test]
    fn dynamic_filter_timeout_large_values_above_lower_bound() {
        let mut h = CredentialArrivalHistory::new(DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY);
        for _ in 0..DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY {
            h.store(Duration::from_millis(5000));
        }
        let timeout = dynamic_filter_timeout(&h).unwrap();
        // 5000 + 50 = 5050ms, which is > 2500ms lower bound
        assert_eq!(timeout, Duration::from_millis(5050));
    }

    #[test]
    fn dynamic_filter_timeout_zero_capacity_returns_none() {
        // When DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY is 0 there's no dynamic timeout
        // We can't test this directly since it's a constant. Instead test empty history.
        let h = CredentialArrivalHistory::new(DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY);
        assert_eq!(dynamic_filter_timeout(&h), None);
    }

    // ---- History window: oldest entries are replaced when full ----

    #[test]
    fn credential_arrival_history_oldest_entries_replaced() {
        let mut h = CredentialArrivalHistory::new(3);
        // Fill the buffer
        h.store(Duration::from_millis(100));
        h.store(Duration::from_millis(200));
        h.store(Duration::from_millis(300));
        assert!(h.is_full());

        // Now overwrite oldest entry (index 0)
        h.store(Duration::from_millis(50));
        assert!(h.is_full());

        // Sorted: [50, 200, 300]
        assert_eq!(h.order_statistics(0), Duration::from_millis(50));
        assert_eq!(h.order_statistics(1), Duration::from_millis(200));
        assert_eq!(h.order_statistics(2), Duration::from_millis(300));

        // Overwrite next (index 1)
        h.store(Duration::from_millis(25));
        // Buffer: [50, 25, 300]. Sorted: [25, 50, 300]
        assert_eq!(h.order_statistics(0), Duration::from_millis(25));
        assert_eq!(h.order_statistics(1), Duration::from_millis(50));
        assert_eq!(h.order_statistics(2), Duration::from_millis(300));
    }

    // ---- History store with zero capacity does nothing ----

    #[test]
    fn credential_arrival_history_zero_capacity_store_noop() {
        let mut h = CredentialArrivalHistory::new(0);
        h.store(Duration::from_millis(100));
        assert!(!h.is_full());
    }

    // ---- order_statistics correct percentile computation ----

    #[test]
    fn credential_arrival_history_order_statistics_percentile() {
        let mut h = CredentialArrivalHistory::new(10);
        // Store values 1..=10
        for i in 1..=10 {
            h.store(Duration::from_millis(i * 100));
        }
        assert!(h.is_full());
        // The sorted array is [100, 200, 300, ..., 1000]
        // Index 0 is 100ms (0th percentile), index 9 is 1000ms (90th percentile)
        assert_eq!(h.order_statistics(0), Duration::from_millis(100));
        assert_eq!(h.order_statistics(4), Duration::from_millis(500));
        assert_eq!(h.order_statistics(9), Duration::from_millis(1000));
    }

    #[test]
    fn credential_arrival_history_order_statistics_with_duplicates() {
        let mut h = CredentialArrivalHistory::new(5);
        h.store(Duration::from_millis(100));
        h.store(Duration::from_millis(100));
        h.store(Duration::from_millis(100));
        h.store(Duration::from_millis(200));
        h.store(Duration::from_millis(200));
        assert!(h.is_full());
        assert_eq!(h.order_statistics(0), Duration::from_millis(100));
        assert_eq!(h.order_statistics(2), Duration::from_millis(100));
        assert_eq!(h.order_statistics(3), Duration::from_millis(200));
        assert_eq!(h.order_statistics(4), Duration::from_millis(200));
    }

    #[test]
    fn credential_arrival_history_order_statistics_reverse_order() {
        let mut h = CredentialArrivalHistory::new(5);
        h.store(Duration::from_millis(500));
        h.store(Duration::from_millis(400));
        h.store(Duration::from_millis(300));
        h.store(Duration::from_millis(200));
        h.store(Duration::from_millis(100));
        assert!(h.is_full());
        // Should be sorted ascending
        assert_eq!(h.order_statistics(0), Duration::from_millis(100));
        assert_eq!(h.order_statistics(4), Duration::from_millis(500));
    }

    // ---- CredentialArrivalHistory default ----

    #[test]
    fn credential_arrival_history_default_size() {
        let h = CredentialArrivalHistory::default();
        assert!(!h.is_full());
        // Default should have capacity DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY = 40
        let mut h2 = h.clone();
        for _ in 0..DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY {
            h2.store(Duration::from_millis(100));
        }
        assert!(h2.is_full());
    }

    // ---- vote_fresh edge cases ----

    #[test]
    fn vote_fresh_next_round_period_0_allowed() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(0),
            player_step: SOFT,
            player_last_concluding: Step(0),
        };
        let vote = make_uv(Round(11), Period(0), SOFT);
        assert!(vote_fresh(&fd, &vote).is_ok());
    }

    #[test]
    fn vote_fresh_next_round_period_nonzero_rejected() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(0),
            player_step: SOFT,
            player_last_concluding: Step(0),
        };
        let vote = make_uv(Round(11), Period(1), SOFT);
        assert!(vote_fresh(&fd, &vote).is_err());
    }

    #[test]
    fn vote_fresh_previous_period_with_last_concluding() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(2),
            player_step: SOFT,
            player_last_concluding: Step(3), // next
        };
        // Vote from period 1 (previous), step 3 (next) should be fresh
        let vote = make_uv(Round(10), Period(1), Step(3));
        assert!(vote_fresh(&fd, &vote).is_ok());
    }

    #[test]
    fn vote_fresh_next_period_only_propagated_steps() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(2),
            player_step: SOFT,
            player_last_concluding: Step(0),
        };
        // Vote from period 3 (next), step SOFT should be fresh
        let vote = make_uv(Round(10), Period(3), SOFT);
        assert!(vote_fresh(&fd, &vote).is_ok());

        // Vote from period 3, step 5 (arbitrary recovery step between next and late)
        // should be filtered because it's in the gap between next (3) and late (253)
        let vote2 = make_uv(Round(10), Period(3), Step(5));
        assert!(vote_fresh(&fd, &vote2).is_err());
    }

    // ---- bundle_fresh edge cases ----

    #[test]
    fn bundle_fresh_cert_bundle_always_fresh() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(5),
            player_step: SOFT,
            player_last_concluding: Step(0),
        };
        // Cert bundles are always fresh regardless of period
        let b = crate::bundle::UnauthenticatedBundle {
            round: Round(10),
            period: Period(0),
            step: CERT,
            proposal: BOTTOM,
            votes: vec![],
            equivocation_votes: vec![],
        };
        assert!(bundle_fresh(&fd, &b).is_ok());
    }

    #[test]
    fn bundle_fresh_stale_non_cert_bundle() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(5),
            player_step: SOFT,
            player_last_concluding: Step(0),
        };
        // Non-cert bundle from period 2 (5-1=4 > 2), should be stale
        let b = crate::bundle::UnauthenticatedBundle {
            round: Round(10),
            period: Period(2),
            step: Step(3), // next
            proposal: BOTTOM,
            votes: vec![],
            equivocation_votes: vec![],
        };
        assert!(bundle_fresh(&fd, &b).is_err());
    }

    // ---- proposal_useful_for_credential_history tests ----

    #[test]
    fn proposal_useful_for_credential_history_recent_round() {
        let lag = credential_round_lag();
        // Vote from round 5, player at round 5 + lag = 13
        let uv = make_uv(Round(5), Period(0), Step(0));
        assert!(proposal_useful_for_credential_history(Round(5 + lag), &uv));
    }

    #[test]
    fn proposal_useful_for_credential_history_too_old() {
        let lag = credential_round_lag();
        // Vote from round 5, player at round 5 + lag + 1 = 14
        let uv = make_uv(Round(5), Period(0), Step(0));
        assert!(!proposal_useful_for_credential_history(
            Round(5 + lag + 1),
            &uv
        ));
    }

    #[test]
    fn proposal_useful_for_credential_history_nonzero_period() {
        let lag = credential_round_lag();
        // Vote from round 5, period 1 (not period 0) -> not useful
        let uv = make_uv(Round(5), Period(1), Step(0));
        assert!(!proposal_useful_for_credential_history(Round(5 + lag), &uv));
    }

    #[test]
    fn proposal_useful_for_credential_history_nonzero_step() {
        let lag = credential_round_lag();
        // Vote from round 5, period 0, step 1 (not step 0) -> not useful
        let uv = make_uv(Round(5), Period(0), Step(1));
        assert!(!proposal_useful_for_credential_history(Round(5 + lag), &uv));
    }

    #[test]
    fn proposal_useful_for_credential_history_current_round() {
        // Vote from current round (not old) -> not useful
        let uv = make_uv(Round(10), Period(0), Step(0));
        assert!(!proposal_useful_for_credential_history(Round(10), &uv));
    }

    // ---- vote_step_fresh edge cases ----

    #[test]
    fn vote_step_fresh_stale_step() {
        // Steps <= NEXT (3) are always propagated, so we need to use steps > NEXT
        // and < LATE. mine = 10, vote = 5 => 10-1=9 > 5, filtered
        assert!(vote_step_fresh("test", Step(10), Step(5)).is_err());
    }

    #[test]
    fn vote_step_fresh_premature_step() {
        // mine = 5, vote = 8 => 5+1=6 < 8, filtered (but only if not in always-propagated range)
        // Steps 4..252 fall between NEXT(3) and LATE(253), so they go through the check
        assert!(vote_step_fresh("test", Step(5), Step(8)).is_err());
    }

    #[test]
    fn vote_step_fresh_adjacent_steps() {
        // mine = 5, vote = 4 => 5-1=4 <= 4, ok
        assert!(vote_step_fresh("test", Step(5), Step(4)).is_ok());
        // mine = 5, vote = 6 => 5+1=6 >= 6, ok
        assert!(vote_step_fresh("test", Step(5), Step(6)).is_ok());
    }

    #[test]
    fn vote_step_fresh_mine_zero() {
        // When mine is 0, the subtraction wrapping check: 0 != 0 is false,
        // so the stale check is skipped. vote = 0 should be fine.
        assert!(vote_step_fresh("test", Step(0), Step(0)).is_ok());
    }

    // ---- proposal_fresh edge cases ----

    #[test]
    fn proposal_fresh_period_0_adjacent_periods() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(0),
            player_step: Step(0),
            player_last_concluding: Step(0),
        };
        // Period 0 with player_period 0: period - 1 wraps, so no stale check
        let vote = make_uv(Round(10), Period(0), Step(0));
        assert!(proposal_fresh(&fd, &vote).is_ok());

        // Period 1 with player_period 0: 0 + 1 = 1 >= 1, ok
        let vote = make_uv(Round(10), Period(1), Step(0));
        assert!(proposal_fresh(&fd, &vote).is_ok());
    }

    #[test]
    fn proposal_fresh_premature_period() {
        let fd = FreshnessData {
            player_round: Round(10),
            player_period: Period(2),
            player_step: Step(0),
            player_last_concluding: Step(0),
        };
        // Period 4 with player_period 2: 2 + 1 = 3 < 4, premature
        let vote = make_uv(Round(10), Period(4), Step(0));
        assert!(proposal_fresh(&fd, &vote).is_err());
    }

    // ---- Helpers ----

    fn make_zero_sig() -> OneTimeSignature {
        OneTimeSignature {
            sig: [0u8; 64],
            pk: [0u8; 32],
            pk_sig_old: [0u8; 64],
            pk2: [0u8; 32],
            pk1_sig: [0u8; 64],
            pk2_sig: [0u8; 64],
        }
    }

    fn make_uv(round: Round, period: Period, step: Step) -> UnauthenticatedVote {
        UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round,
                period,
                step,
                proposal: ProposalValue {
                    original_period: Period(0),
                    original_proposer: Address([0x01; 32]),
                    block_digest: Digest([0xaa; 32]),
                    encoding_digest: Digest([0xbb; 32]),
                },
            },
            cred: UnauthenticatedCredential::new([0u8; 80]),
            sig: make_zero_sig(),
        }
    }

    fn test_params() -> ConsensusParams {
        algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
            .expect("v41 params")
    }
}
