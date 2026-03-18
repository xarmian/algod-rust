// Step and Period types, matching go-algorand/agreement/types.go.
//
// Step maps directly to committee-size / threshold parameters in
// ConsensusParams via `committee_size` and `committee_threshold`.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use algo_types::ConsensusParams;

/// Proposal step — the leader broadcasts a candidate block.
pub const PROPOSE: Step = Step(0);
/// Soft-vote step — committee members vote to narrow to one proposal.
pub const SOFT: Step = Step(1);
/// Cert-vote step — committee members certify the chosen proposal.
pub const CERT: Step = Step(2);
/// Next-vote step — first recovery step (and default for higher steps).
pub const NEXT: Step = Step(3);
/// Late recovery step (fast partition recovery).
pub const LATE: Step = Step(253);
/// Redo recovery step.
pub const REDO: Step = Step(254);
/// Down recovery step.
pub const DOWN: Step = Step(255);

/// A step in the agreement protocol, wrapping a `u64`.
///
/// Matches Go: `type step uint64`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Step(pub u64);

impl Step {
    /// Returns the committee size for this step, pulling the appropriate
    /// parameter from `ConsensusParams`.
    ///
    /// Mirrors `(step).committeeSize` in go-algorand/agreement/types.go.
    pub fn committee_size(&self, params: &ConsensusParams) -> u64 {
        match self.0 {
            0 => params.num_proposers,
            1 => params.soft_committee_size,
            2 => params.cert_committee_size,
            253 => params.late_committee_size,
            254 => params.redo_committee_size,
            255 => params.down_committee_size,
            // next (3) and all other numbered steps use NextCommitteeSize
            _ => params.next_committee_size,
        }
    }

    /// Returns the vote-weight threshold for this step.
    ///
    /// Mirrors `(step).threshold` in go-algorand/agreement/types.go.
    /// For `propose` (step 0) the threshold is 0 — there is no quorum
    /// check for proposals.
    pub fn committee_threshold(&self, params: &ConsensusParams) -> u64 {
        match self.0 {
            0 => 0, // propose — no threshold
            1 => params.soft_committee_threshold,
            2 => params.cert_committee_threshold,
            253 => params.late_committee_threshold,
            254 => params.redo_committee_threshold,
            255 => params.down_committee_threshold,
            _ => params.next_committee_threshold,
        }
    }

    /// Returns `true` when `weight` reaches the quorum threshold for this step.
    ///
    /// Mirrors `(step).reachesQuorum` in go-algorand/agreement/types.go.
    /// Propose always returns `false` (Go logs a warning).
    pub fn reaches_quorum(&self, params: &ConsensusParams, weight: u64) -> bool {
        if self.0 == 0 {
            // Go: logging.Base().Warn("Called Propose.ReachesQuorum"); return false
            return false;
        }
        weight >= self.committee_threshold(params)
    }

    /// Returns the lower and upper time bounds for sending a next-vote at this
    /// step.
    ///
    /// The bounds are calculated relative to the start of the current period.
    /// The first next-vote fires at `deadline_timeout` and each subsequent step
    /// doubles the extra timeout.
    ///
    /// Mirrors Go's `(step).nextVoteRanges` in agreement/types.go.
    ///
    /// # Arguments
    ///
    /// * `deadline_timeout` - the deadline timeout for the current period
    ///   (from `DeadlineTimeout()`).
    pub fn next_vote_ranges(&self, deadline_timeout: Duration) -> (Duration, Duration) {
        // recoveryExtraTimeout = SmallLambda = 2000ms
        let recovery_extra_timeout = Duration::from_millis(2000);

        let mut extra = recovery_extra_timeout;
        let mut lower = deadline_timeout;
        let mut upper = lower + extra;

        // For each step above `next`, double the extra timeout
        let mut i = NEXT.0;
        while i < self.0 {
            extra *= 2;
            lower = upper;
            upper = lower + extra;
            i += 1;
        }

        (lower, upper)
    }
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => write!(f, "propose"),
            1 => write!(f, "soft"),
            2 => write!(f, "cert"),
            3 => write!(f, "next"),
            253 => write!(f, "late"),
            254 => write!(f, "redo"),
            255 => write!(f, "down"),
            n => write!(f, "next+{}", n - 3),
        }
    }
}

/// A period in the agreement protocol, wrapping a `u64`.
///
/// Matches Go: `type period uint64`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Period(pub u64);

impl std::fmt::Display for Period {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::consensus::consensus_params_for_version;

    /// Helper: get current (v41) consensus params for testing.
    fn v41_params() -> ConsensusParams {
        consensus_params_for_version(algo_types::CONSENSUS_V41).expect("v41 params must exist")
    }

    #[test]
    fn committee_size_propose() {
        let p = v41_params();
        assert_eq!(PROPOSE.committee_size(&p), p.num_proposers);
    }

    #[test]
    fn committee_size_soft() {
        let p = v41_params();
        assert_eq!(SOFT.committee_size(&p), p.soft_committee_size);
    }

    #[test]
    fn committee_size_cert() {
        let p = v41_params();
        assert_eq!(CERT.committee_size(&p), p.cert_committee_size);
    }

    #[test]
    fn committee_size_next() {
        let p = v41_params();
        assert_eq!(NEXT.committee_size(&p), p.next_committee_size);
    }

    #[test]
    fn committee_size_late() {
        let p = v41_params();
        assert_eq!(LATE.committee_size(&p), p.late_committee_size);
    }

    #[test]
    fn committee_size_redo() {
        let p = v41_params();
        assert_eq!(REDO.committee_size(&p), p.redo_committee_size);
    }

    #[test]
    fn committee_size_down() {
        let p = v41_params();
        assert_eq!(DOWN.committee_size(&p), p.down_committee_size);
    }

    #[test]
    fn committee_size_higher_step_uses_next() {
        let p = v41_params();
        // Steps 4..252 should all use NextCommitteeSize
        for s in [4u64, 10, 100, 252] {
            assert_eq!(
                Step(s).committee_size(&p),
                p.next_committee_size,
                "step {} should use next_committee_size",
                s
            );
        }
    }

    #[test]
    fn threshold_propose_is_zero() {
        let p = v41_params();
        assert_eq!(PROPOSE.committee_threshold(&p), 0);
    }

    #[test]
    fn threshold_soft() {
        let p = v41_params();
        assert_eq!(SOFT.committee_threshold(&p), p.soft_committee_threshold);
    }

    #[test]
    fn threshold_cert() {
        let p = v41_params();
        assert_eq!(CERT.committee_threshold(&p), p.cert_committee_threshold);
    }

    #[test]
    fn threshold_next_and_higher() {
        let p = v41_params();
        assert_eq!(NEXT.committee_threshold(&p), p.next_committee_threshold);
        assert_eq!(Step(7).committee_threshold(&p), p.next_committee_threshold);
    }

    #[test]
    fn threshold_late() {
        let p = v41_params();
        assert_eq!(LATE.committee_threshold(&p), p.late_committee_threshold);
    }

    #[test]
    fn threshold_redo() {
        let p = v41_params();
        assert_eq!(REDO.committee_threshold(&p), p.redo_committee_threshold);
    }

    #[test]
    fn threshold_down() {
        let p = v41_params();
        assert_eq!(DOWN.committee_threshold(&p), p.down_committee_threshold);
    }

    #[test]
    fn reaches_quorum_propose_always_false() {
        let p = v41_params();
        assert!(!PROPOSE.reaches_quorum(&p, u64::MAX));
    }

    #[test]
    fn reaches_quorum_soft() {
        let p = v41_params();
        assert!(!SOFT.reaches_quorum(&p, p.soft_committee_threshold - 1));
        assert!(SOFT.reaches_quorum(&p, p.soft_committee_threshold));
        assert!(SOFT.reaches_quorum(&p, p.soft_committee_threshold + 1));
    }

    #[test]
    fn reaches_quorum_cert() {
        let p = v41_params();
        assert!(!CERT.reaches_quorum(&p, p.cert_committee_threshold - 1));
        assert!(CERT.reaches_quorum(&p, p.cert_committee_threshold));
    }

    #[test]
    fn display_step() {
        assert_eq!(format!("{}", PROPOSE), "propose");
        assert_eq!(format!("{}", SOFT), "soft");
        assert_eq!(format!("{}", CERT), "cert");
        assert_eq!(format!("{}", NEXT), "next");
        assert_eq!(format!("{}", LATE), "late");
        assert_eq!(format!("{}", REDO), "redo");
        assert_eq!(format!("{}", DOWN), "down");
        assert_eq!(format!("{}", Step(5)), "next+2");
    }

    #[test]
    fn period_display() {
        assert_eq!(format!("{}", Period(0)), "0");
        assert_eq!(format!("{}", Period(42)), "42");
    }
}
