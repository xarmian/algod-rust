// Period-level and round-level vote tracking.
//
// Mirrors go-algorand/agreement/voteAuxiliary.go.
//
// VoteTrackerPeriod manages VoteTrackers for each step within a period and
// caches next-threshold status. VoteTrackerRound manages VoteTrackerPeriods
// for each period within a round and tracks the freshest bundle.

use std::collections::HashMap;

use algo_types::ConsensusParams;

use crate::events::{
    EmptyEvent, Event, EventType, FreshestBundleEvent, NextThresholdStatusEvent, ThresholdEvent,
};
use crate::step::{Period, Step, NEXT};
use crate::vote::BOTTOM;
use crate::vote_tracker::VoteTracker;

// ---------------------------------------------------------------------------
// VoteTrackerPeriod
// ---------------------------------------------------------------------------

/// Per-(round, period) vote tracker that manages VoteTrackers for each step
/// and caches next-threshold status.
///
/// Mirrors Go's `voteTrackerPeriod` in agreement/voteAuxiliary.go.
#[derive(Debug, Clone, Default)]
pub struct VoteTrackerPeriod {
    /// Per-step VoteTrackers within this period.
    trackers: HashMap<Step, VoteTracker>,

    /// Cached next-threshold status for this period.
    cached: NextThresholdStatusEvent,
}

impl VoteTrackerPeriod {
    /// Returns a mutable reference to the VoteTracker for the given step,
    /// creating one if it does not exist.
    fn tracker_for_step(&mut self, step: Step) -> &mut VoteTracker {
        self.trackers.entry(step).or_default()
    }

    /// Handles an incoming event for this period.
    ///
    /// Handles event types: VoteAccepted, NextThreshold, NextThresholdStatusRequest.
    ///
    /// Mirrors Go's `voteTrackerPeriod.handle()`.
    pub fn handle(&mut self, event: &Event, params: &ConsensusParams) -> Event {
        match event.event_type() {
            EventType::VoteAccepted => {
                let e = match event {
                    Event::VoteAccepted(e) => e,
                    _ => unreachable!(),
                };
                let step = e.vote.raw_vote.step;

                // Forward to the step-level tracker
                let tracker = self.tracker_for_step(step);
                let result = tracker.handle(event, params);

                // If a next-threshold was emitted, dispatch to self for caching
                if result.event_type() != EventType::None {
                    if let Event::Threshold(ref te) = result {
                        if te.step >= NEXT {
                            self.handle_next_threshold(te);
                        }
                    }
                }

                // Return the threshold event (or none) back to the round
                result
            }
            EventType::NextThreshold => {
                // Cache next thresholds
                if let Event::Threshold(te) = event {
                    self.handle_next_threshold(te);
                }
                Event::Empty(EmptyEvent)
            }
            EventType::NextThresholdStatusRequest => {
                Event::NextThresholdStatus(self.cached.clone())
            }
            EventType::VoteFilterRequest => {
                // Forward filter requests to the appropriate step tracker
                if let Event::VoteFilterRequest(e) = event {
                    let step = e.raw_vote.step;
                    let tracker = self.tracker_for_step(step);
                    tracker.handle(event, params)
                } else {
                    unreachable!()
                }
            }
            EventType::DumpVotesRequest => {
                // Forward to all step trackers, aggregate results
                let mut all_votes = Vec::new();
                for tracker in self.trackers.values_mut() {
                    let result = tracker.handle(event, params);
                    if let Event::DumpVotes(dv) = result {
                        all_votes.extend(dv.votes);
                    }
                }
                Event::DumpVotes(crate::events::DumpVotesEvent { votes: all_votes })
            }
            _ => {
                panic!(
                    "voteTrackerPeriod: bad event type: observed an event of type {:?}",
                    event.event_type()
                );
            }
        }
    }

    /// Cache a next-threshold event.
    fn handle_next_threshold(&mut self, te: &ThresholdEvent) {
        if te.proposal == BOTTOM {
            self.cached.bottom = true;
        } else {
            self.cached.proposal = te.proposal;
        }
    }
}

// ---------------------------------------------------------------------------
// VoteTrackerRound
// ---------------------------------------------------------------------------

/// Per-round vote tracker that manages VoteTrackerPeriods for each period
/// and tracks the freshest bundle seen.
///
/// Mirrors Go's `voteTrackerRound` in agreement/voteAuxiliary.go.
#[derive(Debug, Clone, Default)]
pub struct VoteTrackerRound {
    /// Per-period VoteTrackerPeriods within this round.
    periods: HashMap<Period, VoteTrackerPeriod>,

    /// The freshest threshold event seen this round.
    freshest: ThresholdEvent,

    /// True if any threshold event has been seen.
    ok: bool,
}

impl VoteTrackerRound {
    /// Returns a mutable reference to the VoteTrackerPeriod for the given
    /// period, creating one if it does not exist.
    fn tracker_for_period(&mut self, period: Period) -> &mut VoteTrackerPeriod {
        self.periods.entry(period).or_default()
    }

    /// Handles an incoming event for this round.
    ///
    /// Handles event types: VoteAccepted, SoftThreshold, CertThreshold,
    /// NextThreshold, FreshestBundleRequest.
    ///
    /// Mirrors Go's `voteTrackerRound.handle()`.
    pub fn handle(&mut self, event: &Event, params: &ConsensusParams) -> Event {
        match event.event_type() {
            EventType::VoteAccepted => {
                let period = match event {
                    Event::VoteAccepted(e) => e.vote.raw_vote.period,
                    _ => unreachable!(),
                };

                // Forward to the period-level tracker
                let period_tracker = self.tracker_for_period(period);
                let result = period_tracker.handle(event, params);

                // If a threshold event was emitted, dispatch to self for
                // freshest bundle tracking
                if result.event_type() != EventType::None {
                    return self.handle_threshold(&result);
                }

                Event::Empty(EmptyEvent)
            }
            EventType::SoftThreshold | EventType::CertThreshold | EventType::NextThreshold => {
                self.handle_threshold(event)
            }
            EventType::FreshestBundleRequest => Event::FreshestBundle(FreshestBundleEvent {
                ok: self.ok,
                event: self.freshest.clone(),
            }),
            EventType::VoteFilterRequest => {
                // Forward filter requests to the appropriate period tracker
                if let Event::VoteFilterRequest(e) = event {
                    let period = e.raw_vote.period;
                    let period_tracker = self.tracker_for_period(period);
                    period_tracker.handle(event, params)
                } else {
                    unreachable!()
                }
            }
            EventType::NextThresholdStatusRequest => {
                // This is a period-level query; we need to know which period.
                // In Go, dispatch routes this based on coordinates.
                // For now, panic as this should be routed through period tracker.
                panic!("voteTrackerRound: nextThresholdStatusRequest should be dispatched to period tracker directly");
            }
            EventType::DumpVotesRequest => {
                // Forward to all period trackers
                let mut all_votes = Vec::new();
                for period_tracker in self.periods.values_mut() {
                    let result = period_tracker.handle(event, params);
                    if let Event::DumpVotes(dv) = result {
                        all_votes.extend(dv.votes);
                    }
                }
                Event::DumpVotes(crate::events::DumpVotesEvent { votes: all_votes })
            }
            _ => {
                panic!(
                    "voteTrackerRound: bad event type: observed an event of type {:?}",
                    event.event_type()
                );
            }
        }
    }

    /// Handle a threshold event, updating the freshest bundle if this event is
    /// fresher.
    fn handle_threshold(&mut self, event: &Event) -> Event {
        if let Event::Threshold(te) = event {
            if te.fresher_than(&self.freshest) {
                self.freshest = te.clone();
                self.ok = true;
                return event.clone();
            }
        }
        Event::Empty(EmptyEvent)
    }

    /// Returns the NextThresholdStatusEvent for a specific period.
    ///
    /// This is a convenience method for direct queries to a period tracker.
    pub fn next_threshold_status(&mut self, period: Period) -> NextThresholdStatusEvent {
        let period_tracker = self.tracker_for_period(period);
        let result = period_tracker.handle(
            &Event::NextThresholdStatusRequest(crate::events::NextThresholdStatusRequestEvent),
            &ConsensusParams::default(),
        );
        match result {
            Event::NextThresholdStatus(status) => status,
            _ => NextThresholdStatusEvent::default(),
        }
    }

    /// Returns the FreshestBundleEvent for this round.
    pub fn freshest_bundle(&self) -> FreshestBundleEvent {
        FreshestBundleEvent {
            ok: self.ok,
            event: self.freshest.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::Credential;
    use crate::events::VoteAcceptedEvent;
    use crate::step::SOFT;
    use crate::vote::{ProposalValue, RawVote, Vote};
    use algo_consensus_crypto::OneTimeSignature;
    use algo_types::{Address, Digest, Round};

    fn make_vote(
        sender: Address,
        round: Round,
        period: Period,
        step: Step,
        proposal: ProposalValue,
        weight: u64,
    ) -> Vote {
        Vote {
            raw_vote: RawVote {
                sender,
                round,
                period,
                step,
                proposal,
            },
            cred: Credential {
                weight,
                vrf_out: Digest([0u8; 32]),
                domain_separation_enabled: false,
                hashable: crate::credential::HashableCredential::default(),
                proof: [0u8; 80],
            },
            sig: OneTimeSignature {
                sig: [0u8; 64],
                pk: [0u8; 32],
                pk_sig_old: [0u8; 64],
                pk2: [0u8; 32],
                pk1_sig: [0u8; 64],
                pk2_sig: [0u8; 64],
            },
        }
    }

    fn test_params() -> ConsensusParams {
        algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
            .expect("v41 params")
    }

    fn test_proposal() -> ProposalValue {
        ProposalValue {
            original_period: Period(0),
            original_proposer: Address([0x01; 32]),
            block_digest: Digest([0xaa; 32]),
            encoding_digest: Digest([0xbb; 32]),
        }
    }

    #[test]
    fn vote_tracker_period_single_vote() {
        let mut period_tracker = VoteTrackerPeriod::default();
        let params = test_params();
        let vote = make_vote(
            Address([0x01; 32]),
            Round(1),
            Period(0),
            SOFT,
            test_proposal(),
            1,
        );
        let event = Event::VoteAccepted(VoteAcceptedEvent {
            vote,
            proto: String::new(),
        });
        let result = period_tracker.handle(&event, &params);
        // Single vote with weight 1 should not reach threshold
        assert_eq!(result.event_type(), EventType::None);
    }

    #[test]
    fn vote_tracker_period_caches_next_threshold_bottom() {
        let mut period_tracker = VoteTrackerPeriod::default();

        let te = ThresholdEvent {
            t: EventType::NextThreshold,
            round: Round(1),
            period: Period(0),
            step: NEXT,
            proposal: BOTTOM,
            ..ThresholdEvent::default()
        };
        period_tracker.handle_next_threshold(&te);

        assert!(period_tracker.cached.bottom);
        assert_eq!(period_tracker.cached.proposal, BOTTOM);
    }

    #[test]
    fn vote_tracker_period_caches_next_threshold_value() {
        let mut period_tracker = VoteTrackerPeriod::default();
        let proposal = test_proposal();

        let te = ThresholdEvent {
            t: EventType::NextThreshold,
            round: Round(1),
            period: Period(0),
            step: NEXT,
            proposal,
            ..ThresholdEvent::default()
        };
        period_tracker.handle_next_threshold(&te);

        assert!(!period_tracker.cached.bottom);
        assert_eq!(period_tracker.cached.proposal, proposal);
    }

    #[test]
    fn vote_tracker_round_freshest_bundle_empty() {
        let round_tracker = VoteTrackerRound::default();
        let fb = round_tracker.freshest_bundle();
        assert!(!fb.ok);
    }

    #[test]
    fn vote_tracker_round_threshold_updates_freshest() {
        let mut round_tracker = VoteTrackerRound::default();

        let te = Event::Threshold(ThresholdEvent {
            t: EventType::SoftThreshold,
            round: Round(1),
            period: Period(0),
            step: SOFT,
            proposal: test_proposal(),
            ..ThresholdEvent::default()
        });
        let result = round_tracker.handle_threshold(&te);
        assert_eq!(result.event_type(), EventType::SoftThreshold);
        assert!(round_tracker.ok);
    }

    #[test]
    fn vote_tracker_round_cert_fresher_than_soft() {
        let mut round_tracker = VoteTrackerRound::default();

        // First a soft threshold
        let soft_te = Event::Threshold(ThresholdEvent {
            t: EventType::SoftThreshold,
            round: Round(1),
            period: Period(0),
            step: SOFT,
            proposal: test_proposal(),
            ..ThresholdEvent::default()
        });
        round_tracker.handle_threshold(&soft_te);

        // Then a cert threshold (should be fresher)
        let cert_te = Event::Threshold(ThresholdEvent {
            t: EventType::CertThreshold,
            round: Round(1),
            period: Period(0),
            step: Step(2),
            proposal: test_proposal(),
            ..ThresholdEvent::default()
        });
        let result = round_tracker.handle_threshold(&cert_te);
        assert_eq!(result.event_type(), EventType::CertThreshold);
    }

    #[test]
    fn vote_tracker_round_stale_threshold_dropped() {
        let mut round_tracker = VoteTrackerRound::default();

        // First a cert threshold
        let cert_te = Event::Threshold(ThresholdEvent {
            t: EventType::CertThreshold,
            round: Round(1),
            period: Period(0),
            step: Step(2),
            proposal: test_proposal(),
            ..ThresholdEvent::default()
        });
        round_tracker.handle_threshold(&cert_te);

        // Then a soft threshold (should be dropped as stale)
        let soft_te = Event::Threshold(ThresholdEvent {
            t: EventType::SoftThreshold,
            round: Round(1),
            period: Period(0),
            step: SOFT,
            proposal: test_proposal(),
            ..ThresholdEvent::default()
        });
        let result = round_tracker.handle_threshold(&soft_te);
        assert_eq!(result.event_type(), EventType::None);
    }
}
