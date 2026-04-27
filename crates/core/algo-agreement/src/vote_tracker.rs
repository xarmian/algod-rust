// Per-step vote tracking: duplication, equivocation, threshold detection, and
// bundle generation.
//
// Mirrors go-algorand/agreement/voteTracker.go.
//
// A VoteTracker handles votes for a single (round, period, step) tuple. It
// detects duplicate votes, equivocations (same sender voting for different
// proposals), counts vote weights per proposal, and emits threshold events when
// a quorum is reached.

use std::collections::HashMap;

use algo_consensus_crypto::OneTimeSignature;
use algo_types::{Address, ConsensusParams, Round};
use serde::{Deserialize, Serialize};

use crate::bundle::{EquivocationVoteAuthenticator, UnauthenticatedBundle, VoteAuthenticator};
use crate::credential::{Credential, UnauthenticatedCredential};
use crate::events::{
    DumpVotesEvent, EmptyEvent, Event, EventType, FilteredStepEvent, ThresholdEvent,
    VoteAcceptedEvent, VoteFilterRequestEvent,
};
use crate::step::{Period, Step, CERT, SOFT};
use crate::vote::{ProposalValue, RawVote, UnauthenticatedVote, Vote};

// ---------------------------------------------------------------------------
// EquivocationVote — internal verified equivocation vote pair
// ---------------------------------------------------------------------------

/// A verified equivocation vote — a pair of votes from the same sender that
/// votes for two different proposals.
///
/// Mirrors Go's `equivocationVote` in agreement/vote.go.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationVote {
    /// The sender of the equivocating votes.
    pub sender: Address,
    /// The round of the equivocating votes.
    pub round: Round,
    /// The period of the equivocating votes.
    pub period: Period,
    /// The step of the equivocating votes.
    pub step: Step,
    /// The verified credential (from the first vote).
    pub cred: Credential,
    /// The two conflicting proposal values.
    pub proposals: [ProposalValue; 2],
    /// The two OTS signatures.
    pub sigs: [OneTimeSignature; 2],
}

impl EquivocationVote {
    /// Returns the first vote of the equivocation pair.
    ///
    /// Mirrors Go's `equivocationVote.v0()`.
    pub fn v0(&self) -> Vote {
        Vote {
            raw_vote: RawVote {
                sender: self.sender,
                round: self.round,
                period: self.period,
                step: self.step,
                proposal: self.proposals[0],
            },
            cred: self.cred.clone(),
            sig: self.sigs[0].clone(),
        }
    }

    /// Returns the second vote of the equivocation pair.
    ///
    /// Mirrors Go's `equivocationVote.v1()`.
    pub fn v1(&self) -> Vote {
        Vote {
            raw_vote: RawVote {
                sender: self.sender,
                round: self.round,
                period: self.period,
                step: self.step,
                proposal: self.proposals[1],
            },
            cred: self.cred.clone(),
            sig: self.sigs[1].clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// ProposalVoteCounter
// ---------------------------------------------------------------------------

/// Tracks the count and individual votes for a specific proposal value.
///
/// Mirrors Go's `proposalVoteCounter`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ProposalVoteCounter {
    /// Accumulated weight of votes for this proposal.
    count: u64,
    /// Individual votes keyed by sender address.
    votes: HashMap<Address, Vote>,
}

// ---------------------------------------------------------------------------
// VoteTracker
// ---------------------------------------------------------------------------

/// Per-(round, period, step) vote tracker.
///
/// Handles duplication and equivocation detection, counts votes, and emits
/// threshold events.
///
/// Mirrors Go's `voteTracker` in agreement/voteTracker.go.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VoteTracker {
    /// Set of voters who have voted in this step. Used to detect equivocation.
    voters: HashMap<Address, Vote>,

    /// Weighted vote counts per proposal value, along with individual votes.
    counts: HashMap<ProposalValue, ProposalVoteCounter>,

    /// Set of voters who have already equivocated once. Future votes from
    /// these voters are dropped and not propagated.
    equivocators: HashMap<Address, EquivocationVote>,

    /// Total weight of equivocating votes (counts toward any proposal).
    equivocators_count: u64,
}

impl VoteTracker {
    /// Returns the total vote weight for a proposal: direct votes plus
    /// equivocator weight.
    ///
    /// Mirrors Go's `voteTracker.count()`.
    fn count(&self, proposal: &ProposalValue) -> u64 {
        let direct = self.counts.get(proposal).map_or(0, |pc| pc.count);
        direct + self.equivocators_count
    }

    /// Returns an arbitrary proposal that is over the step threshold, or `None`
    /// if none exists.
    ///
    /// Mirrors Go's `voteTracker.overThreshold()`.
    fn over_threshold(&self, params: &ConsensusParams, step: Step) -> Option<ProposalValue> {
        let mut result: Option<ProposalValue> = None;
        for proposal in self.counts.keys() {
            if step.reaches_quorum(params, self.count(proposal)) {
                if result.is_some() {
                    panic!("voteTracker: more than one value reached a threshold in a given step");
                }
                result = Some(*proposal);
            }
        }
        result
    }

    /// Generates a bundle which proves that a quorum of votes exists for the
    /// given proposal value.
    ///
    /// Mirrors Go's `voteTracker.genBundle()`.
    fn gen_bundle(
        &self,
        params: &ConsensusParams,
        proposal: ProposalValue,
        proposal_votes: &ProposalVoteCounter,
    ) -> UnauthenticatedBundle {
        // Collect all votes for the proposal and sort by weight descending,
        // then by sender address descending for deterministic ordering.
        let mut votes: Vec<Vote> = proposal_votes.votes.values().cloned().collect();
        votes.sort_by(|a, b| {
            b.cred
                .weight
                .cmp(&a.cred.weight)
                .then_with(|| b.raw_vote.sender.0.cmp(&a.raw_vote.sender.0))
        });

        // Pack votes until quorum is reached
        let step = votes.first().map(|v| v.raw_vote.step).unwrap_or(Step(0));
        let mut cutoff = 0;
        let mut weight: u64 = 0;
        while !step.reaches_quorum(params, weight) && cutoff < votes.len() {
            weight += votes[cutoff].cred.weight;
            cutoff += 1;
        }
        let votes_for_bundle = &votes[..cutoff];

        // Pack equivocation votes similarly
        let mut equi_pairs: Vec<EquivocationVote> = self.equivocators.values().cloned().collect();
        equi_pairs.sort_by(|a, b| {
            b.cred
                .weight
                .cmp(&a.cred.weight)
                .then_with(|| b.sender.0.cmp(&a.sender.0))
        });
        let mut equi_cutoff = 0;
        while !step.reaches_quorum(params, weight) && equi_cutoff < equi_pairs.len() {
            weight += equi_pairs[equi_cutoff].cred.weight;
            equi_cutoff += 1;
        }
        let equi_for_bundle = &equi_pairs[..equi_cutoff];

        make_bundle(params, proposal, votes_for_bundle, equi_for_bundle)
    }

    /// Handles an incoming event. Returns a threshold event if a quorum was
    /// newly reached, or an empty/default threshold event otherwise.
    ///
    /// Handles event types: VoteAccepted, VoteFilterRequest, DumpVotesRequest.
    ///
    /// Mirrors Go's `voteTracker.handle()`.
    pub fn handle(&mut self, event: &Event, params: &ConsensusParams) -> Event {
        match event {
            Event::VoteAccepted(e) => self.handle_vote_accepted(e, params),
            Event::VoteFilterRequest(e) => self.handle_vote_filter_request(e),
            Event::DumpVotesRequest(_) => self.handle_dump_votes_request(),
            _ => {
                panic!(
                    "voteTracker: bad event type: observed an event of type {:?}",
                    event.event_type()
                );
            }
        }
    }

    /// Process a vote-accepted event.
    fn handle_vote_accepted(&mut self, e: &VoteAcceptedEvent, params: &ConsensusParams) -> Event {
        let sender = e.vote.raw_vote.sender;

        // Check if sender is already a known equivocator — drop
        if self.equivocators.contains_key(&sender) {
            return Event::Threshold(ThresholdEvent::default());
        }

        let over_before = self.over_threshold(params, e.vote.raw_vote.step);

        if let Some(old_vote) = self.voters.get(&sender).cloned() {
            // Sender already voted
            if old_vote.raw_vote.proposal == e.vote.raw_vote.proposal {
                // Duplicate vote for the same proposal — silently drop
                return Event::Threshold(ThresholdEvent::default());
            }

            // Equivocation detected: sender voted for a different proposal
            self.equivocators_count += e.vote.cred.weight;

            if e.vote
                .raw_vote
                .step
                .reaches_quorum(params, self.equivocators_count)
            {
                panic!(
                    "too many equivocators for step {:?}: {}",
                    e.vote.raw_vote.step, self.equivocators_count
                );
            }

            // Decrease their weight from the proposal they previously voted for
            let old_proposal = old_vote.raw_vote.proposal;
            if let Some(pvc) = self.counts.get(&old_proposal) {
                if pvc.count <= old_vote.cred.weight {
                    // This was the only vote for this proposal
                    self.counts.remove(&old_proposal);
                } else {
                    let pvc = self.counts.get_mut(&old_proposal).unwrap();
                    pvc.count -= old_vote.cred.weight;
                    pvc.votes.remove(&sender);
                }
            }

            // Mark the sender as an equivocator
            self.equivocators.insert(
                sender,
                EquivocationVote {
                    sender: old_vote.raw_vote.sender,
                    round: old_vote.raw_vote.round,
                    period: old_vote.raw_vote.period,
                    step: old_vote.raw_vote.step,
                    cred: old_vote.cred.clone(),
                    proposals: [old_vote.raw_vote.proposal, e.vote.raw_vote.proposal],
                    sigs: [old_vote.sig.clone(), e.vote.sig.clone()],
                },
            );

            // Remove the equivocator from the set of regular voters
            self.voters.remove(&sender);

            // If no regular voters remain, we can't generate a bundle
            if self.voters.is_empty() {
                return Event::Threshold(ThresholdEvent::default());
            }
        } else {
            // First vote from this sender
            self.voters.insert(sender, e.vote.clone());

            let pvc = self.counts.entry(e.vote.raw_vote.proposal).or_default();
            pvc.count += e.vote.cred.weight;
            pvc.votes.insert(sender, e.vote.clone());
        }

        let over_after = self.over_threshold(params, e.vote.raw_vote.step);

        if over_before.is_some() || over_after.is_none() {
            return Event::Threshold(ThresholdEvent::default());
        }

        // Threshold just reached — generate the appropriate event
        let prop = over_after.unwrap();
        let proposal_votes = self.counts.get(&prop).unwrap();

        let round = e.vote.raw_vote.round;
        let period = e.vote.raw_vote.period;
        let step = e.vote.raw_vote.step;

        let t = match step {
            SOFT => EventType::SoftThreshold,
            CERT => EventType::CertThreshold,
            _ => EventType::NextThreshold,
        };

        let bundle = self.gen_bundle(params, prop, proposal_votes);

        Event::Threshold(ThresholdEvent {
            t,
            round,
            period,
            step,
            proposal: prop,
            bundle,
            proto: e.proto.clone(),
        })
    }

    /// Process a vote-filter-request event.
    fn handle_vote_filter_request(&self, e: &VoteFilterRequestEvent) -> Event {
        // Check if sender is a known equivocator
        if self.equivocators.contains_key(&e.raw_vote.sender) {
            return Event::FilteredStep(FilteredStepEvent {
                t: EventType::VoteFilteredStep,
            });
        }

        // Check if sender already voted for the same proposal
        if let Some(v) = self.voters.get(&e.raw_vote.sender) {
            if e.raw_vote.proposal == v.raw_vote.proposal {
                return Event::FilteredStep(FilteredStepEvent {
                    t: EventType::VoteFilteredStep,
                });
            }
        }

        Event::Empty(EmptyEvent)
    }

    /// Process a dump-votes-request event.
    fn handle_dump_votes_request(&self) -> Event {
        let mut votes: Vec<UnauthenticatedVote> =
            Vec::with_capacity(self.voters.len() + 2 * self.equivocators.len());

        for v in self.voters.values() {
            votes.push(v.to_unauthenticated());
        }
        for ev in self.equivocators.values() {
            votes.push(ev.v0().to_unauthenticated());
            votes.push(ev.v1().to_unauthenticated());
        }

        Event::DumpVotes(DumpVotesEvent { votes })
    }
}

// ---------------------------------------------------------------------------
// make_bundle — free function mirroring Go's makeBundle
// ---------------------------------------------------------------------------

/// Creates an unauthenticated bundle from the given votes and equivocation
/// votes.
///
/// Mirrors Go's `makeBundle()` in agreement/bundle.go.
fn make_bundle(
    params: &ConsensusParams,
    target_proposal: ProposalValue,
    votes: &[Vote],
    equivocation_votes: &[EquivocationVote],
) -> UnauthenticatedBundle {
    assert!(
        !votes.is_empty(),
        "makeBundle: no votes present in bundle (len(equivocationVotes) = {})",
        equivocation_votes.len()
    );

    // Verify all votes are for the target proposal
    for v in votes {
        assert_eq!(
            v.raw_vote.proposal, target_proposal,
            "makeBundle: invalid vote passed into function"
        );
    }

    let step = votes[0].raw_vote.step;
    let mut packed_so_far: u64 = 0;

    // Pack regular votes until quorum
    let mut cert_votes: Vec<VoteAuthenticator> = Vec::new();
    for v in votes {
        if step.reaches_quorum(params, packed_so_far) {
            break;
        }
        cert_votes.push(VoteAuthenticator {
            sender: v.raw_vote.sender,
            cred: UnauthenticatedCredential::new(v.cred.proof),
            sig: v.sig.clone(),
        });
        packed_so_far += v.cred.weight;
    }

    // Pack equivocation votes until quorum
    let mut cert_equi_votes: Vec<EquivocationVoteAuthenticator> = Vec::new();
    for ev in equivocation_votes {
        if step.reaches_quorum(params, packed_so_far) {
            break;
        }
        cert_equi_votes.push(EquivocationVoteAuthenticator {
            sender: ev.sender,
            cred: UnauthenticatedCredential::new(ev.cred.proof),
            sigs: ev.sigs.clone(),
            proposals: ev.proposals,
        });
        packed_so_far += ev.cred.weight;
    }

    assert!(
        step.reaches_quorum(params, packed_so_far),
        "not enough votes to generate bundle for {:?}: have {} < {}",
        target_proposal,
        packed_so_far,
        step.committee_threshold(params)
    );

    UnauthenticatedBundle {
        round: votes[0].raw_vote.round,
        period: votes[0].raw_vote.period,
        step: votes[0].raw_vote.step,
        proposal: target_proposal,
        votes: cert_votes,
        equivocation_votes: cert_equi_votes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::Digest;

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

    fn test_proposal_2() -> ProposalValue {
        ProposalValue {
            original_period: Period(0),
            original_proposer: Address([0x02; 32]),
            block_digest: Digest([0xcc; 32]),
            encoding_digest: Digest([0xdd; 32]),
        }
    }

    #[test]
    fn vote_tracker_empty_count() {
        let tracker = VoteTracker::default();
        assert_eq!(tracker.count(&test_proposal()), 0);
    }

    #[test]
    fn vote_tracker_single_vote() {
        let mut tracker = VoteTracker::default();
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
        let result = tracker.handle(&event, &params);
        // Single vote with weight 1 should not reach threshold
        assert_eq!(result.event_type(), EventType::None);
        assert_eq!(tracker.count(&test_proposal()), 1);
    }

    #[test]
    fn vote_tracker_duplicate_vote_same_proposal() {
        let mut tracker = VoteTracker::default();
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
            vote: vote.clone(),
            proto: String::new(),
        });
        tracker.handle(&event, &params);
        // Same vote again (duplicate)
        let result = tracker.handle(&event, &params);
        assert_eq!(result.event_type(), EventType::None);
        // Count should still be 1 (no double-counting)
        assert_eq!(tracker.count(&test_proposal()), 1);
    }

    #[test]
    fn vote_tracker_equivocation_detection() {
        let mut tracker = VoteTracker::default();
        let params = test_params();
        let sender = Address([0x01; 32]);

        // First vote for proposal A
        let vote1 = make_vote(sender, Round(1), Period(0), SOFT, test_proposal(), 1);
        let event1 = Event::VoteAccepted(VoteAcceptedEvent {
            vote: vote1,
            proto: String::new(),
        });
        tracker.handle(&event1, &params);

        // Second vote from same sender for proposal B (equivocation)
        let vote2 = make_vote(sender, Round(1), Period(0), SOFT, test_proposal_2(), 1);
        let event2 = Event::VoteAccepted(VoteAcceptedEvent {
            vote: vote2,
            proto: String::new(),
        });
        tracker.handle(&event2, &params);

        // Sender should be in equivocators
        assert!(tracker.equivocators.contains_key(&sender));
        assert!(!tracker.voters.contains_key(&sender));
        assert_eq!(tracker.equivocators_count, 1);
    }

    #[test]
    fn vote_tracker_filter_request_duplicate() {
        let mut tracker = VoteTracker::default();
        let params = test_params();
        let sender = Address([0x01; 32]);
        let proposal = test_proposal();

        let vote = make_vote(sender, Round(1), Period(0), SOFT, proposal, 1);
        let event = Event::VoteAccepted(VoteAcceptedEvent {
            vote,
            proto: String::new(),
        });
        tracker.handle(&event, &params);

        // Filter request for same sender, same proposal — should be filtered
        let filter_req = Event::VoteFilterRequest(VoteFilterRequestEvent {
            raw_vote: RawVote {
                sender,
                round: Round(1),
                period: Period(0),
                step: SOFT,
                proposal,
            },
        });
        let result = tracker.handle(&filter_req, &params);
        assert_eq!(result.event_type(), EventType::VoteFilteredStep);
    }

    #[test]
    fn vote_tracker_filter_request_equivocator() {
        let mut tracker = VoteTracker::default();
        let params = test_params();
        let sender = Address([0x01; 32]);

        // Create equivocation
        let vote1 = make_vote(sender, Round(1), Period(0), SOFT, test_proposal(), 1);
        let event1 = Event::VoteAccepted(VoteAcceptedEvent {
            vote: vote1,
            proto: String::new(),
        });
        tracker.handle(&event1, &params);

        let vote2 = make_vote(sender, Round(1), Period(0), SOFT, test_proposal_2(), 1);
        let event2 = Event::VoteAccepted(VoteAcceptedEvent {
            vote: vote2,
            proto: String::new(),
        });
        tracker.handle(&event2, &params);

        // Filter request for equivocator — should be filtered
        let filter_req = Event::VoteFilterRequest(VoteFilterRequestEvent {
            raw_vote: RawVote {
                sender,
                round: Round(1),
                period: Period(0),
                step: SOFT,
                proposal: test_proposal(),
            },
        });
        let result = tracker.handle(&filter_req, &params);
        assert_eq!(result.event_type(), EventType::VoteFilteredStep);
    }

    #[test]
    fn vote_tracker_dump_votes() {
        let mut tracker = VoteTracker::default();
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
        tracker.handle(&event, &params);

        let dump_req = Event::DumpVotesRequest(crate::events::DumpVotesRequestEvent);
        let result = tracker.handle(&dump_req, &params);
        if let Event::DumpVotes(dv) = result {
            assert_eq!(dv.votes.len(), 1);
        } else {
            panic!("expected DumpVotes event");
        }
    }

    #[test]
    fn vote_tracker_threshold_reached() {
        let mut tracker = VoteTracker::default();
        let params = test_params();
        let proposal = test_proposal();
        let threshold = SOFT.committee_threshold(&params);

        // Add enough votes to reach the threshold
        let mut last_result = Event::Empty(EmptyEvent);
        for i in 0..threshold {
            let sender = Address({
                let mut a = [0u8; 32];
                a[0] = (i & 0xff) as u8;
                a[1] = ((i >> 8) & 0xff) as u8;
                a
            });
            let vote = make_vote(sender, Round(1), Period(0), SOFT, proposal, 1);
            let event = Event::VoteAccepted(VoteAcceptedEvent {
                vote,
                proto: String::new(),
            });
            last_result = tracker.handle(&event, &params);
        }

        // The last vote should have triggered the threshold
        assert_eq!(last_result.event_type(), EventType::SoftThreshold);
        if let Event::Threshold(te) = last_result {
            assert_eq!(te.proposal, proposal);
            assert_eq!(te.round, Round(1));
            assert_eq!(te.period, Period(0));
            assert_eq!(te.step, SOFT);
        } else {
            panic!("expected Threshold event");
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // BF-2 tests (TASK-93): port of go-algorand
    // agreement/voteTracker_test.go.
    //
    // Helpers:
    //   - `index_address(i)`: stable per-test sender for vote-maker index `i`,
    //     mirroring Go's `voteMakerHelper` per-index Address fabrication.
    //   - `pv_with_digest(b)`: minimal proposal value distinguishable by
    //     `block_digest`, mirroring Go's `proposalValue{BlockDigest: hash}`
    //     pattern in vote_tracker tests.
    //
    // Two of the 13 Go tests assert panics that Go's `voteTrackerContract`
    // enforces as wrapper preconditions/postconditions around the bare
    // `voteTracker`. The Rust port has only the bare `VoteTracker` and no
    // contract layer, so those two are #[ignore]'d here with a pointer to
    // TASK-97 (port the contract-layer panics). All other 11 tests
    // exercise behavior that's already implemented and behaves the same
    // as Go.
    // ───────────────────────────────────────────────────────────────────

    /// Stable per-index sender address. Mirrors Go's
    /// `voteMakerHelper.addressIndex(i)` — the i'th address is
    /// deterministic but distinct from address j ≠ i.
    fn index_address(i: u64) -> Address {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&i.to_le_bytes());
        // Salt with a non-zero byte so index 0 doesn't collide with the
        // all-zero `BOTTOM`/default address used elsewhere in the tests.
        bytes[31] = 0x5a;
        Address(bytes)
    }

    /// Minimal proposal value distinguishable by `block_digest`. Mirrors
    /// the `proposalValue{BlockDigest: hash}` shape used by Go's
    /// vote_tracker tests, which only ever inspect the digest.
    fn pv_with_digest(b: u8) -> ProposalValue {
        ProposalValue {
            original_period: Period(0),
            original_proposer: Address([0u8; 32]),
            block_digest: Digest([b; 32]),
            encoding_digest: Digest([0u8; 32]),
        }
    }

    /// Drive a single VoteAccepted into the tracker.
    fn accept(
        tracker: &mut VoteTracker,
        params: &ConsensusParams,
        i: u64,
        step: Step,
        proposal: ProposalValue,
    ) -> Event {
        let vote = make_vote(index_address(i), Round(1), Period(0), step, proposal, 1);
        tracker.handle(
            &Event::VoteAccepted(VoteAcceptedEvent {
                vote,
                proto: String::new(),
            }),
            params,
        )
    }

    // -- Threshold boundary tests ---------------------------------------

    /// Port of `TestVoteTrackerSoftQuorum`. Exactly N=threshold votes →
    /// SoftThreshold on the last vote; N-1 votes → no threshold.
    #[test]
    fn vote_tracker_soft_quorum_boundary() {
        let params = test_params();
        let pv = test_proposal();
        let n = SOFT.committee_threshold(&params);

        // Exactly threshold votes → SoftThreshold on the last one.
        let mut tracker = VoteTracker::default();
        for i in 0..(n - 1) {
            assert_eq!(
                accept(&mut tracker, &params, i, SOFT, pv).event_type(),
                EventType::None,
                "vote {i} below threshold should not fire",
            );
        }
        let last = accept(&mut tracker, &params, n - 1, SOFT, pv);
        assert_eq!(last.event_type(), EventType::SoftThreshold);
        if let Event::Threshold(te) = last {
            assert_eq!(te.proposal, pv);
        }

        // Threshold − 1 votes → no SoftThreshold.
        let mut tracker = VoteTracker::default();
        for i in 0..(n - 1) {
            assert_eq!(
                accept(&mut tracker, &params, i, SOFT, pv).event_type(),
                EventType::None,
            );
        }
    }

    /// Port of `TestVoteTrackerCertQuorum`. Same shape as the soft case.
    #[test]
    fn vote_tracker_cert_quorum_boundary() {
        let params = test_params();
        let pv = test_proposal();
        let n = CERT.committee_threshold(&params);

        let mut tracker = VoteTracker::default();
        for i in 0..(n - 1) {
            assert_eq!(
                accept(&mut tracker, &params, i, CERT, pv).event_type(),
                EventType::None,
            );
        }
        let last = accept(&mut tracker, &params, n - 1, CERT, pv);
        assert_eq!(last.event_type(), EventType::CertThreshold);

        let mut tracker = VoteTracker::default();
        for i in 0..(n - 1) {
            assert_eq!(
                accept(&mut tracker, &params, i, CERT, pv).event_type(),
                EventType::None,
            );
        }
    }

    /// Port of `TestVoteTrackerNextQuorum`.
    #[test]
    fn vote_tracker_next_quorum_boundary() {
        let params = test_params();
        let pv = test_proposal();
        let n = crate::step::NEXT.committee_threshold(&params);

        let mut tracker = VoteTracker::default();
        for i in 0..(n - 1) {
            assert_eq!(
                accept(&mut tracker, &params, i, crate::step::NEXT, pv).event_type(),
                EventType::None,
            );
        }
        let last = accept(&mut tracker, &params, n - 1, crate::step::NEXT, pv);
        assert_eq!(last.event_type(), EventType::NextThreshold);

        let mut tracker = VoteTracker::default();
        for i in 0..(n - 1) {
            assert_eq!(
                accept(&mut tracker, &params, i, crate::step::NEXT, pv).event_type(),
                EventType::None,
            );
        }
    }

    // -- Equivocator weight + multi-value tests --------------------------

    /// Port of `TestVoteTrackerEquivocatorWeightCountedOnce`. Cast
    /// `threshold − 1` valid votes, then equivocate sender 0 → no
    /// SoftThreshold, because the equivocator's weight gets MOVED to
    /// `equivocators_count` (which contributes to count() once) but the
    /// original direct vote was REMOVED. The total count for the original
    /// proposal is therefore `threshold − 1`, still below quorum.
    #[test]
    fn vote_tracker_equivocator_weight_counted_once() {
        let params = test_params();
        let pv = test_proposal();
        let n = SOFT.committee_threshold(&params);

        let mut tracker = VoteTracker::default();
        for i in 0..(n - 1) {
            assert_eq!(
                accept(&mut tracker, &params, i, SOFT, pv).event_type(),
                EventType::None,
            );
        }
        // Sender 0 already voted for `pv`; voting again for a different
        // proposal triggers equivocation logic.
        let result = accept(&mut tracker, &params, 0, SOFT, test_proposal_2());
        assert_eq!(
            result.event_type(),
            EventType::None,
            "equivocator weight must not double-count to push past threshold",
        );
        assert_eq!(tracker.equivocators_count, 1);
    }

    /// Port of `TestVoteTrackerEquivDoesntReemitThreshold`. Once the
    /// SoftThreshold fires for a proposal, an equivocation by an existing
    /// voter (followed by a brand-new vote) must NOT emit a second
    /// threshold.
    #[test]
    fn vote_tracker_equiv_doesnt_reemit_threshold() {
        let params = test_params();
        let pv = test_proposal();
        let n = SOFT.committee_threshold(&params);

        let mut tracker = VoteTracker::default();
        for i in 0..(n - 1) {
            accept(&mut tracker, &params, i, SOFT, pv);
        }
        let crossed = accept(&mut tracker, &params, n - 1, SOFT, pv);
        assert_eq!(crossed.event_type(), EventType::SoftThreshold);

        // Equivocate sender 0 onto a different proposal.
        let dup = accept(&mut tracker, &params, 0, SOFT, test_proposal_2());
        assert_eq!(
            dup.event_type(),
            EventType::None,
            "post-threshold equivocation must not re-emit threshold",
        );

        // Add a fresh voter — still no re-emission.
        let extra = accept(&mut tracker, &params, n + 1, SOFT, pv);
        assert_eq!(extra.event_type(), EventType::None);
    }

    /// Port of `TestVoteTrackerEquivocationsCount`. Half-threshold votes
    /// for v1, half-threshold votes for v2 (different senders), then the
    /// v2 voters equivocate onto v1 → the v1 proposal reaches quorum on
    /// the last equivocation event because the equivocators' weight
    /// contributes to the v1 count via `equivocators_count`.
    #[test]
    fn vote_tracker_equivocations_count() {
        let params = test_params();
        let v1 = pv_with_digest(0xa1);
        let v2 = pv_with_digest(0xa2);
        let n = CERT.committee_threshold(&params);
        let half = n / 2;

        let mut tracker = VoteTracker::default();
        // First `half` voters vote for v1.
        for i in 0..half {
            assert_eq!(
                accept(&mut tracker, &params, i, CERT, v1).event_type(),
                EventType::None,
            );
        }
        // Next `n - half` voters vote for v2.
        for i in half..n {
            assert_eq!(
                accept(&mut tracker, &params, i, CERT, v2).event_type(),
                EventType::None,
            );
        }
        // The v2 voters equivocate onto v1. The last one crosses the
        // CertThreshold for v1 (direct + equivocator weight).
        let mut last = Event::Empty(EmptyEvent);
        for i in half..n {
            last = accept(&mut tracker, &params, i, CERT, v1);
        }
        assert_eq!(last.event_type(), EventType::CertThreshold);
        if let Event::Threshold(te) = last {
            assert_eq!(te.proposal, v1);
        }
    }

    /// Port of `TestVoteTrackerSuperEquivocationsCount`. Same as the
    /// previous test but the equivocations are onto v3 (a third value
    /// distinct from v1 and v2). v1 still reaches quorum because
    /// `equivocators_count` contributes to *every* proposal's `count()`.
    #[test]
    fn vote_tracker_super_equivocations_count() {
        let params = test_params();
        let v1 = pv_with_digest(0xb1);
        let v2 = pv_with_digest(0xb2);
        let v3 = pv_with_digest(0xb3);
        let n = CERT.committee_threshold(&params);
        let half = n / 2;

        let mut tracker = VoteTracker::default();
        for i in 0..half {
            accept(&mut tracker, &params, i, CERT, v1);
        }
        for i in half..n {
            accept(&mut tracker, &params, i, CERT, v2);
        }
        let mut last = Event::Empty(EmptyEvent);
        for i in half..n {
            last = accept(&mut tracker, &params, i, CERT, v3);
        }
        assert_eq!(last.event_type(), EventType::CertThreshold);
        if let Event::Threshold(te) = last {
            // Quorum landed on v1, the proposal whose `count()` benefited
            // from the equivocators (v2 voters had their direct weight
            // removed; v3 has only equivocators).
            assert_eq!(te.proposal, v1);
        }
    }

    // -- Equivocation forwarding behavior -------------------------------

    /// Port of `TestVoteTrackerForwardsFirstEquivocation`. The first
    /// equivocation from sender X is FORWARDED (filter request returns
    /// Empty), but subsequent equivocations from the same sender are
    /// FILTERED. Mirrors the asymmetry between `voters` (cleared on
    /// equivocation) and `equivocators` (set on equivocation).
    #[test]
    fn vote_tracker_forwards_first_equivocation() {
        let params = test_params();
        let v1 = pv_with_digest(0xc1);
        let v2 = pv_with_digest(0xc2);
        let v3 = pv_with_digest(0xc3);

        let mut tracker = VoteTracker::default();
        // Sender 0 votes for v1.
        accept(&mut tracker, &params, 0, crate::step::NEXT, v1);

        // Filter for sender 0 + v1: same proposal → filtered (duplicate).
        let dup = tracker.handle(
            &Event::VoteFilterRequest(VoteFilterRequestEvent {
                raw_vote: RawVote {
                    sender: index_address(0),
                    round: Round(1),
                    period: Period(0),
                    step: crate::step::NEXT,
                    proposal: v1,
                },
            }),
            &params,
        );
        assert_eq!(dup.event_type(), EventType::VoteFilteredStep);

        // Filter for sender 0 + v2 (different proposal): the first
        // equivocation is forwarded — filter returns empty so the
        // network actually relays the second vote.
        let first_equi = tracker.handle(
            &Event::VoteFilterRequest(VoteFilterRequestEvent {
                raw_vote: RawVote {
                    sender: index_address(0),
                    round: Round(1),
                    period: Period(0),
                    step: crate::step::NEXT,
                    proposal: v2,
                },
            }),
            &params,
        );
        assert_eq!(
            first_equi.event_type(),
            EventType::None,
            "first equivocation must be forwarded (not filtered)",
        );

        // Drive the equivocation through.
        accept(&mut tracker, &params, 0, crate::step::NEXT, v2);

        // Now sender 0 is in `equivocators`. A filter request for v3 (a
        // third value) is filtered as a future equivocation.
        let future_equi = tracker.handle(
            &Event::VoteFilterRequest(VoteFilterRequestEvent {
                raw_vote: RawVote {
                    sender: index_address(0),
                    round: Round(1),
                    period: Period(0),
                    step: crate::step::NEXT,
                    proposal: v3,
                },
            }),
            &params,
        );
        assert_eq!(future_equi.event_type(), EventType::VoteFilteredStep);
    }

    /// Port of `TestVoteTrackerFiltersFutureEquivocations`. Once a sender
    /// is a known equivocator, every subsequent filter request from them
    /// returns FilteredStep, regardless of the proposal value.
    #[test]
    fn vote_tracker_filters_future_equivocations() {
        let params = test_params();
        let v1 = pv_with_digest(0xd1);
        let v2 = pv_with_digest(0xd2);

        let mut tracker = VoteTracker::default();
        // Build the equivocation: sender 0 votes for v1, then v2.
        accept(&mut tracker, &params, 0, SOFT, v1);
        // First filter for v2 (the equivocation about to land) — forwarded.
        let first = tracker.handle(
            &Event::VoteFilterRequest(VoteFilterRequestEvent {
                raw_vote: RawVote {
                    sender: index_address(0),
                    round: Round(1),
                    period: Period(0),
                    step: SOFT,
                    proposal: v2,
                },
            }),
            &params,
        );
        assert_eq!(first.event_type(), EventType::None);
        accept(&mut tracker, &params, 0, SOFT, v2);

        // Now any future filter request from sender 0 is rejected.
        for digest in 0xd3u8..0xd3 + 16 {
            let val = pv_with_digest(digest);
            let result = tracker.handle(
                &Event::VoteFilterRequest(VoteFilterRequestEvent {
                    raw_vote: RawVote {
                        sender: index_address(0),
                        round: Round(1),
                        period: Period(0),
                        step: SOFT,
                        proposal: val,
                    },
                }),
                &params,
            );
            assert_eq!(
                result.event_type(),
                EventType::VoteFilteredStep,
                "future equivocation for digest {digest} should be filtered",
            );
        }
    }

    // -- Invariant-panic tests ------------------------------------------

    /// Port of `TestVoteTrackerPanicsOnTwoSoftQuorums`. Cross the
    /// SoftThreshold for v1, then drive votes for v2 from disjoint
    /// senders to push v2 over its quorum. The second crossing trips
    /// `over_threshold`'s panic guard ("more than one value reached a
    /// threshold").
    #[test]
    #[should_panic(expected = "more than one value reached a threshold")]
    fn vote_tracker_panics_on_two_soft_quorums() {
        let params = test_params();
        let v1 = pv_with_digest(0xe1);
        let v2 = pv_with_digest(0xe2);
        let n = SOFT.committee_threshold(&params);

        let mut tracker = VoteTracker::default();
        for i in 0..n {
            accept(&mut tracker, &params, i, SOFT, v1);
        }
        // Disjoint sender range pushes v2 over quorum from a clean state
        // for v2's `count()` — total count includes equivocators from
        // earlier (none here, since each sender voted exactly once).
        for i in n..(2 * n) {
            accept(&mut tracker, &params, i, SOFT, v2);
        }
    }

    /// Port of `TestVoteTrackerPanicsOnTwoNextQuorums`. Same shape as the
    /// soft case but at next-step, with v1 = bottom and v2 = a real
    /// proposal — both can reach quorum at next-step in Go.
    #[test]
    #[should_panic(expected = "more than one value reached a threshold")]
    fn vote_tracker_panics_on_two_next_quorums() {
        let params = test_params();
        let v_bot = ProposalValue::default(); // BOTTOM
        let v2 = pv_with_digest(0xf2);
        let n = crate::step::NEXT.committee_threshold(&params);

        let mut tracker = VoteTracker::default();
        for i in 0..n {
            accept(&mut tracker, &params, i, crate::step::NEXT, v_bot);
        }
        for i in n..(2 * n) {
            accept(&mut tracker, &params, i, crate::step::NEXT, v2);
        }
    }

    /// Port of `TestVoteTrackerRejectsTooManyEquivocators`. Pair every
    /// sender with a fresh equivocation. After enough pairs the
    /// `equivocators_count` itself reaches quorum, tripping the
    /// "too many equivocators" panic.
    #[test]
    #[should_panic(expected = "too many equivocators")]
    fn vote_tracker_rejects_too_many_equivocators() {
        let params = test_params();
        let n = SOFT.committee_threshold(&params);

        let mut tracker = VoteTracker::default();
        // Drive 2N votes, paired by sender (i / 2). Every odd index
        // triggers an equivocation, incrementing `equivocators_count`.
        // After the count reaches quorum, `handle_vote_accepted` panics
        // — which the `#[should_panic]` annotation catches. We use a
        // unique block-digest per index so distinct proposals can't
        // collide and accidentally satisfy a duplicate-vote drop.
        let mut digest = 0u8;
        for i in 0..(2 * n) {
            digest = digest.wrapping_add(1);
            accept(&mut tracker, &params, i / 2, SOFT, pv_with_digest(digest));
        }
    }

    /// Port of `TestVoteTrackerRejectsUnknownEvent`. The bare
    /// `voteTracker.handle()` panics on event types it doesn't recognize.
    #[test]
    #[should_panic(expected = "voteTracker: bad event type")]
    fn vote_tracker_rejects_unknown_event() {
        let params = test_params();
        let mut tracker = VoteTracker::default();
        // Empty event is not a VoteAccepted / VoteFilterRequest /
        // DumpVotesRequest.
        let _ = tracker.handle(&Event::Empty(EmptyEvent), &params);
    }

    // -- Conformance gaps deferred to TASK-97 ---------------------------

    /// Port of `TestVoteTrackerProposeNoOp`. Go's
    /// `voteTrackerContract.preconditions` panics on propose-step
    /// votes wrapped around the bare `voteTracker`. The Rust port has
    /// no contract layer — `VoteTracker::handle_vote_accepted` accepts
    /// propose-step votes and silently produces no threshold (because
    /// `propose.reaches_quorum()` is always false). Behaviorally
    /// equivalent for consensus, but operator-observable: Go panics,
    /// Rust does not. Tracked in TASK-97.
    #[test]
    #[ignore = "see TASK-97 — port voteTrackerContract precondition panics"]
    fn vote_tracker_propose_no_op_panics() {
        // When TASK-97 lands, replace this with the panic test.
        // The shape of the test would be:
        //   #[should_panic(expected = "propose")]
        //   fn ... { accept(&mut tracker, &params, 0, PROPOSE, test_proposal()); }
    }

    /// Port of `TestVoteTrackerPanicsOnSoftBotQuorum`. Same gap as
    /// above — Go's contract postcondition panics if a SoftThreshold
    /// event fires for proposal=bottom. The Rust port does not enforce
    /// this. Tracked in TASK-97.
    #[test]
    #[ignore = "see TASK-97 — port voteTrackerContract postcondition panic"]
    fn vote_tracker_panics_on_soft_bot_quorum() {
        // When TASK-97 lands, replace with the panic test that drives
        // `threshold` votes for `BOTTOM` at the soft step and asserts
        // a panic on the threshold-emission boundary.
    }

    #[test]
    fn equivocation_vote_v0_v1() {
        let ev = EquivocationVote {
            sender: Address([0x01; 32]),
            round: Round(1),
            period: Period(0),
            step: SOFT,
            cred: Credential {
                weight: 1,
                vrf_out: Digest([0u8; 32]),
                domain_separation_enabled: false,
                hashable: crate::credential::HashableCredential::default(),
                proof: [0u8; 80],
            },
            proposals: [test_proposal(), test_proposal_2()],
            sigs: [
                OneTimeSignature {
                    sig: [0u8; 64],
                    pk: [0u8; 32],
                    pk_sig_old: [0u8; 64],
                    pk2: [0u8; 32],
                    pk1_sig: [0u8; 64],
                    pk2_sig: [0u8; 64],
                },
                OneTimeSignature {
                    sig: [1u8; 64],
                    pk: [0u8; 32],
                    pk_sig_old: [0u8; 64],
                    pk2: [0u8; 32],
                    pk1_sig: [0u8; 64],
                    pk2_sig: [0u8; 64],
                },
            ],
        };

        let v0 = ev.v0();
        assert_eq!(v0.raw_vote.proposal, test_proposal());
        let v1 = ev.v1();
        assert_eq!(v1.raw_vote.proposal, test_proposal_2());
    }
}
