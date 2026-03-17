// Top-level vote/bundle aggregation.
//
// Mirrors go-algorand/agreement/voteAggregator.go.
//
// VoteAggregator applies relay rules to incoming votes and converts accepted
// votes into threshold events. It handles vote/bundle present and verified
// events, performing freshness checks and dispatching to the underlying vote
// tracking hierarchy.

use algo_types::ConsensusParams;

use crate::bundle::UnauthenticatedBundle;
use crate::events::{
    self, EmptyEvent, Event, EventType, FilterableMessageEvent, FilteredEvent, SerializableError,
    VoteAcceptedEvent, VoteFilterRequestEvent,
};
use crate::types;
use crate::vote::{UnauthenticatedVote, Vote};
use crate::vote_auxiliary::VoteTrackerRound;

// ---------------------------------------------------------------------------
// VoteAggregator
// ---------------------------------------------------------------------------

/// Top-level vote and bundle aggregator.
///
/// Applies relay rules to incoming votes and converts accepted votes into
/// threshold events. This is the entry point for all vote/bundle processing
/// in the agreement state machine.
///
/// Mirrors Go's `voteAggregator` in agreement/voteAggregator.go.
#[derive(Debug, Clone, Default)]
pub struct VoteAggregator {
    /// Per-round vote tracking. Typically contains at most 2 entries (current
    /// round and next round for pipelining).
    rounds: std::collections::HashMap<algo_types::Round, VoteTrackerRound>,
}

impl VoteAggregator {
    /// Returns a mutable reference to the VoteTrackerRound for the given round,
    /// creating one if it does not exist.
    fn tracker_for_round(&mut self, round: algo_types::Round) -> &mut VoteTrackerRound {
        self.rounds.entry(round).or_default()
    }

    /// Main entry point for processing filterable message events.
    ///
    /// Handles event types: VotePresent, VoteVerified, BundlePresent,
    /// BundleVerified.
    ///
    /// Mirrors Go's `voteAggregator.handle()`.
    pub fn handle(&mut self, event: &FilterableMessageEvent, params: &ConsensusParams) -> Event {
        let me = &event.message_event;
        let fresh_data = &event.freshness_data;

        match me.t {
            EventType::VotePresent => {
                if me.proto.err.is_some() {
                    return Event::Filtered(FilteredEvent {
                        t: EventType::VoteFiltered,
                        err: me.proto.err.as_ref().map(SerializableError::new),
                        ..FilteredEvent::default()
                    });
                }

                let uv = &me.input.unauthenticated_vote;
                match self.filter_vote(params, uv, fresh_data) {
                    Ok(()) => Event::Empty(EmptyEvent),
                    Err(msg) => Event::Filtered(FilteredEvent {
                        t: EventType::VoteFiltered,
                        err: Some(SerializableError::new(msg)),
                        ..FilteredEvent::default()
                    }),
                }
            }
            EventType::VoteVerified => {
                if me.cancelled {
                    return Event::Filtered(FilteredEvent {
                        t: EventType::VoteFiltered,
                        err: me.err.clone(),
                        ..FilteredEvent::default()
                    });
                }
                if me.proto.err.is_some() {
                    return Event::Filtered(FilteredEvent {
                        t: EventType::VoteFiltered,
                        err: me.err.clone(),
                        ..FilteredEvent::default()
                    });
                }
                if me.err.is_some() {
                    return Event::Filtered(FilteredEvent {
                        t: EventType::VoteMalformed,
                        err: me.err.clone(),
                        ..FilteredEvent::default()
                    });
                }

                let v = match &me.input.vote {
                    Some(v) => v,
                    None => {
                        return Event::Filtered(FilteredEvent {
                            t: EventType::VoteMalformed,
                            err: Some(SerializableError::new("missing verified vote")),
                            ..FilteredEvent::default()
                        });
                    }
                };

                // Re-check freshness with the unauthenticated form
                let uv = v.to_unauthenticated();
                if let Err(msg) = self.filter_vote(params, &uv, fresh_data) {
                    return Event::Filtered(FilteredEvent {
                        t: EventType::VoteFiltered,
                        err: Some(SerializableError::new(msg)),
                        ..FilteredEvent::default()
                    });
                }

                // Deliver the accepted vote to the round tracker
                let deliver = Event::VoteAccepted(VoteAcceptedEvent {
                    vote: v.clone(),
                    proto: me.proto.version.clone(),
                });

                let round_tracker = self.tracker_for_round(v.raw_vote.round);
                let result = round_tracker.handle(&deliver, params);

                if result.event_type() == EventType::None {
                    return result;
                }

                // Check which round the threshold is for
                if let Event::Threshold(ref te) = result {
                    if te.round == fresh_data.player_round {
                        return result;
                    } else if te.round == algo_types::Round(fresh_data.player_round.0 + 1) {
                        // Pipelined threshold for next round — don't propagate
                        return Event::Empty(EmptyEvent);
                    }
                    panic!("bad round ({:?}, {:?})", te.round, fresh_data.player_round);
                }

                result
            }
            EventType::BundlePresent => {
                let ub = &me.input.unauthenticated_bundle;
                match self.filter_bundle(ub, fresh_data) {
                    Ok(()) => Event::Empty(EmptyEvent),
                    Err(msg) => Event::Filtered(FilteredEvent {
                        t: EventType::BundleFiltered,
                        err: Some(SerializableError::new(msg)),
                        ..FilteredEvent::default()
                    }),
                }
            }
            EventType::BundleVerified => {
                if me.cancelled {
                    return Event::Filtered(FilteredEvent {
                        t: EventType::BundleFiltered,
                        err: me.err.clone(),
                        ..FilteredEvent::default()
                    });
                }
                if me.proto.err.is_some() {
                    return Event::Filtered(FilteredEvent {
                        t: EventType::BundleFiltered,
                        err: me.err.clone(),
                        ..FilteredEvent::default()
                    });
                }
                if me.err.is_some() {
                    return Event::Filtered(FilteredEvent {
                        t: EventType::BundleMalformed,
                        err: me.err.clone(),
                        ..FilteredEvent::default()
                    });
                }

                let ub = &me.input.unauthenticated_bundle;
                if let Err(msg) = self.filter_bundle(ub, fresh_data) {
                    return Event::Filtered(FilteredEvent {
                        t: EventType::BundleFiltered,
                        err: Some(SerializableError::new(msg)),
                        ..FilteredEvent::default()
                    });
                }

                // Replay each verified vote from the bundle through the round
                // tracker. This matches Go's behavior where verified bundle
                // votes are individually dispatched to the voteTracker.
                let votes = &me.input.verified_bundle_votes;

                let mut thresh_event: Option<Event> = None;
                for vote in votes {
                    let deliver = Event::VoteAccepted(VoteAcceptedEvent {
                        vote: vote.clone(),
                        proto: me.proto.version.clone(),
                    });
                    let round_tracker = self.tracker_for_round(vote.raw_vote.round);
                    let result = round_tracker.handle(&deliver, params);
                    match result.event_type() {
                        EventType::SoftThreshold
                        | EventType::CertThreshold
                        | EventType::NextThreshold => {
                            thresh_event = Some(result);
                        }
                        _ => {}
                    }
                }

                if let Some(te) = thresh_event {
                    return te;
                }

                Event::Filtered(FilteredEvent {
                    t: EventType::BundleFiltered,
                    err: Some(SerializableError::new(format!(
                        "bundle for ({}, {}, {}: {:?}) failed to cause a significant state change",
                        ub.round, ub.period, ub.step, ub.proposal
                    ))),
                    ..FilteredEvent::default()
                })
            }
            _ => {
                panic!(
                    "voteAggregator: bad event type: observed an event of type {:?}",
                    me.t
                );
            }
        }
    }

    /// Handles a verified bundle by replaying its individual votes through the
    /// round tracker.
    ///
    /// This is the proper implementation for bundle processing, called when
    /// verified Vote objects are available.
    ///
    /// Mirrors the bundleVerified case in Go's `voteAggregator.handle()`.
    pub fn handle_verified_bundle(
        &mut self,
        votes: &[Vote],
        ub: &UnauthenticatedBundle,
        fresh_data: &events::FreshnessData,
        proto: &str,
        params: &ConsensusParams,
    ) -> Event {
        if let Err(msg) = self.filter_bundle(ub, fresh_data) {
            return Event::Filtered(FilteredEvent {
                t: EventType::BundleFiltered,
                err: Some(SerializableError::new(msg)),
                ..FilteredEvent::default()
            });
        }

        // Send each vote to the round tracker, track threshold events
        let mut thresh_event: Option<Event> = None;
        for vote in votes {
            let deliver = Event::VoteAccepted(VoteAcceptedEvent {
                vote: vote.clone(),
                proto: proto.to_string(),
            });
            let round_tracker = self.tracker_for_round(vote.raw_vote.round);
            let result = round_tracker.handle(&deliver, params);
            match result.event_type() {
                EventType::SoftThreshold | EventType::CertThreshold | EventType::NextThreshold => {
                    thresh_event = Some(result);
                }
                _ => {}
            }
        }

        if let Some(te) = thresh_event {
            return te;
        }

        Event::Filtered(FilteredEvent {
            t: EventType::BundleFiltered,
            err: Some(SerializableError::new(format!(
                "bundle for ({}, {}, {}: {:?}) failed to cause a significant state change",
                ub.round, ub.period, ub.step, ub.proposal
            ))),
            ..FilteredEvent::default()
        })
    }

    /// Filters a vote, checking freshness and duplicate/equivocation status.
    ///
    /// Mirrors Go's `voteAggregator.filterVote()`.
    fn filter_vote(
        &mut self,
        params: &ConsensusParams,
        uv: &UnauthenticatedVote,
        fresh_data: &events::FreshnessData,
    ) -> Result<(), String> {
        types::vote_fresh(fresh_data, uv)?;

        // Check the step-level tracker for duplicates/equivocations
        let filter_req = Event::VoteFilterRequest(VoteFilterRequestEvent {
            raw_vote: uv.raw_vote.clone(),
        });
        let round_tracker = self.tracker_for_round(uv.raw_vote.round);
        let filter_result = round_tracker.handle(&filter_req, params);

        match filter_result.event_type() {
            EventType::VoteFilteredStep => Err(format!(
                "voteAggregator: rejected vote: sender {:?} had already sent a vote in round {} period {} step {}",
                uv.raw_vote.sender, uv.raw_vote.round, uv.raw_vote.period, uv.raw_vote.step
            )),
            EventType::None => Ok(()),
            other => panic!(
                "voteAggregator: bad event type: while filtering, observed an event of type {:?}",
                other
            ),
        }
    }

    /// Filters a bundle, checking freshness.
    ///
    /// Mirrors Go's `voteAggregator.filterBundle()`.
    fn filter_bundle(
        &self,
        ub: &UnauthenticatedBundle,
        fresh_data: &events::FreshnessData,
    ) -> Result<(), String> {
        types::bundle_fresh(fresh_data, ub)
            .map_err(|e| format!("voteAggregator: rejected bundle due to age: {e}"))
    }

    /// Returns the VoteTrackerRound for a specific round (if it exists).
    ///
    /// Useful for queries like freshest bundle or next-threshold status.
    pub fn round_tracker(&mut self, round: algo_types::Round) -> &mut VoteTrackerRound {
        self.tracker_for_round(round)
    }

    /// Trim old round state. Called when the player advances to a new round.
    ///
    /// Removes trackers for rounds older than `keep_from`.
    pub fn trim(&mut self, keep_from: algo_types::Round) {
        self.rounds.retain(|&r, _| r >= keep_from);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{
        ConsensusVersionView, FilterableMessageEvent, FreshnessData, InternalMessage, MessageEvent,
    };
    use crate::step::{Period, Step, SOFT};
    use crate::vote::{ProposalValue, RawVote};
    use algo_types::{Address, Digest, Round};

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

    fn make_uv(
        sender: Address,
        round: Round,
        period: Period,
        step: Step,
        proposal: ProposalValue,
    ) -> UnauthenticatedVote {
        use crate::credential::UnauthenticatedCredential;
        use algo_consensus_crypto::OneTimeSignature;

        UnauthenticatedVote {
            raw_vote: RawVote {
                sender,
                round,
                period,
                step,
                proposal,
            },
            cred: UnauthenticatedCredential::new([0u8; 80]),
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

    fn make_fresh_data(round: Round, period: Period, step: Step) -> FreshnessData {
        FreshnessData {
            player_round: round,
            player_period: period,
            player_step: step,
            player_last_concluding: Step(0),
        }
    }

    fn make_vote_present_event(
        uv: UnauthenticatedVote,
        fresh_data: FreshnessData,
    ) -> FilterableMessageEvent {
        FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VotePresent,
                input: InternalMessage {
                    unauthenticated_vote: uv,
                    ..InternalMessage::default()
                },
                proto: ConsensusVersionView {
                    err: None,
                    version: algo_types::CONSENSUS_V41.to_string(),
                },
                ..MessageEvent::default()
            },
            freshness_data: fresh_data,
        }
    }

    fn make_bundle_present_event(
        ub: UnauthenticatedBundle,
        fresh_data: FreshnessData,
    ) -> FilterableMessageEvent {
        FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::BundlePresent,
                input: InternalMessage {
                    unauthenticated_bundle: ub,
                    ..InternalMessage::default()
                },
                proto: ConsensusVersionView {
                    err: None,
                    version: algo_types::CONSENSUS_V41.to_string(),
                },
                ..MessageEvent::default()
            },
            freshness_data: fresh_data,
        }
    }

    #[test]
    fn vote_aggregator_vote_present_fresh() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let uv = make_uv(
            Address([0x01; 32]),
            Round(10),
            Period(0),
            SOFT,
            test_proposal(),
        );
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);
        let event = make_vote_present_event(uv, fresh_data);
        let result = agg.handle(&event, &params);
        assert_eq!(result.event_type(), EventType::None);
    }

    #[test]
    fn vote_aggregator_vote_present_stale() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        // Vote from round 5, but player is at round 10
        let uv = make_uv(
            Address([0x01; 32]),
            Round(5),
            Period(0),
            SOFT,
            test_proposal(),
        );
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);
        let event = make_vote_present_event(uv, fresh_data);
        let result = agg.handle(&event, &params);
        assert_eq!(result.event_type(), EventType::VoteFiltered);
    }

    #[test]
    fn vote_aggregator_vote_present_proto_error() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let uv = make_uv(
            Address([0x01; 32]),
            Round(10),
            Period(0),
            SOFT,
            test_proposal(),
        );
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);
        let mut event = make_vote_present_event(uv, fresh_data);
        event.message_event.proto.err = Some("consensus error".to_string());
        let result = agg.handle(&event, &params);
        assert_eq!(result.event_type(), EventType::VoteFiltered);
    }

    #[test]
    fn vote_aggregator_bundle_present_fresh() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let ub = UnauthenticatedBundle {
            round: Round(10),
            period: Period(0),
            step: Step(2), // cert
            proposal: test_proposal(),
            votes: vec![],
            equivocation_votes: vec![],
        };
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);
        let event = make_bundle_present_event(ub, fresh_data);
        let result = agg.handle(&event, &params);
        assert_eq!(result.event_type(), EventType::None);
    }

    #[test]
    fn vote_aggregator_bundle_present_stale() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let ub = UnauthenticatedBundle {
            round: Round(5),
            period: Period(0),
            step: Step(2),
            proposal: test_proposal(),
            votes: vec![],
            equivocation_votes: vec![],
        };
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);
        let event = make_bundle_present_event(ub, fresh_data);
        let result = agg.handle(&event, &params);
        assert_eq!(result.event_type(), EventType::BundleFiltered);
    }

    #[test]
    fn vote_aggregator_trim_old_rounds() {
        let mut agg = VoteAggregator::default();
        // Add trackers for several rounds
        agg.tracker_for_round(Round(5));
        agg.tracker_for_round(Round(10));
        agg.tracker_for_round(Round(15));

        assert_eq!(agg.rounds.len(), 3);

        // Trim rounds older than 10
        agg.trim(Round(10));

        assert_eq!(agg.rounds.len(), 2);
        assert!(!agg.rounds.contains_key(&Round(5)));
        assert!(agg.rounds.contains_key(&Round(10)));
        assert!(agg.rounds.contains_key(&Round(15)));
    }

    #[test]
    fn vote_aggregator_filter_vote_fresh_same_round() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let uv = make_uv(
            Address([0x01; 32]),
            Round(10),
            Period(0),
            SOFT,
            test_proposal(),
        );
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);
        assert!(agg.filter_vote(&params, &uv, &fresh_data).is_ok());
    }

    #[test]
    fn vote_aggregator_filter_vote_stale_round() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let uv = make_uv(
            Address([0x01; 32]),
            Round(5),
            Period(0),
            SOFT,
            test_proposal(),
        );
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);
        assert!(agg.filter_vote(&params, &uv, &fresh_data).is_err());
    }

    #[test]
    fn vote_aggregator_filter_bundle_fresh() {
        let agg = VoteAggregator::default();
        let ub = UnauthenticatedBundle {
            round: Round(10),
            period: Period(0),
            step: Step(2),
            proposal: test_proposal(),
            votes: vec![],
            equivocation_votes: vec![],
        };
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);
        assert!(agg.filter_bundle(&ub, &fresh_data).is_ok());
    }

    #[test]
    fn vote_aggregator_filter_bundle_stale() {
        let agg = VoteAggregator::default();
        let ub = UnauthenticatedBundle {
            round: Round(5),
            period: Period(0),
            step: Step(2),
            proposal: test_proposal(),
            votes: vec![],
            equivocation_votes: vec![],
        };
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);
        assert!(agg.filter_bundle(&ub, &fresh_data).is_err());
    }

    fn make_verified_vote(
        sender: Address,
        round: Round,
        period: crate::step::Period,
        step: Step,
        proposal: crate::vote::ProposalValue,
        weight: u64,
    ) -> crate::vote::Vote {
        crate::vote::Vote {
            raw_vote: crate::vote::RawVote {
                sender,
                round,
                period,
                step,
                proposal,
            },
            cred: crate::credential::Credential {
                weight,
                vrf_out: Digest([0u8; 32]),
                domain_separation_enabled: false,
                hashable: crate::credential::HashableCredential::default(),
                proof: [0u8; 80],
            },
            sig: algo_consensus_crypto::OneTimeSignature {
                sig: [0u8; 64],
                pk: [0u8; 32],
                pk_sig_old: [0u8; 64],
                pk2: [0u8; 32],
                pk1_sig: [0u8; 64],
                pk2_sig: [0u8; 64],
            },
        }
    }

    fn make_vote_verified_event(
        vote: crate::vote::Vote,
        fresh_data: FreshnessData,
    ) -> FilterableMessageEvent {
        let uv = vote.to_unauthenticated();
        FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VoteVerified,
                input: InternalMessage {
                    vote: Some(vote),
                    unauthenticated_vote: uv,
                    ..InternalMessage::default()
                },
                proto: ConsensusVersionView {
                    err: None,
                    version: algo_types::CONSENSUS_V41.to_string(),
                },
                ..MessageEvent::default()
            },
            freshness_data: fresh_data,
        }
    }

    // ---- Soft threshold detection ----

    #[test]
    fn vote_aggregator_soft_threshold_detection() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let proposal = test_proposal();
        let threshold = SOFT.committee_threshold(&params);
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);

        let mut last_result = Event::Empty(events::EmptyEvent);
        for i in 0..threshold {
            let sender = Address({
                let mut a = [0u8; 32];
                a[0] = (i & 0xff) as u8;
                a[1] = ((i >> 8) & 0xff) as u8;
                a
            });
            let vote =
                make_verified_vote(sender, Round(10), crate::step::Period(0), SOFT, proposal, 1);
            let event = make_vote_verified_event(vote, fresh_data);
            last_result = agg.handle(&event, &params);
        }

        assert_eq!(last_result.event_type(), EventType::SoftThreshold);
        if let Event::Threshold(te) = last_result {
            assert_eq!(te.proposal, proposal);
            assert_eq!(te.round, Round(10));
        }
    }

    // ---- Cert threshold detection ----

    #[test]
    fn vote_aggregator_cert_threshold_detection() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let proposal = test_proposal();
        let threshold = Step(2).committee_threshold(&params);
        let fresh_data = make_fresh_data(Round(10), Period(0), Step(2));

        let mut last_result = Event::Empty(events::EmptyEvent);
        for i in 0..threshold {
            let sender = Address({
                let mut a = [0u8; 32];
                a[0] = (i & 0xff) as u8;
                a[1] = ((i >> 8) & 0xff) as u8;
                a
            });
            let vote = make_verified_vote(
                sender,
                Round(10),
                crate::step::Period(0),
                Step(2),
                proposal,
                1,
            );
            let event = make_vote_verified_event(vote, fresh_data);
            last_result = agg.handle(&event, &params);
        }

        assert_eq!(last_result.event_type(), EventType::CertThreshold);
    }

    // ---- Next threshold detection ----

    #[test]
    fn vote_aggregator_next_threshold_detection() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let proposal = test_proposal();
        let threshold = Step(3).committee_threshold(&params);
        let fresh_data = make_fresh_data(Round(10), Period(0), Step(3));

        let mut last_result = Event::Empty(events::EmptyEvent);
        for i in 0..threshold {
            let sender = Address({
                let mut a = [0u8; 32];
                a[0] = (i & 0xff) as u8;
                a[1] = ((i >> 8) & 0xff) as u8;
                a
            });
            let vote = make_verified_vote(
                sender,
                Round(10),
                crate::step::Period(0),
                Step(3),
                proposal,
                1,
            );
            let event = make_vote_verified_event(vote, fresh_data);
            last_result = agg.handle(&event, &params);
        }

        assert_eq!(last_result.event_type(), EventType::NextThreshold);
    }

    // ---- Duplicate vote filter ----

    #[test]
    fn vote_aggregator_duplicate_vote_filtered_after_verified() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let sender = Address([0x01; 32]);
        let proposal = test_proposal();
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);

        // First: accept a verified vote (this records it in the tracker)
        let vote = make_verified_vote(sender, Round(10), crate::step::Period(0), SOFT, proposal, 1);
        let event1 = make_vote_verified_event(vote, fresh_data);
        let result1 = agg.handle(&event1, &params);
        assert_eq!(result1.event_type(), EventType::None);

        // Second: present the same vote again (should be filtered as duplicate)
        let uv = make_uv(sender, Round(10), crate::step::Period(0), SOFT, proposal);
        let event2 = make_vote_present_event(uv, fresh_data);
        let result2 = agg.handle(&event2, &params);
        assert_eq!(result2.event_type(), EventType::VoteFiltered);
    }

    // ---- Vote verified cancelled ----

    #[test]
    fn vote_aggregator_vote_verified_cancelled() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);

        let event = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VoteVerified,
                cancelled: true,
                err: Some(events::SerializableError::new("cancelled")),
                proto: ConsensusVersionView {
                    err: None,
                    version: algo_types::CONSENSUS_V41.to_string(),
                },
                ..MessageEvent::default()
            },
            freshness_data: fresh_data,
        };
        let result = agg.handle(&event, &params);
        assert_eq!(result.event_type(), EventType::VoteFiltered);
    }

    // ---- Vote verified with error ----

    #[test]
    fn vote_aggregator_vote_verified_error() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);

        let event = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VoteVerified,
                err: Some(events::SerializableError::new("verification failed")),
                proto: ConsensusVersionView {
                    err: None,
                    version: algo_types::CONSENSUS_V41.to_string(),
                },
                ..MessageEvent::default()
            },
            freshness_data: fresh_data,
        };
        let result = agg.handle(&event, &params);
        assert_eq!(result.event_type(), EventType::VoteMalformed);
    }

    // ---- Vote verified missing vote ----

    #[test]
    fn vote_aggregator_vote_verified_missing_vote() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);

        let event = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VoteVerified,
                input: InternalMessage {
                    vote: None,
                    ..InternalMessage::default()
                },
                proto: ConsensusVersionView {
                    err: None,
                    version: algo_types::CONSENSUS_V41.to_string(),
                },
                ..MessageEvent::default()
            },
            freshness_data: fresh_data,
        };
        let result = agg.handle(&event, &params);
        assert_eq!(result.event_type(), EventType::VoteMalformed);
    }

    // ---- Vote verified with proto error ----

    #[test]
    fn vote_aggregator_vote_verified_proto_error() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);

        let event = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VoteVerified,
                proto: ConsensusVersionView {
                    err: Some("consensus error".to_string()),
                    version: String::new(),
                },
                ..MessageEvent::default()
            },
            freshness_data: fresh_data,
        };
        let result = agg.handle(&event, &params);
        assert_eq!(result.event_type(), EventType::VoteFiltered);
    }

    // ---- Bundle verified cancelled ----

    #[test]
    fn vote_aggregator_bundle_verified_cancelled() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);

        let event = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::BundleVerified,
                cancelled: true,
                err: Some(events::SerializableError::new("cancelled")),
                proto: ConsensusVersionView {
                    err: None,
                    version: algo_types::CONSENSUS_V41.to_string(),
                },
                ..MessageEvent::default()
            },
            freshness_data: fresh_data,
        };
        let result = agg.handle(&event, &params);
        assert_eq!(result.event_type(), EventType::BundleFiltered);
    }

    // ---- Bundle verified with error ----

    #[test]
    fn vote_aggregator_bundle_verified_error() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);

        let event = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::BundleVerified,
                err: Some(events::SerializableError::new("bad bundle")),
                proto: ConsensusVersionView {
                    err: None,
                    version: algo_types::CONSENSUS_V41.to_string(),
                },
                ..MessageEvent::default()
            },
            freshness_data: fresh_data,
        };
        let result = agg.handle(&event, &params);
        assert_eq!(result.event_type(), EventType::BundleMalformed);
    }

    // ---- Bundle verified with proto error ----

    #[test]
    fn vote_aggregator_bundle_verified_proto_error() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);

        let event = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::BundleVerified,
                proto: ConsensusVersionView {
                    err: Some("consensus error".to_string()),
                    version: String::new(),
                },
                ..MessageEvent::default()
            },
            freshness_data: fresh_data,
        };
        let result = agg.handle(&event, &params);
        assert_eq!(result.event_type(), EventType::BundleFiltered);
    }

    // ---- Bundle verified with votes producing threshold ----

    #[test]
    fn vote_aggregator_bundle_verified_with_votes_produces_threshold() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let proposal = test_proposal();
        let threshold = SOFT.committee_threshold(&params);
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);

        // Create enough verified votes for a bundle
        let mut verified_votes = Vec::new();
        for i in 0..threshold {
            let sender = Address({
                let mut a = [0u8; 32];
                a[0] = (i & 0xff) as u8;
                a[1] = ((i >> 8) & 0xff) as u8;
                a
            });
            verified_votes.push(make_verified_vote(
                sender,
                Round(10),
                crate::step::Period(0),
                SOFT,
                proposal,
                1,
            ));
        }

        let ub = UnauthenticatedBundle {
            round: Round(10),
            period: crate::step::Period(0),
            step: SOFT,
            proposal,
            votes: vec![],
            equivocation_votes: vec![],
        };

        let event = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::BundleVerified,
                input: InternalMessage {
                    unauthenticated_bundle: ub,
                    verified_bundle_votes: verified_votes,
                    ..InternalMessage::default()
                },
                proto: ConsensusVersionView {
                    err: None,
                    version: algo_types::CONSENSUS_V41.to_string(),
                },
                ..MessageEvent::default()
            },
            freshness_data: fresh_data,
        };

        let result = agg.handle(&event, &params);
        assert_eq!(result.event_type(), EventType::SoftThreshold);
    }

    // ---- Equivocation handling ----

    #[test]
    fn vote_aggregator_equivocating_voters_not_double_counted() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let proposal_a = test_proposal();
        let proposal_b = crate::vote::ProposalValue {
            original_period: crate::step::Period(0),
            original_proposer: Address([0x02; 32]),
            block_digest: Digest([0xcc; 32]),
            encoding_digest: Digest([0xdd; 32]),
        };
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);
        let sender = Address([0x01; 32]);

        // First vote for proposal A
        let vote1 = make_verified_vote(
            sender,
            Round(10),
            crate::step::Period(0),
            SOFT,
            proposal_a,
            1,
        );
        let event1 = make_vote_verified_event(vote1, fresh_data);
        agg.handle(&event1, &params);

        // Second vote from same sender for proposal B (equivocation)
        let vote2 = make_verified_vote(
            sender,
            Round(10),
            crate::step::Period(0),
            SOFT,
            proposal_b,
            1,
        );
        let event2 = make_vote_verified_event(vote2, fresh_data);
        agg.handle(&event2, &params);

        // Third vote from same sender: the freshness filter_vote will catch
        // the equivocator since VotePresent re-checks filter_vote which sees
        // the equivocator. For VoteVerified, the vote reaches the tracker which
        // sees the equivocator and silently drops it (returning None threshold).
        // However, at the aggregator level, the re-check with filter_vote
        // filters the vote before it reaches the tracker. So the result is VoteFiltered.
        let uv3 = make_uv(sender, Round(10), crate::step::Period(0), SOFT, proposal_a);
        let event3 = make_vote_present_event(uv3, fresh_data);
        let result = agg.handle(&event3, &params);

        // Equivocator is filtered at the step level
        assert_eq!(result.event_type(), EventType::VoteFiltered);
    }

    // ---- handle_verified_bundle ----

    #[test]
    fn vote_aggregator_handle_verified_bundle_stale() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);

        let ub = UnauthenticatedBundle {
            round: Round(5),
            period: crate::step::Period(0),
            step: SOFT,
            proposal: test_proposal(),
            votes: vec![],
            equivocation_votes: vec![],
        };

        let result =
            agg.handle_verified_bundle(&[], &ub, &fresh_data, algo_types::CONSENSUS_V41, &params);
        assert_eq!(result.event_type(), EventType::BundleFiltered);
    }

    // ---- Vote from next round pipelined ----

    #[test]
    fn vote_aggregator_vote_from_next_round_pipelined() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let proposal = test_proposal();

        // Vote from round 11 (next round), player is at round 10
        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);
        let uv = make_uv(
            Address([0x01; 32]),
            Round(11),
            crate::step::Period(0),
            SOFT,
            proposal,
        );
        let event = make_vote_present_event(uv, fresh_data);
        let result = agg.handle(&event, &params);

        // Should be accepted for pipelining
        assert_eq!(result.event_type(), EventType::None);
    }

    // ---- Filter vote from future period ----

    #[test]
    fn vote_aggregator_filter_vote_future_round_beyond_next() {
        let mut agg = VoteAggregator::default();
        let params = test_params();
        let proposal = test_proposal();

        let fresh_data = make_fresh_data(Round(10), Period(0), SOFT);
        let uv = make_uv(
            Address([0x01; 32]),
            Round(12),
            crate::step::Period(0),
            SOFT,
            proposal,
        );
        let result = agg.filter_vote(&params, &uv, &fresh_data);
        assert!(result.is_err());
    }
}
