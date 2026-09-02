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

// Proposal manager matching go-algorand/agreement/proposalManager.go.
//
// - `ProposalManager`: top-level proposal lifecycle management. Applies relay
//   rules to incoming proposal-votes and proposal payloads, absorbs threshold
//   events, and emits `ProposalCommittable` events as proposals become
//   committable.
//
// Handles: `VotePresent`, `VoteVerified`, `PayloadPresent`, `PayloadVerified`,
// `RoundInterruption`, `SoftThreshold`, `CertThreshold`, `NextThreshold`.
//
// Returns: `VoteFiltered`, `VoteMalformed`, `PayloadPipelined`,
// `PayloadRejected`, `PayloadAccepted`, `ProposalAccepted`,
// `ProposalCommittable`.
//
// Mirrors Go's `proposalManager` (the `proposalMachine`).

use algo_types::Round;
use serde::{Deserialize, Serialize};

use crate::events::{
    EmptyEvent, Event, EventType, FilterableMessageEvent, FilteredEvent,
    LateCredentialTrackingEffect, NewPeriodEvent, PayloadProcessedEvent, SerializableError,
    ThresholdEvent, VoteFilterRequestEvent,
};
use crate::proposal_store::ProposalStore;
use crate::step::Period;
use crate::vote::UnauthenticatedVote;

// ---------------------------------------------------------------------------
// ProposalManager
// ---------------------------------------------------------------------------

/// Top-level proposal lifecycle management.
///
/// Applies relay rules to incoming proposal-votes and proposal payloads,
/// absorbs threshold events, and emits `ProposalCommittable` events as
/// proposals become committable.
///
/// Mirrors Go's `proposalManager` (the `proposalMachine`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProposalManager {
    /// Per-round proposal stores. In Go, the router maintains these; here
    /// we track them directly. The key is the round number.
    stores: std::collections::HashMap<Round, ProposalStore>,
}

impl ProposalManager {
    /// Get or create a ProposalStore for the given round.
    fn store_for(&mut self, round: Round) -> &mut ProposalStore {
        self.stores.entry(round).or_default()
    }

    /// Crate-internal accessor for the per-round `ProposalStore`.
    ///
    /// Used by:
    /// * `RootRouter::dispatch` for `ProposalMachineRound` lookups, so
    ///   `staged_value` / `pinned_value` queries observe the same per-round
    ///   state that the message-handling dispatch mutates.
    /// * `crate::test_support` to inject preconditions
    ///   (assemblers, duplicates, staging values) for white-box tests.
    ///
    /// `pub(crate)` keeps the surface internal — external callers should go
    /// through dispatch. The per-round store is created on demand if it
    /// doesn't already exist, matching the message-dispatch behavior.
    pub(crate) fn store_for_round(&mut self, round: Round) -> &mut ProposalStore {
        self.store_for(round)
    }

    /// Handle an event dispatched to this proposalMachine.
    ///
    /// `player_round`, `player_period` describe the player's current state.
    ///
    /// Mirrors Go's `proposalManager.handle`.
    pub fn handle(&mut self, player_round: Round, player_period: Period, e: Event) -> Event {
        match e.event_type() {
            EventType::VotePresent
            | EventType::VoteVerified
            | EventType::PayloadPresent
            | EventType::PayloadVerified => {
                let fme = match e {
                    Event::FilterableMessage(fme) => fme,
                    _ => panic!("proposalManager: expected FilterableMessageEvent"),
                };
                self.handle_message_event(player_round, player_period, fme)
            }

            EventType::RoundInterruption => {
                let rie = match e {
                    Event::RoundInterruption(rie) => rie,
                    _ => panic!("proposalManager: expected RoundInterruptionEvent"),
                };
                self.handle_new_round(player_period, rie.round)
            }

            EventType::SoftThreshold | EventType::CertThreshold => {
                let te = match e {
                    Event::Threshold(te) => te,
                    _ => panic!("proposalManager: expected ThresholdEvent"),
                };
                if player_period < te.period {
                    self.handle_new_period(player_period, &te);
                }
                let round = te.round;
                let period = te.period;
                let store = self.store_for(round);
                store.handle(period, Event::Threshold(te))
            }

            EventType::NextThreshold => {
                let te = match e {
                    Event::Threshold(te) => te,
                    _ => panic!("proposalManager: expected ThresholdEvent"),
                };
                self.handle_new_period(player_period, &te);
                Event::Empty(EmptyEvent)
            }

            other => {
                panic!(
                    "proposalManager: bad event type: observed an event of type {}",
                    other
                );
            }
        }
    }

    /// Handle a new round event.
    ///
    /// Mirrors Go's `proposalManager.handleNewRound`.
    fn handle_new_round(&mut self, player_period: Period, round: Round) -> Event {
        let store = self.store_for(round);
        store.handle(player_period, Event::NewRound(crate::events::NewRoundEvent))
    }

    /// Handle a new period triggered by a threshold event.
    ///
    /// Mirrors Go's `proposalManager.handleNewPeriod`.
    ///
    /// `player_period` is the player's current period at the time of the call
    /// (before the period change). In Go, the player object `p` is passed
    /// through to `proposalStore.handle`, which uses `p.Period` for staging
    /// queries and authenticator trimming.
    fn handle_new_period(&mut self, player_period: Period, e: &ThresholdEvent) {
        let target = if e.t == EventType::NextThreshold {
            Period(e.period.0 + 1)
        } else {
            e.period
        };

        let en = NewPeriodEvent {
            period: target,
            proposal: e.proposal,
        };
        let store = self.store_for(e.round);
        store.handle(player_period, Event::NewPeriod(en));
    }

    /// Handle a filterable message event (vote or payload present/verified).
    ///
    /// Mirrors Go's `proposalManager.handleMessageEvent`.
    fn handle_message_event(
        &mut self,
        player_round: Round,
        player_period: Period,
        e: FilterableMessageEvent,
    ) -> Event {
        match e.message_event.t {
            EventType::VotePresent => {
                let (verify_for_cred_history, err) = self.filter_proposal_vote(
                    player_round,
                    player_period,
                    &e.message_event.input.unauthenticated_vote,
                    &e.freshness_data,
                );
                if let Some(err) = err {
                    let cred_tracking_note = if verify_for_cred_history {
                        LateCredentialTrackingEffect::UnverifiedLateCredentialForTracking
                    } else {
                        LateCredentialTrackingEffect::NoLateCredentialTrackingImpact
                    };
                    return Event::Filtered(FilteredEvent {
                        t: EventType::VoteFiltered,
                        err: Some(SerializableError::new(err)),
                        late_credential_tracking_note: cred_tracking_note,
                    });
                }
                Event::Empty(EmptyEvent)
            }

            EventType::VoteVerified => {
                if e.message_event.cancelled {
                    return Event::Filtered(FilteredEvent {
                        t: EventType::VoteFiltered,
                        err: e.message_event.err.clone(),
                        ..FilteredEvent::default()
                    });
                }

                if e.message_event.err.is_some() {
                    return Event::Filtered(FilteredEvent {
                        t: EventType::VoteMalformed,
                        err: e.message_event.err.clone(),
                        ..FilteredEvent::default()
                    });
                }

                // A `VoteVerified` event with no error must carry the
                // authenticated vote (the crypto verifier attaches it, as
                // Go does in `asyncVoteVerifier.go:107`). Drop the event
                // rather than panicking if it somehow does not: this is
                // network-sourced input on a consensus-critical thread,
                // and a panic here takes the whole agreement service — and
                // with it the catchup service — down (issue #478).
                let Some(v) = e.message_event.input.vote.as_ref() else {
                    return Event::Filtered(FilteredEvent {
                        t: EventType::VoteMalformed,
                        err: Some(SerializableError::new(
                            "proposalManager: VoteVerified without a vote".to_string(),
                        )),
                        ..FilteredEvent::default()
                    });
                };
                let uv = v.to_unauthenticated();

                let err = crate::types::proposal_fresh(&e.freshness_data, &uv);
                let mut keep_for_late_credential_tracking = false;
                if let Err(fresh_err) = &err {
                    keep_for_late_credential_tracking =
                        crate::types::proposal_useful_for_credential_history(
                            e.freshness_data.player_round,
                            &uv,
                        );
                    if !keep_for_late_credential_tracking {
                        let err_msg = format!(
                            "proposalManager: ignoring proposal-vote due to age: {}",
                            fresh_err
                        );
                        return Event::Filtered(FilteredEvent {
                            t: EventType::VoteFiltered,
                            err: Some(SerializableError::new(err_msg)),
                            ..FilteredEvent::default()
                        });
                    }
                }

                let vote_round = v.raw_vote.round;
                let vote_period = v.raw_vote.period;

                let store = self.store_for(vote_round);
                let result = store.handle(vote_period, Event::Message(e.message_event));

                if keep_for_late_credential_tracking {
                    let err_msg = if let Err(fresh_err) = err {
                        format!(
                            "proposalManager: ignoring proposal-vote due to age: {}",
                            fresh_err
                        )
                    } else {
                        "proposalManager: ignoring proposal-vote due to age".to_string()
                    };

                    if result.event_type() == EventType::VoteFiltered {
                        let cred_note = match &result {
                            Event::Filtered(fe) => {
                                let note = fe.late_credential_tracking_note;
                                if note
                                    != LateCredentialTrackingEffect::VerifiedBetterLateCredentialForTracking
                                    && note
                                        != LateCredentialTrackingEffect::NoLateCredentialTrackingImpact
                                {
                                    LateCredentialTrackingEffect::NoLateCredentialTrackingImpact
                                } else {
                                    note
                                }
                            }
                            _ => LateCredentialTrackingEffect::NoLateCredentialTrackingImpact,
                        };
                        return Event::Filtered(FilteredEvent {
                            t: EventType::VoteFiltered,
                            err: Some(SerializableError::new(err_msg)),
                            late_credential_tracking_note: cred_note,
                        });
                    }
                    // The proposalMachineRound didn't filter the vote, so it must
                    // have had a better credential
                    return Event::Filtered(FilteredEvent {
                        t: EventType::VoteFiltered,
                        err: Some(SerializableError::new(err_msg)),
                        late_credential_tracking_note:
                            LateCredentialTrackingEffect::VerifiedBetterLateCredentialForTracking,
                    });
                }
                result
            }

            EventType::PayloadPresent => {
                let prop_round = e.message_event.input.unauthenticated_proposal.round();
                let input = e.message_event;

                if player_round == prop_round {
                    let store = self.store_for(player_round);
                    let e1 = store.handle(player_period, Event::Message(input));
                    if e1.event_type() == EventType::PayloadRejected {
                        return e1;
                    }

                    let mut ep = match e1 {
                        Event::PayloadProcessed(ep) => ep,
                        _ => panic!("proposalManager: expected PayloadProcessedEvent"),
                    };
                    ep.round = player_round;
                    return Event::PayloadProcessed(ep);
                }

                // Pipeline for next round
                let next_round = Round(player_round.0 + 1);
                let store = self.store_for(next_round);
                let e2 = store.handle(Period(0), Event::Message(input));
                if e2.event_type() == EventType::PayloadRejected {
                    return e2;
                }
                let mut ep = match e2 {
                    Event::PayloadProcessed(ep) => ep,
                    _ => panic!("proposalManager: expected PayloadProcessedEvent"),
                };
                ep.round = next_round;
                Event::PayloadProcessed(ep)
            }

            EventType::PayloadVerified => {
                if e.message_event.cancelled {
                    return Event::PayloadProcessed(PayloadProcessedEvent {
                        t: EventType::PayloadRejected,
                        err: e.message_event.err.clone(),
                        ..PayloadProcessedEvent::default()
                    });
                }

                if e.message_event.err.is_some() {
                    return Event::Filtered(FilteredEvent {
                        t: EventType::PayloadMalformed,
                        err: e.message_event.err.clone(),
                        ..FilteredEvent::default()
                    });
                }

                let store = self.store_for(player_round);
                store.handle(player_period, Event::Message(e.message_event))
            }

            other => {
                panic!(
                    "proposalManager: handleMessageEvent: bad event type: {}",
                    other
                );
            }
        }
    }

    /// Filters a proposal vote, checking if it is both fresh and not a
    /// duplicate.
    ///
    /// Returns `(verify_for_cred_history, Option<error_message>)`.
    ///
    /// Mirrors Go's `proposalManager.filterProposalVote`.
    fn filter_proposal_vote(
        &mut self,
        _player_round: Round,
        _player_period: Period,
        uv: &UnauthenticatedVote,
        fresh_data: &crate::events::FreshnessData,
    ) -> (bool, Option<String>) {
        // Check if the vote is within the credential history window
        let cred_history =
            crate::types::proposal_useful_for_credential_history(fresh_data.player_round, uv);

        // checkDup asks proposalTracker if the vote is a duplicate
        let check_dup = |mgr: &mut Self| -> bool {
            let qe = Event::VoteFilterRequest(VoteFilterRequestEvent {
                raw_vote: uv.raw_vote.clone(),
            });
            let store = mgr.store_for(uv.raw_vote.round);
            let saw_vote = store.dispatch_to_tracker(uv.raw_vote.period, qe);
            saw_vote.event_type() == EventType::VoteFiltered
        };

        // Check the vote against the current player's freshness rules
        let err = crate::types::proposal_fresh(fresh_data, uv);
        if let Err(fresh_err) = err {
            // Not fresh, but possibly useful for credential history: ensure
            // not a duplicate
            let mut cred_history = cred_history;
            if cred_history && check_dup(self) {
                cred_history = false;
            }
            let err_msg = format!(
                "proposalManager: filtered proposal-vote due to age: {}",
                fresh_err
            );
            return (cred_history, Some(err_msg));
        }

        if check_dup(self) {
            let err_msg = format!(
                "proposalManager: filtered proposal-vote: sender {:?} had already sent a vote in round {} period {}",
                uv.raw_vote.sender, uv.raw_vote.round, uv.raw_vote.period
            );
            return (cred_history, Some(err_msg));
        }
        (cred_history, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{
        ConsensusVersionView, FilterableMessageEvent, FreshnessData, InternalMessage, MessageEvent,
        RoundInterruptionEvent,
    };
    use crate::step::Step;
    use crate::vote::{ProposalValue, RawVote, UnauthenticatedVote, BOTTOM};
    use algo_types::{Address, Digest};

    fn make_freshness_data(round: Round, period: Period) -> FreshnessData {
        FreshnessData {
            player_round: round,
            player_period: period,
            player_step: Step(0),
            player_last_concluding: Step(0),
        }
    }

    fn make_uv(round: Round, period: Period) -> UnauthenticatedVote {
        UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round,
                period,
                step: Step(0),
                proposal: ProposalValue {
                    original_period: Period(0),
                    original_proposer: Address([0x01; 32]),
                    block_digest: Digest([0xaa; 32]),
                    encoding_digest: Digest([0xbb; 32]),
                },
            },
            ..UnauthenticatedVote::default()
        }
    }

    #[test]
    fn proposal_manager_round_interruption() {
        let mut mgr = ProposalManager::default();
        let e = Event::RoundInterruption(RoundInterruptionEvent {
            round: Round(1),
            proto: ConsensusVersionView::default(),
        });
        let result = mgr.handle(Round(1), Period(0), e);
        // Should return empty (no pipelined payload)
        assert_eq!(result.event_type(), EventType::None);
    }

    #[test]
    fn proposal_manager_next_threshold() {
        let mut mgr = ProposalManager::default();
        let te = ThresholdEvent {
            t: EventType::NextThreshold,
            round: Round(1),
            period: Period(0),
            proposal: BOTTOM,
            ..ThresholdEvent::default()
        };
        let result = mgr.handle(Round(1), Period(0), Event::Threshold(te));
        assert_eq!(result.event_type(), EventType::None);
    }

    #[test]
    fn proposal_manager_vote_present_fresh() {
        let mut mgr = ProposalManager::default();
        let uv = make_uv(Round(1), Period(0));
        let fd = make_freshness_data(Round(1), Period(0));
        let fme = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VotePresent,
                input: InternalMessage {
                    unauthenticated_vote: uv,
                    ..InternalMessage::default()
                },
                ..MessageEvent::default()
            },
            freshness_data: fd,
        };
        let result = mgr.handle(Round(1), Period(0), Event::FilterableMessage(fme));
        // Fresh vote, not duplicate => empty (proceed to verify)
        assert_eq!(result.event_type(), EventType::None);
    }

    #[test]
    fn proposal_manager_vote_present_stale() {
        let mut mgr = ProposalManager::default();
        let uv = make_uv(Round(5), Period(0));
        let fd = make_freshness_data(Round(1), Period(0));
        let fme = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VotePresent,
                input: InternalMessage {
                    unauthenticated_vote: uv,
                    ..InternalMessage::default()
                },
                ..MessageEvent::default()
            },
            freshness_data: fd,
        };
        let result = mgr.handle(Round(1), Period(0), Event::FilterableMessage(fme));
        assert_eq!(result.event_type(), EventType::VoteFiltered);
    }

    #[test]
    fn proposal_manager_vote_verified_cancelled() {
        let mut mgr = ProposalManager::default();
        let fd = make_freshness_data(Round(1), Period(0));
        let fme = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VoteVerified,
                cancelled: true,
                err: Some(SerializableError::new("cancelled")),
                ..MessageEvent::default()
            },
            freshness_data: fd,
        };
        let result = mgr.handle(Round(1), Period(0), Event::FilterableMessage(fme));
        assert_eq!(result.event_type(), EventType::VoteFiltered);
    }

    /// Regression test for issue #478.
    ///
    /// A successful `VoteVerified` must carry the authenticated vote; the
    /// crypto verifier attaches it to the message exactly as Go does in
    /// `asyncVoteVerifier.go:107` (`req.message.Vote = v`). Before that fix
    /// `input.vote` was always `None`, and this arm's `expect` panicked on
    /// the very first successfully-verified proposal-vote — killing the
    /// agreement thread (and, through the dropped certificate channel, the
    /// catchup service with it).
    ///
    /// Whatever the cause, network-sourced input must never panic a
    /// consensus thread: it has to be filtered.
    #[test]
    fn proposal_manager_vote_verified_without_vote_is_filtered_not_panic() {
        let mut mgr = ProposalManager::default();
        let fd = make_freshness_data(Round(1), Period(0));
        let fme = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VoteVerified,
                // No error, not cancelled, but `input.vote` is `None`.
                ..MessageEvent::default()
            },
            freshness_data: fd,
        };
        let result = mgr.handle(Round(1), Period(0), Event::FilterableMessage(fme));
        assert_eq!(result.event_type(), EventType::VoteMalformed);
    }

    #[test]
    fn proposal_manager_vote_verified_malformed() {
        let mut mgr = ProposalManager::default();
        let fd = make_freshness_data(Round(1), Period(0));
        let fme = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VoteVerified,
                err: Some(SerializableError::new("malformed")),
                ..MessageEvent::default()
            },
            freshness_data: fd,
        };
        let result = mgr.handle(Round(1), Period(0), Event::FilterableMessage(fme));
        assert_eq!(result.event_type(), EventType::VoteMalformed);
    }

    /// TestProposalManagerRejectsUnknownEvent (go: agreement/proposalManager_test.go):
    /// an event type the manager doesn't recognize (`bundleVerified` is
    /// valid for the vote/bundle machinery but not for the proposal
    /// manager) must panic rather than be silently accepted. Mirrors go's
    /// `t.errorf`-then-panic ("bad event type") behavior in `handle`'s
    /// default arm above.
    #[test]
    #[should_panic(expected = "bad event type")]
    fn proposal_manager_rejects_unknown_event() {
        let mut mgr = ProposalManager::default();
        let ev = Event::Message(MessageEvent {
            t: EventType::BundleVerified,
            ..MessageEvent::default()
        });
        mgr.handle(Round(1), Period(0), ev);
    }

    #[test]
    fn proposal_manager_payload_verified_cancelled() {
        let mut mgr = ProposalManager::default();
        let fd = make_freshness_data(Round(1), Period(0));
        let fme = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::PayloadVerified,
                cancelled: true,
                err: Some(SerializableError::new("cancelled")),
                ..MessageEvent::default()
            },
            freshness_data: fd,
        };
        let result = mgr.handle(Round(1), Period(0), Event::FilterableMessage(fme));
        assert_eq!(result.event_type(), EventType::PayloadRejected);
    }

    #[test]
    fn proposal_manager_payload_verified_malformed() {
        let mut mgr = ProposalManager::default();
        let fd = make_freshness_data(Round(1), Period(0));
        let fme = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::PayloadVerified,
                cancelled: false,
                err: Some(SerializableError::new("bad payload")),
                ..MessageEvent::default()
            },
            freshness_data: fd,
        };
        let result = mgr.handle(Round(1), Period(0), Event::FilterableMessage(fme));
        assert_eq!(result.event_type(), EventType::PayloadMalformed);
    }

    // ---- Proposal accepted flow: vote verified with valid vote ----

    fn make_verified_vote(
        round: Round,
        period: Period,
        sender: algo_types::Address,
    ) -> crate::vote::Vote {
        crate::vote::Vote {
            raw_vote: crate::vote::RawVote {
                sender,
                round,
                period,
                step: Step(0), // propose step
                proposal: ProposalValue {
                    original_period: Period(0),
                    original_proposer: sender,
                    block_digest: algo_types::Digest([0xaa; 32]),
                    encoding_digest: algo_types::Digest([0xbb; 32]),
                },
            },
            cred: crate::credential::Credential {
                weight: 1,
                vrf_out: algo_types::Digest([0x10; 32]),
                domain_separation_enabled: true,
                hashable: crate::credential::HashableCredential {
                    raw_out: [0x10; 64],
                    member: sender,
                    iter: 0,
                },
                proof: [0u8; crate::VRF_PROOF_SIZE],
            },
            sig: algo_consensus_crypto::OneTimeSignature {
                sig: [0u8; 64],
                pk: [0u8; 32],
                pk_sig_old: [0u8; 64],
                pk2: [0u8; 32],
                pk1_sig: [0u8; 64],
                pk2_sig: [0u8; 64],
            },
            validated_at: std::time::Duration::ZERO,
        }
    }

    #[test]
    fn proposal_manager_vote_verified_accepted() {
        let mut mgr = ProposalManager::default();
        let sender = algo_types::Address([0x01; 32]);
        let vote = make_verified_vote(Round(1), Period(0), sender);
        let uv = vote.to_unauthenticated();
        let fd = make_freshness_data(Round(1), Period(0));

        let fme = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VoteVerified,
                input: InternalMessage {
                    vote: Some(vote),
                    unauthenticated_vote: uv,
                    ..InternalMessage::default()
                },
                ..MessageEvent::default()
            },
            freshness_data: fd,
        };
        let result = mgr.handle(Round(1), Period(0), Event::FilterableMessage(fme));
        // Should be accepted as a proposal
        assert_eq!(result.event_type(), EventType::ProposalAccepted);
    }

    // ---- Duplicate vote from same sender filtered ----

    #[test]
    fn proposal_manager_vote_verified_duplicate_sender_filtered() {
        let mut mgr = ProposalManager::default();
        let sender = algo_types::Address([0x01; 32]);
        let vote = make_verified_vote(Round(1), Period(0), sender);
        let uv = vote.to_unauthenticated();
        let fd = make_freshness_data(Round(1), Period(0));

        // Accept first vote
        let fme = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VoteVerified,
                input: InternalMessage {
                    vote: Some(vote.clone()),
                    unauthenticated_vote: uv.clone(),
                    ..InternalMessage::default()
                },
                ..MessageEvent::default()
            },
            freshness_data: fd,
        };
        let result1 = mgr.handle(Round(1), Period(0), Event::FilterableMessage(fme));
        assert_eq!(result1.event_type(), EventType::ProposalAccepted);

        // Second vote from same sender should be filtered as duplicate
        let fme2 = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VoteVerified,
                input: InternalMessage {
                    vote: Some(vote),
                    unauthenticated_vote: uv,
                    ..InternalMessage::default()
                },
                ..MessageEvent::default()
            },
            freshness_data: fd,
        };
        let result2 = mgr.handle(Round(1), Period(0), Event::FilterableMessage(fme2));
        assert_eq!(result2.event_type(), EventType::VoteFiltered);
    }

    // ---- New period transition ----

    #[test]
    fn proposal_manager_soft_threshold_triggers_new_period_when_ahead() {
        let mut mgr = ProposalManager::default();
        let pv = ProposalValue {
            original_period: Period(0),
            original_proposer: algo_types::Address([0x01; 32]),
            block_digest: algo_types::Digest([0xaa; 32]),
            encoding_digest: algo_types::Digest([0xbb; 32]),
        };
        let te = ThresholdEvent {
            t: EventType::SoftThreshold,
            round: Round(1),
            period: Period(2),
            proposal: pv,
            ..ThresholdEvent::default()
        };

        // Player is at period 0, threshold is for period 2 => should trigger new period
        let result = mgr.handle(Round(1), Period(0), Event::Threshold(te));
        // The result depends on the store state, but it should not panic
        assert!(
            result.event_type() == EventType::ProposalAccepted
                || result.event_type() == EventType::None
                || result.event_type() == EventType::ProposalCommittable
        );
    }

    // ---- Cross-round dispatch ----

    #[test]
    fn proposal_manager_cert_threshold_dispatches_to_correct_round() {
        let mut mgr = ProposalManager::default();
        let pv = ProposalValue {
            original_period: Period(0),
            original_proposer: algo_types::Address([0x01; 32]),
            block_digest: algo_types::Digest([0xaa; 32]),
            encoding_digest: algo_types::Digest([0xbb; 32]),
        };

        // Cert threshold for round 5, period 0
        let te = ThresholdEvent {
            t: EventType::CertThreshold,
            round: Round(5),
            period: Period(0),
            proposal: pv,
            ..ThresholdEvent::default()
        };

        // Player is at round 5, period 0
        let result = mgr.handle(Round(5), Period(0), Event::Threshold(te));
        // Should be dispatched to the round-5 store, which should accept it
        assert!(
            result.event_type() == EventType::ProposalAccepted
                || result.event_type() == EventType::ProposalCommittable
        );
    }

    // ---- Duplicate vote detection ----

    #[test]
    fn proposal_manager_duplicate_vote_present_filtered() {
        let mut mgr = ProposalManager::default();
        let uv = make_uv(Round(1), Period(0));
        let fd = make_freshness_data(Round(1), Period(0));

        // First vote present
        let fme1 = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VotePresent,
                input: InternalMessage {
                    unauthenticated_vote: uv.clone(),
                    ..InternalMessage::default()
                },
                ..MessageEvent::default()
            },
            freshness_data: fd,
        };
        mgr.handle(Round(1), Period(0), Event::FilterableMessage(fme1));

        // To generate a duplicate, first we need to "accept" the vote through VoteVerified
        let sender = algo_types::Address([0x01; 32]);
        let vote = make_verified_vote(Round(1), Period(0), sender);
        let uv_v = vote.to_unauthenticated();
        let fme_v = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VoteVerified,
                input: InternalMessage {
                    vote: Some(vote),
                    unauthenticated_vote: uv_v,
                    ..InternalMessage::default()
                },
                ..MessageEvent::default()
            },
            freshness_data: fd,
        };
        mgr.handle(Round(1), Period(0), Event::FilterableMessage(fme_v));

        // Now a second VotePresent from the same sender should be filtered as duplicate
        let fme2 = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::VotePresent,
                input: InternalMessage {
                    unauthenticated_vote: uv,
                    ..InternalMessage::default()
                },
                ..MessageEvent::default()
            },
            freshness_data: fd,
        };
        let result = mgr.handle(Round(1), Period(0), Event::FilterableMessage(fme2));
        assert_eq!(result.event_type(), EventType::VoteFiltered);
    }

    // ---- Next threshold creates new period ----

    #[test]
    fn proposal_manager_next_threshold_returns_empty() {
        let mut mgr = ProposalManager::default();
        let pv = ProposalValue {
            original_period: Period(0),
            original_proposer: algo_types::Address([0x01; 32]),
            block_digest: algo_types::Digest([0xaa; 32]),
            encoding_digest: algo_types::Digest([0xbb; 32]),
        };
        let te = ThresholdEvent {
            t: EventType::NextThreshold,
            round: Round(1),
            period: Period(0),
            proposal: pv,
            ..ThresholdEvent::default()
        };
        let result = mgr.handle(Round(1), Period(0), Event::Threshold(te));
        // Next threshold always returns empty from proposal manager
        assert_eq!(result.event_type(), EventType::None);
    }

    // ---- PayloadPresent for current round ----

    #[test]
    fn proposal_manager_payload_present_no_assembler_rejected() {
        let mut mgr = ProposalManager::default();
        let fd = make_freshness_data(Round(1), Period(0));

        let fme = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::PayloadPresent,
                input: InternalMessage {
                    unauthenticated_proposal: crate::proposal::UnauthenticatedProposal::default(),
                    ..InternalMessage::default()
                },
                ..MessageEvent::default()
            },
            freshness_data: fd,
        };
        let result = mgr.handle(Round(1), Period(0), Event::FilterableMessage(fme));
        // No assembler exists => should be rejected
        assert_eq!(result.event_type(), EventType::PayloadRejected);
    }

    // ---- PayloadVerified for current round ----

    #[test]
    fn proposal_manager_payload_verified_no_assembler_rejected() {
        let mut mgr = ProposalManager::default();
        let fd = make_freshness_data(Round(1), Period(0));

        let pp = crate::events::Proposal::default();
        let fme = FilterableMessageEvent {
            message_event: MessageEvent {
                t: EventType::PayloadVerified,
                input: InternalMessage {
                    proposal: Some(pp),
                    ..InternalMessage::default()
                },
                ..MessageEvent::default()
            },
            freshness_data: fd,
        };
        let result = mgr.handle(Round(1), Period(0), Event::FilterableMessage(fme));
        // No assembler exists => should be rejected
        assert_eq!(result.event_type(), EventType::PayloadRejected);
    }
}
