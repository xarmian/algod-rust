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

// Proposal tracker types matching go-algorand/agreement/proposalTracker.go.
//
// - `ProposalSeeker`: finds the vote with the lowest credential until freeze()
//   is called.
// - `ProposalTracker`: de-duplicates proposal-votes seen in a given period and
//   records the lowest credential seen and the period's staging proposal-value.
//
// These correspond to Go's `proposalSeeker` and `proposalTracker` types
// (the proposalMachinePeriod state machine).

use std::collections::HashMap;
use std::fmt;

use algo_types::{Address, Round};
use serde::{Deserialize, Serialize};

use crate::events::{
    EmptyEvent, Event, EventType, FilteredEvent, LateCredentialTrackingEffect,
    ProposalAcceptedEvent, SerializableError,
};
use crate::step::Period;
use crate::vote::{ProposalValue, Vote, BOTTOM};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Error: the proposalSeeker is already frozen.
///
/// Mirrors Go's `errProposalSeekerFrozen`.
#[derive(Debug, Clone)]
pub struct ErrProposalSeekerFrozen;

impl fmt::Display for ErrProposalSeekerFrozen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "proposalSeeker.accept: seeker is already frozen")
    }
}

impl std::error::Error for ErrProposalSeekerFrozen {}

/// Error: the new credential is not less than the current lowest.
///
/// Mirrors Go's `errProposalSeekerNotLess`.
#[derive(Debug, Clone)]
pub struct ErrProposalSeekerNotLess {
    pub new_sender: Address,
    pub lowest_sender: Address,
}

impl fmt::Display for ErrProposalSeekerNotLess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "proposalSeeker.accept: credential from {:?} is not less than credential from {:?}",
            self.new_sender, self.lowest_sender
        )
    }
}

impl std::error::Error for ErrProposalSeekerNotLess {}

/// Error: duplicate sender in the proposalTracker.
///
/// Mirrors Go's `errProposalTrackerSenderDup`.
#[derive(Debug, Clone)]
pub struct ErrProposalTrackerSenderDup {
    pub sender: Address,
    pub round: Round,
    pub period: Period,
}

impl fmt::Display for ErrProposalTrackerSenderDup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "proposalTracker: filtered vote: sender {:?} had already sent a vote in round {} period {}",
            self.sender, self.round, self.period
        )
    }
}

impl std::error::Error for ErrProposalTrackerSenderDup {}

/// Error: a proposal value has already been staged.
///
/// Mirrors Go's `errProposalTrackerStaged`.
#[derive(Debug, Clone)]
pub struct ErrProposalTrackerStaged;

impl fmt::Display for ErrProposalTrackerStaged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "proposalTracker: value already staged")
    }
}

impl std::error::Error for ErrProposalTrackerStaged {}

/// Error: wrapping a proposalSeeker sub-error.
///
/// Mirrors Go's `errProposalTrackerPS`.
#[derive(Debug, Clone)]
pub struct ErrProposalTrackerPS {
    pub sub: String,
}

impl fmt::Display for ErrProposalTrackerPS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "proposalTracker: filtered vote: {}", self.sub)
    }
}

impl std::error::Error for ErrProposalTrackerPS {}

// ---------------------------------------------------------------------------
// ProposalSeeker
// ---------------------------------------------------------------------------

/// Finds the vote with the lowest credential until `freeze()` is called.
///
/// Mirrors Go's `proposalSeeker`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProposalSeeker {
    /// The vote with the lowest credential seen so far.
    pub lowest: Vote,
    /// Whether any vote has been seen.
    pub filled: bool,
    /// Whether the seeker has been frozen.
    pub frozen: bool,

    /// Tracks the lowest credential observed, even after the `lowest` value
    /// has been frozen.
    lowest_including_late: Vote,
    has_lowest_including_late: bool,
}

impl ProposalSeeker {
    /// Compares a given vote with the current lowest-credentialled vote and
    /// sets it if freeze has not been called.
    ///
    /// Returns:
    /// - The updated `ProposalSeeker` state.
    /// - A `LateCredentialTrackingEffect` describing the usefulness of the
    ///   proposal-vote's credential for late credential tracking.
    /// - `Ok(())` on success, or an error if the proposal was not better than
    ///   the lowest seen, or the seeker was already frozen.
    ///
    /// Mirrors Go's `proposalSeeker.accept`.
    pub fn accept(
        mut self,
        v: Vote,
    ) -> (
        ProposalSeeker,
        LateCredentialTrackingEffect,
        Result<(), String>,
    ) {
        if self.frozen {
            let mut effect = LateCredentialTrackingEffect::NoLateCredentialTrackingImpact;
            // Continue tracking and forwarding the lowest proposal even when frozen
            if !self.has_lowest_including_late || v.cred.less(&self.lowest_including_late.cred) {
                self.lowest_including_late = v;
                self.has_lowest_including_late = true;
                effect = LateCredentialTrackingEffect::VerifiedBetterLateCredentialForTracking;
            }
            let err = ErrProposalSeekerFrozen;
            return (self, effect, Err(err.to_string()));
        }

        if self.filled && !v.cred.less(&self.lowest.cred) {
            let err = ErrProposalSeekerNotLess {
                new_sender: v.raw_vote.sender,
                lowest_sender: self.lowest.raw_vote.sender,
            };
            return (
                self,
                LateCredentialTrackingEffect::NoLateCredentialTrackingImpact,
                Err(err.to_string()),
            );
        }

        self.lowest = v.clone();
        self.filled = true;
        self.lowest_including_late = v;
        self.has_lowest_including_late = true;
        (
            self,
            LateCredentialTrackingEffect::VerifiedBetterLateCredentialForTracking,
            Ok(()),
        )
    }

    /// Copies the late credential tracking state from another seeker.
    ///
    /// Mirrors Go's `proposalSeeker.copyLateCredentialTrackingState`.
    pub fn copy_late_credential_tracking_state(&mut self, other: &ProposalSeeker) {
        self.has_lowest_including_late = other.has_lowest_including_late;
        self.lowest_including_late = other.lowest_including_late.clone();
    }

    /// Freezes the state of the seeker so that future `accept()` calls no
    /// longer change the `lowest` or `filled` fields.
    ///
    /// Mirrors Go's `proposalSeeker.freeze`.
    pub fn freeze(mut self) -> ProposalSeeker {
        self.frozen = true;
        self
    }
}

// ---------------------------------------------------------------------------
// ProposalTracker
// ---------------------------------------------------------------------------

/// A per-period state machine that de-duplicates proposal-votes and records
/// the lowest credential seen and the period's staging proposal-value.
///
/// Handles: `VoteFilterRequest`, `VoteVerified`, `ProposalFrozen`,
/// `ReadLowestVote`, `SoftThreshold`, `CertThreshold`, `ReadStaging`.
///
/// Returns: `VoteFiltered`, `ProposalAccepted`, `ReadStaging`,
/// `ProposalFrozen`, `ReadLowestVote`.
///
/// Mirrors Go's `proposalTracker` (the `proposalMachinePeriod`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalTracker {
    /// The set of senders which have been seen by this tracker.
    /// A duplicate or equivocating proposal-vote is dropped.
    pub duplicate: HashMap<Address, bool>,
    /// Seeks the proposal-vote with the lowest credential.
    pub freezer: ProposalSeeker,
    /// The staging proposal-value (set by soft/cert threshold).
    pub staging: ProposalValue,
}

impl Default for ProposalTracker {
    fn default() -> Self {
        Self {
            duplicate: HashMap::new(),
            freezer: ProposalSeeker::default(),
            staging: BOTTOM,
        }
    }
}

impl ProposalTracker {
    /// Handle an event dispatched to this proposalMachinePeriod.
    ///
    /// Dispatches on event type and returns the resulting event.
    ///
    /// Mirrors Go's `proposalTracker.handle`.
    pub fn handle(&mut self, e: Event) -> Event {
        match e.event_type() {
            EventType::VoteFilterRequest => {
                let vfr = match e {
                    Event::VoteFilterRequest(ref vfr) => vfr,
                    _ => panic!("proposalTracker: expected VoteFilterRequest event"),
                };
                let v = &vfr.raw_vote;
                if self.duplicate.contains_key(&v.sender) {
                    let err = ErrProposalTrackerSenderDup {
                        sender: v.sender,
                        round: v.round,
                        period: v.period,
                    };
                    return Event::Filtered(FilteredEvent {
                        t: EventType::VoteFiltered,
                        err: Some(SerializableError::new(err.to_string())),
                        ..FilteredEvent::default()
                    });
                }
                Event::Empty(EmptyEvent)
            }

            EventType::VoteVerified => {
                let me = match e {
                    Event::Message(ref me) => me.clone(),
                    _ => panic!("proposalTracker: expected MessageEvent for VoteVerified"),
                };
                let v = me
                    .input
                    .vote
                    .as_ref()
                    .expect("proposalTracker: VoteVerified event must have vote")
                    .clone();

                if self.duplicate.contains_key(&v.raw_vote.sender) {
                    let err = ErrProposalTrackerSenderDup {
                        sender: v.raw_vote.sender,
                        round: v.raw_vote.round,
                        period: v.raw_vote.period,
                    };
                    return Event::Filtered(FilteredEvent {
                        t: EventType::VoteFiltered,
                        err: Some(SerializableError::new(err.to_string())),
                        ..FilteredEvent::default()
                    });
                }
                self.duplicate.insert(v.raw_vote.sender, true);

                let (new_freezer, effect, err) = self.freezer.clone().accept(v.clone());
                self.freezer
                    .copy_late_credential_tracking_state(&new_freezer);

                if self.staging != BOTTOM {
                    let err = ErrProposalTrackerStaged;
                    return Event::Filtered(FilteredEvent {
                        t: EventType::VoteFiltered,
                        late_credential_tracking_note: effect,
                        err: Some(SerializableError::new(err.to_string())),
                    });
                }

                if let Err(err_msg) = err {
                    let err = ErrProposalTrackerPS { sub: err_msg };
                    return Event::Filtered(FilteredEvent {
                        t: EventType::VoteFiltered,
                        late_credential_tracking_note: effect,
                        err: Some(SerializableError::new(err.to_string())),
                    });
                }
                self.freezer = new_freezer;

                Event::ProposalAccepted(ProposalAcceptedEvent {
                    round: v.raw_vote.round,
                    period: v.raw_vote.period,
                    proposal: v.raw_vote.proposal,
                    ..ProposalAcceptedEvent::default()
                })
            }

            EventType::ProposalFrozen => {
                let mut pfe = match e {
                    Event::ProposalFrozen(pfe) => pfe,
                    _ => panic!("proposalTracker: expected ProposalFrozenEvent"),
                };
                pfe.proposal = self.freezer.lowest.raw_vote.proposal;
                self.freezer = self.freezer.clone().freeze();
                Event::ProposalFrozen(pfe)
            }

            EventType::ReadLowestVote => {
                let mut rle = match e {
                    Event::ReadLowest(rle) => rle,
                    _ => panic!("proposalTracker: expected ReadLowestEvent"),
                };
                rle.vote = Some(self.freezer.lowest.clone());
                rle.filled = self.freezer.filled;
                rle.lowest_including_late = Some(self.freezer.lowest_including_late.clone());
                rle.has_lowest_including_late = self.freezer.has_lowest_including_late;
                Event::ReadLowest(rle)
            }

            EventType::SoftThreshold | EventType::CertThreshold => {
                let te = match e {
                    Event::Threshold(ref te) => te.clone(),
                    _ => panic!("proposalTracker: expected ThresholdEvent"),
                };
                self.staging = te.proposal;

                Event::ProposalAccepted(ProposalAcceptedEvent {
                    round: te.round,
                    period: te.period,
                    proposal: te.proposal,
                    ..ProposalAcceptedEvent::default()
                })
            }

            EventType::ReadStaging => {
                let mut se = match e {
                    Event::StagingValue(se) => se,
                    _ => panic!("proposalTracker: expected StagingValueEvent"),
                };
                se.proposal = self.staging;
                Event::StagingValue(se)
            }

            other => {
                panic!(
                    "proposalTracker: bad event type: observed an event of type {}",
                    other
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{Credential, HashableCredential};
    use crate::events::{
        ProposalFrozenEvent, StagingValueEvent, ThresholdEvent, VoteFilterRequestEvent,
    };
    use crate::vote::RawVote;
    use crate::VRF_PROOF_SIZE;
    use algo_types::Digest;

    fn make_vote(sender: Address, cred_val: u8) -> Vote {
        Vote {
            raw_vote: RawVote {
                sender,
                round: Round(1),
                period: Period(0),
                step: crate::step::Step(0),
                proposal: ProposalValue {
                    original_period: Period(0),
                    original_proposer: sender,
                    block_digest: Digest([cred_val; 32]),
                    encoding_digest: Digest([cred_val; 32]),
                },
            },
            cred: Credential {
                weight: 1,
                vrf_out: Digest([cred_val; 32]),
                domain_separation_enabled: true,
                hashable: HashableCredential {
                    raw_out: [cred_val; 64],
                    member: sender,
                    iter: 0,
                },
                proof: [0u8; VRF_PROOF_SIZE],
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
    fn seeker_accept_first_vote() {
        let seeker = ProposalSeeker::default();
        let v = make_vote(Address([0x01; 32]), 0x10);
        let (s, effect, result) = seeker.accept(v);
        assert!(result.is_ok());
        assert!(s.filled);
        assert!(!s.frozen);
        assert_eq!(
            effect,
            LateCredentialTrackingEffect::VerifiedBetterLateCredentialForTracking
        );
    }

    #[test]
    fn seeker_accept_frozen() {
        let seeker = ProposalSeeker::default().freeze();
        let v = make_vote(Address([0x01; 32]), 0x10);
        let (s, _effect, result) = seeker.accept(v);
        assert!(result.is_err());
        assert!(s.frozen);
    }

    #[test]
    fn seeker_freeze() {
        let seeker = ProposalSeeker::default();
        let v = make_vote(Address([0x01; 32]), 0x10);
        let (s, _, _) = seeker.accept(v);
        let s = s.freeze();
        assert!(s.frozen);
        assert!(s.filled);
    }

    #[test]
    fn tracker_vote_filter_request_empty() {
        let mut tracker = ProposalTracker::default();
        let e = Event::VoteFilterRequest(VoteFilterRequestEvent {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round: Round(1),
                period: Period(0),
                step: crate::step::Step(0),
                proposal: BOTTOM,
            },
        });
        let result = tracker.handle(e);
        assert_eq!(result.event_type(), EventType::None);
    }

    #[test]
    fn tracker_vote_filter_request_duplicate() {
        let mut tracker = ProposalTracker::default();
        tracker.duplicate.insert(Address([0x01; 32]), true);
        let e = Event::VoteFilterRequest(VoteFilterRequestEvent {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round: Round(1),
                period: Period(0),
                step: crate::step::Step(0),
                proposal: BOTTOM,
            },
        });
        let result = tracker.handle(e);
        assert_eq!(result.event_type(), EventType::VoteFiltered);
    }

    #[test]
    fn tracker_proposal_frozen() {
        let mut tracker = ProposalTracker::default();
        let e = Event::ProposalFrozen(ProposalFrozenEvent::default());
        let result = tracker.handle(e);
        assert_eq!(result.event_type(), EventType::ProposalFrozen);
        assert!(tracker.freezer.frozen);
    }

    #[test]
    fn tracker_read_staging_empty() {
        let mut tracker = ProposalTracker::default();
        let e = Event::StagingValue(StagingValueEvent::default());
        let result = tracker.handle(e);
        assert_eq!(result.event_type(), EventType::ReadStaging);
        if let Event::StagingValue(se) = result {
            assert_eq!(se.proposal, BOTTOM);
        } else {
            panic!("expected StagingValue");
        }
    }

    #[test]
    fn tracker_soft_threshold_sets_staging() {
        let mut tracker = ProposalTracker::default();
        let pv = ProposalValue {
            original_period: Period(0),
            original_proposer: Address([0x01; 32]),
            block_digest: Digest([0xaa; 32]),
            encoding_digest: Digest([0xbb; 32]),
        };
        let te = ThresholdEvent {
            t: EventType::SoftThreshold,
            round: Round(1),
            period: Period(0),
            proposal: pv,
            ..ThresholdEvent::default()
        };
        let result = tracker.handle(Event::Threshold(te));
        assert_eq!(result.event_type(), EventType::ProposalAccepted);
        assert_eq!(tracker.staging, pv);
    }
}
