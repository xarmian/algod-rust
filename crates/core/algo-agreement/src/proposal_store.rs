// Proposal store types matching go-algorand/agreement/proposalStore.go.
//
// - `BlockAssembler`: assembles a block from proposal + payload, handling
//   pipelining (payload can arrive before or after proposal-vote).
// - `ProposalStore`: per-round proposal storage containing proposal trackers
//   per period and block assemblers per proposal-value.
//
// These correspond to Go's `blockAssembler` and `proposalStore` types
// (the proposalMachineRound state machine).

use std::collections::HashMap;

use algo_types::Round;

use crate::events::{
    CommittableEvent, EmptyEvent, Event, EventType, PayloadProcessedEvent, Proposal,
    ProposalAcceptedEvent, SerializableError, StagingValueEvent,
};
use crate::proposal::UnauthenticatedProposal;
use crate::proposal_tracker::ProposalTracker;
use crate::step::Period;
use crate::vote::{ProposalValue, Vote, BOTTOM};

// ---------------------------------------------------------------------------
// BlockAssembler
// ---------------------------------------------------------------------------

/// Contains the proposal data associated with some proposal-value.
///
/// When an unauthenticated proposal first arrives at the state machine, it is
/// pipelined by the blockAssembler. Subsequent duplicates are filtered.
///
/// Once a proposal is successfully validated, it is stored by the
/// blockAssembler.
///
/// Mirrors Go's `blockAssembler`.
#[derive(Debug, Clone, Default)]
pub struct BlockAssembler {
    /// A proposal which has not yet been validated. The proposal might be
    /// inside the cryptoVerifier, or it might be a pipelined proposal from
    /// the next round.
    pub pipeline: UnauthenticatedProposal,
    /// Whether the blockAssembler has seen a pipelined proposal.
    pub filled: bool,

    /// A valid proposal seen by the blockAssembler.
    pub payload: Option<Proposal>,
    /// Whether the blockAssembler has seen a valid proposal.
    pub assembled: bool,

    /// Caches the set of proposal-votes which have been seen for a given
    /// proposal-value. When a proposal payload is relayed by the state
    /// machine, a matching vote can be concatenated with the payload to ensure
    /// peers do not drop it.
    pub authenticators: Vec<Vote>,
}

impl BlockAssembler {
    /// Adds the given unvalidated proposal to the blockAssembler, returning
    /// an error if the pipelining operation is redundant.
    ///
    /// Mirrors Go's `blockAssembler.pipeline`.
    pub fn pipeline(mut self, p: UnauthenticatedProposal) -> Result<BlockAssembler, String> {
        if self.assembled {
            return Err("blockAssembler.pipeline: already assembled".to_string());
        }

        if self.filled {
            return Err("blockAssembler.pipeline: already filled".to_string());
        }

        self.pipeline = p;
        self.filled = true;

        Ok(self)
    }

    /// Adds the given validated proposal to the blockAssembler, returning an
    /// error if a validated proposal has already been received.
    ///
    /// Mirrors Go's `blockAssembler.bind`.
    pub fn bind(mut self, p: Proposal) -> Result<BlockAssembler, String> {
        if self.assembled {
            return Err("blockAssembler.pipeline: already assembled".to_string());
        }

        // In Go, `receivedAt` is copied from the pipeline's
        // unauthenticatedProposal into the bound proposal. In our Rust
        // implementation, `received_at` lives on the authenticated `Proposal`
        // type (in events.rs), not on `UnauthenticatedProposal`. The caller
        // is responsible for setting `received_at` before calling `bind`.
        self.payload = Some(p);
        self.assembled = true;

        Ok(self)
    }

    /// Returns a proposal-vote which matches the blockAssembler's proposal
    /// for the given period, or `None` if none exists.
    ///
    /// Mirrors Go's `blockAssembler.authenticator`.
    pub fn authenticator(&self, p: Period) -> Option<Vote> {
        for v in &self.authenticators {
            if v.raw_vote.period == p {
                return Some(v.clone());
            }
        }
        None
    }

    /// Removes authenticators older than the given period from the
    /// blockAssembler.
    ///
    /// Mirrors Go's `blockAssembler.trim`.
    pub fn trim(mut self, p: Period) -> BlockAssembler {
        let old = std::mem::take(&mut self.authenticators);
        self.authenticators = Vec::new();
        for v in old {
            if v.raw_vote.period >= p {
                self.authenticators.push(v);
            }
        }
        self
    }
}

// ---------------------------------------------------------------------------
// ProposalStore
// ---------------------------------------------------------------------------

/// A per-round state machine that stores payload data and caches
/// proposal-votes for a given round in a space-efficient manner.
///
/// Handles: `VoteVerified`, `PayloadPresent`, `PayloadVerified`, `NewRound`,
/// `NewPeriod`, `SoftThreshold`, `CertThreshold`, `ReadStaging`,
/// `ReadLowestVote`, `ReadPinned`.
///
/// Mirrors Go's `proposalStore` (the `proposalMachineRound`).
#[derive(Debug, Clone)]
pub struct ProposalStore {
    /// Current collection of important proposal-values in the round.
    /// Indexed by period; the `ProposalValue` is the last one reported by
    /// the corresponding `ProposalTracker`.
    pub relevant: HashMap<Period, ProposalValue>,
    /// The extra proposal-value (not tracked in `relevant`) for which a
    /// certificate may have formed (i.e., vbar in the spec).
    pub pinned: ProposalValue,

    /// The set of proposal-values currently tracked and held by the
    /// proposalStore, keyed by proposal-value.
    pub assemblers: HashMap<ProposalValue, BlockAssembler>,

    /// Per-period proposal trackers. In Go these are dispatched via the
    /// router; here we maintain them directly.
    pub trackers: HashMap<Period, ProposalTracker>,
}

impl Default for ProposalStore {
    fn default() -> Self {
        Self {
            relevant: HashMap::new(),
            pinned: BOTTOM,
            assemblers: HashMap::new(),
            trackers: HashMap::new(),
        }
    }
}

impl ProposalStore {
    /// Dispatch an event to the `ProposalTracker` for the given period,
    /// creating one if it does not exist.
    ///
    /// This replaces Go's `r.dispatch(p, e, proposalMachinePeriod, ...)`.
    pub(crate) fn dispatch_to_tracker(&mut self, period: Period, e: Event) -> Event {
        let tracker = self.trackers.entry(period).or_default();
        tracker.handle(e)
    }

    /// Query the staging value for a given round and period.
    ///
    /// Mirrors Go's `stagedValue` free function.
    fn staged_value(&mut self, round: Round, period: Period) -> StagingValueEvent {
        let qe = Event::StagingValue(StagingValueEvent {
            round,
            period,
            ..StagingValueEvent::default()
        });
        let result = self.dispatch_to_tracker(period, qe);
        match result {
            Event::StagingValue(se) => se,
            _ => panic!("proposalStore: stagedValue: expected StagingValueEvent"),
        }
    }

    /// Returns `(period, pinned)` where `pinned` is true if the given
    /// proposal-value is the pinned value; otherwise, returns the greatest
    /// period for which the proposal-value is relevant.
    ///
    /// Mirrors Go's `proposalStore.lastRelevant`.
    fn last_relevant(&self, pv: ProposalValue) -> (Period, bool) {
        if self.pinned == pv {
            return (Period(0), true);
        }

        let mut best = Period(0);
        for (&per, ref_pv) in &self.relevant {
            if per > best && *ref_pv == pv {
                best = per;
            }
        }
        (best, false)
    }

    /// Reduces the size of `assemblers` to account for a minimal set of
    /// proposal-values.
    ///
    /// Mirrors Go's `proposalStore.trim`.
    fn trim(&mut self, current_period: Period) {
        let old = std::mem::take(&mut self.assemblers);
        self.assemblers = HashMap::new();

        // Always keep the pinned assembler
        self.assemblers.insert(
            self.pinned,
            old.get(&self.pinned)
                .cloned()
                .unwrap_or_default()
                .trim(current_period),
        );

        // Keep all relevant assemblers
        for pv in self.relevant.values() {
            self.assemblers.insert(
                *pv,
                old.get(pv)
                    .cloned()
                    .unwrap_or_default()
                    .trim(current_period),
            );
        }

        // Remove the bottom assembler if pinned is not set
        self.assemblers.remove(&BOTTOM);
    }

    /// Handle an event dispatched to this proposalMachineRound.
    ///
    /// Dispatches on event type and returns the resulting event.
    ///
    /// Mirrors Go's `proposalStore.handle`.
    pub fn handle(&mut self, current_period: Period, e: Event) -> Event {
        match e.event_type() {
            EventType::VoteVerified => {
                let me = match &e {
                    Event::Message(me) => me.clone(),
                    _ => panic!("proposalStore: expected MessageEvent for VoteVerified"),
                };
                let v = me
                    .input
                    .vote
                    .as_ref()
                    .expect("proposalStore: VoteVerified must have vote")
                    .clone();

                let period = v.raw_vote.period;
                let ev = self.dispatch_to_tracker(period, e);

                if ev.event_type() == EventType::ProposalAccepted {
                    let mut pae = match ev {
                        Event::ProposalAccepted(pae) => pae,
                        _ => unreachable!(),
                    };

                    let ea = self.assemblers.entry(pae.proposal).or_default();
                    ea.authenticators.push(v.clone());

                    let payload = ea.payload.clone();
                    let assembled = ea.assembled;

                    self.relevant.insert(period, pae.proposal);
                    self.trim(current_period);

                    pae.payload = payload;
                    pae.payload_ok = assembled;
                    return Event::ProposalAccepted(pae);
                }

                ev
            }

            EventType::PayloadPresent => {
                let me = match &e {
                    Event::Message(me) => me.clone(),
                    _ => panic!("proposalStore: expected MessageEvent for PayloadPresent"),
                };
                let up = me.input.unauthenticated_proposal.clone();
                let pv = up.value();

                let ea = match self.assemblers.get(&pv) {
                    Some(ea) => ea.clone(),
                    None => {
                        return Event::PayloadProcessed(PayloadProcessedEvent {
                            t: EventType::PayloadRejected,
                            err: Some(SerializableError::new(
                                "proposalStore: no accepting blockAssembler found on payloadPresent",
                            )),
                            ..PayloadProcessedEvent::default()
                        });
                    }
                };

                match ea.clone().pipeline(up.clone()) {
                    Ok(new_ea) => {
                        let auth_vote = ea.authenticator(current_period);
                        let (relevant_period, pinned) = self.last_relevant(pv);
                        self.assemblers.insert(pv, new_ea);
                        Event::PayloadProcessed(PayloadProcessedEvent {
                            t: EventType::PayloadPipelined,
                            vote: auth_vote,
                            period: relevant_period,
                            pinned,
                            proposal: pv,
                            unauthenticated_payload: up,
                            ..PayloadProcessedEvent::default()
                        })
                    }
                    Err(err) => Event::PayloadProcessed(PayloadProcessedEvent {
                        t: EventType::PayloadRejected,
                        err: Some(SerializableError::new(err)),
                        ..PayloadProcessedEvent::default()
                    }),
                }
            }

            EventType::PayloadVerified => {
                let me = match &e {
                    Event::Message(me) => me.clone(),
                    _ => panic!("proposalStore: expected MessageEvent for PayloadVerified"),
                };
                let pp = me
                    .input
                    .proposal
                    .as_ref()
                    .expect("proposalStore: PayloadVerified must have proposal")
                    .clone();
                let pv = pp.unauthenticated_proposal.value();

                let ea = match self.assemblers.get(&pv) {
                    Some(ea) => ea.clone(),
                    None => {
                        return Event::PayloadProcessed(PayloadProcessedEvent {
                            t: EventType::PayloadRejected,
                            err: Some(SerializableError::new(
                                "proposalStore: no accepting blockAssembler found on payloadVerified",
                            )),
                            ..PayloadProcessedEvent::default()
                        });
                    }
                };

                match ea.clone().bind(pp) {
                    Ok(new_ea) => {
                        let auth_vote = ea.authenticator(current_period);
                        self.assemblers.insert(pv, new_ea);

                        let staged = self.staged_value(Round(0), current_period);
                        if staged.proposal == pv {
                            return Event::Committable(CommittableEvent {
                                proposal: pv,
                                vote: auth_vote,
                            });
                        }
                        Event::PayloadProcessed(PayloadProcessedEvent {
                            t: EventType::PayloadAccepted,
                            vote: auth_vote,
                            proposal: pv,
                            ..PayloadProcessedEvent::default()
                        })
                    }
                    Err(err) => Event::PayloadProcessed(PayloadProcessedEvent {
                        t: EventType::PayloadRejected,
                        err: Some(SerializableError::new(err)),
                        ..PayloadProcessedEvent::default()
                    }),
                }
            }

            EventType::NewPeriod => {
                let npe = match &e {
                    Event::NewPeriod(npe) => npe.clone(),
                    _ => panic!("proposalStore: expected NewPeriodEvent"),
                };
                let starting = npe.proposal;
                let staged = self.staged_value(Round(0), current_period);

                if starting != BOTTOM {
                    self.pinned = starting;
                } else if staged.proposal != BOTTOM {
                    self.pinned = staged.proposal;
                }

                // Clean up old periods: remove those more than 1 period behind
                // the new target period.
                let target_period = npe.period;
                let periods_to_remove: Vec<Period> = self
                    .relevant
                    .keys()
                    .filter(|per| per.0 + 1 < target_period.0)
                    .copied()
                    .collect();
                for per in periods_to_remove {
                    self.relevant.remove(&per);
                }
                self.trim(current_period);
                Event::Empty(EmptyEvent)
            }

            EventType::NewRound => {
                if self.assemblers.len() > 1 {
                    // This is an implementation invariant; in Go it panics
                    panic!("proposalStore: too many assemblers");
                }
                for (pv, ea) in &self.assemblers {
                    if ea.filled {
                        let auth_vote = ea.authenticator(current_period);
                        let (relevant_period, pinned) = self.last_relevant(*pv);
                        return Event::PayloadProcessed(PayloadProcessedEvent {
                            t: EventType::PayloadPipelined,
                            vote: auth_vote,
                            period: relevant_period,
                            pinned,
                            proposal: *pv,
                            unauthenticated_payload: ea.pipeline.clone(),
                            ..PayloadProcessedEvent::default()
                        });
                    }
                }
                Event::Empty(EmptyEvent)
            }

            EventType::SoftThreshold | EventType::CertThreshold => {
                let te = match &e {
                    Event::Threshold(te) => te.clone(),
                    _ => panic!("proposalStore: expected ThresholdEvent"),
                };
                let period = te.period;

                // Dispatch to the proposalTracker, which sets staging = val(threshold)
                let ev = self.dispatch_to_tracker(period, e);
                let pae = match ev {
                    Event::ProposalAccepted(pae) => pae,
                    _ => panic!("proposalStore: expected ProposalAccepted from tracker"),
                };

                // Return committableEvent if the block is assembled
                if let Some(ea) = self.assemblers.get(&pae.proposal) {
                    if ea.assembled {
                        let auth_vote = ea.authenticator(current_period);
                        return Event::Committable(CommittableEvent {
                            proposal: pae.proposal,
                            vote: auth_vote,
                        });
                    }
                }

                // Ensure an assembler exists for this proposal value
                let ea = self.assemblers.entry(pae.proposal).or_default();
                let payload = ea.payload.clone();
                let assembled = ea.assembled;

                self.relevant.insert(period, pae.proposal);
                self.trim(current_period);

                Event::ProposalAccepted(ProposalAcceptedEvent {
                    round: pae.round,
                    period: pae.period,
                    proposal: pae.proposal,
                    payload,
                    payload_ok: assembled,
                })
            }

            EventType::ReadStaging => {
                let se = match e {
                    Event::StagingValue(se) => se,
                    _ => panic!("proposalStore: expected StagingValueEvent"),
                };
                let period = se.period;
                let mut result = {
                    let qe = Event::StagingValue(se);
                    let ev = self.dispatch_to_tracker(period, qe);
                    match ev {
                        Event::StagingValue(se) => se,
                        _ => panic!("proposalStore: expected StagingValueEvent from tracker"),
                    }
                };
                let ea = self
                    .assemblers
                    .get(&result.proposal)
                    .cloned()
                    .unwrap_or_default();
                result.committable = ea.assembled;
                result.payload = ea.payload;
                Event::StagingValue(result)
            }

            EventType::ReadLowestVote => {
                let rle = match e {
                    Event::ReadLowest(rle) => rle,
                    _ => panic!("proposalStore: expected ReadLowestEvent"),
                };
                let period = rle.period;
                let ev = self.dispatch_to_tracker(period, Event::ReadLowest(rle));
                match ev {
                    Event::ReadLowest(rle) => Event::ReadLowest(rle),
                    _ => panic!("proposalStore: expected ReadLowestEvent from tracker"),
                }
            }

            EventType::ReadPinned => {
                let mut se = match e {
                    Event::PinnedValue(se) => se,
                    _ => panic!("proposalStore: expected PinnedValueEvent"),
                };
                let ea = self
                    .assemblers
                    .get(&self.pinned)
                    .cloned()
                    .unwrap_or_default();
                se.proposal = self.pinned;
                se.payload_ok = ea.assembled;
                se.payload = ea.payload;
                Event::PinnedValue(se)
            }

            other => {
                panic!(
                    "proposalStore: bad event type: observed an event of type {}",
                    other
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{NewPeriodEvent, PinnedValueEvent};
    use crate::vote::RawVote;
    use algo_types::{Address, Digest};

    fn make_proposal_value(id: u8) -> ProposalValue {
        ProposalValue {
            original_period: Period(0),
            original_proposer: Address([id; 32]),
            block_digest: Digest([id; 32]),
            encoding_digest: Digest([id; 32]),
        }
    }

    #[test]
    fn block_assembler_pipeline() {
        let ba = BlockAssembler::default();
        assert!(!ba.filled);
        let up = UnauthenticatedProposal::default();
        let ba = ba.pipeline(up).expect("pipeline should succeed");
        assert!(ba.filled);
    }

    #[test]
    fn block_assembler_pipeline_already_filled() {
        let ba = BlockAssembler {
            filled: true,
            ..BlockAssembler::default()
        };
        let up = UnauthenticatedProposal::default();
        let result = ba.pipeline(up);
        assert!(result.is_err());
    }

    #[test]
    fn block_assembler_pipeline_already_assembled() {
        let ba = BlockAssembler {
            assembled: true,
            ..BlockAssembler::default()
        };
        let up = UnauthenticatedProposal::default();
        let result = ba.pipeline(up);
        assert!(result.is_err());
    }

    #[test]
    fn block_assembler_trim() {
        use crate::credential::{Credential, HashableCredential};
        use crate::VRF_PROOF_SIZE;

        let make_auth = |period: u64| Vote {
            raw_vote: RawVote {
                period: Period(period),
                ..RawVote {
                    sender: Address([0; 32]),
                    round: Round(1),
                    period: Period(period),
                    step: crate::step::Step(0),
                    proposal: BOTTOM,
                }
            },
            cred: Credential {
                weight: 1,
                vrf_out: Digest([0; 32]),
                domain_separation_enabled: true,
                hashable: HashableCredential::default(),
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
        };

        let ba = BlockAssembler {
            authenticators: vec![make_auth(0), make_auth(1), make_auth(2)],
            ..BlockAssembler::default()
        };
        let ba = ba.trim(Period(1));
        assert_eq!(ba.authenticators.len(), 2);
        assert!(ba
            .authenticators
            .iter()
            .all(|v| v.raw_vote.period >= Period(1)));
    }

    #[test]
    fn proposal_store_new_period() {
        let mut store = ProposalStore::default();
        let pv = make_proposal_value(0xaa);
        store.relevant.insert(Period(0), pv);
        store.assemblers.insert(pv, BlockAssembler::default());

        let e = Event::NewPeriod(NewPeriodEvent {
            period: Period(3),
            proposal: BOTTOM,
        });
        let result = store.handle(Period(0), e);
        assert_eq!(result.event_type(), EventType::None);
        // Period 0 should have been removed since 0 + 1 < 3
        assert!(!store.relevant.contains_key(&Period(0)));
    }

    #[test]
    fn proposal_store_new_round_empty() {
        let mut store = ProposalStore::default();
        let e = Event::NewRound(crate::events::NewRoundEvent);
        let result = store.handle(Period(0), e);
        assert_eq!(result.event_type(), EventType::None);
    }

    #[test]
    fn proposal_store_read_pinned_empty() {
        let mut store = ProposalStore::default();
        let e = Event::PinnedValue(PinnedValueEvent::default());
        let result = store.handle(Period(0), e);
        assert_eq!(result.event_type(), EventType::ReadPinned);
        if let Event::PinnedValue(pve) = result {
            assert_eq!(pve.proposal, BOTTOM);
            assert!(!pve.payload_ok);
        } else {
            panic!("expected PinnedValue");
        }
    }

    #[test]
    fn proposal_store_read_staging() {
        let mut store = ProposalStore::default();
        let se = StagingValueEvent {
            round: Round(1),
            period: Period(0),
            ..StagingValueEvent::default()
        };
        let result = store.handle(Period(0), Event::StagingValue(se));
        assert_eq!(result.event_type(), EventType::ReadStaging);
        if let Event::StagingValue(se) = result {
            assert_eq!(se.proposal, BOTTOM);
        } else {
            panic!("expected StagingValue");
        }
    }
}
