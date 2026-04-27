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
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    // ───────────────────────────────────────────────────────────────────
    // BF-5 tests (TASK-94): port of go-algorand
    // agreement/proposalStore_test.go.
    //
    // Two are regression tests for shipped Go bugs (b29ea57 and 39387501)
    // that previously corrupted proposal-store state for proposals across
    // period transitions. Without Rust counterparts those bugs could
    // silently re-emerge.
    // ───────────────────────────────────────────────────────────────────

    /// Build a `Vote` for the given period — only the `period` field is
    /// inspected by `BlockAssembler::authenticator`, so the rest is
    /// zero-filled to keep the helper minimal. Mirrors Go's
    /// `makeVoteTesting` shape (which fabricates an OTS-signed vote)
    /// reduced to what `authenticator()` actually reads.
    fn vote_in_period(period: Period) -> Vote {
        use crate::credential::{Credential, HashableCredential};
        use crate::VRF_PROOF_SIZE;
        Vote {
            raw_vote: RawVote {
                sender: Address([0u8; 32]),
                round: Round(1),
                period,
                step: crate::step::Step(0),
                proposal: BOTTOM,
            },
            cred: Credential {
                weight: 1,
                vrf_out: Digest([0u8; 32]),
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
        }
    }

    // -- TestBlockAssemblerBind -----------------------------------------

    /// First bind on a fresh assembler must succeed. Mirrors the
    /// `assembled: false` row of go-algorand's `TestBlockAssemblerBind`.
    #[test]
    fn block_assembler_bind_accepts_first() {
        let ba = BlockAssembler::default();
        let result = ba.bind(Proposal::default());
        let bound = result.expect("first bind should succeed");
        assert!(bound.assembled, "bind sets assembled = true");
        assert!(bound.payload.is_some(), "bind stores payload");
    }

    /// Second bind on an already-assembled assembler must fail. Mirrors
    /// the `assembled: true` row of `TestBlockAssemblerBind`.
    #[test]
    fn block_assembler_bind_rejects_double() {
        let ba = BlockAssembler {
            assembled: true,
            ..BlockAssembler::default()
        };
        let result = ba.bind(Proposal::default());
        assert!(
            result.is_err(),
            "bind on already-assembled must reject (Go: 'already assembled')",
        );
    }

    // -- TestBlockAssemblerAuthenticator --------------------------------

    /// `authenticator(p)` returns the first vote whose period matches.
    /// Mirrors the "test with vote authenticators" row of Go's
    /// `TestBlockAssemblerAuthenticator`.
    #[test]
    fn block_assembler_authenticator_returns_first_vote() {
        let v = vote_in_period(Period(0));
        let ba = BlockAssembler {
            authenticators: vec![v.clone()],
            ..BlockAssembler::default()
        };
        let got = ba.authenticator(Period(0)).expect("expected matching vote");
        // Identity check via raw_vote — the helper zeroes the cred/sig,
        // so RawVote equality is the meaningful comparison.
        assert_eq!(got.raw_vote, v.raw_vote);
    }

    /// `authenticator(p)` returns `None` when no votes are stored. Go
    /// returns the zero `vote{}`; Rust returns `Option::None` — same
    /// semantics. Mirrors the "no vote authenticators" row.
    #[test]
    fn block_assembler_authenticator_returns_empty_when_none() {
        let ba = BlockAssembler::default();
        assert!(ba.authenticator(Period(0)).is_none());
    }

    // -- TestProposalStoreGetPinnedValue (with-payload) -----------------

    /// Once a `PayloadVerified` event lands an assembled `Proposal` for
    /// the pinned value, a subsequent `ReadPinned` must return both the
    /// proposal AND the payload (with `payload_ok = true`). Pre-PR Rust
    /// only covered the empty/no-payload case; this fills the with-
    /// payload gap that go-algorand's `TestProposalStoreGetPinnedValue`
    /// asserts.
    #[test]
    fn proposal_store_get_pinned_value_with_payload() {
        let pv = make_proposal_value(0xa1);
        let mut store = ProposalStore {
            pinned: pv,
            ..ProposalStore::default()
        };

        // 1. Without an assembled payload: ReadPinned returns the
        //    proposal but `payload_ok = false`.
        let pinned_event = Event::PinnedValue(PinnedValueEvent::default());
        let result = store.handle(Period(0), pinned_event);
        if let Event::PinnedValue(pve) = result {
            assert_eq!(pve.proposal, pv);
            assert!(!pve.payload_ok, "no payload yet → payload_ok must be false");
        } else {
            panic!("expected PinnedValue event");
        }

        // 2. Drive a PayloadVerified through the store, binding the
        //    payload to the pinned value's assembler.
        let mut payload = Proposal::default();
        payload.unauthenticated_proposal.original_period = pv.original_period;
        payload.unauthenticated_proposal.original_proposer = pv.original_proposer;
        // Force the proposal's value() to match `pv` exactly, so the
        // store's PayloadVerified path hits the pinned assembler. We
        // pre-seed the assembler under `pv` so the lookup succeeds even
        // though `payload.value()` may differ in encoding_digest.
        store.assemblers.insert(pv, BlockAssembler::default());

        // The PayloadVerified path uses payload.value() to look up the
        // assembler. Mirror Go's "white-box" pattern: stuff the payload
        // we want into the pinned assembler directly via PayloadVerified
        // by routing through a payload whose value() matches `pv`.
        // Since constructing such a proposal requires reproducing the
        // canonical-encoding hash, we shortcut by directly binding:
        let bound = store
            .assemblers
            .remove(&pv)
            .unwrap()
            .bind(payload.clone())
            .expect("bind succeeds on fresh assembler");
        store.assemblers.insert(pv, bound);

        // 3. ReadPinned now returns the proposal AND payload.
        let pinned_event = Event::PinnedValue(PinnedValueEvent::default());
        let result = store.handle(Period(0), pinned_event);
        if let Event::PinnedValue(pve) = result {
            assert_eq!(pve.proposal, pv);
            assert!(pve.payload_ok, "pinned with assembled payload → payload_ok");
            assert!(pve.payload.is_some(), "payload must be returned");
        } else {
            panic!("expected PinnedValue event");
        }
    }

    // -- Regression tests for shipped Go bugs ---------------------------

    /// Build a minimal authenticated `Proposal` whose
    /// `unauthenticated_proposal` carries the given `original_period`
    /// and `original_proposer`. Mirrors the
    /// `proposal{ unauthenticatedProposal: unauthenticatedProposal{ ... }}`
    /// pattern in Go's regression tests.
    fn proposal_for_regression(original_period: Period, proposer: Address) -> Proposal {
        Proposal {
            unauthenticated_proposal: UnauthenticatedProposal {
                original_period,
                original_proposer: proposer,
                ..UnauthenticatedProposal::default()
            },
            ..Proposal::default()
        }
    }

    /// Build a vote-verified `MessageEvent` carrying the proposal's value
    /// in `raw_vote.proposal`. Mirrors Go's
    /// `messageEvent{T: voteVerified, Input: msg}` shape.
    fn vote_verified_event(
        round: Round,
        period: Period,
        sender: Address,
        pv: ProposalValue,
    ) -> Event {
        let v = Vote {
            raw_vote: RawVote {
                sender,
                round,
                period,
                step: crate::step::Step(0),
                proposal: pv,
            },
            ..vote_in_period(period)
        };
        Event::Message(crate::events::MessageEvent {
            t: EventType::VoteVerified,
            input: crate::events::InternalMessage {
                vote: Some(v.clone()),
                unauthenticated_vote: v.to_unauthenticated(),
                ..crate::events::InternalMessage::default()
            },
            ..crate::events::MessageEvent::default()
        })
    }

    /// Build a payload-verified or payload-present `MessageEvent`
    /// carrying the given proposal. Choose the event type via `t`.
    fn payload_event(t: EventType, payload: Proposal) -> Event {
        Event::Message(crate::events::MessageEvent {
            t,
            input: crate::events::InternalMessage {
                proposal: Some(payload.clone()),
                unauthenticated_proposal: payload.unauthenticated_proposal,
                ..crate::events::InternalMessage::default()
            },
            ..crate::events::MessageEvent::default()
        })
    }

    /// Regression for go-algorand bug `b29ea57` (port of
    /// `TestProposalStoreRegressionBlockRedeliveryBug_b29ea57`).
    ///
    /// **What the bug was:** When the proposal-store handled two
    /// proposals with different `OriginalPeriod` fields (e.g., one from
    /// period 1 reproposed and one freshly proposed in period 2), the
    /// store could mistake the second proposal's payload for a duplicate
    /// of the first and reject it. The fix in commit `b29ea57` ensured
    /// the proposal-value's `original_period` is part of the key, so the
    /// two payloads are tracked under distinct assemblers.
    ///
    /// **What this test guards:** drive period 1 + period 2 through the
    /// store; both payloads must be ACCEPTED (not REJECTED). Repeats 10
    /// times because Go's `HashMap` iteration order made the bug
    /// intermittent.
    #[test]
    fn proposal_store_regression_block_redelivery_b29ea57() {
        let cur_round = Round(10);
        let proposer = Address([0xab; 32]);

        for _ in 0..10 {
            let mut store = ProposalStore::default();

            // Period 1.
            let pay1 = proposal_for_regression(Period(1), proposer);
            let pv1 = pay1.unauthenticated_proposal.value();
            assert_eq!(
                store
                    .handle(
                        Period(0),
                        Event::NewPeriod(NewPeriodEvent {
                            period: Period(1),
                            proposal: BOTTOM,
                        })
                    )
                    .event_type(),
                EventType::None,
            );
            let res = store.handle(
                Period(0),
                vote_verified_event(cur_round, Period(1), proposer, pv1),
            );
            assert_eq!(res.event_type(), EventType::ProposalAccepted);
            let res = store.handle(Period(0), payload_event(EventType::PayloadVerified, pay1));
            assert_eq!(res.event_type(), EventType::PayloadAccepted);

            // Period 2 — a *different* proposal value (different
            // original_period AND different encoding_digest because the
            // unauthenticated_proposal's `original_period` is part of
            // the canonical encoding).
            let pay2 = proposal_for_regression(Period(2), proposer);
            let pv2 = pay2.unauthenticated_proposal.value();
            assert_ne!(pv1, pv2, "test malformed: PVs must differ across periods");

            assert_eq!(
                store
                    .handle(
                        Period(0),
                        Event::NewPeriod(NewPeriodEvent {
                            period: Period(2),
                            proposal: BOTTOM,
                        })
                    )
                    .event_type(),
                EventType::None,
            );
            let res = store.handle(
                Period(0),
                vote_verified_event(cur_round, Period(2), proposer, pv2),
            );
            assert_eq!(res.event_type(), EventType::ProposalAccepted);

            let res = store.handle(Period(0), payload_event(EventType::PayloadVerified, pay2));
            assert_ne!(
                res.event_type(),
                EventType::PayloadRejected,
                "bug b29ea57: payload from new original period was rejected as duplicate",
            );
            assert_eq!(res.event_type(), EventType::PayloadAccepted);
        }
    }

    /// Regression for go-algorand bug `39387501` (port of
    /// `TestProposalStoreRegressionWrongPipelinePeriodBug_39387501`).
    ///
    /// **What the bug was:** When a payload pipelined for a period-1
    /// proposal arrived AFTER the store had already processed period-2
    /// votes/payloads, the pipelined event's `period` field was
    /// incorrectly set to the current period (2) rather than the
    /// proposal's owning period (1). Downstream consumers used `period`
    /// to attribute the payload to the wrong relevant slot. The fix
    /// uses `last_relevant(pv)` to pick the period of the proposal that
    /// owns the payload.
    ///
    /// **What this test guards:** after period transitions and out-of-
    /// order payload arrivals, the `PayloadPipelined` event for a
    /// payload bound to a period-1 PV must report `period = 1`, not
    /// the current period.
    #[test]
    fn proposal_store_regression_wrong_pipeline_period_39387501() {
        let cur_round = Round(10);
        let proposer = Address([0xcd; 32]);
        let mut store = ProposalStore::default();

        let pay1 = proposal_for_regression(Period(1), proposer);
        let pv1 = pay1.unauthenticated_proposal.value();
        let pay2 = proposal_for_regression(Period(2), proposer);
        let pv2 = pay2.unauthenticated_proposal.value();
        assert_ne!(pv1, pv2);

        // Period 1: NewPeriod + voteVerified (binds assembler entry under pv1).
        store.handle(
            Period(0),
            Event::NewPeriod(NewPeriodEvent {
                period: Period(1),
                proposal: BOTTOM,
            }),
        );
        let res = store.handle(
            Period(0),
            vote_verified_event(cur_round, Period(1), proposer, pv1),
        );
        assert_eq!(res.event_type(), EventType::ProposalAccepted);

        // Period 2: NewPeriod + voteVerified (binds assembler under pv2).
        store.handle(
            Period(0),
            Event::NewPeriod(NewPeriodEvent {
                period: Period(2),
                proposal: BOTTOM,
            }),
        );
        let res = store.handle(
            Period(0),
            vote_verified_event(cur_round, Period(2), proposer, pv2),
        );
        assert_eq!(res.event_type(), EventType::ProposalAccepted);

        // PayloadPresent for pay2 — pipelined with period == 2.
        let res = store.handle(Period(0), payload_event(EventType::PayloadPresent, pay2));
        assert_eq!(res.event_type(), EventType::PayloadPipelined);
        if let Event::PayloadProcessed(pe) = res {
            assert_eq!(pe.period, Period(2));
        } else {
            panic!("expected PayloadProcessed event");
        }

        // PayloadPresent for pay1, arriving AFTER pay2 — must report
        // period = 1 (its own period), NOT period = 2 (current).
        let res = store.handle(Period(0), payload_event(EventType::PayloadPresent, pay1));
        assert_eq!(res.event_type(), EventType::PayloadPipelined);
        if let Event::PayloadProcessed(pe) = res {
            assert_ne!(
                pe.period,
                Period(2),
                "bug 39387501: out-of-order period-1 payload reported as period 2",
            );
            assert_eq!(pe.period, Period(1));
        } else {
            panic!("expected PayloadProcessed event");
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
