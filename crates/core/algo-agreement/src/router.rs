// Router hierarchy for the agreement protocol state machine.
//
// Mirrors go-algorand/agreement/router.go.
//
// The router dispatches events to the correct state machine (proposal or vote
// subsystem) at the correct hierarchical level (root, round, period, step).
// It also manages garbage collection of old round/period state.
//
// Architecture:
//   RootRouter -> RoundRouter (per round) -> PeriodRouter (per period) -> StepRouter (per step)
//
// The root-level state machines are:
//   - ProposalManager (proposalMachine) — handles proposals and proposal-votes
//   - VoteAggregator (voteMachine) — handles votes and bundles
//
// Each level owns its sub-level state machines:
//   - RoundRouter: ProposalStore (proposalMachineRound), VoteTrackerRound (voteMachineRound)
//   - PeriodRouter: ProposalTracker (proposalMachinePeriod), VoteTrackerPeriod (voteMachinePeriod)
//   - StepRouter: VoteTracker (voteMachineStep)

use std::collections::HashMap;

use algo_types::{ConsensusParams, Round};
use serde::{Deserialize, Serialize};

use crate::actions::Action;
use crate::events::{Event, PinnedValueEvent, StagingValueEvent};
use crate::proposal_manager::ProposalManager;
use crate::proposal_store::ProposalStore;
use crate::proposal_tracker::ProposalTracker;
use crate::step::{Period, Step};
use crate::types::credential_round_lag;
use crate::vote_aggregator::VoteAggregator;
use crate::vote_auxiliary::{VoteTrackerPeriod, VoteTrackerRound};
use crate::vote_tracker::VoteTracker;

// ---------------------------------------------------------------------------
// StateMachineTag
// ---------------------------------------------------------------------------

/// Uniquely identifies the type of a state machine.
///
/// Rounds, periods, and steps may be used to further disambiguate different
/// state machine instances of the same type.
///
/// Mirrors Go's `stateMachineTag`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum StateMachineTag {
    /// The demux (event multiplexer).
    Demultiplexer = 0,
    /// The player state machine.
    PlayerMachine = 1,
    /// The top-level vote aggregator.
    VoteMachine = 2,
    /// Per-round vote tracker.
    VoteMachineRound = 3,
    /// Per-(round, period) vote tracker.
    VoteMachinePeriod = 4,
    /// Per-(round, period, step) vote tracker.
    VoteMachineStep = 5,
    /// The top-level proposal manager.
    ProposalMachine = 6,
    /// Per-round proposal store.
    ProposalMachineRound = 7,
    /// Per-(round, period) proposal tracker.
    ProposalMachinePeriod = 8,
}

impl std::fmt::Display for StateMachineTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Demultiplexer => "demultiplexer",
            Self::PlayerMachine => "playerMachine",
            Self::VoteMachine => "voteMachine",
            Self::VoteMachineRound => "voteMachineRound",
            Self::VoteMachinePeriod => "voteMachinePeriod",
            Self::VoteMachineStep => "voteMachineStep",
            Self::ProposalMachine => "proposalMachine",
            Self::ProposalMachineRound => "proposalMachineRound",
            Self::ProposalMachinePeriod => "proposalMachinePeriod",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Player (forward declaration for dispatch signatures)
// ---------------------------------------------------------------------------

// The Player struct is defined in player.rs. We use the re-exported type.
use crate::player::Player;

// ---------------------------------------------------------------------------
// RootRouter
// ---------------------------------------------------------------------------

/// Top-level router that dispatches events to the proposal and vote subsystems.
///
/// Contains the player (actor), ProposalManager, VoteAggregator, and per-round
/// RoundRouters.
///
/// Mirrors Go's `rootRouter`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RootRouter {
    /// The proposal manager (proposalMachine).
    pub proposal_manager: ProposalManager,
    /// The vote aggregator (voteMachine).
    pub vote_aggregator: VoteAggregator,
    /// Per-round routers, keyed by round number.
    pub children: HashMap<Round, RoundRouter>,
}

impl RootRouter {
    /// Create a new root router for the given player.
    ///
    /// Mirrors Go's `makeRootRouter`.
    pub fn new(_player: &Player) -> Self {
        Self::default()
    }

    /// Ensure the router state is up-to-date for the given round, performing
    /// garbage collection of old round routers if `gc` is true.
    ///
    /// Mirrors Go's `rootRouter.update`.
    pub fn update(&mut self, state: &Player, r: Round, gc: bool) {
        self.children.entry(r).or_default();

        if gc {
            let cred_lag = credential_round_lag();
            let mut children = HashMap::new();
            for (&rnd, child) in &self.children {
                // Keep old round routers around for as long as credentials may
                // arrive, to keep track of them.
                let rr = Round(rnd.0.saturating_add(cred_lag));
                if rr.0 >= state.round.0 {
                    children.insert(rnd, child.clone());
                }
            }
            self.children = children;
        }
    }

    /// Submit an event directly to the player (the root of the state machine
    /// tree).
    ///
    /// Returns the updated player and the list of actions.
    ///
    /// Mirrors Go's `rootRouter.submitTop`.
    pub fn submit_top(
        &mut self,
        state: Player,
        e: Event,
        params: &ConsensusParams,
    ) -> (Player, Vec<Action>) {
        self.update(&state, Round(0), true);
        let mut player = state;
        let actions = player.handle(self, e, params);
        (player, actions)
    }

    /// Dispatch an event to the appropriate state machine at this level.
    ///
    /// Mirrors Go's `rootRouter.dispatch`.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch(
        &mut self,
        state: &Player,
        e: Event,
        dest: StateMachineTag,
        r: Round,
        p: Period,
        s: Step,
        params: &ConsensusParams,
    ) -> Event {
        self.update(state, r, true);

        match dest {
            StateMachineTag::ProposalMachine => {
                self.proposal_manager.handle(state.round, state.period, e)
            }
            // ProposalMachineRound queries (`staged_value`, `pinned_value`,
            // `read_lowest`, etc.) must consult the SAME per-round
            // ProposalStore that the message-handling dispatch mutates —
            // otherwise the Player will read empty state and conclude
            // proposals are not committable. Route through the canonical
            // ProposalManager.stores rather than the legacy mirror under
            // RoundRouter.proposal_store. The mirror remains in the tree
            // for now (persistence shape, future refactor in follow-up
            // task), but no production dispatch hits it.
            StateMachineTag::ProposalMachineRound => {
                self.proposal_manager.store_for_round(r).handle(p, e)
            }
            // ProposalMachinePeriod queries (`ProposalFrozen`, `ReadLowest`,
            // `ReadStaging`, etc.) must consult the SAME per-period
            // `ProposalTracker` that VoteVerified events mutate. Those are
            // stored inside `ProposalStore.trackers[period]` (canonical),
            // populated by `proposal_manager.handle` → `store.handle(period, ...)`
            // → `dispatch_to_tracker(period, ...)`. The legacy mirror under
            // `PeriodRouter.proposal_tracker` is never written by production
            // dispatch, so reading from it returns BOTTOM and `issue_soft_vote`
            // sees no proposal. Route through the canonical
            // `ProposalManager.stores[r].trackers[p]` so freezer / staging
            // queries see the real state. Mirrors the ProposalMachineRound
            // fix above, and matches go-algorand where the periodRouter
            // delegates back into the same proposalManager state via
            // `roundRouter.proposalStore.dispatch_to_tracker` (`agreement/router.go`).
            StateMachineTag::ProposalMachinePeriod => self
                .proposal_manager
                .store_for_round(r)
                .dispatch_to_tracker(p, e),
            StateMachineTag::VoteMachine => {
                // Wrap in a FilterableMessageEvent for the vote aggregator
                if let Event::FilterableMessage(ref fme) = e {
                    self.vote_aggregator.handle(fme, params)
                } else {
                    // For non-filterable events dispatched to vote machine
                    // (e.g., freshestBundleRequest), forward to the round tracker
                    if let Some(round_router) = self.children.get_mut(&r) {
                        round_router.dispatch(state, e, dest, r, p, s, params)
                    } else {
                        Event::default()
                    }
                }
            }
            // Delegate to the round router
            _ => {
                if let Some(round_router) = self.children.get_mut(&r) {
                    round_router.dispatch(state, e, dest, r, p, s, params)
                } else {
                    panic!("rootRouter.dispatch: no round router for round {:?}", r);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RoundRouter
// ---------------------------------------------------------------------------

/// Per-round router containing a ProposalStore, VoteTrackerRound, and per-period
/// PeriodRouters.
///
/// Mirrors Go's `roundRouter`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoundRouter {
    /// Per-round proposal storage.
    pub proposal_store: ProposalStore,
    /// Per-round vote tracking.
    pub vote_tracker_round: VoteTrackerRound,
    /// Per-period routers.
    pub children: HashMap<Period, PeriodRouter>,
}

impl RoundRouter {
    /// Ensure the router state is up-to-date for the given period, with
    /// optional garbage collection.
    ///
    /// Mirrors Go's `roundRouter.update`.
    pub fn update(&mut self, state: &Player, p: Period, gc: bool) {
        self.children.entry(p).or_default();

        if gc {
            let mut children = HashMap::new();
            for (&per, child) in &self.children {
                if per.0 + 1 >= state.period.0 {
                    children.insert(per, child.clone());
                } else if per.0 <= 1 {
                    // Avoid garbage-collecting (next round, period 0/1) state.
                    // This is conservative; we can collect more eagerly if the
                    // router's round is passed in.
                    children.insert(per, child.clone());
                }
            }
            self.children = children;
        }
    }

    /// Dispatch an event to the appropriate state machine at this level.
    ///
    /// Mirrors Go's `roundRouter.dispatch`.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch(
        &mut self,
        state: &Player,
        e: Event,
        dest: StateMachineTag,
        r: Round,
        p: Period,
        s: Step,
        params: &ConsensusParams,
    ) -> Event {
        self.update(state, p, true);

        match dest {
            StateMachineTag::ProposalMachineRound => self.proposal_store.handle(p, e),
            StateMachineTag::VoteMachineRound => self.vote_tracker_round.handle(&e, params),
            _ => {
                if let Some(period_router) = self.children.get_mut(&p) {
                    period_router.dispatch(state, e, dest, r, p, s, params)
                } else {
                    panic!("roundRouter.dispatch: no period router for period {:?}", p);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PeriodRouter
// ---------------------------------------------------------------------------

/// Per-(round, period) router containing a ProposalTracker, VoteTrackerPeriod,
/// and per-step StepRouters.
///
/// Mirrors Go's `periodRouter`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeriodRouter {
    /// Per-period proposal tracking.
    pub proposal_tracker: ProposalTracker,
    /// Per-period vote tracking.
    pub vote_tracker_period: VoteTrackerPeriod,
    /// Per-step routers.
    pub children: HashMap<Step, StepRouter>,
}

impl PeriodRouter {
    /// Ensure the router state is up-to-date for the given step.
    /// Steps are not garbage-collected because memory grows logarithmically.
    ///
    /// Mirrors Go's `periodRouter.update`.
    pub fn update(&mut self, s: Step) {
        self.children.entry(s).or_default();
    }

    /// Dispatch an event to the appropriate state machine at this level.
    ///
    /// Mirrors Go's `periodRouter.dispatch`.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch(
        &mut self,
        state: &Player,
        e: Event,
        dest: StateMachineTag,
        r: Round,
        p: Period,
        s: Step,
        params: &ConsensusParams,
    ) -> Event {
        self.update(s);

        match dest {
            StateMachineTag::ProposalMachinePeriod => self.proposal_tracker.handle(e),
            StateMachineTag::VoteMachinePeriod => self.vote_tracker_period.handle(&e, params),
            _ => {
                if let Some(step_router) = self.children.get_mut(&s) {
                    step_router.dispatch(state, e, dest, r, p, s, params)
                } else {
                    panic!("periodRouter.dispatch: no step router for step {:?}", s);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// StepRouter
// ---------------------------------------------------------------------------

/// Per-(round, period, step) router containing a VoteTracker.
///
/// Mirrors Go's `stepRouter`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StepRouter {
    /// Per-step vote tracking.
    pub vote_tracker: VoteTracker,
}

impl StepRouter {
    /// Dispatch an event to the vote tracker at this level.
    ///
    /// Mirrors Go's `stepRouter.dispatch`.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch(
        &mut self,
        _state: &Player,
        e: Event,
        dest: StateMachineTag,
        _r: Round,
        _p: Period,
        _s: Step,
        params: &ConsensusParams,
    ) -> Event {
        match dest {
            StateMachineTag::VoteMachineStep => self.vote_tracker.handle(&e, params),
            _ => panic!("stepRouter.dispatch: bad destination {:?}", dest),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Gets the staged value for some (r, p).
///
/// i.e., sigma(state, r, p)
///
/// Mirrors Go's `stagedValue` free function.
pub fn staged_value(
    player: &Player,
    router: &mut RootRouter,
    r: Round,
    p: Period,
    params: &ConsensusParams,
) -> StagingValueEvent {
    let qe = Event::StagingValue(StagingValueEvent {
        round: r,
        period: p,
        ..StagingValueEvent::default()
    });
    let e = router.dispatch(
        player,
        qe,
        StateMachineTag::ProposalMachineRound,
        r,
        p,
        Step(0),
        params,
    );
    match e {
        Event::StagingValue(se) => se,
        _ => panic!("stagedValue: expected StagingValueEvent"),
    }
}

/// Gets the current pinned value for some (r).
///
/// Mirrors Go's `pinnedValue` free function.
pub fn pinned_value(
    player: &Player,
    router: &mut RootRouter,
    r: Round,
    params: &ConsensusParams,
) -> PinnedValueEvent {
    let qe = Event::PinnedValue(PinnedValueEvent {
        round: r,
        ..PinnedValueEvent::default()
    });
    let e = router.dispatch(
        player,
        qe,
        StateMachineTag::ProposalMachineRound,
        r,
        Period(0),
        Step(0),
        params,
    );
    match e {
        Event::PinnedValue(pe) => pe,
        _ => panic!("pinnedValue: expected PinnedValueEvent"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_machine_tag_display() {
        assert_eq!(
            format!("{}", StateMachineTag::Demultiplexer),
            "demultiplexer"
        );
        assert_eq!(
            format!("{}", StateMachineTag::PlayerMachine),
            "playerMachine"
        );
        assert_eq!(format!("{}", StateMachineTag::VoteMachine), "voteMachine");
        assert_eq!(
            format!("{}", StateMachineTag::ProposalMachine),
            "proposalMachine"
        );
    }

    #[test]
    fn root_router_default() {
        let router = RootRouter::default();
        assert!(router.children.is_empty());
    }

    #[test]
    fn root_router_update_creates_round() {
        let mut router = RootRouter::default();
        let player = Player::default();
        router.update(&player, Round(5), false);
        assert!(router.children.contains_key(&Round(5)));
    }

    #[test]
    fn round_router_default() {
        let router = RoundRouter::default();
        assert!(router.children.is_empty());
    }

    #[test]
    fn period_router_default() {
        let router = PeriodRouter::default();
        assert!(router.children.is_empty());
    }

    #[test]
    fn step_router_default() {
        let _router = StepRouter::default();
    }

    #[test]
    fn period_router_update_creates_step() {
        let mut router = PeriodRouter::default();
        router.update(Step(3));
        assert!(router.children.contains_key(&Step(3)));
    }

    #[test]
    fn round_router_update_creates_period() {
        let mut router = RoundRouter::default();
        let player = Player::default();
        router.update(&player, Period(2), false);
        assert!(router.children.contains_key(&Period(2)));
    }

    #[test]
    fn root_router_gc_removes_old_rounds() {
        let mut router = RootRouter::default();
        router.children.insert(Round(1), RoundRouter::default());
        router.children.insert(Round(5), RoundRouter::default());
        router.children.insert(Round(20), RoundRouter::default());

        let player = Player {
            round: Round(20),
            ..Player::default()
        };

        router.update(&player, Round(20), true);

        // Round 1 should be GC'd (1 + credential_round_lag < 20)
        // credential_round_lag = 8, so 1 + 8 = 9 < 20 -> GC'd
        assert!(!router.children.contains_key(&Round(1)));
        // Round 5 should be GC'd (5 + 8 = 13 < 20)
        assert!(!router.children.contains_key(&Round(5)));
        // Round 20 should be kept
        assert!(router.children.contains_key(&Round(20)));
    }

    fn test_params() -> algo_types::ConsensusParams {
        algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
            .expect("v41 params")
    }

    // ---- GC edge cases ----

    #[test]
    fn root_router_gc_false_keeps_all() {
        let mut router = RootRouter::default();
        router.children.insert(Round(1), RoundRouter::default());
        router.children.insert(Round(100), RoundRouter::default());

        let player = Player {
            round: Round(100),
            ..Player::default()
        };

        // gc = false => no garbage collection
        router.update(&player, Round(100), false);

        assert!(router.children.contains_key(&Round(1)));
        assert!(router.children.contains_key(&Round(100)));
    }

    #[test]
    fn root_router_gc_keeps_rounds_within_credential_lag() {
        let mut router = RootRouter::default();
        // Round(12) + 8 = 20 >= 20, should be kept
        router.children.insert(Round(12), RoundRouter::default());
        // Round(13) + 8 = 21 >= 20, should be kept
        router.children.insert(Round(13), RoundRouter::default());
        // Round(11) + 8 = 19 < 20, should be GC'd
        router.children.insert(Round(11), RoundRouter::default());

        let player = Player {
            round: Round(20),
            ..Player::default()
        };

        router.update(&player, Round(20), true);

        assert!(!router.children.contains_key(&Round(11)));
        assert!(router.children.contains_key(&Round(12)));
        assert!(router.children.contains_key(&Round(13)));
    }

    #[test]
    fn round_router_gc_removes_old_periods() {
        let mut router = RoundRouter::default();
        router.children.insert(Period(0), PeriodRouter::default());
        router.children.insert(Period(1), PeriodRouter::default());
        router.children.insert(Period(5), PeriodRouter::default());
        router.children.insert(Period(10), PeriodRouter::default());

        let player = Player {
            period: Period(10),
            ..Player::default()
        };

        router.update(&player, Period(10), true);

        // Period 0 and 1 are always kept (conservative rule per <= 1 check)
        assert!(router.children.contains_key(&Period(0)));
        assert!(router.children.contains_key(&Period(1)));
        // Period 5 should be GC'd (5+1 = 6 < 10)
        assert!(!router.children.contains_key(&Period(5)));
        // Period 10 should be kept (10+1 = 11 >= 10)
        assert!(router.children.contains_key(&Period(10)));
    }

    #[test]
    fn round_router_gc_false_keeps_all() {
        let mut router = RoundRouter::default();
        router.children.insert(Period(0), PeriodRouter::default());
        router.children.insert(Period(100), PeriodRouter::default());

        let player = Player {
            period: Period(100),
            ..Player::default()
        };

        router.update(&player, Period(100), false);

        assert!(router.children.contains_key(&Period(0)));
        assert!(router.children.contains_key(&Period(100)));
    }

    // ---- staged_value and pinned_value helpers ----

    #[test]
    fn staged_value_returns_bottom_initially() {
        let player = Player {
            round: Round(10),
            period: Period(0),
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let sv = staged_value(&player, &mut router, Round(10), Period(0), &params);
        assert_eq!(sv.proposal, crate::vote::BOTTOM);
        assert!(!sv.committable);
    }

    #[test]
    fn pinned_value_returns_bottom_initially() {
        let player = Player {
            round: Round(10),
            period: Period(0),
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let pv = pinned_value(&player, &mut router, Round(10), &params);
        assert_eq!(pv.proposal, crate::vote::BOTTOM);
        assert!(!pv.payload_ok);
    }

    // ---- Event routing tests ----

    #[test]
    fn root_router_dispatch_proposal_machine() {
        let mut router = RootRouter::default();
        let player = Player {
            round: Round(10),
            period: Period(0),
            ..Player::default()
        };
        let params = test_params();

        // Dispatch a round interruption to the proposal machine
        let e = crate::events::Event::RoundInterruption(crate::events::RoundInterruptionEvent {
            round: Round(10),
            ..crate::events::RoundInterruptionEvent::default()
        });
        let result = router.dispatch(
            &player,
            e,
            StateMachineTag::ProposalMachine,
            Round(10),
            Period(0),
            Step(0),
            &params,
        );
        // Should return an empty event (no pipelined payload)
        assert_eq!(result.event_type(), crate::events::EventType::None);
    }

    #[test]
    fn root_router_dispatch_vote_machine_round() {
        let mut router = RootRouter::default();
        let player = Player {
            round: Round(10),
            period: Period(0),
            ..Player::default()
        };
        let params = test_params();

        // Dispatch a freshest bundle request to the round vote machine
        let e =
            crate::events::Event::FreshestBundleRequest(crate::events::FreshestBundleRequestEvent);
        let result = router.dispatch(
            &player,
            e,
            StateMachineTag::VoteMachineRound,
            Round(10),
            Period(0),
            Step(0),
            &params,
        );
        // Should return a freshest bundle event (empty)
        if let crate::events::Event::FreshestBundle(fb) = result {
            assert!(!fb.ok);
        } else {
            panic!("expected FreshestBundle event");
        }
    }

    #[test]
    fn root_router_submit_top_none_event() {
        let mut router = RootRouter::default();
        let player = Player::default();
        let params = test_params();

        let (new_player, actions) =
            router.submit_top(player, crate::events::Event::default(), &params);
        assert!(actions.is_empty());
        assert_eq!(new_player.round, Round(0));
    }

    #[test]
    fn period_router_dispatch_proposal_tracker() {
        let mut router = PeriodRouter::default();
        let player = Player {
            round: Round(10),
            period: Period(0),
            ..Player::default()
        };
        let params = test_params();

        // Dispatch a proposal frozen event to the period-level proposal tracker
        let e = crate::events::Event::ProposalFrozen(crate::events::ProposalFrozenEvent::default());
        let result = router.dispatch(
            &player,
            e,
            StateMachineTag::ProposalMachinePeriod,
            Round(10),
            Period(0),
            Step(0),
            &params,
        );
        assert_eq!(
            result.event_type(),
            crate::events::EventType::ProposalFrozen
        );
    }

    #[test]
    fn period_router_dispatch_vote_tracker_period() {
        let mut router = PeriodRouter::default();
        let player = Player::default();
        let params = test_params();

        // Dispatch a next threshold status request
        let e = crate::events::Event::NextThresholdStatusRequest(
            crate::events::NextThresholdStatusRequestEvent,
        );
        let result = router.dispatch(
            &player,
            e,
            StateMachineTag::VoteMachinePeriod,
            Round(0),
            Period(0),
            Step(0),
            &params,
        );
        assert_eq!(
            result.event_type(),
            crate::events::EventType::NextThresholdStatus
        );
    }

    #[test]
    fn step_router_dispatch_vote_tracker_step() {
        let mut router = StepRouter::default();
        let player = Player::default();
        let params = test_params();

        // Dispatch a dump votes request
        let e = crate::events::Event::DumpVotesRequest(crate::events::DumpVotesRequestEvent);
        let result = router.dispatch(
            &player,
            e,
            StateMachineTag::VoteMachineStep,
            Round(0),
            Period(0),
            Step(0),
            &params,
        );
        if let crate::events::Event::DumpVotes(dv) = result {
            assert!(dv.votes.is_empty());
        } else {
            panic!("expected DumpVotes event");
        }
    }

    // ---- Multiple round updates ----

    #[test]
    fn root_router_update_creates_multiple_rounds() {
        let mut router = RootRouter::default();
        let player = Player::default();
        router.update(&player, Round(1), false);
        router.update(&player, Round(2), false);
        router.update(&player, Round(3), false);
        assert_eq!(router.children.len(), 3);
    }

    #[test]
    fn round_router_update_creates_multiple_periods() {
        let mut router = RoundRouter::default();
        let player = Player::default();
        router.update(&player, Period(0), false);
        router.update(&player, Period(1), false);
        router.update(&player, Period(2), false);
        assert_eq!(router.children.len(), 3);
    }

    #[test]
    fn period_router_update_creates_multiple_steps() {
        let mut router = PeriodRouter::default();
        router.update(Step(0));
        router.update(Step(1));
        router.update(Step(2));
        router.update(Step(3));
        assert_eq!(router.children.len(), 4);
    }

    // ---- Idempotent updates ----

    #[test]
    fn root_router_update_idempotent() {
        let mut router = RootRouter::default();
        let player = Player::default();
        router.update(&player, Round(5), false);
        router.update(&player, Round(5), false);
        assert_eq!(router.children.len(), 1);
    }

    #[test]
    fn round_router_update_idempotent() {
        let mut router = RoundRouter::default();
        let player = Player::default();
        router.update(&player, Period(3), false);
        router.update(&player, Period(3), false);
        assert_eq!(router.children.len(), 1);
    }

    #[test]
    fn period_router_update_idempotent() {
        let mut router = PeriodRouter::default();
        router.update(Step(7));
        router.update(Step(7));
        assert_eq!(router.children.len(), 1);
    }
}
