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

// White-box driver wrapping `Player + RootRouter + IoTrace`.
//
// Mirrors go-algorand `agreement/state_machine_test.go::ioAutomataConcretePlayer`.
//
// The Go test injects events directly via `submitTop`, capturing both the
// input and any returned actions in an `ioTrace`. Permutation-style
// preconditions reach into the router hierarchy (e.g.
// `pM.Children[r].ProposalStore.Assemblers`) before driving the test event.
// We mirror both shapes: `transition` is the public driver,
// `set_*_for_test` methods encapsulate the deep mutations the Go test
// performs ad-hoc.

use std::panic::{catch_unwind, AssertUnwindSafe};

use algo_types::{ConsensusParams, Round};

use crate::actions::Action;
use crate::events::{Event, EventType, ThresholdEvent};
use crate::player::Player;
use crate::proposal_store::BlockAssembler;
use crate::router::RootRouter;
use crate::step::Period;
use crate::vote::ProposalValue;

use super::io_trace::IoTrace;

// ---------------------------------------------------------------------------
// IoAutomataConcretePlayer
// ---------------------------------------------------------------------------

/// A composed test machine: `Player + RootRouter + IoTrace`.
///
/// Mirrors Go's `ioAutomataConcretePlayer`. Each `transition` call:
///
/// 1. Records the input event in the trace.
/// 2. Calls `RootRouter::submit_top(player, event, params)`, catching panics
///    via `std::panic::catch_unwind` (mirroring Go's deferred `recover()`).
/// 3. Records every emitted action in the trace.
///
/// Tests can then read the trace via [`IoAutomataConcretePlayer::trace`]
/// and assert against it. State-injection helpers ([`set_proposal_assembler`],
/// [`set_proposal_duplicate`], [`set_cert_threshold`]) encapsulate the
/// router-state mutations needed by the permutation preconditions.
pub struct IoAutomataConcretePlayer {
    player: Player,
    router: RootRouter,
    trace: IoTrace,
    /// Consensus parameters threaded into every `submit_top`. Tests pick a
    /// specific `ConsensusParams` (stock V41, V41+dynamic-filter) via
    /// [`super::override_consensus_with_dynamic_filter`].
    params: ConsensusParams,
    /// Set to `true` after a `transition` call panics. Subsequent
    /// `transition` calls return `Err("automata poisoned")` so callers
    /// can't accidentally drive a partially-mutated `RootRouter` (the
    /// player itself is replaced with `Default::default()` on panic, but
    /// the router's per-round/period maps may have been left
    /// half-updated). Permutation tests panic-then-abort so this never
    /// trips today; the flag exists so future reusers (TASK-92/93/94)
    /// don't silently produce nonsense traces after a panic.
    poisoned: bool,
}

impl IoAutomataConcretePlayer {
    /// Create a new test driver around the given `(player, router, params)`.
    pub fn new(player: Player, router: RootRouter, params: ConsensusParams) -> Self {
        Self {
            player,
            router,
            trace: IoTrace::new(),
            params,
            poisoned: false,
        }
    }

    /// Whether a previous `transition` call panicked. Once poisoned the
    /// machine refuses to drive further transitions.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Borrow the underlying player.
    ///
    /// Mirrors Go's `ioAutomataConcretePlayer.underlying()`.
    pub fn player(&self) -> &Player {
        &self.player
    }

    /// Borrow the underlying player mutably. Used by setup helpers; tests
    /// should prefer [`Self::set_proposal_assembler`] etc.
    pub fn player_mut(&mut self) -> &mut Player {
        &mut self.player
    }

    /// Borrow the underlying router.
    pub fn router(&self) -> &RootRouter {
        &self.router
    }

    /// Borrow the underlying router mutably. Used by setup helpers.
    pub fn router_mut(&mut self) -> &mut RootRouter {
        &mut self.router
    }

    /// Borrow the recorded trace.
    pub fn trace(&self) -> &IoTrace {
        &self.trace
    }

    /// Reset the trace.
    pub fn reset_trace(&mut self) {
        self.trace.reset();
    }

    /// Replace the consensus parameters used by future transitions. Used by
    /// the permutation runner to swap between stock-V41 and
    /// dynamic-filter-on V41 between iterations without rebuilding the
    /// full machine.
    pub fn set_params(&mut self, params: ConsensusParams) {
        self.params = params;
    }

    /// Borrow the current consensus parameters.
    pub fn params(&self) -> &ConsensusParams {
        &self.params
    }

    /// Drive one transition, recording input + outputs in the trace.
    ///
    /// Returns `Ok(())` on success, `Err("automata poisoned: ...")` if a
    /// previous transition panicked, or `Err(panic_msg)` if THIS
    /// transition panicked. Mirrors Go's `ioAutomataConcretePlayer.transition`
    /// which returns `(err, panicErr)`. We collapse both into a single
    /// `Result` since panics are the only failure mode worth
    /// distinguishing in a synchronous test driver.
    ///
    /// On panic the player is replaced with `Default::default()` and the
    /// machine is marked poisoned; subsequent calls short-circuit. The
    /// router may have been left partially mutated (HashMap::entry
    /// inserts, etc., happen before panics farther down the call stack),
    /// so reusing a poisoned machine would produce nonsense traces.
    pub fn transition(&mut self, e: Event) -> Result<(), String> {
        if self.poisoned {
            return Err("automata poisoned: previous transition panicked".to_string());
        }

        self.trace.extend_input(e.clone());

        // Move the player out, leaving a default placeholder. On success
        // we put it back; on panic we leave the placeholder in place
        // (`std::mem::take` already wrote it) and set `poisoned = true`.
        // `AssertUnwindSafe` lets us borrow the router across the unwind
        // boundary — `std::panic::catch_unwind` requires unwind-safe
        // args, but the alternative is an unrecoverable process abort,
        // which is worse for test ergonomics.
        let player = std::mem::take(&mut self.player);
        let router = &mut self.router;
        let params = &self.params;
        let actions_result = catch_unwind(AssertUnwindSafe(|| {
            router.submit_top(player, e, params, None)
        }));

        match actions_result {
            Ok((player, actions)) => {
                self.player = player;
                for a in actions {
                    self.trace.extend_output(a);
                }
                Ok(())
            }
            Err(panic) => {
                self.poisoned = true;
                // Best-effort extraction of the panic message.
                let msg = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_string()))
                    .unwrap_or_else(|| "<non-string panic payload>".to_string());
                Err(msg)
            }
        }
    }

    // -- Setup helpers --------------------------------------------------------

    /// Ensure the round/period routers exist for `(round, period)`. Mirrors
    /// Go's chained `pM.update(plyr, r, true) → pM.Children[r].update(plyr,
    /// p, true) → pM.Children[r].Children[p].update(0)`. Subsequent
    /// `set_*_for_test` calls assume this has been invoked first.
    pub fn ensure_round_period(&mut self, round: Round, period: Period) {
        self.router.update(&self.player, round, true);
        let round_router = self
            .router
            .children
            .get_mut(&round)
            .expect("update() inserted child router");
        round_router.update(&self.player, period, true);
        let period_router = round_router
            .children
            .get_mut(&period)
            .expect("update() inserted period router");
        // PeriodRouter::update takes a Step; pass step 0 to mirror Go's
        // `pM.Children[r].Children[p].update(0)` which inserts the step-0
        // entry. The step value isn't consulted further by the permutation
        // tests.
        period_router.update(crate::step::Step(0));
    }

    /// Insert (or overwrite) a `BlockAssembler` for `(round, value)` in the
    /// per-round `ProposalStore`. Mirrors Go's
    /// `pM.Children[r].ProposalStore.Assemblers[pV] = blockAssembler{...}`.
    ///
    /// Writes to both per-round stores: the canonical one in
    /// `ProposalManager.stores[r]` (consulted by vote/payload dispatch) and
    /// the legacy mirror in `RoundRouter.children[r].proposal_store`
    /// (consulted by `staged_value()` / `pinned_value()` helpers). The Rust
    /// port maintains both because the original architecture didn't
    /// consolidate the duplicate hierarchies; mirroring keeps the test
    /// observable from either lookup path.
    pub fn set_proposal_assembler(
        &mut self,
        round: Round,
        value: ProposalValue,
        assembler: BlockAssembler,
    ) {
        // Canonical: the store the vote/payload dispatch path actually consults.
        self.router
            .proposal_manager
            .store_for_round(round)
            .assemblers
            .insert(value, assembler.clone());
        // Legacy mirror under RoundRouter — kept in sync so any helper
        // that still goes through `staged_value`/`pinned_value` sees the
        // same precondition.
        if let Some(round_router) = self.router.children.get_mut(&round) {
            round_router
                .proposal_store
                .assemblers
                .insert(value, assembler);
        }
    }

    /// Mark `address` as having already submitted a proposal-vote in
    /// `(round, period)`, so the next event from the same sender is
    /// filtered. Mirrors Go's
    /// `pM.Children[r].Children[p].ProposalTracker.Duplicate[addr] = true`.
    ///
    /// Mirrors the duplicate flag into both per-round stores (see
    /// [`set_proposal_assembler`] for why both paths exist).
    pub fn set_proposal_duplicate(
        &mut self,
        round: Round,
        period: Period,
        address: algo_types::Address,
    ) {
        // Canonical store under ProposalManager.
        let canonical_store = self.router.proposal_manager.store_for_round(round);
        canonical_store
            .trackers
            .entry(period)
            .or_default()
            .duplicate
            .insert(address, true);
        // Legacy mirror under RoundRouter.
        if let Some(round_router) = self.router.children.get_mut(&round) {
            if let Some(period_router) = round_router.children.get_mut(&period) {
                period_router
                    .proposal_tracker
                    .duplicate
                    .insert(address, true);
            }
        }
    }

    /// Set the staging proposal-value for `(round, period)`. Mirrors Go's
    /// `pM.Children[r].Children[p].ProposalTracker.Staging = pV`. Mirrored
    /// across both per-round stores.
    pub fn set_proposal_staging(&mut self, round: Round, period: Period, value: ProposalValue) {
        let canonical_store = self.router.proposal_manager.store_for_round(round);
        canonical_store.trackers.entry(period).or_default().staging = value;
        if let Some(round_router) = self.router.children.get_mut(&round) {
            if let Some(period_router) = round_router.children.get_mut(&period) {
                period_router.proposal_tracker.staging = value;
            }
        }
    }

    /// Force a cert-threshold event into the round's vote tracker. Mirrors
    /// Go's
    /// `pM.Children[r].VoteTrackerRound.Freshest = thresholdEvent{T: certThreshold, ...}`
    /// `pM.Children[r].VoteTrackerRound.Ok = true`.
    ///
    /// Writes to the canonical `VoteTrackerRound` held by
    /// `VoteAggregator.rounds[r]` — the only one that exists; algod-rust's
    /// `RootRouter` routes VoteMachineRound/Period/Step events directly
    /// there instead of through a `RoundRouter` mirror (issue #500,
    /// follow-up to #497/#499). Unlike [`set_proposal_assembler`], there is
    /// no second copy to keep in sync.
    ///
    /// **Verbatim port note.** Go's `player_permutation_test.go` also
    /// constructs an internally inconsistent state here: `threshold.Proposal`
    /// is `pV` while `threshold.Bundle` is `unauthenticatedBundle{Round: r}`
    /// (proposal defaults to bottom). Go's player builds the cert from
    /// `freshestRes.Event.Bundle`, so the resulting `ensure` action carries
    /// a bottom-proposal certificate even though the threshold itself is for
    /// `pV`. This is intentional in the Go test (see
    /// `agreement/player_permutation_test.go:104-118` and the
    /// `playerSameRoundReachedCertThreshold × payloadVerified` expected
    /// assertion that hard-codes `Certificate(unauthenticatedBundle{Round:
    /// r})`). We reproduce it byte-for-byte; the corresponding test
    /// expectation matches against `ProposalValue::default()` (bottom). If
    /// future backfill tasks (TASK-92/93/94) want to exercise the
    /// realistic `bundle.proposal == value` path, they should add a
    /// separate setup variant rather than altering this one.
    ///
    /// Calls a `pub(crate)` setter on `VoteTrackerRound`; field-level
    /// surface stays private to keep the production API tight.
    pub fn set_cert_threshold(&mut self, round: Round, period: Period, value: ProposalValue) {
        let bundle = crate::bundle::UnauthenticatedBundle {
            round,
            period: Period(0),
            step: crate::step::Step(0),
            proposal: crate::vote::BOTTOM,
            votes: Vec::new(),
            equivocation_votes: Vec::new(),
        };
        let te = ThresholdEvent {
            t: EventType::CertThreshold,
            round,
            period,
            step: crate::step::Step(0),
            proposal: value,
            bundle,
            proto: String::new(),
        };
        // vote_aggregator.rounds[r] is what the VoteMachine dispatch path
        // filters bundles against — the only VoteTrackerRound instance.
        self.router
            .vote_aggregator
            .round_tracker(round)
            .force_freshest_for_test(te);
    }
}

// Eagerly drop unused imports if the actions module is later restructured.
#[allow(dead_code)]
fn _action_lints(_: &Action) {}
