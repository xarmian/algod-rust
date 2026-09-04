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

// White-box test helpers for the agreement state machine.
//
// Mirrors go-algorand's in-test scaffolding from
// `agreement/state_machine_test.go`, `agreement/player_test.go`, and
// `agreement/common_test.go`. These helpers let tests construct a `Player`
// at a known `(round, period, step)`, drive it via direct event injection
// (bypassing the demux + service runtime), and assert against an in-memory
// trace of inputs and emitted actions.
//
// ## Why a dedicated module
//
// The full agreement service requires real participation keys, a clock,
// gossip, and a ledger that produces blocks. Permutation-style state-machine
// tests don't care about any of that — they want to enumerate
// `(player_state, event)` pairs and check that the right action falls out.
// Mirroring Go's test harness (`ioAutomata`, `voteMakerHelper`, `setupP`)
// keeps the port mechanical and lets us re-use these helpers across all
// future subsystem-level backfill tests (vote, bundle, proposal_store, etc).
//
// ## Feature gating
//
// The module is compiled only under `cfg(any(test, feature = "test-support"))`
// so that release builds of `algo-agreement` never ship the helpers. The
// crate's own `[dev-dependencies]` self-reference activates the
// `test-support` feature unconditionally during `cargo test`, so integration
// tests can `use algo_agreement::test_support::*` with no extra flags.
//
// ## Public surface
//
// - [`IoTrace`] — append-only record of inputs + emitted actions.
// - [`IoAutomataConcretePlayer`] — wraps `Player + RootRouter + IoTrace`
//   and exposes `transition(event)` plus state-injection helpers needed
//   by the permutation preconditions.
// - [`VoteMakerHelper`] — index-keyed per-test fabricator of `Vote`,
//   `Bundle`, `RawVote` values. Mirrors Go's `voteMakerHelper`.
// - [`setup_p`] — construct a fresh `(Player, IoAutomataConcretePlayer,
//   VoteMakerHelper)` triple at a target `(round, period, step)`.
// - [`make_random_proposal_payload`] — fabricate a minimal `Proposal`
//   whose `value()` digest is consistent within a test run.
// - [`override_consensus_with_dynamic_filter`] — return a `ConsensusParams`
//   value with the dynamic-filter-timeout flag flipped, mirroring Go's
//   `overrideConfigWithDynamicFilterParam` without mutating any global.

pub mod credential_history;
pub mod io_automata;
pub mod io_trace;
pub mod setup;
pub mod vote_maker;

pub use credential_history::{
    assert_payload_timings, assert_single_credential_arrival, move_to_round, send_compound_message,
    send_compound_message_for_vote, send_payload_present, send_payload_present_at,
    send_vote_present, send_vote_verified, send_vote_verified_for_vote, test_clock_for_round,
};
pub use io_automata::IoAutomataConcretePlayer;
pub use io_trace::{IoTrace, TraceEntry};
pub use setup::{
    override_consensus_with_dynamic_filter, setup_p, OverriddenConsensus,
    CONSENSUS_VERSION_FOR_TEST,
};
pub use vote_maker::{make_random_proposal_payload, random_block_hash, VoteMakerHelper};
