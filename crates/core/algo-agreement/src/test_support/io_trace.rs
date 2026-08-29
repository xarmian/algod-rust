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

// In-memory trace recorder for the white-box agreement test harness.
//
// Mirrors go-algorand `agreement/state_machine_test.go::ioTrace` (the
// in-memory `[]event` recorder used by all white-box state-machine tests).
//
// Distinct from `crate::trace` (the cadaver binary log). This trace is only
// used by tests to assert "did the player emit `<action>` in response to
// `<event>`" — there is no on-disk format and no codec compatibility with
// Go.
//
// ## API shape
//
// Go uses `trace.Contains(ev(action))`, which is a structural-equality scan.
// Rust's `Action` does not derive `PartialEq` (the embedded
// `MessageHandle` and `SerializableError` types prevent it), so the
// equivalent is `contains_action_fn` with a closure predicate. For the
// permutation test all expected-action checks are predicate-based anyway —
// `expect_ignore`, `expect_relay`, `expect_disconnect`, `expect_verify`
// (matching Go's `expectIgnore`, etc.) plus structural matchers for
// network/pseudonode/ensure/rezero/stage_digest actions.

use crate::actions::Action;
use crate::events::Event;

// ---------------------------------------------------------------------------
// TraceEntry
// ---------------------------------------------------------------------------

/// One record in an [`IoTrace`].
///
/// Entries are appended in order: the input event delivered to the player
/// followed by every action the player emits in response. Mirrors the
/// `wrappedActionEvent`/`event` distinction in Go: rather than wrap every
/// action as an event variant, we store the action inline.
///
/// Both variants are boxed to keep the enum size compact — `Event` and
/// `Action` are large discriminated unions (>500 bytes), and the trace
/// holds a `Vec<TraceEntry>` that benefits from small per-element overhead.
#[derive(Debug, Clone)]
pub enum TraceEntry {
    /// An event delivered to the state machine via `transition`.
    Input(Box<Event>),
    /// An action emitted by the state machine in response to the previous
    /// `Input`.
    Output(Box<Action>),
}

// ---------------------------------------------------------------------------
// IoTrace
// ---------------------------------------------------------------------------

/// Append-only record of inputs + outputs for one test run.
///
/// Mirrors Go's `ioTrace`. Tests construct an `IoTrace` indirectly by calling
/// [`IoAutomataConcretePlayer::transition`](super::IoAutomataConcretePlayer::transition);
/// they then read it back via [`IoTrace::count_actions`],
/// [`IoTrace::contains_action`], and [`IoTrace::contains_action_fn`] to
/// assert the player produced the expected outputs.
#[derive(Debug, Clone, Default)]
pub struct IoTrace {
    entries: Vec<TraceEntry>,
}

impl IoTrace {
    /// Create an empty trace.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an input event.
    pub fn extend_input(&mut self, e: Event) {
        self.entries.push(TraceEntry::Input(Box::new(e)));
    }

    /// Append an output action.
    pub fn extend_output(&mut self, a: Action) {
        self.entries.push(TraceEntry::Output(Box::new(a)));
    }

    /// Number of entries (inputs + outputs).
    ///
    /// Mirrors Go's `ioTrace.length()`.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the trace is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Count only output actions.
    ///
    /// Mirrors Go's `ioTrace.countAction()`. Used by the permutation test
    /// to assert "the player emitted exactly N actions".
    pub fn count_actions(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e, TraceEntry::Output(_)))
            .count()
    }

    /// All output actions, in emission order.
    pub fn actions(&self) -> impl Iterator<Item = &Action> {
        self.entries.iter().filter_map(|e| match e {
            TraceEntry::Output(a) => Some(a.as_ref()),
            TraceEntry::Input(_) => None,
        })
    }

    /// Returns `true` if any output action satisfies `f`.
    ///
    /// Mirrors Go's `ioTrace.ContainsFn(compareFn)`.
    pub fn contains_action_fn<F: Fn(&Action) -> bool>(&self, f: F) -> bool {
        self.actions().any(f)
    }

    /// Returns `true` if any output action equals `target` per the supplied
    /// equality function.
    ///
    /// Convenience wrapper for cases where we want to compare against a
    /// specific reference action via a structural matcher.
    pub fn contains_action<F: Fn(&Action, &Action) -> bool>(&self, target: &Action, eq: F) -> bool {
        self.actions().any(|a| eq(a, target))
    }

    /// All trace entries (inputs + outputs), in order.
    pub fn entries(&self) -> &[TraceEntry] {
        &self.entries
    }

    /// Reset the trace, dropping all recorded entries.
    ///
    /// Mirrors Go's `ioAutomataConcretePlayer.resetTrace`.
    pub fn reset(&mut self) {
        self.entries.clear();
    }
}

impl std::fmt::Display for IoTrace {
    /// Multi-line dump of the trace, one entry per line.
    ///
    /// Used in panic messages so a permutation failure prints the full
    /// in-out sequence that produced the mismatch. Includes enough detail
    /// (action type + key fields) to localize against the Go reference.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, e) in self.entries.iter().enumerate() {
            match e {
                TraceEntry::Input(ev) => writeln!(f, "  [{i:>3}] in  : {}", ev.event_type())?,
                TraceEntry::Output(a) => {
                    writeln!(f, "  [{i:>3}] out : {}", format_action(a.as_ref()))?
                }
            }
        }
        Ok(())
    }
}

/// Compact action dump used by the trace `Display`. Includes the action
/// type plus a small set of fields most useful for debugging permutation
/// failures (round/period/task_index for crypto, tag for network, etc.).
fn format_action(a: &crate::actions::Action) -> String {
    use crate::actions::{Action, ActionType};
    match a {
        Action::Network(na) => match na.t {
            ActionType::Relay | ActionType::Broadcast => {
                format!("{} tag={}", na.t, na.tag)
            }
            ActionType::Ignore | ActionType::Disconnect => {
                format!("{} err={:?}", na.t, na.err)
            }
            _ => na.t.to_string(),
        },
        Action::Crypto(ca) => match ca.t {
            ActionType::VerifyVote => format!(
                "verifyVote r={} p={} task={}",
                ca.round.0, ca.period.0, ca.task_index,
            ),
            ActionType::VerifyPayload => format!(
                "verifyPayload r={} p={} pinned={}",
                ca.round.0, ca.period.0, ca.pinned,
            ),
            ActionType::VerifyBundle => format!(
                "verifyBundle r={} p={} s={}",
                ca.round.0, ca.period.0, ca.step.0,
            ),
            _ => ca.t.to_string(),
        },
        Action::Pseudonode(pa) => format!(
            "{} r={} p={} s={} dig={:?}",
            pa.t, pa.round.0, pa.period.0, pa.step.0, pa.proposal.block_digest,
        ),
        Action::Ensure(ea) => format!(
            "ensure r={} p={} dig={:?}",
            ea.certificate.round.0, ea.certificate.period.0, ea.certificate.proposal.block_digest,
        ),
        Action::StageDigest(sa) => format!(
            "stageDigest r={} p={} dig={:?}",
            sa.certificate.round.0, sa.certificate.period.0, sa.certificate.proposal.block_digest,
        ),
        Action::Rezero(ra) => format!("rezero r={}", ra.round.0),
        Action::Noop(_) => "noop".to_string(),
        Action::Checkpoint(_) => "checkpoint".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{NoopAction, RezeroAction};
    use crate::events::EmptyEvent;
    use algo_types::Round;

    #[test]
    fn empty_trace_has_no_actions() {
        let t = IoTrace::new();
        assert_eq!(t.count_actions(), 0);
        assert!(t.is_empty());
    }

    #[test]
    fn extend_input_does_not_count_as_action() {
        let mut t = IoTrace::new();
        t.extend_input(Event::Empty(EmptyEvent));
        assert_eq!(t.len(), 1);
        assert_eq!(t.count_actions(), 0);
    }

    #[test]
    fn extend_output_increments_action_count() {
        let mut t = IoTrace::new();
        t.extend_input(Event::Empty(EmptyEvent));
        t.extend_output(Action::Noop(NoopAction));
        t.extend_output(Action::Rezero(RezeroAction { round: Round(5) }));
        assert_eq!(t.len(), 3);
        assert_eq!(t.count_actions(), 2);
    }

    #[test]
    fn contains_action_fn_finds_match() {
        let mut t = IoTrace::new();
        t.extend_output(Action::Rezero(RezeroAction { round: Round(7) }));
        assert!(t.contains_action_fn(|a| matches!(a, Action::Rezero(r) if r.round == Round(7))));
        assert!(!t.contains_action_fn(|a| matches!(a, Action::Rezero(r) if r.round == Round(8))));
    }

    #[test]
    fn reset_clears_entries() {
        let mut t = IoTrace::new();
        t.extend_output(Action::Noop(NoopAction));
        assert!(!t.is_empty());
        t.reset();
        assert!(t.is_empty());
    }
}
