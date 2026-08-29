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

// `DropMessageFilter` — drops every Nth message in either direction.
//
// Mirrors `agreement/fuzzer/dropMessageFilter_test.go` (Go) — the
// behavior is *deterministic*, not RNG-driven: the filter keeps two
// counters (one per direction) and drops the message whenever
// `counter % rate == 0` after incrementing.
//
// Rate semantics (matching Go's `rate == 0 || count%rate != 0`
// short-circuit at `dropMessageFilter_test.go:48-52`):
//   * `None`     → no-op; forward every message in this direction.
//   * `Some(0)`  → no-op; the `||` short-circuits to TRUE so Go's
//                  forward branch always runs. To "drop everything"
//                  use `Some(1)` (every counter % 1 == 0).
//   * `Some(N)`  → drop the Nth, 2Nth, 3Nth, … message.
//
// Per-direction rates can be configured independently via
// [`DropMessageFilterBuilder`].

use crate::fuzzer::filter::{Filter, FilterDecision};
use crate::fuzzer::AlgoMessage;

/// Builder that produces [`DropMessageFilter`] instances configured
/// for a particular `(outgoing_rate, incoming_rate)` pair.
#[derive(Clone, Debug, Default)]
pub struct DropMessageFilterBuilder {
    outgoing_rate: Option<u64>,
    incoming_rate: Option<u64>,
}

impl DropMessageFilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the outgoing-direction drop rate. See the module-level
    /// doc for the full semantics table; in short:
    ///   * `None` or `Some(0)` ⇒ no-op (forward every message).
    ///   * `Some(1)` ⇒ drop every message.
    ///   * `Some(N)` for `N > 1` ⇒ drop the Nth, 2Nth, 3Nth, … message.
    pub fn outgoing_rate(mut self, rate: Option<u64>) -> Self {
        self.outgoing_rate = rate;
        self
    }

    /// Configure the incoming-direction drop rate — same semantics as
    /// [`Self::outgoing_rate`] but for traffic arriving at this node.
    pub fn incoming_rate(mut self, rate: Option<u64>) -> Self {
        self.incoming_rate = rate;
        self
    }

    pub fn build(self) -> DropMessageFilter {
        DropMessageFilter {
            outgoing_rate: self.outgoing_rate,
            incoming_rate: self.incoming_rate,
            outgoing_seen: 0,
            incoming_seen: 0,
        }
    }
}

/// Per-node drop filter. See module-level doc for semantics.
pub struct DropMessageFilter {
    outgoing_rate: Option<u64>,
    incoming_rate: Option<u64>,
    outgoing_seen: u64,
    incoming_seen: u64,
}

impl DropMessageFilter {
    /// Number of outgoing messages observed (kept + dropped).
    pub fn outgoing_seen(&self) -> u64 {
        self.outgoing_seen
    }

    /// Number of incoming messages observed (kept + dropped).
    pub fn incoming_seen(&self) -> u64 {
        self.incoming_seen
    }
}

impl Filter for DropMessageFilter {
    fn name(&self) -> &str {
        "DropMessageFilter"
    }

    fn filter_outgoing(&mut self, _msg: &AlgoMessage) -> FilterDecision {
        self.outgoing_seen = self.outgoing_seen.wrapping_add(1);
        decide(self.outgoing_seen, self.outgoing_rate)
    }

    fn filter_incoming(&mut self, _msg: &AlgoMessage) -> FilterDecision {
        self.incoming_seen = self.incoming_seen.wrapping_add(1);
        decide(self.incoming_seen, self.incoming_rate)
    }
}

fn decide(counter: u64, rate: Option<u64>) -> FilterDecision {
    match rate {
        None => FilterDecision::Keep,
        // Match Go's semantics in `agreement/fuzzer/dropMessageFilter_test.go:48-52`:
        // `if rate == 0 || n.sendMessageCount%rate != 0 { downstream.SendMessage(...) }`.
        // The `||` short-circuits to TRUE when `rate == 0`, so the
        // forward branch is taken every time — i.e. `rate == 0` is a
        // no-op (forwards every message), NOT "drop every message".
        // `rate == 1` is the drop-everything configuration since
        // `counter % 1 == 0` is always true.
        Some(0) => FilterDecision::Keep,
        Some(rate) => {
            if counter % rate == 0 {
                FilterDecision::Drop
            } else {
                FilterDecision::Keep
            }
        }
    }
}
