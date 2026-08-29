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

// `DuplicateMessageFilter` — re-emit every Nth message.
//
// Conceptually mirrors `agreement/fuzzer/messageDuplicationFilter_test.go`,
// minus the priority-queue delay. Go's filter inserts duplicates into a
// per-tick min-heap so the duplicate fires later than the original;
// because the drop / duplicate scaffold in TASK-84 doesn't yet integrate
// with a tick-driven Service, we emit the duplicates inline (same tick
// as the original). The semantics that matter for fault-injection
// scenarios — "the recipient sees the same message N+1 times" — are
// preserved; richer delay scheduling lands with the message-delay /
// reorder filters in TASK-85.
//
// Per-direction rates are independent. `Some(N)` for `N > 0` means
// "after every Nth observed message, request `extra_copies` extra
// deliveries". `Some(0)` and `None` are both no-ops (matches Go's
// "no entry for this node" / "rate 0" short-circuits).

use crate::fuzzer::filter::{Filter, FilterDecision};
use crate::fuzzer::AlgoMessage;

/// Builder that produces [`DuplicateMessageFilter`] instances configured
/// for a particular `(outgoing, incoming)` pair of `(rate,
/// extra_copies)` settings.
#[derive(Clone, Debug, Default)]
pub struct DuplicateMessageFilterBuilder {
    outgoing_rate: Option<u64>,
    outgoing_extra_copies: u32,
    incoming_rate: Option<u64>,
    incoming_extra_copies: u32,
}

impl DuplicateMessageFilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// After every `rate` outgoing messages, deliver `extra_copies`
    /// additional copies of that message. `rate = None` or
    /// `extra_copies = 0` ⇒ never duplicate outgoing traffic.
    pub fn outgoing(mut self, rate: Option<u64>, extra_copies: u32) -> Self {
        self.outgoing_rate = rate;
        self.outgoing_extra_copies = extra_copies;
        self
    }

    /// After every `rate` incoming messages, deliver `extra_copies`
    /// additional copies. Same caveats as [`Self::outgoing`].
    pub fn incoming(mut self, rate: Option<u64>, extra_copies: u32) -> Self {
        self.incoming_rate = rate;
        self.incoming_extra_copies = extra_copies;
        self
    }

    pub fn build(self) -> DuplicateMessageFilter {
        DuplicateMessageFilter {
            outgoing_rate: self.outgoing_rate,
            outgoing_extra_copies: self.outgoing_extra_copies,
            incoming_rate: self.incoming_rate,
            incoming_extra_copies: self.incoming_extra_copies,
            outgoing_seen: 0,
            incoming_seen: 0,
        }
    }
}

/// Per-node duplicate filter.
pub struct DuplicateMessageFilter {
    outgoing_rate: Option<u64>,
    outgoing_extra_copies: u32,
    incoming_rate: Option<u64>,
    incoming_extra_copies: u32,
    outgoing_seen: u64,
    incoming_seen: u64,
}

impl DuplicateMessageFilter {
    pub fn outgoing_seen(&self) -> u64 {
        self.outgoing_seen
    }

    pub fn incoming_seen(&self) -> u64 {
        self.incoming_seen
    }
}

impl Filter for DuplicateMessageFilter {
    fn name(&self) -> &str {
        "DuplicateMessageFilter"
    }

    fn filter_outgoing(&mut self, _msg: &AlgoMessage) -> FilterDecision {
        self.outgoing_seen = self.outgoing_seen.wrapping_add(1);
        decide(
            self.outgoing_seen,
            self.outgoing_rate,
            self.outgoing_extra_copies,
        )
    }

    fn filter_incoming(&mut self, _msg: &AlgoMessage) -> FilterDecision {
        self.incoming_seen = self.incoming_seen.wrapping_add(1);
        decide(
            self.incoming_seen,
            self.incoming_rate,
            self.incoming_extra_copies,
        )
    }
}

fn decide(counter: u64, rate: Option<u64>, extra_copies: u32) -> FilterDecision {
    match (rate, extra_copies) {
        (None, _) | (_, 0) => FilterDecision::Keep,
        (Some(0), _) => FilterDecision::Keep, // 0-rate is a no-op (matches Go).
        (Some(rate), extra) => {
            if counter % rate == 0 {
                FilterDecision::Duplicate {
                    extra_copies: extra,
                }
            } else {
                FilterDecision::Keep
            }
        }
    }
}
