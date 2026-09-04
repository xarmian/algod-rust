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

// `MessageRegossipFilter` — suppresses re-sending a message a node has
// already seen arrive as incoming traffic.
//
// Mirrors `agreement/fuzzer/messageRegossipFilter_test.go` (Go):
// `ReceiveMessage` records `sha256(tag ++ data)` for every inbound
// message into `seenIncomingMessages`; `SendMessage` drops (does not
// forward downstream) any outgoing message whose digest is already in
// that set. Net effect: a node that already received a given message
// from one peer will not re-gossip that exact message to its other
// peers a second time just because something asked it to relay/re-send
// it — eliminating the wasted "regossip" traffic while still letting a
// message the node has never seen (including a first relay of
// something it only just received) go out normally.
//
// `TestRegossipinngElimination` (Go, `tests_test.go`) measures this by
// comparing total network traffic across an identical scenario with
// and without this filter installed on every online node. The Rust
// equivalent (`network_scale_regossip_elimination_reduces_growth` in
// `fuzzer_smoke.rs`) does the same comparison at a harness-appropriate
// scale — see that test's doc comment for why the full 20-node/
// 150-tick live-consensus benchmark is out of reach for this
// message-pump-only harness (no live `Service` integration yet; see
// `mod.rs`'s "Out of scope" note).
//
// Unlike `drop_message`/`duplicate_message` (which only ever need one
// direction's state), this filter's `filter_incoming` writes state that
// `filter_outgoing` reads — the same requirement `network_facade.rs`
// documents for a hypothetical future filter. Since `NetworkFacade`
// stores the outgoing and incoming chains as two separate
// `Vec<Box<dyn Filter>>`, a single node needs the SAME underlying
// "seen" set reachable from both chains: construct one
// [`MessageRegossipFilter`] and put `.clone()` of it in both chains
// (cheap — it's an `Arc<Mutex<..>>` handle, not a state copy).

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::fuzzer::filter::{Filter, FilterDecision};
use crate::fuzzer::AlgoMessage;

/// Per-node regossip-elimination filter. See module doc for semantics
/// and for why this is `Clone` (both the outgoing- and incoming-chain
/// copies must share one underlying digest set).
#[derive(Clone, Default)]
pub struct MessageRegossipFilter {
    seen_incoming: Arc<Mutex<HashSet<[u8; 32]>>>,
}

impl MessageRegossipFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct messages ever recorded as incoming, so tests
    /// / scenarios can measure the elimination effect directly instead
    /// of only inferring it from a total-traffic count.
    pub fn seen_count(&self) -> usize {
        self.seen_incoming
            .lock()
            .expect("MessageRegossipFilter poisoned")
            .len()
    }
}

fn digest(msg: &AlgoMessage) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(msg.tag.as_bytes());
    hasher.update(&msg.data);
    hasher.finalize().into()
}

impl Filter for MessageRegossipFilter {
    fn name(&self) -> &str {
        "MessageRegossipFilter"
    }

    fn filter_outgoing(&mut self, msg: &AlgoMessage) -> FilterDecision {
        let seen = self
            .seen_incoming
            .lock()
            .expect("MessageRegossipFilter poisoned");
        if seen.contains(&digest(msg)) {
            FilterDecision::Drop
        } else {
            FilterDecision::Keep
        }
    }

    fn filter_incoming(&mut self, msg: &AlgoMessage) -> FilterDecision {
        self.seen_incoming
            .lock()
            .expect("MessageRegossipFilter poisoned")
            .insert(digest(msg));
        FilterDecision::Keep
    }
}
