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

// `MessageDecoderFilter` — a reusable fuzzer-harness primitive that
// decodes every outgoing vote / proposal-payload / bundle it observes
// and caches the decoded form, keyed by the raw wire bytes.
//
// Mirrors `agreement/fuzzer/messageDecoderFilter_test.go` (Go):
// `SendMessage` dispatches on `protocol.Tag` to `decodeVote` /
// `decodeProposal` / `decodeBundle`, each of which is a best-effort
// `protocol.DecodeStream` that silently no-ops on a decode error (Go:
// `if err != nil { return }`) and otherwise stores the decoded value in
// a shared `msgStore` keyed by `string(data)`. `getDecodedMessageCounts`
// exposes the per-tag cache size, which is exactly what
// `TestMessageDecoderFilter` asserts on (nonzero vote/proposal counts,
// zero bundle count for a scenario that never produces one).
//
// This is deliberately distinct from `demux::demux_garbage_data_does_
// not_crash` (decode-safety at the production `Demux` boundary): this
// filter is a fuzzer-harness *primitive*, reusable in any filter chain
// to observe/cache what actually flowed through a scenario, not a
// one-off crash-safety assertion.
//
// Go shares one `msgStore` across every node's filter instance
// (`CreateFilter` lazily initializes it once on the factory and reuses
// it for every subsequent node) — this port mirrors that via
// `Arc<Mutex<MessageDecoderStore>>`: build one [`MessageDecoderFilterBuilder`]
// per scenario and call [`MessageDecoderFilterBuilder::build`] once per
// node, then read the aggregate counts back off the builder itself.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use algo_agreement::{
    codec, CompoundMessage, UnauthenticatedBundle, UnauthenticatedVote, AGREEMENT_VOTE_TAG,
    PROPOSAL_PAYLOAD_TAG, VOTE_BUNDLE_TAG,
};

use crate::fuzzer::filter::{Filter, FilterDecision};
use crate::fuzzer::AlgoMessage;

/// The shared decode cache. Mirrors Go's `MessageDecoderStore`.
#[derive(Default)]
struct MessageDecoderStore {
    votes: HashMap<Vec<u8>, UnauthenticatedVote>,
    proposals: HashMap<Vec<u8>, CompoundMessage>,
    bundles: HashMap<Vec<u8>, UnauthenticatedBundle>,
}

/// Builder + aggregate-count reader for [`MessageDecoderFilter`].
/// Mirrors Go's `&MessageDecoderFilter{}` factory value, which is
/// itself reused as the assertion target after `testConfig` runs
/// (`msgDecoder.getDecodedMessageCounts(...)` in
/// `TestMessageDecoderFilter`).
#[derive(Clone, Default)]
pub struct MessageDecoderFilterBuilder {
    store: Arc<Mutex<MessageDecoderStore>>,
}

impl MessageDecoderFilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a filter instance sharing this builder's decode cache
    /// — call once per node in the scenario, mirroring Go's
    /// `CreateFilter(nodeID, fuzzer)`.
    pub fn build(&self) -> MessageDecoderFilter {
        MessageDecoderFilter {
            store: Arc::clone(&self.store),
        }
    }

    /// Mirrors `getDecodedMessageCounts(protocol.AgreementVoteTag)`.
    pub fn decoded_vote_count(&self) -> usize {
        self.store
            .lock()
            .expect("MessageDecoderStore poisoned")
            .votes
            .len()
    }

    /// Mirrors `getDecodedMessageCounts(protocol.ProposalPayloadTag)`.
    pub fn decoded_proposal_count(&self) -> usize {
        self.store
            .lock()
            .expect("MessageDecoderStore poisoned")
            .proposals
            .len()
    }

    /// Mirrors `getDecodedMessageCounts(protocol.VoteBundleTag)`.
    pub fn decoded_bundle_count(&self) -> usize {
        self.store
            .lock()
            .expect("MessageDecoderStore poisoned")
            .bundles
            .len()
    }
}

/// Per-node decode-and-cache filter. See module doc for semantics.
pub struct MessageDecoderFilter {
    store: Arc<Mutex<MessageDecoderStore>>,
}

impl Filter for MessageDecoderFilter {
    fn name(&self) -> &str {
        "MessageDecoderFilter"
    }

    /// Mirrors Go's `SendMessage`: decode-and-cache is only performed
    /// on the OUTGOING side (a node's own broadcasts), never on
    /// `ReceiveMessage` (incoming) — `filter_incoming` is left at the
    /// trait default (`Keep`, no-op).
    fn filter_outgoing(&mut self, msg: &AlgoMessage) -> FilterDecision {
        let mut store = self.store.lock().expect("MessageDecoderStore poisoned");
        match msg.tag.as_str() {
            AGREEMENT_VOTE_TAG => {
                if let Ok(uv) = codec::decode_vote(&msg.data) {
                    store.votes.insert(msg.data.clone(), uv);
                }
            }
            PROPOSAL_PAYLOAD_TAG => {
                if let Ok(cm) = codec::decode_compound_message(&msg.data) {
                    store.proposals.insert(msg.data.clone(), cm);
                }
            }
            VOTE_BUNDLE_TAG => {
                if let Ok(ub) = codec::decode_bundle(&msg.data) {
                    store.bundles.insert(msg.data.clone(), ub);
                }
            }
            _ => {}
        }
        // A decode failure is a silent no-op here too — matching Go's
        // `if err != nil { return }` — the message still flows through
        // unmodified either way (Go: `n.downstream.SendMessage(...)`
        // always runs after the decode attempt).
        FilterDecision::Keep
    }
}
