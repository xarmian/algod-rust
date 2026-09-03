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

// In-memory multi-node agreement network, with selective per-vote-type drop
// support.
//
// Mirrors go-algorand's `agreement/service_test.go::testingNetwork` /
// `testingNetworkEndpoint`: N simulated nodes exchange real vote / proposal
// / bundle messages over per-node, per-tag bounded channels, with a shared
// `connected` matrix and a handful of test-only hooks
// (`dropAllSoftVotes`/`dropAllSlowNextVotes`/`dropAllVotes`/`repairAll`)
// used by the fast-recovery scenarios in `agreement/service_test.go`.
//
// Scope: this port carries the subset of go's testingNetwork actually
// exercised by the theme-3 scenarios ported so far (`DownEarly`/`DownMiss`):
// selective vote drop + repair. `pocketAllCertVotes`/`pocketAllSoftVotes`/
// `partition`/`crown`/`makeRelays`/`intercept` are not yet ported — a
// follow-up can add them the same way (see the go source comment on each
// hook below) once a scenario needs them (e.g. `Late`/`Redo`/
// `RecoverBothWorlds`).

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crossbeam_channel::{bounded, Receiver, Sender};

use algo_agreement::codec;
use algo_agreement::{
    AgreementError, AgreementNetwork, Message, MessageHandle, Tag, AGREEMENT_VOTE_TAG, DOWN, LATE,
    NEXT, PROPOSAL_PAYLOAD_TAG, REDO, SOFT, VOTE_BUNDLE_TAG,
};

/// A single node's three per-tag inbound channels (sender kept by the
/// network, receiver handed out via [`TestingNetworkEndpoint::messages`]).
struct NodeChannels {
    vote_tx: Sender<Message>,
    vote_rx: Receiver<Message>,
    payload_tx: Sender<Message>,
    payload_rx: Receiver<Message>,
    bundle_tx: Sender<Message>,
    bundle_rx: Receiver<Message>,
}

struct NetworkState {
    channels: Vec<NodeChannels>,
    /// Symmetric connectivity matrix — mirrors go's `n.connected`.
    connected: Vec<Vec<bool>>,
    next_handle: u64,
    /// Handle id -> source node, mirrors go's `n.source map[MessageHandle]nodeID`.
    source: HashMap<u64, usize>,

    drop_soft_votes: bool,
    drop_slow_next_votes: bool,
    drop_votes: bool,
}

/// Shared multi-node network. Construct once, then hand each node its own
/// [`TestingNetworkEndpoint`] via [`TestingNetwork::endpoint`].
pub struct TestingNetwork {
    state: Mutex<NetworkState>,
}

impl TestingNetwork {
    /// `buf_capacity` is per-node, per-tag channel capacity — mirrors go's
    /// `makeTestingNetwork(nodes, bufferCapacity, validator)`. The harness
    /// doesn't take a `BlockValidator` here (unlike go): algod-rust's
    /// `AgreementNetwork` trait carries no validator hook — block validation
    /// happens via `Parameters::block_validator`, per node.
    pub fn new(nodes: usize, buf_capacity: usize) -> Arc<Self> {
        let mut channels = Vec::with_capacity(nodes);
        for _ in 0..nodes {
            let (vote_tx, vote_rx) = bounded(buf_capacity);
            let (payload_tx, payload_rx) = bounded(buf_capacity);
            let (bundle_tx, bundle_rx) = bounded(buf_capacity);
            channels.push(NodeChannels {
                vote_tx,
                vote_rx,
                payload_tx,
                payload_rx,
                bundle_tx,
                bundle_rx,
            });
        }
        let connected = vec![vec![true; nodes]; nodes];
        Arc::new(Self {
            state: Mutex::new(NetworkState {
                channels,
                connected,
                next_handle: 0,
                source: HashMap::new(),
                drop_soft_votes: false,
                drop_slow_next_votes: false,
                drop_votes: false,
            }),
        })
    }

    /// Number of simulated nodes.
    pub fn node_count(self: &Arc<Self>) -> usize {
        self.state
            .lock()
            .expect("TestingNetwork poisoned")
            .channels
            .len()
    }

    /// Build the `AgreementNetwork` endpoint for node `id`.
    pub fn endpoint(self: &Arc<Self>, id: usize) -> TestingNetworkEndpoint {
        let (vote_rx, payload_rx, bundle_rx) = {
            let state = self.state.lock().expect("TestingNetwork poisoned");
            let c = &state.channels[id];
            (c.vote_rx.clone(), c.payload_rx.clone(), c.bundle_rx.clone())
        };
        TestingNetworkEndpoint {
            id,
            network: Arc::clone(self),
            vote_rx,
            payload_rx,
            bundle_rx,
        }
    }

    /// Mirrors go's `testingNetwork.dropAllSoftVotes`.
    pub fn drop_all_soft_votes(&self) {
        self.state
            .lock()
            .expect("TestingNetwork poisoned")
            .drop_soft_votes = true;
    }

    /// Mirrors go's `testingNetwork.dropAllSlowNextVotes`.
    pub fn drop_all_slow_next_votes(&self) {
        self.state
            .lock()
            .expect("TestingNetwork poisoned")
            .drop_slow_next_votes = true;
    }

    /// Mirrors go's `testingNetwork.dropAllVotes`.
    pub fn drop_all_votes(&self) {
        self.state
            .lock()
            .expect("TestingNetwork poisoned")
            .drop_votes = true;
    }

    /// Mirrors go's `testingNetwork.repairAll` (the subset of drop state this
    /// port tracks — see the module doc for what's not yet ported).
    pub fn repair_all(&self) {
        let mut state = self.state.lock().expect("TestingNetwork poisoned");
        state.drop_soft_votes = false;
        state.drop_slow_next_votes = false;
        state.drop_votes = false;
    }

    /// Total number of messages currently sitting unconsumed in every node's
    /// inbound channels, across all three tags. Used by the harness's
    /// quiescence poll (see `activity_monitor.rs`) as a direct, exact signal
    /// — no risk of racing a "receiver hasn't woken up yet" window, since
    /// this reads the channel length itself rather than a derived counter.
    pub fn pending_message_count(&self) -> usize {
        let state = self.state.lock().expect("TestingNetwork poisoned");
        state
            .channels
            .iter()
            .map(|c| c.vote_rx.len() + c.payload_rx.len() + c.bundle_rx.len())
            .sum()
    }
}

/// Per-node `AgreementNetwork` implementation. Mirrors go's
/// `testingNetworkEndpoint`.
pub struct TestingNetworkEndpoint {
    id: usize,
    network: Arc<TestingNetwork>,
    vote_rx: Receiver<Message>,
    payload_rx: Receiver<Message>,
    bundle_rx: Receiver<Message>,
}

impl AgreementNetwork for TestingNetworkEndpoint {
    fn messages(&self, tag: &Tag) -> Receiver<Message> {
        match tag.0 {
            AGREEMENT_VOTE_TAG => self.vote_rx.clone(),
            VOTE_BUNDLE_TAG => self.bundle_rx.clone(),
            PROPOSAL_PAYLOAD_TAG => self.payload_rx.clone(),
            other => panic!("TestingNetworkEndpoint::messages: bad tag {other}"),
        }
    }

    fn broadcast(&self, tag: &Tag, data: &[u8]) -> Result<(), AgreementError> {
        multicast(&self.network, tag.0, data, self.id, self.id);
        Ok(())
    }

    fn relay(&self, handle: &MessageHandle, tag: &Tag, data: &[u8]) -> Result<(), AgreementError> {
        let source_id = source_of(&self.network, handle).unwrap_or(self.id);
        multicast(&self.network, tag.0, data, self.id, source_id);
        Ok(())
    }

    fn disconnect(&self, handle: &MessageHandle) {
        if let Some(source_id) = source_of(&self.network, handle) {
            let mut state = self.network.state.lock().expect("TestingNetwork poisoned");
            state.connected[self.id][source_id] = false;
            state.connected[source_id][self.id] = false;
        }
    }

    fn start(&self) {}
}

/// Resolve a `MessageHandle` back to the node that originally sent it —
/// mirrors go's `testingNetwork.sourceOf`.
fn source_of(network: &Arc<TestingNetwork>, handle: &MessageHandle) -> Option<usize> {
    let id = handle.as_ref()?.downcast_ref::<u64>().copied()?;
    network
        .state
        .lock()
        .expect("TestingNetwork poisoned")
        .source
        .get(&id)
        .copied()
}

/// Core routing + selective-drop logic. Mirrors go's
/// `testingNetwork.multicast(tag, data, source, exclude)`.
fn multicast(
    network: &Arc<TestingNetwork>,
    tag: &'static str,
    data: &[u8],
    source: usize,
    exclude: usize,
) {
    let mut state = network.state.lock().expect("TestingNetwork poisoned");

    if (state.drop_soft_votes || state.drop_slow_next_votes || state.drop_votes)
        && tag == AGREEMENT_VOTE_TAG
    {
        let Ok(uv) = codec::decode_vote(data) else {
            // A malformed vote would be a harness bug (we only ever feed it
            // real encoded votes) — drop rather than panic to stay close to
            // go's `panic(err)` intent without taking down the whole test on
            // a decode edge case unrelated to what's being tested.
            return;
        };
        let step = uv.raw_vote.step;
        if state.drop_votes {
            return;
        }
        if state.drop_soft_votes && step == SOFT {
            return;
        }
        if state.drop_slow_next_votes
            && step.0 >= NEXT.0
            && step != LATE
            && step != REDO
            && step != DOWN
        {
            return;
        }
    }

    state.next_handle += 1;
    let handle_id = state.next_handle;
    state.source.insert(handle_id, source);
    let handle: MessageHandle = Some(Arc::new(handle_id) as Arc<dyn Any + Send + Sync>);

    let node_count = state.channels.len();
    for peer in 0..node_count {
        if peer == source || peer == exclude {
            continue;
        }
        if !state.connected[source][peer] {
            continue;
        }
        let msg = Message {
            handle: handle.clone(),
            data: data.to_vec(),
        };
        let target = &state.channels[peer];
        let sender = match tag {
            AGREEMENT_VOTE_TAG => &target.vote_tx,
            VOTE_BUNDLE_TAG => &target.bundle_tx,
            PROPOSAL_PAYLOAD_TAG => &target.payload_tx,
            _ => continue,
        };
        // Non-blocking send, matching go's `select { case ch <- msg: default:
        // drop }` — a full channel means the simulated peer is behind, and
        // go's testingNetwork just drops the message rather than blocking
        // the sender (which would deadlock the whole cluster under a single
        // shared mutex, exactly as it would here).
        let _ = sender.try_send(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_agreement::{
        Period, RawVote, Step, UnauthenticatedVote, BOTTOM, CERT, DOWN, LATE, NEXT, REDO,
    };
    use algo_types::{Address, Round};

    fn vote_with_step(step: Step) -> UnauthenticatedVote {
        UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([7u8; 32]),
                round: Round(1),
                period: Period(0),
                step,
                proposal: BOTTOM,
            },
            ..UnauthenticatedVote::default()
        }
    }

    fn recv_vote_count(rx: &Receiver<Message>) -> usize {
        std::iter::from_fn(|| rx.try_recv().ok()).count()
    }

    /// Mirrors go's fast-recovery test setup: `dropAllSoftVotes` drops SOFT
    /// step votes but lets everything else (here: CERT) through.
    #[test]
    fn drop_all_soft_votes_drops_only_soft_step() {
        let net = TestingNetwork::new(2, 16);
        net.drop_all_soft_votes();
        let sender = net.endpoint(0);
        let receiver = net.endpoint(1);

        sender
            .broadcast(
                &Tag(AGREEMENT_VOTE_TAG),
                &codec::encode_vote(&vote_with_step(SOFT)),
            )
            .unwrap();
        sender
            .broadcast(
                &Tag(AGREEMENT_VOTE_TAG),
                &codec::encode_vote(&vote_with_step(CERT)),
            )
            .unwrap();

        let rx = receiver.messages(&Tag(AGREEMENT_VOTE_TAG));
        assert_eq!(
            recv_vote_count(&rx),
            1,
            "only the CERT vote should be delivered"
        );
    }

    /// Mirrors go's `dropAllSlowNextVotes`: drops any step >= NEXT except
    /// LATE/REDO/DOWN, which must still get through.
    #[test]
    fn drop_all_slow_next_votes_excludes_late_redo_down() {
        let net = TestingNetwork::new(2, 16);
        net.drop_all_slow_next_votes();
        let sender = net.endpoint(0);
        let receiver = net.endpoint(1);

        for step in [SOFT, CERT, NEXT, LATE, REDO, DOWN] {
            sender
                .broadcast(
                    &Tag(AGREEMENT_VOTE_TAG),
                    &codec::encode_vote(&vote_with_step(step)),
                )
                .unwrap();
        }

        let rx = receiver.messages(&Tag(AGREEMENT_VOTE_TAG));
        // SOFT, CERT (both < NEXT) and LATE/REDO/DOWN (explicitly excluded
        // from the "slow next votes" drop) survive; only plain NEXT is
        // dropped. 6 sent, 1 dropped -> 5 delivered.
        assert_eq!(
            recv_vote_count(&rx),
            5,
            "only the plain NEXT vote should be dropped"
        );
    }

    /// Mirrors go's `dropAllVotes`: every vote is dropped, regardless of step.
    #[test]
    fn drop_all_votes_drops_everything() {
        let net = TestingNetwork::new(2, 16);
        net.drop_all_votes();
        let sender = net.endpoint(0);
        let receiver = net.endpoint(1);

        for step in [SOFT, CERT, NEXT, LATE] {
            sender
                .broadcast(
                    &Tag(AGREEMENT_VOTE_TAG),
                    &codec::encode_vote(&vote_with_step(step)),
                )
                .unwrap();
        }

        let rx = receiver.messages(&Tag(AGREEMENT_VOTE_TAG));
        assert_eq!(recv_vote_count(&rx), 0, "every vote must be dropped");
    }

    /// Mirrors go's `repairAll`: previously-installed drop rules stop
    /// applying after `repair_all()`.
    #[test]
    fn repair_all_restores_normal_delivery() {
        let net = TestingNetwork::new(2, 16);
        net.drop_all_votes();
        net.repair_all();
        let sender = net.endpoint(0);
        let receiver = net.endpoint(1);

        sender
            .broadcast(
                &Tag(AGREEMENT_VOTE_TAG),
                &codec::encode_vote(&vote_with_step(SOFT)),
            )
            .unwrap();

        let rx = receiver.messages(&Tag(AGREEMENT_VOTE_TAG));
        assert_eq!(
            recv_vote_count(&rx),
            1,
            "delivery must resume after repair_all"
        );
    }

    /// A node's own broadcast never loops back to itself, and `exclude`
    /// on relay correctly skips the original sender — mirrors go's
    /// `multicast` skipping `peerid == source` and `peerid == exclude`.
    #[test]
    fn broadcast_excludes_sender_and_relay_excludes_original_source() {
        let net = TestingNetwork::new(3, 16);
        let node0 = net.endpoint(0);
        let node1 = net.endpoint(1);
        let node2 = net.endpoint(2);

        node0
            .broadcast(
                &Tag(AGREEMENT_VOTE_TAG),
                &codec::encode_vote(&vote_with_step(SOFT)),
            )
            .unwrap();

        // node0 must not receive its own broadcast.
        assert_eq!(
            recv_vote_count(&node0.messages(&Tag(AGREEMENT_VOTE_TAG))),
            0
        );
        // node1 and node2 both receive it.
        let msg1 = node1
            .messages(&Tag(AGREEMENT_VOTE_TAG))
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("node1 receives the broadcast");
        assert_eq!(
            recv_vote_count(&node2.messages(&Tag(AGREEMENT_VOTE_TAG))),
            1
        );

        // node1 relays what it received; node2 (the original recipient, not
        // the original *source*) gets a second copy, but node0 (the
        // original source) is excluded.
        node1
            .relay(&msg1.handle, &Tag(AGREEMENT_VOTE_TAG), &msg1.data)
            .unwrap();
        assert_eq!(
            recv_vote_count(&node0.messages(&Tag(AGREEMENT_VOTE_TAG))),
            0,
            "relay must not bounce the vote back to its original source"
        );
        assert_eq!(
            recv_vote_count(&node2.messages(&Tag(AGREEMENT_VOTE_TAG))),
            1,
            "relay delivers to every OTHER connected peer, including one that already had a copy"
        );
    }
}
