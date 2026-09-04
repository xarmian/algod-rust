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
// Scope: this port carries the subset of go's testingNetwork exercised by
// the theme-3 scenarios ported so far. `dropAllSoftVotes`/
// `dropAllSlowNextVotes`/`dropAllVotes`/`repairAll` (selective vote drop)
// landed with the `DownEarly`/`DownMiss` ports (PR #910/#913).
// `pocketAllCertVotes`/`pocketAllSoftVotes`/`pocketAllCompound` (payload
// pocketing — intercept-and-collect instead of deliver, with a later replay
// via direct `multicast`) and `partition` (two-group delivery filter) are
// ported here for `Late`/`Redo`/`LateCertBug`/`LargePeriods`.
//
// `crown` (deliver only to a given set of recipients, regardless of sender —
// go's `crownedNodes` delivery-side filter) is ported as a primitive
// (`TestingNetwork::crown`, covered by
// `crown_only_delivers_to_crowned_recipients` below) for issue #825's
// remaining `TestAgreementRecoverBothVAndBotQuorums` scope, but that
// scenario's full port is NOT landed yet — see
// `service_multi_node_test.rs`'s module doc comment / issue #825's progress
// notes for why (go's version additionally fires `TimeoutDeadline` on a
// SUBSET of clocks across two different, precisely-timed "next vote range"
// deltas — `(next).nextVoteRanges`/`(next+1).nextVoteRanges` — a mechanic
// this harness has no equivalent driver hook for yet; the primitive is
// landed on its own because it's real, independently useful infrastructure,
// same as `pocket_all_compound` was left in place after `TestAgreementSlow
// Payloads*` proved intractable).
//
// `makeRelays` (star/relay topology — a message is delivered only if its
// source or its recipient is a designated "relay" node, so two "leaf" nodes
// can never reach each other directly) is ported here
// (`TestingNetwork::make_relays`, covered by
// `make_relays_drops_only_leaf_to_leaf_traffic` below), same treatment as
// `crown` above: landed as a standalone, independently useful primitive
// even though the scenario it was built for —
// `TestAgreementCertificateDoesNotStallSingleRelay` — is NOT landed. A full
// port was attempted (partition the relay away from 4 leaves, pocket+replay
// cert votes so the leaves terminate their round without it, heal under the
// star topology, replay the same certificate to the relay, require the
// whole cluster to converge afterward) and found two real harness bugs
// along the way (fixed regardless: `TestLedger::ensure_block`/
// `ensure_validated_block` publishing to `SharedCommits` AFTER advancing
// `next_rnd` instead of before, a genuine race; and this scenario's own
// cert-vote-pocketing needing same-`(round, period)` grouping, not just a
// raw count, once a partition is layered on top of pocketing). Neither fix
// closed a genuine residual flake (~10-20% across several 15-20-run
// batches: the relay's `next_round()` never advances at all across 40
// retry attempts, despite repeatedly re-injecting the exact same evidence
// — ruling out simple message loss/timing races as the cause) — below this
// harness's ~95%+ landing bar, so the scenario itself was not kept. See
// `docs/phase17/parity_agreement.md`'s row for this test for the full
// writeup; a future attempt should start from this primitive and the two
// fixes above, with deeper `Player`/`Service`-thread instrumentation of a
// captured failure to find the actual root cause.
//
// `intercept` (arbitrary per-message rewriting/redirection) is still not
// ported — no scenario landed so far needed anything beyond the structured
// filters above (`partition`/`crown`/`make_relays`/the pocket family); a
// follow-up can add it the same way once one does.
//
// A real limitation found while porting, NOT fixed here:
// `pocketAllCompound` (used by go's `TestAgreementSlowPayloadsPreDeadline`/
// `PostDeadline`) composes badly with this harness's real-thread timing.
// Unlike a vote (generated continuously for as long as a round stays
// unresolved), a node only broadcasts a round/period's proposal payload
// ONCE, automatically, the instant it enters that round/period — including
// immediately as part of the very same settle cascade that
// `AgreementCluster::wait_for_quiet` blocks on after a round commits or a
// period bumps. There is no test-driver-observable point between "the
// round/period transition happened" and "its proposal already went out" at
// which `pocket_all_compound()` can be armed — so unlike
// `pocket_all_cert_votes` (proven reliable by `TestAgreementLateCertBug`'s
// port), `pocket_all_compound` could not be made to reliably intercept a
// specific, predictable proposal broadcast in this harness without also
// either (a) a synchronization hook to pause proposal generation until the
// driver arms pocketing (go's synchronous single-goroutine model gets this
// for free; this harness's real `AsyncPseudonode` threads do not), or (b) a
// suspendable block validator like go's `TestAgreementRegression_
// WrongPeriodPayloadVerificationCancellation_8ba23942` uses for a related
// purpose. Both are out of scope for this pass; `pocket_all_compound` is
// left in place (it is real, working interception logic, and the fix above
// is additive) but no test in this file depends on it.

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crossbeam_channel::{bounded, Receiver, Sender};

use algo_agreement::codec;
use algo_agreement::{
    AgreementError, AgreementNetwork, Message, MessageHandle, Tag, AGREEMENT_VOTE_TAG, CERT, DOWN,
    LATE, NEXT, PROPOSAL_PAYLOAD_TAG, REDO, SOFT, VOTE_BUNDLE_TAG,
};

/// One pocketed (intercepted-instead-of-delivered) message, captured with
/// enough to replay it later via [`TestingNetwork::replay`]. Mirrors go's
/// `multicastParams`.
#[derive(Clone)]
pub struct PocketedMessage {
    tag: &'static str,
    data: Vec<u8>,
    source: usize,
    exclude: usize,
}

impl PocketedMessage {
    /// The raw, still-encoded message payload (a vote or proposal-payload
    /// blob depending on which pocket this came from) — decode with
    /// `algo_agreement::codec::decode_vote` or the payload-equivalent as
    /// needed at the call site.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

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

    /// `Some` while pocketing is active; mirrors go's
    /// `certVotePocket`/`softVotePocket`/`compoundPocket` channel fields
    /// (a plain `Vec` here rather than a channel — the harness never needs
    /// to stream-consume while messages are still arriving).
    cert_vote_pocket: Option<Vec<PocketedMessage>>,
    soft_vote_pocket: Option<Vec<PocketedMessage>>,
    compound_pocket: Option<Vec<PocketedMessage>>,

    /// `Some(flags)` while a two-group partition is active: `flags[i]`
    /// is the group membership of node `i`; a message is only delivered
    /// between nodes in the same group. Mirrors go's `partitionedNodes`.
    partitioned: Option<Vec<bool>>,

    /// `Some(flags)` while `crown` is active: `flags[i]` is true if node
    /// `i` is "crowned" — a message is only delivered to a crowned
    /// recipient, regardless of who sent it (delivery-side filter only,
    /// unlike `partitioned` which is symmetric). Mirrors go's
    /// `crownedNodes`.
    crowned: Option<Vec<bool>>,

    /// `Some(flags)` while `make_relays` is active: `flags[i]` is true if
    /// node `i` is a "relay". A message is delivered between two nodes only
    /// if at least one of them (source or recipient) is a relay — so two
    /// non-relay ("leaf") nodes can never reach each other directly, only
    /// through a relay. Mirrors go's `relayNodes` ("star topology with the
    /// given nodes at the center").
    relay_nodes: Option<Vec<bool>>,

    /// Bounded FIFO of the most recently, normally-delivered (i.e. not
    /// pocketed) `PROPOSAL_PAYLOAD_TAG` broadcasts — a harness-only
    /// payload-catch-up mechanism with no go equivalent, because go's real
    /// `testingNetwork` never needs one: its single-goroutine synchronous
    /// model and generously-buffered channels guarantee every connected
    /// node's payload channel receives every broadcast payload exactly
    /// once, so a node can never fall behind on a payload the way this
    /// harness's real, independently-scheduled `Service` threads sometimes
    /// do (see issue #920's investigation in `service_multi_node_test.rs`).
    /// [`TestingNetwork::redeliver_recent_payloads`] re-multicasts every
    /// cached entry, letting a node that missed (or later locally pruned)
    /// an earlier proposal payload catch up the next time the network is
    /// healed — see [`TestingNetwork::repair_all`], which calls it
    /// automatically.
    payload_history: Vec<PocketedMessage>,
}

/// Cap on [`NetworkState::payload_history`] — bounds memory for
/// long-running scenarios (e.g. `large_periods_five_node`'s 60 periods)
/// while comfortably covering the handful of periods any fast-recovery
/// scenario actually spans.
const PAYLOAD_HISTORY_CAP: usize = 64;

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
                cert_vote_pocket: None,
                soft_vote_pocket: None,
                compound_pocket: None,
                partitioned: None,
                crowned: None,
                relay_nodes: None,
                payload_history: Vec::new(),
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

    /// Mirrors go's `testingNetwork.repairAll` (the subset of drop/pocket/
    /// partition state this port tracks — see the module doc for what's not
    /// yet ported). Deliberately does NOT also call
    /// [`Self::redeliver_recent_payloads`]: an earlier version of this
    /// method did so unconditionally, on the theory that replaying a
    /// harmless duplicate can never hurt — but `late_cert_bug_five_node`
    /// (whose whole point is asserting that replaying a SPECIFIC, already-
    /// pocketed set of votes with no further clock fire is what commits the
    /// round) calls `repair_all()` too, and the extra burst of re-multicast
    /// payload traffic that produced was enough to occasionally perturb its
    /// precisely-timed assertion. Callers that actually need payload
    /// catch-up (`fast_recovery_late_five_node`/`redo_five_node`, via
    /// `force_fast_recovery_into_value`) call
    /// [`Self::redeliver_recent_payloads`] explicitly at the specific points
    /// that need it, instead.
    pub fn repair_all(&self) {
        let mut state = self.state.lock().expect("TestingNetwork poisoned");
        state.drop_soft_votes = false;
        state.drop_slow_next_votes = false;
        state.drop_votes = false;
        state.cert_vote_pocket = None;
        state.soft_vote_pocket = None;
        state.compound_pocket = None;
        state.partitioned = None;
        state.crowned = None;
        state.relay_nodes = None;
    }

    /// Re-multicast every proposal-payload broadcast currently held in
    /// [`NetworkState::payload_history`] through the normal routing path
    /// (respecting whatever drop/pocket/partition state is active now, same
    /// as [`Self::replay`]). This is the harness's payload catch-up
    /// mechanism for issue #920's residual gap: unlike go's real
    /// `testingNetwork` (whose synchronous single-goroutine model guarantees
    /// every connected node's payload channel receives every broadcast
    /// payload exactly once — see `payload_history`'s doc comment), this
    /// harness's real, independently-scheduled `Service` threads can
    /// occasionally leave a node without a payload it needs staged (missed
    /// delivery, or later local pruning across a period transition) with no
    /// other way to recover it — `partition_policy`, the only mechanic that
    /// re-transmits a pinned payload, is gated on `Player::partitioned()`
    /// (`period >= 3`), which never holds at the low periods fast-recovery
    /// scenarios exercise. Called automatically by [`Self::repair_all`];
    /// exposed separately in case a future scenario needs to catch nodes up
    /// without also clearing drop/pocket/partition state.
    pub fn redeliver_recent_payloads(&self) {
        let history = {
            let state = self.state.lock().expect("TestingNetwork poisoned");
            state.payload_history.clone()
        };
        self.replay_all(&history);
    }

    /// Mirrors go's `testingNetwork.pocketAllCertVotes`: from now on, every
    /// CERT-step vote is intercepted (never delivered) and collected instead
    /// — read them back via [`Self::stop_pocketing_cert_votes`].
    pub fn pocket_all_cert_votes(&self) {
        self.state
            .lock()
            .expect("TestingNetwork poisoned")
            .cert_vote_pocket = Some(Vec::new());
    }

    /// Number of cert votes pocketed so far (without stopping) — lets a
    /// caller poll for "enough" before calling
    /// [`Self::stop_pocketing_cert_votes`]. No go equivalent (go's
    /// synchronous single-goroutine model guarantees every node has voted
    /// after one fire; this harness's real threads sometimes need more).
    pub fn cert_vote_pocket_len(&self) -> usize {
        self.state
            .lock()
            .expect("TestingNetwork poisoned")
            .cert_vote_pocket
            .as_ref()
            .map(Vec::len)
            .unwrap_or(0)
    }

    /// Mirrors go's `closeFn` returned by `pocketAllCertVotes`, plus
    /// draining the channel (`for msg := range pocket`) in one step: stops
    /// pocketing and returns everything collected since
    /// [`Self::pocket_all_cert_votes`].
    pub fn stop_pocketing_cert_votes(&self) -> Vec<PocketedMessage> {
        self.state
            .lock()
            .expect("TestingNetwork poisoned")
            .cert_vote_pocket
            .take()
            .unwrap_or_default()
    }

    /// Mirrors go's `testingNetwork.pocketAllSoftVotes`.
    pub fn pocket_all_soft_votes(&self) {
        self.state
            .lock()
            .expect("TestingNetwork poisoned")
            .soft_vote_pocket = Some(Vec::new());
    }

    /// Mirrors the `closeFn` returned by `pocketAllSoftVotes`.
    pub fn stop_pocketing_soft_votes(&self) -> Vec<PocketedMessage> {
        self.state
            .lock()
            .expect("TestingNetwork poisoned")
            .soft_vote_pocket
            .take()
            .unwrap_or_default()
    }

    /// Mirrors go's `testingNetwork.pocketAllCompound`: intercepts every
    /// `ProposalPayloadTag` message (proposal payloads) instead of
    /// delivering it.
    pub fn pocket_all_compound(&self) {
        self.state
            .lock()
            .expect("TestingNetwork poisoned")
            .compound_pocket = Some(Vec::new());
    }

    /// Mirrors the `closeFn` returned by `pocketAllCompound`.
    pub fn stop_pocketing_compound(&self) -> Vec<PocketedMessage> {
        self.state
            .lock()
            .expect("TestingNetwork poisoned")
            .compound_pocket
            .take()
            .unwrap_or_default()
    }

    /// Replay a previously-pocketed message through the normal routing path
    /// (subject to whatever drop/pocket/partition state is active NOW, same
    /// as go's direct `baseNetwork.multicast(p.tag, p.data, p.source,
    /// p.exclude)` calls in `TestAgreementLateCertBug`/
    /// `TestAgreementSlowPayloads*`).
    pub fn replay(&self, msg: &PocketedMessage) {
        multicast(self, msg.tag, &msg.data, msg.source, msg.exclude);
    }

    /// Replay every message in `msgs`, in order. Convenience for the common
    /// "release everything I pocketed" call sites.
    pub fn replay_all(&self, msgs: &[PocketedMessage]) {
        for msg in msgs {
            self.replay(msg);
        }
    }

    /// Mirrors go's `testingNetwork.partition(part...)`: from now on, a
    /// message is only delivered between two nodes that are BOTH in `group`
    /// or BOTH outside it — heals whatever previous partition existed
    /// (matching go's "different mechanism than n.connected" comment: this
    /// is independent of [`Self::endpoint`]'s per-pair `disconnect`).
    pub fn partition(&self, group: &[usize]) {
        let mut state = self.state.lock().expect("TestingNetwork poisoned");
        let n = state.channels.len();
        let mut flags = vec![false; n];
        for &i in group {
            flags[i] = true;
        }
        state.partitioned = Some(flags);
    }

    /// Mirrors go's `testingNetwork.crown(prophets...)`: from now on, only
    /// deliver messages to the given set of nodes — every other node
    /// receives nothing, regardless of who sent the message. Independent of
    /// [`Self::partition`] (both, if set, must pass for delivery — mirrors
    /// go's `multicast` checking `partitionedNodes` and `crownedNodes` as
    /// two separate, both-must-pass filters).
    pub fn crown(&self, prophets: &[usize]) {
        let mut state = self.state.lock().expect("TestingNetwork poisoned");
        let n = state.channels.len();
        let mut flags = vec![false; n];
        for &i in prophets {
            flags[i] = true;
        }
        state.crowned = Some(flags);
    }

    /// Mirrors go's `testingNetwork.makeRelays(relays...)`: star topology
    /// with the given nodes at the center — from now on, a message is
    /// delivered between two nodes only if at least one of them is a
    /// relay, so two non-relay ("leaf") nodes can never reach each other
    /// directly, only via a relay (which must itself actively `relay()` a
    /// message onward for it to fan out to other leaves — this primitive
    /// only changes which direct sends succeed, it doesn't add any
    /// forwarding behavior of its own). To revert, call
    /// [`Self::repair_all`] (go: same — "to revert, call repairAll").
    pub fn make_relays(&self, relays: &[usize]) {
        let mut state = self.state.lock().expect("TestingNetwork poisoned");
        let n = state.channels.len();
        let mut flags = vec![false; n];
        for &i in relays {
            flags[i] = true;
        }
        state.relay_nodes = Some(flags);
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
    network: &TestingNetwork,
    tag: &'static str,
    data: &[u8],
    source: usize,
    exclude: usize,
) {
    let mut state = network.state.lock().expect("TestingNetwork poisoned");

    let pocketing_active = state.cert_vote_pocket.is_some()
        || state.soft_vote_pocket.is_some()
        || state.compound_pocket.is_some();

    if tag == PROPOSAL_PAYLOAD_TAG && state.compound_pocket.is_some() {
        state
            .compound_pocket
            .as_mut()
            .expect("just checked is_some")
            .push(PocketedMessage {
                tag,
                data: data.to_vec(),
                source,
                exclude,
            });
        return;
    }

    if (state.drop_soft_votes || state.drop_slow_next_votes || state.drop_votes || pocketing_active)
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

        if step == CERT {
            if let Some(pocket) = state.cert_vote_pocket.as_mut() {
                pocket.push(PocketedMessage {
                    tag,
                    data: data.to_vec(),
                    source,
                    exclude,
                });
                return;
            }
        }
        if step == SOFT {
            if let Some(pocket) = state.soft_vote_pocket.as_mut() {
                pocket.push(PocketedMessage {
                    tag,
                    data: data.to_vec(),
                    source,
                    exclude,
                });
                return;
            }
        }

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

    // Cache every normally-delivered (not pocketed above) proposal-payload
    // broadcast for `redeliver_recent_payloads` — see `payload_history`'s
    // doc comment. Recorded here rather than at `broadcast`/`relay` call
    // sites so a replay-of-a-replay (`redeliver_recent_payloads` calling
    // `replay_all`, which calls back into this function) re-caches too,
    // keeping recently-redelivered entries from aging out of the FIFO ahead
    // of ones nobody has re-sent in a while.
    if tag == PROPOSAL_PAYLOAD_TAG {
        state.payload_history.push(PocketedMessage {
            tag,
            data: data.to_vec(),
            source,
            exclude,
        });
        let len = state.payload_history.len();
        if len > PAYLOAD_HISTORY_CAP {
            state.payload_history.drain(0..len - PAYLOAD_HISTORY_CAP);
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
        if let Some(part) = &state.partitioned {
            if part[source] != part[peer] {
                continue;
            }
        }
        if let Some(crowned) = &state.crowned {
            if !crowned[peer] {
                continue;
            }
        }
        if let Some(relays) = &state.relay_nodes {
            if !relays[source] && !relays[peer] {
                continue;
            }
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

    /// Mirrors go's `crown`: only the crowned node(s) receive a broadcast,
    /// regardless of who sent it; `repair_all` clears it again.
    #[test]
    fn crown_only_delivers_to_crowned_recipients() {
        let net = TestingNetwork::new(3, 16);
        net.crown(&[0]);
        let node0 = net.endpoint(0);
        let node1 = net.endpoint(1);
        let node2 = net.endpoint(2);

        // node1 broadcasts: only node0 (crowned) should get it, not node2.
        node1
            .broadcast(
                &Tag(AGREEMENT_VOTE_TAG),
                &codec::encode_vote(&vote_with_step(SOFT)),
            )
            .unwrap();
        assert_eq!(
            recv_vote_count(&node0.messages(&Tag(AGREEMENT_VOTE_TAG))),
            1,
            "crowned node0 must receive the broadcast"
        );
        assert_eq!(
            recv_vote_count(&node2.messages(&Tag(AGREEMENT_VOTE_TAG))),
            0,
            "non-crowned node2 must not receive the broadcast"
        );

        // node2 broadcasts: still only node0 gets it (crown is a
        // recipient-side filter, independent of the sender).
        node2
            .broadcast(
                &Tag(AGREEMENT_VOTE_TAG),
                &codec::encode_vote(&vote_with_step(SOFT)),
            )
            .unwrap();
        assert_eq!(
            recv_vote_count(&node0.messages(&Tag(AGREEMENT_VOTE_TAG))),
            1,
            "crowned node0 must receive every broadcast, regardless of sender"
        );

        // repair_all clears the crown; delivery returns to normal.
        net.repair_all();
        node1
            .broadcast(
                &Tag(AGREEMENT_VOTE_TAG),
                &codec::encode_vote(&vote_with_step(SOFT)),
            )
            .unwrap();
        assert_eq!(
            recv_vote_count(&node2.messages(&Tag(AGREEMENT_VOTE_TAG))),
            1,
            "delivery to every connected peer must resume after repair_all"
        );
    }

    /// Mirrors go's `makeRelays`: a message is delivered if either its
    /// source or its recipient is a relay, so leaf-to-leaf traffic is
    /// dropped but relay-to-leaf and leaf-to-relay traffic both go
    /// through; `repair_all` clears it again.
    #[test]
    fn make_relays_drops_only_leaf_to_leaf_traffic() {
        let net = TestingNetwork::new(3, 16);
        // node0 is the relay; node1/node2 are leaves.
        net.make_relays(&[0]);
        let relay = net.endpoint(0);
        let leaf1 = net.endpoint(1);
        let leaf2 = net.endpoint(2);

        // A single leaf broadcast reaches the relay (recipient is a relay)
        // but not the other leaf (neither end is a relay) — one broadcast
        // proves both halves of the filter at once.
        leaf1
            .broadcast(
                &Tag(AGREEMENT_VOTE_TAG),
                &codec::encode_vote(&vote_with_step(SOFT)),
            )
            .unwrap();
        assert_eq!(
            recv_vote_count(&relay.messages(&Tag(AGREEMENT_VOTE_TAG))),
            1,
            "leaf-to-relay traffic must be delivered"
        );
        assert_eq!(
            recv_vote_count(&leaf2.messages(&Tag(AGREEMENT_VOTE_TAG))),
            0,
            "leaf-to-leaf traffic must be dropped under a relay topology"
        );

        // Relay -> leaf: delivered (source is a relay), and fans out to
        // every other connected leaf, not just one.
        relay
            .broadcast(
                &Tag(AGREEMENT_VOTE_TAG),
                &codec::encode_vote(&vote_with_step(SOFT)),
            )
            .unwrap();
        assert_eq!(
            recv_vote_count(&leaf1.messages(&Tag(AGREEMENT_VOTE_TAG))),
            1,
            "relay-to-leaf traffic must be delivered"
        );
        assert_eq!(
            recv_vote_count(&leaf2.messages(&Tag(AGREEMENT_VOTE_TAG))),
            1,
            "relay-to-leaf traffic must fan out to every leaf"
        );

        // repair_all clears the relay topology; leaf-to-leaf resumes.
        net.repair_all();
        leaf1
            .broadcast(
                &Tag(AGREEMENT_VOTE_TAG),
                &codec::encode_vote(&vote_with_step(SOFT)),
            )
            .unwrap();
        assert_eq!(
            recv_vote_count(&leaf2.messages(&Tag(AGREEMENT_VOTE_TAG))),
            1,
            "leaf-to-leaf delivery must resume after repair_all"
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
