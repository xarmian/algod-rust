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

//! Peer registration and release (go v5.1.1 `network: fix peer registration and
//! release around Stop`, #6750, and `claim outgoing throttle slots when the peer
//! is registered`, #6751; issue #2554). Rust analogues of
//! `TestWebsocketNetworkThrottleSlotNotLeakedOnIdentityDedup` and
//! `TestWebsocketPeerSweep`: every way a peer leaves the registry (Stop,
//! DisconnectPeers, a disconnect, the remote closing) gives back its throttle
//! slot and its identity claim exactly once, a peer rejected by identity dedup
//! never holds a slot, and a peer added after Stop is not registered.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use algo_network::connect::{try_connect, ConnectConfig};
use algo_network::identity::IdentityDedupHook;
use algo_network::ws_network::{PeerDirection, WebsocketNetwork, WebsocketNetworkConfig};
use algo_network::WsConnectError;
use algo_network::{GossipNode, Phonebook};
use ed25519_dalek::{SigningKey, VerifyingKey};

const GENESIS: &str = "test-v1.0";

#[derive(Default)]
struct RecordingHook {
    claims: Mutex<Vec<String>>,
    releases: Mutex<Vec<String>>,
    refuse: bool,
}

impl IdentityDedupHook for RecordingHook {
    fn claim(&self, conn: &str, _identity: VerifyingKey) -> bool {
        self.claims.lock().unwrap().push(conn.to_string());
        !self.refuse
    }
    fn release(&self, conn: &str, _identity: &VerifyingKey) {
        self.releases.lock().unwrap().push(conn.to_string());
    }
}

fn node(relay: bool, fanout: usize) -> Arc<WebsocketNetwork> {
    let config = WebsocketNetworkConfig {
        genesis_id: GENESIS.to_string(),
        network_id: "test".to_string(),
        net_address: relay.then(|| "127.0.0.1:0".to_string()),
        relay_messages: relay,
        gossip_fanout: fanout,
        mesh_interval: Duration::from_secs(3600),
        ..Default::default()
    };
    Arc::new(WebsocketNetwork::new(
        config,
        Arc::new(Phonebook::new(10, Duration::from_secs(60))),
    ))
}

async fn relay_with_identity() -> (Arc<WebsocketNetwork>, String) {
    let relay = node(true, 4);
    relay.set_identity(
        SigningKey::from_bytes(&[21u8; 32]),
        Arc::new(RecordingHook::default()),
    );
    relay.start_arc().await.expect("relay start");
    let (addr, _) = relay.address();
    (relay, addr)
}

fn dial_config(hook: Arc<RecordingHook>) -> ConnectConfig {
    ConnectConfig {
        genesis_id: GENESIS.to_string(),
        our_identity_key: Some(SigningKey::from_bytes(&[22u8; 32])),
        identity_dedup_hook: Some(hook),
        ..ConnectConfig::default()
    }
}

/// B dials the relay with a verified identity (the claim is made in
/// `try_connect`) and registers the connection.
async fn dialed(addr: &str) -> (Arc<WebsocketNetwork>, Arc<RecordingHook>) {
    let hook = Arc::new(RecordingHook::default());
    let dialer = node(false, 4);
    // the network's own hook is the one `remove`/sweeps release through
    dialer.set_identity(SigningKey::from_bytes(&[22u8; 32]), hook.clone());
    let handle = try_connect(addr, &dial_config(hook.clone()))
        .await
        .expect("dial");
    assert!(handle.identity_verified());
    dialer.add_peer(handle, PeerDirection::Outbound, None).await;
    assert_eq!(dialer.peer_count().await, 1);
    assert_eq!(
        dialer.available_throttle_slots(),
        3,
        "outgoing peers hold a slot"
    );
    assert_eq!(*hook.claims.lock().unwrap(), vec![addr.to_string()]);
    (dialer, hook)
}

async fn assert_given_back(dialer: &WebsocketNetwork, hook: &RecordingHook, addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline
        && (dialer.peer_count().await != 0
            || dialer.available_throttle_slots() != 4
            || hook.releases.lock().unwrap().is_empty())
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // give a (wrong) second release a chance to show up
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(dialer.peer_count().await, 0);
    assert_eq!(
        dialer.available_throttle_slots(),
        4,
        "throttle slot not given back"
    );
    assert_eq!(
        *hook.releases.lock().unwrap(),
        vec![addr.to_string()],
        "identity not released exactly once"
    );
}

#[tokio::test]
async fn disconnect_peers_gives_back_slot_and_identity() {
    let (relay, addr) = relay_with_identity().await;
    let (dialer, hook) = dialed(&addr).await;
    dialer.disconnect_peers();
    assert_given_back(&dialer, &hook, &addr).await;
    relay.stop().await;
}

#[tokio::test]
async fn stop_gives_back_slot_and_identity() {
    let (relay, addr) = relay_with_identity().await;
    let (dialer, hook) = dialed(&addr).await;
    dialer.stop().await;
    assert_given_back(&dialer, &hook, &addr).await;
    relay.stop().await;
}

#[tokio::test]
async fn remove_peer_gives_back_slot_and_identity() {
    let (relay, addr) = relay_with_identity().await;
    let (dialer, hook) = dialed(&addr).await;
    assert!(dialer.remove_peer(&addr).await);
    assert_given_back(&dialer, &hook, &addr).await;
    relay.stop().await;
}

/// The remote closing the connection removes the peer from the registry from
/// the peer's own receive task, which must give back what the peer holds too.
#[tokio::test]
async fn remote_close_gives_back_slot_and_identity() {
    let (relay, addr) = relay_with_identity().await;
    let (dialer, hook) = dialed(&addr).await;
    relay.stop().await;
    assert_given_back(&dialer, &hook, &addr).await;
    dialer.stop().await;
}

/// go `TestWebsocketNetworkThrottleSlotNotLeakedOnIdentityDedup`: an outgoing
/// peer rejected by identity dedup is not registered and holds no slot; the
/// next connection registers, takes the slot and gives it back.
#[tokio::test]
async fn identity_dedup_rejection_does_not_leak_a_throttle_slot() {
    let (relay, addr) = relay_with_identity().await;
    let dialer = node(false, 4);
    let slots = dialer.available_throttle_slots();
    assert_eq!(slots, 4);

    let refusing = Arc::new(RecordingHook {
        refuse: true,
        ..Default::default()
    });
    match try_connect(&addr, &dial_config(refusing.clone())).await {
        Err(WsConnectError::DuplicateIdentity) => {}
        other => panic!("want DuplicateIdentity, got {:?}", other.map(|_| ())),
    }
    assert_eq!(dialer.peer_count().await, 0);
    assert_eq!(dialer.available_throttle_slots(), slots);

    let (dialer2, hook) = dialed(&addr).await;
    dialer2.remove_peer(&addr).await;
    assert_given_back(&dialer2, &hook, &addr).await;
    relay.stop().await;
}

/// go `TestWebsocketPeerSweep` ("After innerStop, addPeer must reject a new
/// peer without claiming anything for it"): a peer handed to a stopped
/// network is closed, not registered, and takes no slot.
#[tokio::test]
async fn add_peer_after_stop_is_rejected_without_claiming_a_slot() {
    let (relay, addr) = relay_with_identity().await;
    let dialer = node(false, 4);
    let hook = Arc::new(RecordingHook::default());
    dialer.set_identity(SigningKey::from_bytes(&[22u8; 32]), hook.clone());
    dialer.stop().await;
    let handle = try_connect(&addr, &dial_config(hook.clone()))
        .await
        .expect("dial");
    dialer.add_peer(handle, PeerDirection::Outbound, None).await;
    assert_eq!(
        dialer.peer_count().await,
        0,
        "a stopped network registered a peer"
    );
    assert_eq!(dialer.available_throttle_slots(), 4);
    assert_eq!(
        hook.releases.lock().unwrap().len(),
        1,
        "the identity claimed by the dial must be given back"
    );
    relay.stop().await;
}

/// A hook whose `claim` parks until the test lets it go: the verification
/// message of a peer is then handled *after* the peer left the registry.
struct ParkedClaimHook {
    claimed_by: Mutex<Option<String>>,
    go: (Mutex<bool>, std::sync::Condvar),
    releases: Mutex<Vec<String>>,
}

impl IdentityDedupHook for ParkedClaimHook {
    fn claim(&self, conn: &str, _identity: VerifyingKey) -> bool {
        *self.claimed_by.lock().unwrap() = Some(conn.to_string());
        let (lock, cv) = &self.go;
        let mut open = lock.lock().unwrap();
        while !*open {
            open = cv.wait(open).unwrap();
        }
        true
    }
    fn release(&self, conn: &str, _identity: &VerifyingKey) {
        self.releases.lock().unwrap().push(conn.to_string());
    }
}

/// Opens the gate when the test ends, so a failing assertion cannot leave the
/// runtime waiting on the parked `claim`.
struct OpenOnDrop(Arc<ParkedClaimHook>);

impl Drop for OpenOnDrop {
    fn drop(&mut self) {
        let (lock, cv) = &self.0.go;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
}

/// go `TestIdentityTrackerHandlerDepartedPeer`: a verification message handled
/// after its peer left the registry must not keep the identity, because nothing
/// would give it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verification_handled_after_the_peer_departed_does_not_keep_the_identity() {
    let hook = Arc::new(ParkedClaimHook {
        claimed_by: Mutex::new(None),
        go: (Mutex::new(false), std::sync::Condvar::new()),
        releases: Mutex::new(Vec::new()),
    });
    let _gate = OpenOnDrop(hook.clone());
    let relay = node(true, 4);
    relay.set_identity(SigningKey::from_bytes(&[21u8; 32]), hook.clone());
    relay.start_arc().await.expect("relay start");
    let (addr, _) = relay.address();

    let dial_hook = Arc::new(RecordingHook::default());
    let handle = try_connect(&addr, &dial_config(dial_hook))
        .await
        .expect("dial");
    // the relay's read loop is now parked inside `claim` for the dialer's
    // verification message
    let deadline = Instant::now() + Duration::from_secs(5);
    let conn = loop {
        if let Some(c) = hook.claimed_by.lock().unwrap().clone() {
            break c;
        }
        assert!(Instant::now() < deadline, "no verification message arrived");
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert!(
        relay.remove_peer(&conn).await,
        "the inbound peer is registered"
    );

    // let the claim through: the peer has departed, so the claim is given back
    {
        let (lock, cv) = &hook.go;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while hook.releases.lock().unwrap().is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(*hook.releases.lock().unwrap(), vec![conn]);
    handle.close();
    relay.stop().await;
}

/// go `TestWebsocketNetworkStopEndsMessagesOfInterestThread`: the
/// messages-of-interest task is one of the tasks `stop` awaits, so `stop`
/// returning means it ended (go v5.1.1 fixed it outliving `Stop`).
#[tokio::test]
async fn stop_ends_the_messages_of_interest_task() {
    let net = node(true, 4);
    net.start_arc().await.expect("start");
    tokio::time::timeout(Duration::from_secs(5), net.stop())
        .await
        .expect("stop did not finish: a background task outlived it");
}
