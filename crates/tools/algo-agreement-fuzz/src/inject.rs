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

//! Raw gossip injection: put exactly one agreement message on the wire to a
//! live go-algorand node and observe what it does.
//!
//! This deliberately bypasses `algo-agreement`'s service/pseudonode stack. That
//! stack is built to *never* construct an invalid message, so a fault-injection
//! tool cannot go through it. What it does reuse is the real wire layer —
//! [`algo_network::connect::try_connect`] performs the genuine Algorand
//! handshake (`/v1/{genesisID}/gossip`, `X-Algorand-*` headers, identity
//! challenge, `NI` then `MI`) and [`algo_network::framing`] applies the genuine
//! two-byte tag framing — so the only thing non-standard about the connection is
//! the payload we choose to send.
//!
//! ## What counts as "Go rejected it"
//!
//! go-algorand's agreement player answers a vote that fails verification with a
//! `disconnectAction` (`agreement/player.go`, `voteMalformed`), which
//! `WebsocketNetwork.Disconnect` turns into `disconnectBadData` — the peer
//! connection is closed and the node logs `Peer <addr> disconnected: BadData`
//! (`network/wsPeer.go:141`, `network/wsNetwork.go` `removePeer`). So the
//! observable, in-band signal is: **our socket is closed shortly after we send
//! the message, and we sent nothing else.**
//!
//! A closed socket alone is not attribution — an undecodable payload would also
//! produce it. Attribution comes from the Go node's own log line
//! (`malformed vote for (r, p, s): rejected message since it was invalid: …`,
//! `agreement/trace.go`), which the shell driver greps for the fault's
//! [`crate::VoteFault::expected_go_error`].

use std::time::{Duration, Instant};

use algo_network::connect::{try_connect, ConnectConfig};
use algo_network::message::OutgoingMessage;
use algo_network::peer_features::PeerFeatureFlags;
use algo_network::tag::Tag;
use anyhow::{Context, Result};

/// How the injector should identify itself and where it should connect.
#[derive(Debug, Clone)]
pub struct InjectorConfig {
    /// `host:port` of the Go node's gossip listener (e.g. `127.0.0.1:4161`).
    pub peer_addr: String,
    /// Genesis ID, e.g. `phase6net-v1`.
    pub genesis_id: String,
    /// How long to wait after sending before declaring "not disconnected".
    pub observe: Duration,
    /// Handshake timeout.
    pub handshake_timeout: Duration,
}

impl InjectorConfig {
    /// A config with the usual timeouts.
    pub fn new(peer_addr: impl Into<String>, genesis_id: impl Into<String>) -> Self {
        Self {
            peer_addr: peer_addr.into(),
            genesis_id: genesis_id.into(),
            observe: Duration::from_secs(20),
            handshake_timeout: Duration::from_secs(30),
        }
    }
}

/// What the Go node did after receiving the single injected message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionOutcome {
    /// Go closed the connection within [`InjectorConfig::observe`].
    pub disconnected: bool,
    /// Milliseconds between the send and the disconnect (or the full observe
    /// window if there was no disconnect).
    pub elapsed_ms: u128,
    /// Tags Go sent us after the injection, in order. Useful to prove the node
    /// stayed alive and kept gossiping when it *didn't* disconnect us.
    pub frames_received: Vec<String>,
}

/// Build a throwaway connection identity. Nothing about it is registered in the
/// ledger — it is a plain gossip client, exactly like an observer node.
fn throwaway_config(cfg: &InjectorConfig) -> ConnectConfig {
    let mut seed = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut seed);
    ConnectConfig {
        genesis_id: cfg.genesis_id.clone(),
        node_random: rand::random(),
        our_identity_key: Some(ed25519_dalek::SigningKey::from_bytes(&seed)),
        our_address: None,
        instance_name: "algo-agreement-fuzz".to_string(),
        location: String::new(),
        telemetry_id: String::new(),
        our_features: PeerFeatureFlags::COMPRESSED_PROPOSAL,
        handshake_timeout: cfg.handshake_timeout,
        peer_config: None,
    }
}

/// Connect, send exactly one tagged message, and observe.
///
/// Sends nothing else on the connection — no votes, no proposals, no relayed
/// traffic — so any disconnect is a response to this single message.
pub async fn inject_one(
    cfg: &InjectorConfig,
    tag: Tag,
    payload: Vec<u8>,
) -> Result<InjectionOutcome> {
    let mut handle = try_connect(&cfg.peer_addr, &throwaway_config(cfg))
        .await
        .with_context(|| format!("gossip handshake with {} failed", cfg.peer_addr))?;

    tracing::info!(
        peer = %cfg.peer_addr,
        version = handle.version(),
        "handshake complete; injecting one {} message ({} bytes)",
        tag.as_str(),
        payload.len()
    );

    let sent_at = Instant::now();
    handle
        .send_priority(OutgoingMessage::new(tag, payload))
        .map_err(|e| anyhow::anyhow!("failed to enqueue injected message: {e:?}"))?;

    let mut frames = Vec::new();
    let deadline = sent_at + cfg.observe;
    let disconnected = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break false;
        }
        match tokio::time::timeout(remaining, handle.recv()).await {
            // Channel closed ⇒ the read loop ended ⇒ Go closed the socket.
            Ok(None) => break true,
            Ok(Some(msg)) => frames.push(msg.tag.as_str().to_string()),
            Err(_) => break false,
        }
    };

    let elapsed_ms = sent_at.elapsed().as_millis();
    handle.close();

    Ok(InjectionOutcome {
        disconnected,
        elapsed_ms,
        frames_received: frames,
    })
}

/// Connect as a plain observer and return the first proposal payload (`PP`)
/// the node relays to us.
///
/// The injector has no ledger of its own, so this is the only way to obtain a
/// payload that is valid in every respect — correct previous-block pointer,
/// correct seed and seed proof, correct transaction commitment — before a
/// single field is corrupted. Nothing is sent on this connection beyond the
/// handshake's `NI`/`MI`.
pub async fn capture_proposal(cfg: &InjectorConfig) -> Result<Vec<u8>> {
    let mut handle = try_connect(&cfg.peer_addr, &throwaway_config(cfg))
        .await
        .with_context(|| format!("gossip handshake with {} failed", cfg.peer_addr))?;

    let deadline = Instant::now() + cfg.observe;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            handle.close();
            anyhow::bail!(
                "no proposal payload seen on {} within {:?}",
                cfg.peer_addr,
                cfg.observe
            );
        }
        match tokio::time::timeout(remaining, handle.recv()).await {
            Ok(Some(msg)) if msg.tag == Tag::ProposalPayload => {
                handle.close();
                return Ok(msg.data);
            }
            Ok(Some(_)) => continue,
            Ok(None) => {
                anyhow::bail!("peer {} closed before relaying a proposal", cfg.peer_addr)
            }
            Err(_) => {
                handle.close();
                anyhow::bail!(
                    "no proposal payload seen on {} within {:?}",
                    cfg.peer_addr,
                    cfg.observe
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_are_sane() {
        let c = InjectorConfig::new("127.0.0.1:4161", "phase6net-v1");
        assert_eq!(c.peer_addr, "127.0.0.1:4161");
        assert_eq!(c.genesis_id, "phase6net-v1");
        assert!(c.observe >= Duration::from_secs(5));
        assert!(c.handshake_timeout >= c.observe / 2);
    }

    #[test]
    fn throwaway_identities_are_unique_per_connection() {
        let c = InjectorConfig::new("127.0.0.1:4161", "phase6net-v1");
        let a = throwaway_config(&c);
        let b = throwaway_config(&c);
        assert_ne!(a.node_random, b.node_random);
        assert_ne!(
            a.our_identity_key.as_ref().unwrap().to_bytes(),
            b.our_identity_key.as_ref().unwrap().to_bytes()
        );
        assert_eq!(a.genesis_id, "phase6net-v1");
    }

    #[test]
    fn outcome_is_comparable() {
        let o = InjectionOutcome {
            disconnected: true,
            elapsed_ms: 12,
            frames_received: vec!["AV".into()],
        };
        assert_eq!(o.clone(), o);
    }
}
