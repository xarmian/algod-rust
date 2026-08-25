//! P2P transport mode selection and the libp2p-backed transport actor that
//! node startup (`participate`) brings up alongside or instead of the
//! existing WS-gossip stack (`algo-network`).
//!
//! Mirrors go-algorand's `config.Local` P2P surface
//! (`../go-algorand/config/localTemplate.go`: `EnableP2P`,
//! `EnableP2PHybridMode`, `P2PPersistPeerID`) and `node/node.go`'s
//! mode-selection wiring (`recreateNetwork` in `newNode`, quoted in full in
//! issue #542): when `EnableP2PHybridMode` is set, both a WS network and a
//! P2P network are constructed; when only `EnableP2P` is set, only the P2P
//! network is constructed and no WS listener is ever opened; otherwise
//! (go's default) only the WS network is constructed.
//!
//! `algo-p2p`'s own `lib.rs` doc comment explicitly calls out that wiring
//! its pubsub/DHT stack into `algo-network`'s interfaces and node startup
//! is this issue's job ("a later, separate sub-issue of the P2P epic
//! (#544, see #542)").

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use algo_p2p::{IdentityConfig, MessageValidationResult, P2pBehaviourEvent, P2pHost};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{gossipsub, kad, Multiaddr, PeerId};
use tokio::sync::mpsc;

use crate::config::P2pConfig;

/// Which transport(s) a node brings up. Mirrors go-algorand's precedence:
/// "When both EnableP2P and EnableP2PHybridMode are set,
/// EnableP2PHybridMode takes precedence" (`config/localTemplate.go`,
/// `EnableP2P`'s doc comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Only the WS-gossip stack (`algo-network`). Default — preserves
    /// pre-#542 behavior exactly.
    WsOnly,
    /// Only the libp2p P2P stack (`algo-p2p`). No WS-gossip listener is
    /// ever opened. Go: `EnableP2P && !EnableP2PHybridMode`.
    P2pOnly,
    /// Both stacks active simultaneously. Go: `EnableP2PHybridMode`.
    Hybrid,
}

impl NetworkMode {
    /// Resolve the effective mode from the two enable flags, matching
    /// go's precedence exactly (hybrid wins over plain P2P).
    pub fn resolve(enable_p2p: bool, enable_p2p_hybrid_mode: bool) -> Self {
        if enable_p2p_hybrid_mode {
            NetworkMode::Hybrid
        } else if enable_p2p {
            NetworkMode::P2pOnly
        } else {
            NetworkMode::WsOnly
        }
    }

    /// Whether the libp2p P2P stack should be brought up under this mode.
    pub fn p2p_active(self) -> bool {
        matches!(self, NetworkMode::P2pOnly | NetworkMode::Hybrid)
    }

    /// Whether the WS-gossip stack's inbound listener should be opened
    /// under this mode. `WsOnly` and `Hybrid` both run WS-gossip;
    /// `P2pOnly` must never open a WS listener — that is the "no leak"
    /// guarantee #542 requires.
    pub fn ws_listener_active(self) -> bool {
        matches!(self, NetworkMode::WsOnly | NetworkMode::Hybrid)
    }
}

/// Raw `participate` CLI flag values for P2P transport selection, plus the
/// parsed `[p2p]` TOML section. Mirrors [`RestOptions`]'s
/// CLI-overrides-file merge pattern
/// (`crate::commands::participate::RestOptions`).
#[derive(Debug, Clone, Default)]
pub struct P2pOptions {
    pub enable_p2p: bool,
    pub enable_p2p_hybrid_mode: bool,
    pub p2p_persist_peer_id: bool,
    pub p2p_bootstrap_peers: Vec<String>,
    pub p2p_listen_address: Option<String>,
    pub file_p2p: Option<P2pConfig>,
}

/// Fully-resolved P2P configuration, ready to hand to [`P2pTransport::start`].
#[derive(Debug, Clone)]
pub struct ResolvedP2p {
    pub mode: NetworkMode,
    pub persist_peer_id: bool,
    pub bootstrap_peers: Vec<String>,
    pub listen_address: Option<String>,
}

impl P2pOptions {
    /// Merge CLI flags with the `[p2p]` TOML section: a CLI bool flag
    /// enables a setting even if the file doesn't (`||`), and a CLI value
    /// for `Option`/`Vec` fields wins over the file's when both are set —
    /// same precedence [`RestOptions::resolve`] uses for REST settings.
    pub fn resolve(&self) -> ResolvedP2p {
        let file = self.file_p2p.as_ref();
        let enable_p2p = self.enable_p2p || file.is_some_and(|f| f.enable_p2p);
        let enable_p2p_hybrid_mode =
            self.enable_p2p_hybrid_mode || file.is_some_and(|f| f.enable_p2p_hybrid_mode);
        let persist_peer_id =
            self.p2p_persist_peer_id || file.is_some_and(|f| f.p2p_persist_peer_id);
        let bootstrap_peers = if !self.p2p_bootstrap_peers.is_empty() {
            self.p2p_bootstrap_peers.clone()
        } else {
            file.map(|f| f.p2p_bootstrap_peers.clone())
                .unwrap_or_default()
        };
        let listen_address = self
            .p2p_listen_address
            .clone()
            .or_else(|| file.and_then(|f| f.p2p_listen_address.clone()));

        ResolvedP2p {
            mode: NetworkMode::resolve(enable_p2p, enable_p2p_hybrid_mode),
            persist_peer_id,
            bootstrap_peers,
            listen_address,
        }
    }
}

/// Configuration for starting a [`P2pTransport`].
#[derive(Debug, Clone, Default)]
pub struct P2pTransportConfig {
    /// Algorand network ID, used to derive the DHT protocol name (see
    /// `algo_p2p::dht_protocol_name`).
    pub network_id: String,
    /// Listen multiaddr, if this node should accept inbound P2P dials.
    pub listen_multiaddr: Option<Multiaddr>,
    /// Bootstrap peer multiaddrs to dial at startup (may or may not carry
    /// a trailing `/p2p/<peer-id>` component).
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Whether to persist the generated peer identity to disk.
    pub persist_peer_id: bool,
    /// Data directory the persisted identity key is written under.
    pub data_dir: Option<PathBuf>,
}

/// Split a multiaddr into its dialable transport address and an optional
/// trailing `/p2p/<peer-id>` component.
fn split_peer_id(addr: &Multiaddr) -> (Multiaddr, Option<PeerId>) {
    let mut base = Multiaddr::empty();
    let mut peer = None;
    for proto in addr.iter() {
        if let Protocol::P2p(p) = proto {
            peer = Some(p);
        } else {
            base.push(proto);
        }
    }
    (base, peer)
}

/// A running libp2p P2P transport: owns a background task driving an
/// `algo_p2p::P2pHost`'s swarm event loop, subscribed to the
/// go-compatible transaction gossipsub topic
/// (`algo_p2p::pubsub::TX_TOPIC`) so transactions can propagate over P2P
/// exactly as they do over WS-gossip's `Transaction` tag.
///
/// Routing block proposals and votes (`PROPOSAL_PAYLOAD_TOPIC`,
/// `AGREEMENT_VOTE_TOPIC`, `VOTE_BUNDLE_TOPIC`) through the agreement
/// service is tracked as a follow-up (see the PR this module landed in) —
/// this transport brings the P2P stack itself up correctly gated by mode,
/// and wires the transaction path end-to-end, but does not yet bridge
/// `AgreementNetworkBridge`.
pub struct P2pTransport {
    peer_id: PeerId,
    listen_addrs: Arc<Mutex<Vec<Multiaddr>>>,
    connected_peers: Arc<Mutex<Vec<PeerId>>>,
    cmd_tx: mpsc::UnboundedSender<P2pCommand>,
    _task: tokio::task::JoinHandle<()>,
}

enum P2pCommand {
    PublishTx(Vec<u8>),
}

impl P2pTransport {
    /// Build and start a P2P transport: creates the host, optionally
    /// listens, dials bootstrap peers, subscribes the TX topic, and spawns
    /// the background swarm-driving task. Returns the transport handle and
    /// a channel yielding raw transaction payload bytes received over
    /// gossipsub (the caller feeds these into the same pool-ingestion path
    /// used for WS-received transactions).
    pub async fn start(
        cfg: P2pTransportConfig,
    ) -> Result<(Self, mpsc::UnboundedReceiver<Vec<u8>>), anyhow::Error> {
        let identity_cfg = IdentityConfig {
            private_key_path: None,
            data_dir: cfg.data_dir.clone(),
            persist_peer_id: cfg.persist_peer_id,
        };
        let mut host = P2pHost::new(&identity_cfg, &cfg.network_id)
            .map_err(|e| anyhow::anyhow!("failed to build P2P host: {e}"))?;
        let peer_id = host.peer_id();

        if let Some(addr) = &cfg.listen_multiaddr {
            host.listen(addr.clone())
                .map_err(|e| anyhow::anyhow!("failed to listen on {addr}: {e}"))?;
            // A node meant to be discoverable (has a listen address) should
            // run the DHT in Server mode — mirrors go's
            // `cfg.IsListenServer()` (see `P2pHost::set_dht_mode`'s doc
            // comment).
            host.set_dht_mode(Some(kad::Mode::Server));
        }

        for addr in &cfg.bootstrap_peers {
            let (base, peer) = split_peer_id(addr);
            if let Some(peer) = peer {
                host.add_bootstrap_peer(peer, base);
            }
            if let Err(e) = host.dial(addr.clone()) {
                tracing::warn!(addr = %addr, error = %e, "failed to dial P2P bootstrap peer");
            }
        }
        if !cfg.bootstrap_peers.is_empty() {
            host.bootstrap_dht();
        }

        host.gossipsub_subscribe(algo_p2p::TX_TOPIC)
            .map_err(|e| anyhow::anyhow!("failed to subscribe to TX topic: {e}"))?;

        let listen_addrs: Arc<Mutex<Vec<Multiaddr>>> = Arc::new(Mutex::new(Vec::new()));
        let connected_peers: Arc<Mutex<Vec<PeerId>>> = Arc::new(Mutex::new(Vec::new()));
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<P2pCommand>();
        let (tx_out, tx_in) = mpsc::unbounded_channel::<Vec<u8>>();

        let la = Arc::clone(&listen_addrs);
        let cp = Arc::clone(&connected_peers);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = host.next_event() => {
                        match event {
                            SwarmEvent::NewListenAddr { address, .. } => {
                                la.lock().expect("listen_addrs mutex poisoned").push(address);
                            }
                            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                cp.lock().expect("connected_peers mutex poisoned").push(peer_id);
                            }
                            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                                cp.lock()
                                    .expect("connected_peers mutex poisoned")
                                    .retain(|p| *p != peer_id);
                            }
                            SwarmEvent::Behaviour(P2pBehaviourEvent::Gossipsub(
                                gossipsub::Event::Message {
                                    propagation_source,
                                    message_id,
                                    message,
                                },
                            )) => {
                                // Accept-by-default: this transport does not
                                // yet apply the same signature/format checks
                                // `TxTagHandler` runs for WS-received
                                // transactions before reporting a result;
                                // the pool ingestion path downstream still
                                // rejects anything malformed. See this
                                // module's doc comment for the follow-up
                                // this is tracked under.
                                host.report_message_validation_result(
                                    &message_id,
                                    &propagation_source,
                                    MessageValidationResult::Accept,
                                );
                                let _ = tx_out.send(message.data);
                            }
                            _ => {}
                        }
                    }
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            Some(P2pCommand::PublishTx(data)) => {
                                if let Err(e) = host.gossipsub_publish(algo_p2p::TX_TOPIC, data) {
                                    tracing::debug!(error = %e, "P2P tx publish failed");
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        Ok((
            Self {
                peer_id,
                listen_addrs,
                connected_peers,
                cmd_tx,
                _task: task,
            },
            tx_in,
        ))
    }

    /// This transport's libp2p `PeerId`.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Addresses this host has confirmed it is listening on (populated as
    /// `NewListenAddr` events arrive from the background task — may be
    /// empty immediately after `start()` returns if no listen address was
    /// configured, or briefly while the first listen address is still
    /// being confirmed).
    pub fn listen_addrs(&self) -> Vec<Multiaddr> {
        self.listen_addrs
            .lock()
            .expect("listen_addrs mutex poisoned")
            .clone()
    }

    /// Whether this host has bound at least one listen address (i.e. it is
    /// dialable, not outbound-only).
    pub fn is_listening(&self) -> bool {
        !self.listen_addrs().is_empty()
    }

    /// Currently connected peer count.
    ///
    /// Not yet called from `participate`'s startup path — reserved for the
    /// follow-up that bridges outbound local-transaction propagation and
    /// diagnostics through this transport (see this module's doc comment
    /// on `P2pTransport`). Exercised directly by this module's own tests.
    #[allow(dead_code)]
    pub fn connected_peer_count(&self) -> usize {
        self.connected_peers
            .lock()
            .expect("connected_peers mutex poisoned")
            .len()
    }

    /// Publish a transaction payload on the go-compatible TX gossipsub
    /// topic. Fire-and-forget: the background task logs (rather than
    /// propagates) a publish failure, matching `GossipNode::broadcast`'s
    /// best-effort semantics for other transports.
    ///
    /// Not yet called from `participate`'s startup path — see
    /// [`P2pTransport::connected_peer_count`]'s doc comment for why.
    /// Exercised directly by this module's own tests
    /// (`two_transports_connect_and_propagate_a_transaction_over_p2p`).
    #[allow(dead_code)]
    pub fn publish_tx(&self, data: Vec<u8>) -> Result<(), anyhow::Error> {
        self.cmd_tx
            .send(P2pCommand::PublishTx(data))
            .map_err(|_| anyhow::anyhow!("P2P transport task has stopped"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // NetworkMode resolution — parity with go's EnableP2P/EnableP2PHybridMode
    // precedence (`config/localTemplate.go`).
    // -----------------------------------------------------------------------

    #[test]
    fn default_mode_is_ws_only() {
        assert_eq!(NetworkMode::resolve(false, false), NetworkMode::WsOnly);
    }

    #[test]
    fn enable_p2p_alone_is_p2p_only() {
        assert_eq!(NetworkMode::resolve(true, false), NetworkMode::P2pOnly);
    }

    #[test]
    fn hybrid_flag_alone_is_hybrid() {
        assert_eq!(NetworkMode::resolve(false, true), NetworkMode::Hybrid);
    }

    #[test]
    fn hybrid_takes_precedence_when_both_set() {
        // Go: "When both EnableP2P and EnableP2PHybridMode are set,
        // EnableP2PHybridMode takes precedence."
        assert_eq!(NetworkMode::resolve(true, true), NetworkMode::Hybrid);
    }

    #[test]
    fn ws_only_runs_ws_listener_and_no_p2p() {
        let mode = NetworkMode::WsOnly;
        assert!(mode.ws_listener_active());
        assert!(!mode.p2p_active());
    }

    #[test]
    fn p2p_only_runs_no_ws_listener() {
        let mode = NetworkMode::P2pOnly;
        assert!(!mode.ws_listener_active());
        assert!(mode.p2p_active());
    }

    #[test]
    fn hybrid_runs_both() {
        let mode = NetworkMode::Hybrid;
        assert!(mode.ws_listener_active());
        assert!(mode.p2p_active());
    }

    // -----------------------------------------------------------------------
    // P2pOptions::resolve — CLI-overrides-file merge, mirroring
    // RestOptions::resolve's pattern.
    // -----------------------------------------------------------------------

    #[test]
    fn cli_flag_enables_even_when_file_does_not() {
        let opts = P2pOptions {
            enable_p2p: true,
            ..Default::default()
        };
        assert_eq!(opts.resolve().mode, NetworkMode::P2pOnly);
    }

    #[test]
    fn file_flag_enables_even_when_cli_does_not() {
        let opts = P2pOptions {
            file_p2p: Some(P2pConfig {
                enable_p2p: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(opts.resolve().mode, NetworkMode::P2pOnly);
    }

    #[test]
    fn cli_bootstrap_peers_override_file() {
        let opts = P2pOptions {
            p2p_bootstrap_peers: vec!["/ip4/9.9.9.9/tcp/1".to_string()],
            file_p2p: Some(P2pConfig {
                p2p_bootstrap_peers: vec!["/ip4/1.1.1.1/tcp/1".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            opts.resolve().bootstrap_peers,
            vec!["/ip4/9.9.9.9/tcp/1".to_string()]
        );
    }

    #[test]
    fn file_bootstrap_peers_used_when_cli_empty() {
        let opts = P2pOptions {
            file_p2p: Some(P2pConfig {
                p2p_bootstrap_peers: vec!["/ip4/1.1.1.1/tcp/1".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            opts.resolve().bootstrap_peers,
            vec!["/ip4/1.1.1.1/tcp/1".to_string()]
        );
    }

    // -----------------------------------------------------------------------
    // split_peer_id
    // -----------------------------------------------------------------------

    #[test]
    fn split_peer_id_extracts_trailing_p2p_component() {
        let peer_id = PeerId::random();
        let addr: Multiaddr = format!("/ip4/1.2.3.4/tcp/4190/p2p/{peer_id}")
            .parse()
            .unwrap();
        let (base, extracted) = split_peer_id(&addr);
        assert_eq!(extracted, Some(peer_id));
        assert_eq!(base, "/ip4/1.2.3.4/tcp/4190".parse::<Multiaddr>().unwrap());
    }

    #[test]
    fn split_peer_id_handles_addr_without_peer_id() {
        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/4190".parse().unwrap();
        let (base, extracted) = split_peer_id(&addr);
        assert_eq!(extracted, None);
        assert_eq!(base, addr);
    }

    // -----------------------------------------------------------------------
    // P2pTransport — mode-selection TDD anchors for #542. Two independent
    // transports (each with its own generated identity) dial and observe
    // each other, proving the P2P stack this issue wires in via config
    // actually comes up and interoperates.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn p2p_only_style_transport_listens_and_has_no_ws_dependency() {
        // A transport started with a listen address and no bootstrap peers
        // is exactly what P2pOnly / Hybrid mode brings up — this test
        // proves the transport itself opens a real, connectable P2P
        // listener with zero involvement of `algo-network`'s WS stack.
        let (transport, _rx) = P2pTransport::start(P2pTransportConfig {
            network_id: "test-542".to_string(),
            listen_multiaddr: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
            bootstrap_peers: vec![],
            persist_peer_id: false,
            data_dir: None,
        })
        .await
        .expect("start p2p transport");

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while transport.listen_addrs().is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            transport.is_listening(),
            "P2pOnly/Hybrid-style transport should confirm a listen address"
        );
    }

    #[tokio::test]
    async fn no_listen_address_means_transport_never_binds() {
        // Mirrors what P2pOnly mode looks like for a node with no
        // `--p2p-listen-address` configured: outbound-only, no bound
        // listener at all.
        let (transport, _rx) = P2pTransport::start(P2pTransportConfig {
            network_id: "test-542".to_string(),
            listen_multiaddr: None,
            bootstrap_peers: vec![],
            persist_peer_id: false,
            data_dir: None,
        })
        .await
        .expect("start p2p transport");

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!transport.is_listening());
    }

    #[tokio::test]
    async fn two_transports_connect_and_propagate_a_transaction_over_p2p() {
        let (listener, mut rx_a) = P2pTransport::start(P2pTransportConfig {
            network_id: "test-542".to_string(),
            listen_multiaddr: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
            bootstrap_peers: vec![],
            persist_peer_id: false,
            data_dir: None,
        })
        .await
        .expect("start listener");

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while listener.listen_addrs().is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let listen_addr = listener
            .listen_addrs()
            .first()
            .cloned()
            .expect("listener bound an address");
        let dial_addr = listen_addr.with(Protocol::P2p(listener.peer_id()));

        let (dialer, _rx_b) = P2pTransport::start(P2pTransportConfig {
            network_id: "test-542".to_string(),
            listen_multiaddr: None,
            bootstrap_peers: vec![dial_addr],
            persist_peer_id: false,
            data_dir: None,
        })
        .await
        .expect("start dialer");

        // Wait for the two-way mesh to form before publishing, mirroring
        // `algo_p2p::host`'s own gossipsub test's reasoning: a
        // freshly-subscribed peer is not immediately meshed.
        let mesh_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while tokio::time::Instant::now() < mesh_deadline {
            if listener.connected_peer_count() > 0 && dialer.connected_peer_count() > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let payload = b"a signed txn's msgpack bytes".to_vec();
        dialer.publish_tx(payload.clone()).expect("publish");

        let received = tokio::time::timeout(std::time::Duration::from_secs(10), rx_a.recv())
            .await
            .expect("timed out waiting for the transaction to arrive over P2P")
            .expect("transport task closed its channel");
        assert_eq!(
            received, payload,
            "expected the listener to receive the dialer's exact tx payload via P2P gossipsub"
        );
    }
}
