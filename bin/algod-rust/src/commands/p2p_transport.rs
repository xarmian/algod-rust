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
//!
//! # Agreement traffic: gossipsub *and* the `/algorand-ws/2.2.0` stream (#560)
//!
//! Issue #560's investigation found that go-algorand v5.0.0-stable's own
//! `gossipSubTags` map wires gossipsub up for the `TX` tag **only** — a
//! real go-algorand P2P node never subscribes to (or publishes on) a
//! gossipsub topic for proposals/votes/vote-bundles. Instead it opens one
//! raw bidirectional libp2p stream per connected peer on the
//! `/algorand-ws/2.2.0` protocol (`algo_p2p::wsproto`'s doc comment has the
//! full go-source citation) and tunnels the same tag-prefixed message
//! framing algo-network's own WS-gossip transport uses.
//!
//! This module now drives that stream in addition to gossipsub for AV/PP/VB
//! (`Tag::AgreementVote`/`Tag::ProposalPayload`/`Tag::VoteBundle`):
//! [`P2pTransport::start`] opens an outbound stream to every peer it dials
//! and accepts inbound ones, and [`P2pTransport::publish`] fans a
//! non-`TX` frame out over both gossipsub *and* every open stream. Against a
//! real go-algorand peer, the gossipsub publish is a harmless no-op (go
//! never subscribed) and the stream frame is what actually gets received;
//! against another algod-rust `P2pTransport`, both paths deliver the same
//! message (redundant but harmless — existing rust-to-rust tests below only
//! ever consume one delivery per `recv`/`recv_timeout` call).

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use algo_network::gossip_node::UnicastPeer;
use algo_network::handler::{Multiplexer, TaggedMessageHandler, TaggedMessageValidatorHandler};
use algo_network::peer_features::{
    advertise_vote_compression, decode_peer_features, encode_peer_features, stateful_table_size,
    PeerFeatureFlags,
};
use algo_network::topics::{Topic, Topics};
use algo_network::vpack::{StatefulDecoder, StatefulEncoder, VOTE_COMPRESSION_ABORT_BYTE};
use algo_network::ws_peer::{compress_outgoing_vote, decompress_incoming_vote_core};
use algo_network::{
    encode_uvarint, hash_topics, ForwardingPolicy, GossipNode, IncomingMessage, Peer, PeerError,
    PeerOption, RequestTracker, Router, Tag, DEFAULT_REQUEST_TIMEOUT, RESPONSE_HASH_FIELD,
};
use algo_p2p::{
    build_headers, handshake_inbound, handshake_outbound, libp2p_stream, read_frame,
    resolve_dht_mode, should_initiate_stream, write_frame, DispatchError, IdentityConfig,
    IdentityTracker, LogLevel, MessageValidationResult, P2pBehaviourEvent, P2pHost, P2pHostConfig,
    PeerMetaHeaders, StreamManager, ALGORAND_HTTP_PROTOCOL, ALGORAND_WS_PROTOCOL_V22,
};
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use libp2p::futures::{AsyncReadExt, StreamExt as _};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{ConnectionId, Stream as P2pRawStream, SwarmEvent};
use libp2p::{gossipsub, Multiaddr, PeerId};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use tokio::sync::mpsc;
use tokio_util::compat::FuturesAsyncReadCompatExt;

use crate::config::P2pConfig;

/// go's own `SupportedProtocolVersions`/`ProtocolVersion` for the
/// `/algorand-ws/*` handshake (`algo_network::handshake::PROTOCOL_VERSION`
/// — kept as a literal here rather than a cross-crate import since
/// `algo-p2p` deliberately has no `algo-network` dependency; see
/// `algo_p2p::wsproto`'s doc comment).
const ALGORAND_WS_SUPPORTED_VERSIONS: &[&str] = &["2.2"];

/// Default stateful vpack vote-compression table size this P2P transport
/// advertises during the `/algorand-ws/2.2.0` handshake, alongside stateless
/// compression.
///
/// Matches go-algorand's `config.Local` defaults (`EnableVoteCompression:
/// true`, `StatefulVoteCompressionTableSize: 2048`) — the *same*
/// hardcoded-not-yet-configurable value `algo_network::ws_network`'s
/// `DEFAULT_VOTE_COMPRESSION_TABLE_SIZE` already uses for the classic
/// WS-gossip transport (issue #817), for the identical reason: not yet
/// exposed as a configurable knob on this crate's side.
///
/// Go: `network/p2pNetwork.go` threads `cfg.EnableVoteCompression` into the
/// P2P transport's per-peer `wsPeer` construction exactly as it does for
/// the classic transport (`network/p2pNetwork.go:1014`'s
/// `enableVoteCompression`/`voteCompressionTableSize` fields on the `wsPeer`
/// literal at `baseWsStreamHandler`) — go's P2P transport reuses the
/// *identical* `wsPeer`/`wsPeerMsgCodec` compression machinery as the
/// classic transport, not a separate implementation (verified by reading
/// `network/p2pNetwork.go`'s `baseWsStreamHandler`, which wraps every
/// libp2p stream in a real `wsPeer{conn: &wsPeerConnP2P{stream: stream},
/// ...}`), which is why this module reuses `algo_network::ws_peer`'s
/// `compress_outgoing_vote`/`decompress_incoming_vote_core` verbatim below
/// rather than reimplementing the vpack state machine.
const DEFAULT_VOTE_COMPRESSION_TABLE_SIZE: u32 = 2048;

/// Everything [`P2pTransport`] tracks for one currently-established
/// `/algorand-ws/2.2.0` stream peer: the outgoing frame sender
/// [`P2pTransport::stream_broadcast`] fans agreement traffic out to, and
/// (issue #591) the [`RequestTracker`] that correlates this peer's
/// `TopicMsgResp` replies to our own outstanding `UniEnsBlockReq`
/// catch-up-fetch requests — mirroring `ws_peer.rs`'s per-peer
/// `request_tracker`, since a P2P `/algorand-ws` stream is a
/// request/response-capable channel exactly like a WS peer connection.
struct StreamPeerHandle {
    /// Sends an (unframed, uncompressed) `(tag, payload)` pair to this
    /// peer's writer task. Framing (`algo_network::framing::encode_frame`)
    /// and, for `AgreementVote`, vpack compression now happen inside the
    /// writer task itself (issue #925) rather than at the call site, since
    /// vote compression state (the stateful encoder's LRU table) is
    /// per-peer — a single pre-framed/pre-compressed buffer can no longer
    /// be computed once and cloned out to every peer, mirroring
    /// `ws_peer.rs`'s `write_loop`, which frames+compresses per outgoing
    /// message, per peer.
    tx: mpsc::UnboundedSender<(Tag, Vec<u8>)>,
    /// Correlates outbound unicast requests (see [`P2pTransport::unicast_peers`])
    /// to this peer's `TopicMsgResp` replies.
    request_tracker: Arc<RequestTracker>,
    /// Monotonically increasing id assigned when this handle is installed
    /// into the shared [`StreamManager`] (issue #952's live wiring) — lets a
    /// stream's own cleanup task (see `spawn_ws_peer`) tell whether it is
    /// still the currently-installed handle for its peer before removing
    /// the entry, so a *stale* task (one whose stream was already replaced
    /// by a newer successful dispatch — go's "Replacing old stream"
    /// scenario in `streamHandler`) can't race and evict the newer stream
    /// out from under it. `StreamManager` itself does not compare handle
    /// identity (its `S` is caller-defined), so this is the mechanism this
    /// caller supplies for that guarantee.
    generation: u64,
    /// This stream's negotiated vote-compression feature set (issue #925):
    /// the intersection of both peers' advertised `PeerFeatureFlags`,
    /// computed once from the `/algorand-ws/2.2.0` handshake's peer-meta
    /// headers — mirrors `algo_network::connect`'s
    /// `remote_features.intersection(config.our_features)`. Read-only after
    /// construction; exposed for tests via
    /// [`P2pTransport::stream_peer_vote_compression`]. `cfg(test)`-only:
    /// production code already gets the equivalent visibility from
    /// `spawn_ws_peer`'s own `tracing::debug!` at negotiation time, so this
    /// field would otherwise sit unused in a release build.
    #[cfg(test)]
    negotiated_features: PeerFeatureFlags,
    /// Whether *this* side opened the `/algorand-ws/2.2.0` stream (as
    /// opposed to accepting an inbound one) — i.e. whether
    /// [`should_initiate_stream`] decided this side should dial, mirroring
    /// go's `streamManager.Connected`'s `localPeer > remotePeer` ordering
    /// rule (issue #952). `cfg(test)`-only: proves the live wiring actually
    /// governs *which side* opens the stream (peer-ID order, not raw TCP
    /// dial direction), not just that a stream came up at all — see
    /// `p2p_stream_open_side_follows_peer_id_order_not_dial_direction`.
    #[cfg(test)]
    initiated_locally: bool,
}

/// Registry of currently-established `/algorand-ws/2.2.0` streams, keyed by
/// peer.
///
/// Backed by [`algo_p2p::StreamManager`] (issue #952's live wiring) rather
/// than a bare `HashMap`, so the already-tested dispatch-error/unprotect/
/// replace-on-success semantics that module encodes — see its own doc
/// comment — actually govern these real, live streams: [`spawn_ws_peer`]
/// installs a newly (successfully) handshaken stream via
/// [`StreamManager::set_stream`] (never before a successful handshake,
/// mirroring go's `streamHandler`'s "dispatch first, install only on
/// success"), and the swarm event loop below gates a fresh outbound dial on
/// [`StreamManager::should_skip_dial`]/[`StreamManager::begin_peer_attempt`]/
/// [`StreamManager::end_peer_attempt`] exactly as go's `handleConnected`
/// does.
type StreamPeers = Arc<Mutex<StreamManager<StreamPeerHandle>>>;

/// Run the post-handshake read/write loop for one peer's `/algorand-ws`
/// stream: registers a [`StreamPeerHandle`] in `stream_peers` (its sender is
/// what [`P2pTransport::stream_broadcast`] fans agreement traffic out to,
/// and what [`P2pTransport::unicast_peers`] hands to a
/// [`P2pUnicastPeer`] for request/response traffic), dispatches every
/// non-`TopicMsgResp` frame this peer sends into `mux` (the same
/// [`Multiplexer`] gossipsub messages are dispatched to), and — issue #591 —
/// actually writes back a `Respond`-action handler result as a `TopicMsgResp`
/// frame, and routes an incoming `TopicMsgResp` to this peer's own
/// `RequestTracker` instead of `mux` (mirroring `ws_peer.rs`'s read loop's
/// "(c) Request/response correlation" step, which this stream never had
/// before this issue — every P2P catch-up fetch attempt failed with
/// `NoPeersAvailable` because `mux.handle`'s `Respond` result was silently
/// dropped and no `TopicMsgResp` was ever written back).
fn spawn_ws_peer(
    peer_id: PeerId,
    stream: P2pRawStream,
    mux: Arc<Multiplexer>,
    stream_manager: StreamPeers,
    stream_generation: Arc<AtomicU64>,
    negotiated_features: PeerFeatureFlags,
    initiated_locally: bool,
) {
    #[cfg(not(test))]
    let _ = initiated_locally;
    let (tx, mut rx) = mpsc::unbounded_channel::<(Tag, Vec<u8>)>();
    let request_tracker = Arc::new(RequestTracker::new());
    // A clone of `tx` outlives the map insertion below so the reader half
    // (see the `Respond` handling further down, and the VP-abort send on a
    // stateful vpack decode failure) can still queue a message onto this
    // same peer's writer task.
    let reply_tx = tx.clone();
    // This handshake has already succeeded by the time `spawn_ws_peer` is
    // called (both `handle_inbound_ws_stream`/`handle_outbound_ws_stream`
    // only call it on `Ok(meta)`) — installing the handle here via
    // `StreamManager::set_stream` is therefore exactly go's `streamHandler`
    // "install only after a successful dispatch" rule, and any stream this
    // one displaces is a real "Replacing old stream" event (go:
    // `streamHandler`'s `if oldStream != nil { ... oldStream.Close() }`).
    // Dropping the displaced handle's `tx` below closes its writer loop
    // (`rx.recv()` returns `None`), which in turn ends its `tokio::select!`
    // and lets its own cleanup below run and no-op (its `generation` no
    // longer matches what's installed — see the cleanup comment below).
    let generation = stream_generation.fetch_add(1, AtomicOrdering::Relaxed);
    let mut guard = stream_manager.lock().expect("stream_peers mutex poisoned");
    let displaced = guard.set_stream(
        peer_id,
        StreamPeerHandle {
            tx,
            request_tracker: Arc::clone(&request_tracker),
            generation,
            #[cfg(test)]
            negotiated_features,
            #[cfg(test)]
            initiated_locally,
        },
    );
    // Go: `handleConnected`/`streamHandler` both call `endPeerAttempt` via
    // `defer` right after `dispatch` returns — a successful dispatch (this
    // function is only reached on one, see the doc comment above) still
    // ends the in-flight attempt that started it, but only *after*
    // `set_stream` above, so `end_peer_attempt`'s own `has_stream` check
    // observes the just-installed stream and correctly reports "do not
    // unprotect" (`ending_attempt_does_not_unprotect_while_stream_installed`
    // in `algo_p2p::streams`'s own tests pin this ordering).
    let should_unprotect = guard.end_peer_attempt(peer_id);
    drop(guard);
    drop(displaced);
    if should_unprotect {
        // Go unprotects the peer in the connection manager here
        // (`n.host.ConnManager().Unprotect`) once neither a live stream nor
        // another in-flight attempt remains — `libp2p-connection-limits`
        // (this crate's connection-manager equivalent, see
        // `algo_p2p::conn_limits`'s module doc comment) has no
        // protect/unprotect tag concept to release, so this is a no-op
        // beyond the diagnostic below.
        tracing::trace!(%peer_id, "P2P algorand-ws stream attempt settled with no in-flight/live stream remaining");
    }

    tokio::spawn(async move {
        let (mut read_half, mut write_half) = stream.split();
        let remote_addr = peer_id.to_string();

        // Vote-compression negotiation (issue #925): reuses
        // `algo_network::ws_peer`'s exact stateless/stateful vpack state
        // machine (see `DEFAULT_VOTE_COMPRESSION_TABLE_SIZE`'s doc comment
        // for why this stream reuses rather than reimplements it) — a
        // stateful tier is enabled only when both sides' advertised
        // feature bits intersected to a shared table-size tier, mirroring
        // go's `wsPeerMsgCodec.statefulVoteEnabled`. Shared between the
        // reader and writer tasks below so either side's decode/encode
        // failure (or a received abort) disables both directions for the
        // rest of this stream's lifetime.
        let vote_table_size = stateful_table_size(negotiated_features);
        let stateful_vote_enabled = Arc::new(AtomicBool::new(vote_table_size > 0));
        tracing::debug!(
            peer = %remote_addr,
            features = ?negotiated_features,
            stateless_vote_compression =
                negotiated_features.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK),
            stateful_vote_table_size = vote_table_size,
            "P2P algorand-ws stream: vpack vote compression negotiated"
        );

        let writer = async {
            // vpack stateful encoder state, owned exclusively by this task
            // — mirrors `ws_peer.rs`'s `write_loop`.
            let mut stateful_encoder: Option<StatefulEncoder> = None;
            while let Some((tag, payload)) = rx.recv().await {
                // Optionally vpack-compress AV (AgreementVote) tag
                // payloads. Mirrors go-algorand's `wsPeerMsgCodec.compress()`
                // via the exact same shared core `ws_peer.rs` uses for the
                // classic transport.
                let vote_compressed = if tag == Tag::AgreementVote
                    && negotiated_features.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK)
                    && !payload.is_empty()
                {
                    let (frame, need_abort) = compress_outgoing_vote(
                        &payload,
                        vote_table_size,
                        &stateful_vote_enabled,
                        &mut stateful_encoder,
                        &remote_addr,
                    );
                    if need_abort {
                        match algo_network::framing::encode_frame(
                            &Tag::VotePacked,
                            &[VOTE_COMPRESSION_ABORT_BYTE],
                        ) {
                            Ok(abort_frame) => {
                                if write_frame(&mut write_half, &abort_frame).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => tracing::warn!(
                                %peer_id,
                                error = %e,
                                "P2P algorand-ws stream: failed to encode VP abort frame"
                            ),
                        }
                    }
                    frame
                } else {
                    None
                };

                let frame = if let Some(frame) = vote_compressed {
                    frame
                } else {
                    match algo_network::framing::encode_frame(&tag, &payload) {
                        Ok(f) => f,
                        Err(e) => {
                            tracing::warn!(
                                %peer_id,
                                %tag,
                                error = %e,
                                "P2P algorand-ws stream: dropping oversized outbound message"
                            );
                            continue;
                        }
                    }
                };

                if write_frame(&mut write_half, &frame).await.is_err() {
                    break;
                }
            }
        };
        let reader = async {
            // vpack decompression state, owned exclusively by this task —
            // mirrors `ws_peer.rs`'s `read_loop`.
            let mut stateful_decoder: Option<StatefulDecoder> = None;
            loop {
                let body = match read_frame(&mut read_half).await {
                    Ok(b) => b,
                    Err(_) => break,
                };
                if let Ok((mut tag, raw_payload)) = algo_network::framing::decode_frame(&body) {
                    // Request/response correlation (issue #591): a
                    // `TopicMsgResp` reply to one of *our* outbound unicast
                    // requests (see [`P2pUnicastPeer::request`]) is routed to
                    // this peer's `RequestTracker`, not dispatched into
                    // `mux` — mirrors `ws_peer.rs`'s read loop step "(c)
                    // Request/response correlation".
                    if tag == Tag::TopicMsgResp {
                        if let Err(e) = request_tracker.handle_response(raw_payload).await {
                            tracing::debug!(
                                %peer_id,
                                error = %e,
                                "P2P algorand-ws stream: failed to handle TopicMsgResp"
                            );
                        }
                        continue;
                    }

                    // vpack vote (de)compression (issue #925): AV
                    // (stateless) and VP (stateful) frames both go through
                    // the shared core, which also re-tags a decoded VP
                    // frame to AV in place. Mirrors go-algorand's
                    // `wsPeerMsgCodec.decompress()`.
                    let vpack_result = if tag == Tag::AgreementVote || tag == Tag::VotePacked {
                        let (result, need_abort) = decompress_incoming_vote_core(
                            &mut tag,
                            raw_payload.to_vec(),
                            negotiated_features,
                            vote_table_size,
                            &mut stateful_decoder,
                            &stateful_vote_enabled,
                            &remote_addr,
                        );
                        if need_abort {
                            let _ =
                                reply_tx.send((Tag::VotePacked, vec![VOTE_COMPRESSION_ABORT_BYTE]));
                        }
                        match result {
                            Some(p) => p,
                            None => continue,
                        }
                    } else {
                        raw_payload.to_vec()
                    };

                    // Decompress PP (proposal) payloads that carry the zstd
                    // frame magic — go-algorand compresses *every* proposal
                    // broadcast unconditionally once the wsnet protocol
                    // version is 2.2 (`network/wsNetwork.go`:
                    // "Compress proposals -- all proposals are compressed
                    // as of wsnet 2.2", in `msgBroadcaster.preparePeerData`,
                    // which runs before any per-peer feature negotiation),
                    // and this stream is negotiated at exactly that version
                    // (`ALGORAND_WS_SUPPORTED_VERSIONS = ["2.2"]` above).
                    // Without this, every proposal a real go-algorand peer
                    // sends over `/algorand-ws/2.2.0` arrives as raw zstd
                    // bytes, fails `algo_agreement::demux`'s msgpack decode,
                    // and the node can never validate/vote on a peer's
                    // proposal — issue #478 fixed the identical gap for the
                    // WS-gossip transport's `ws_peer.rs` read loop; this
                    // stream (added by #560/#590) never got the same fix,
                    // found live while proving out issue #589's
                    // stake-holding P2P consensus participant.
                    let payload = if tag == Tag::ProposalPayload
                        && algo_network::compression::is_zstd_compressed(&vpack_result)
                    {
                        match algo_network::compression::zstd_decompress(
                            &vpack_result,
                            algo_network::compression::MAX_DECOMPRESSED_MESSAGE_SIZE,
                        ) {
                            Ok(decompressed) => decompressed,
                            Err(e) => {
                                tracing::warn!(
                                    %peer_id,
                                    error = %e,
                                    "P2P algorand-ws stream: PP decompression failed"
                                );
                                continue;
                            }
                        }
                    } else {
                        vpack_result
                    };
                    // The response-hash correlation (below) is computed over
                    // the exact bytes the requester hashed on their side —
                    // the raw, pre-dispatch request payload — so capture it
                    // before `msg` (and thus `payload`) is moved into
                    // `mux.handle`.
                    let request_payload_for_hash = payload.clone();
                    let msg = IncomingMessage::new(
                        tag,
                        payload,
                        peer_id.to_string(),
                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
                    );
                    let out = mux.handle(msg).await;

                    // Issue #591: a handler that answers with
                    // `ForwardingPolicy::Respond` (e.g.
                    // `ParticipateBlockRequestHandler` answering an inbound
                    // `UniEnsBlockReq`) previously had its result silently
                    // dropped — this stream never wrote a `TopicMsgResp`
                    // back, so a P2P peer's catch-up fetch against this node
                    // always timed out. Mirrors `ws_peer.rs`'s read loop's
                    // `ForwardingPolicy::Respond` arm: hash the *request*
                    // payload, append it as the `RequestHash` topic, and
                    // send the result back as a `TopicMsgResp` frame over
                    // this same peer's stream.
                    if out.action == ForwardingPolicy::Respond {
                        let request_hash = hash_topics(&request_payload_for_hash);
                        let mut response_topics = out.topics.unwrap_or_else(Topics::new);
                        response_topics.0.push(Topic::new(
                            RESPONSE_HASH_FIELD,
                            encode_uvarint(request_hash),
                        ));
                        let serialized = response_topics.marshal();
                        let _ = reply_tx.send((Tag::TopicMsgResp, serialized));
                    }
                }
            }
        };
        tokio::select! {
            _ = writer => {}
            _ = reader => {}
        }
        // Only remove the entry if it is still *this* task's own handle —
        // go's `Disconnected` always removes unconditionally because it
        // holds `streamsLock` around both the removal and
        // `streamHandler`'s replacement swap, so the two can never race.
        // This port instead lets a replacement install (`set_stream` above)
        // happen concurrently with an old stream's teardown, so a stale
        // task finishing late must check its `generation` before removing —
        // otherwise it could evict a *newer*, healthy stream that replaced
        // it in the meantime (see `StreamPeerHandle::generation`'s doc
        // comment).
        let mut guard = stream_manager.lock().expect("stream_peers mutex poisoned");
        if guard.get(&peer_id).map(|h| h.generation) == Some(generation) {
            guard.remove_stream(&peer_id);
        }
    });
}

/// Complete the inbound (listener) side of the `/algorand-ws/2.2.0`
/// handshake (go: the `incoming` branch of `wsStreamHandlerV22`) and, on
/// success, start this peer's read/write loop.
async fn handle_inbound_ws_stream(
    peer_id: PeerId,
    mut stream: P2pRawStream,
    our_headers: PeerMetaHeaders,
    our_features: PeerFeatureFlags,
    mux: Arc<Multiplexer>,
    stream_manager: StreamPeers,
    stream_generation: Arc<AtomicU64>,
) {
    match handshake_inbound(&mut stream, &our_headers, ALGORAND_WS_SUPPORTED_VERSIONS).await {
        Ok(meta) => {
            let negotiated =
                decode_peer_features(&meta.version, &meta.features).intersection(our_features);
            spawn_ws_peer(
                peer_id,
                stream,
                mux,
                stream_manager,
                stream_generation,
                negotiated,
                false,
            )
        }
        Err(e) => {
            // A failed dispatch still ends the in-flight attempt
            // `begin_peer_attempt` (called by this handler's caller, the
            // accept-loop) started — go's `streamHandler` does the same via
            // `defer n.endPeerAttempt(remotePeer)`, unconditionally on
            // dispatch success *or* failure. Never installs a stream here
            // (mirrors go's "dispatch first, install only on success" — see
            // `spawn_ws_peer`'s doc comment), so an existing healthy stream
            // for this peer, if any, survives untouched.
            stream_manager
                .lock()
                .expect("stream_peers mutex poisoned")
                .end_peer_attempt(peer_id);
            // Go: `wsStreamHandlerV22`'s handshake failures are all
            // `logging.Warn`-level `p2p.StreamHandlerLoggedError`s (see
            // `p2pNetwork.go`'s `wsStreamHandlerV22`) — an inbound
            // handshake failure is routine (a peer speaking an
            // incompatible version, or dropping mid-handshake), not a
            // node-local bug, so it is logged at `Warn` via
            // `DispatchError`'s explicit-level constructor rather than the
            // `Error` level a bare error would default to (see
            // `algo_p2p::streams::DispatchError::log_level`'s doc comment).
            let dispatch_err =
                DispatchError::with_level(format!("inbound handshake failed: {e}"), LogLevel::Warn);
            log_dispatch_error(&peer_id, &dispatch_err);
        }
    }
}

/// Complete the outbound (dialer) side of the `/algorand-ws/2.2.0`
/// handshake (go: the `!incoming` branch of `wsStreamHandlerV22`) and, on
/// success, start this peer's read/write loop.
async fn handle_outbound_ws_stream(
    peer_id: PeerId,
    mut stream: P2pRawStream,
    our_headers: PeerMetaHeaders,
    our_features: PeerFeatureFlags,
    mux: Arc<Multiplexer>,
    stream_manager: StreamPeers,
    stream_generation: Arc<AtomicU64>,
) {
    match handshake_outbound(&mut stream, &our_headers, ALGORAND_WS_SUPPORTED_VERSIONS).await {
        Ok(meta) => {
            let negotiated =
                decode_peer_features(&meta.version, &meta.features).intersection(our_features);
            spawn_ws_peer(
                peer_id,
                stream,
                mux,
                stream_manager,
                stream_generation,
                negotiated,
                true,
            )
        }
        Err(e) => {
            // See `handle_inbound_ws_stream`'s matching comment: ends the
            // in-flight attempt `begin_peer_attempt` (called by this
            // handler's caller, the swarm event loop's outbound-dial arm)
            // started, without installing a stream.
            stream_manager
                .lock()
                .expect("stream_peers mutex poisoned")
                .end_peer_attempt(peer_id);
            let dispatch_err = DispatchError::with_level(
                format!("outbound handshake failed: {e}"),
                LogLevel::Warn,
            );
            log_dispatch_error(&peer_id, &dispatch_err);
        }
    }
}

/// Log a [`DispatchError`] at the severity it carries — the live-wiring
/// counterpart of go's `streamManager.logDispatchError` (issue #952):
/// `streams.rs`'s `DispatchError`/`LogLevel` types are ported and
/// unit-tested there, but nothing previously called `log_level()` from a
/// real code path. `tracing`'s macros can't take a runtime-selected level
/// directly, hence the explicit match.
fn log_dispatch_error(peer_id: &PeerId, err: &DispatchError) {
    match err.log_level() {
        LogLevel::Debug => {
            tracing::debug!(%peer_id, error = %err, "P2P algorand-ws stream dispatch")
        }
        LogLevel::Info => tracing::info!(%peer_id, error = %err, "P2P algorand-ws stream dispatch"),
        LogLevel::Warn => tracing::warn!(%peer_id, error = %err, "P2P algorand-ws stream dispatch"),
        LogLevel::Error => {
            tracing::error!(%peer_id, error = %err, "P2P algorand-ws stream dispatch")
        }
    }
}

/// Map an `algo-network` protocol [`Tag`] to the gossipsub topic name it
/// publishes/subscribes on, via `algo_p2p::pubsub`'s tag-code convention
/// (see that module's doc comment). Returns `None` for a tag this crate
/// does not carry over P2P (only TX/AV/PP/VB have a defined topic).
fn tag_to_topic(tag: Tag) -> Option<&'static str> {
    algo_p2p::topic_name_for_tag_code(tag.as_str())
}

/// Reverse of [`tag_to_topic`]: recover the `Tag` a received gossipsub
/// message's topic name corresponds to.
fn topic_to_tag(topic: &str) -> Option<Tag> {
    match topic {
        t if t == algo_p2p::TX_TOPIC => Some(Tag::Transaction),
        t if t == algo_p2p::AGREEMENT_VOTE_TOPIC => Some(Tag::AgreementVote),
        t if t == algo_p2p::PROPOSAL_PAYLOAD_TOPIC => Some(Tag::ProposalPayload),
        t if t == algo_p2p::VOTE_BUNDLE_TOPIC => Some(Tag::VoteBundle),
        _ => None,
    }
}

/// A lightweight [`Peer`] implementation wrapping a libp2p [`PeerId`]'s
/// string form. P2P peers are identified purely by `PeerId` (there is no
/// per-peer measured latency or IP routing address surfaced at this layer
/// yet), so [`Peer::get_connection_latency`] and [`Peer::routing_addr`]
/// return the same "unknown" defaults [`GossipNode`]'s doc comment allows.
struct P2pPeerRef {
    peer_id: String,
}

impl Peer for P2pPeerRef {
    fn get_address(&self) -> &str {
        &self.peer_id
    }

    fn get_connection_latency(&self) -> Duration {
        Duration::ZERO
    }

    fn routing_addr(&self) -> &[u8] {
        &[]
    }
}

/// A [`UnicastPeer`] backed by one peer's `/algorand-ws/2.2.0` stream
/// (issue #591): request/response traffic (currently `UniEnsBlockReq`
/// catch-up block fetches) is sent as a normal tag+payload frame over the
/// same stream AV/PP/VB traffic already uses, correlated to its
/// `TopicMsgResp` reply via `request_tracker` — the same mechanism
/// `ws_peer.rs`'s `UnicastPeerRef` uses for the WS-gossip transport,
/// re-implemented here because the P2P stream's framing/dispatch lives in
/// this module (`algo-p2p` deliberately has no `algo-network` dependency —
/// see `algo_p2p::wsproto`'s doc comment).
struct P2pUnicastPeer {
    /// `PeerId`'s string form, cached at construction since
    /// [`Peer::get_address`] returns `&str` and `PeerId::to_string()`
    /// allocates.
    peer_id_str: String,
    /// Sends an unframed `(tag, payload)` pair to this peer's writer task —
    /// the same channel [`P2pTransport::stream_broadcast`] uses. See
    /// [`StreamPeerHandle::tx`]'s doc comment for why framing/compression
    /// now happen in the writer task rather than at the call site.
    tx: mpsc::UnboundedSender<(Tag, Vec<u8>)>,
    request_tracker: Arc<RequestTracker>,
    request_timeout: Duration,
}

impl Peer for P2pUnicastPeer {
    fn get_address(&self) -> &str {
        &self.peer_id_str
    }

    fn get_connection_latency(&self) -> Duration {
        Duration::ZERO
    }

    fn routing_addr(&self) -> &[u8] {
        &[]
    }
}

#[async_trait]
impl UnicastPeer for P2pUnicastPeer {
    /// Send a `UniEnsBlockReq`-style request over this peer's
    /// `/algorand-ws` stream and await the correlated `TopicMsgResp`.
    /// Mirrors `ws_peer.rs`'s `UnicastPeerRef::request` exactly (same
    /// `RequestTracker` protocol), just framed onto this stream's own
    /// outgoing sender instead of a WS write-command channel.
    async fn request(&self, tag: Tag, topics: Topics) -> Result<Topics, PeerError> {
        let (serialized, hash, rx) = self.request_tracker.prepare_request(topics).await;

        if self.tx.send((tag, serialized)).is_err() {
            self.request_tracker.cancel_request(hash).await;
            return Err(PeerError::ConnectionClosed);
        }

        match tokio::time::timeout(self.request_timeout, rx).await {
            Ok(Ok(response_topics)) => Ok(response_topics),
            Ok(Err(_recv_error)) => Err(PeerError::ResponseChannelClosed),
            Err(_timeout) => {
                self.request_tracker.cancel_request(hash).await;
                Err(PeerError::RequestTimeout)
            }
        }
    }

    /// Send a response to a previously received request over this peer's
    /// stream. Not exercised by the catch-up-fetch client path (this
    /// module's read loop replies to inbound requests directly — see
    /// `spawn_ws_peer`'s `ForwardingPolicy::Respond` handling), but
    /// implemented for `UnicastPeer` trait completeness and parity with
    /// `ws_peer.rs`'s `UnicastPeerRef::respond`.
    async fn respond(&self, request_hash: u64, topics: Topics) -> Result<(), PeerError> {
        let mut response_topics = topics;
        response_topics.0.push(Topic::new(
            RESPONSE_HASH_FIELD,
            encode_uvarint(request_hash),
        ));
        let serialized = response_topics.marshal();
        self.tx
            .send((Tag::TopicMsgResp, serialized))
            .map_err(|_| PeerError::ConnectionClosed)
    }
}

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
    /// The actual `enable_p2p`/`enable_p2p_hybrid_mode` values `mode` was
    /// derived from (CLI-flag/`[p2p]`-TOML precedence already applied).
    /// Exposed so call sites can feed `algo_config`'s canonical
    /// `is_listen_server`/`is_hybrid_server`/`validate_p2p_hybrid_config`
    /// derivations with the flags that actually drove this run's
    /// `NetworkMode`, rather than the possibly-stale `Local::enable_p2p`/
    /// `enable_p2p_hybrid_mode` loaded from `config.json` (issue #949) —
    /// `config.json`'s copies of these two flags are not currently part of
    /// this precedence chain at all (a pre-existing, separate gap; not
    /// closed here).
    pub enable_p2p: bool,
    pub enable_p2p_hybrid_mode: bool,
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
            enable_p2p,
            enable_p2p_hybrid_mode,
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
    /// Custom path to the P2P peer-ID private key file, overriding the
    /// `data_dir`-derived default location. Matches go's
    /// `P2PPrivateKeyLocation` (`config.Local`, issue #768) — an empty
    /// value (the default) means "use `data_dir`'s conventional location",
    /// the same as go's own empty-string default.
    pub private_key_path: Option<PathBuf>,
    /// Whether the DHT is used for peer discovery and capabilities
    /// advertisement at all. Matches go's `EnableDHTProviders`
    /// (`config.Local`, issue #768; go default `false`). When `false`,
    /// this host never seeds/bootstraps the DHT or advertises a mode —
    /// the underlying `kad::Behaviour` is still composed into the swarm
    /// (rust-libp2p has no cheaper way to omit a `NetworkBehaviour` field
    /// at runtime), but it is never given bootstrap peers, never
    /// bootstrapped, and never promoted out of its default client mode,
    /// so it neither advertises this node nor is queried for routing.
    pub enable_dht_providers: bool,
    /// DHT operation mode string. Matches go's `DHTMode` (`config.Local`,
    /// issue #768) — see [`resolve_dht_mode`]'s doc comment for the exact
    /// `""`/`"server"`/`"client"` semantics. Only consulted when
    /// `enable_dht_providers` is `true`.
    pub dht_mode: String,
    /// Matches go's `cfg.GossipFanout` — fed to
    /// [`algo_p2p::derive_conn_limits`]/[`algo_p2p::derive_algorand_gossipsub_params`]
    /// via [`P2pHostConfig`] (issue #952). `Default::default()` gives `0`,
    /// unlike [`P2pHostConfig::default`]'s go-config-matching `4` — a
    /// caller building a real node config should always set this from its
    /// actual `GossipFanout`, mirroring how every other field on this
    /// struct already requires an explicit value from the caller.
    pub gossip_fanout: i64,
    /// Matches go's `cfg.IncomingConnectionsLimit`. Only consulted when
    /// `is_listen_server` is `true` — see
    /// [`algo_p2p::derive_conn_limits`]'s doc comment.
    pub incoming_connections_limit: i64,
    /// Matches go's `cfg.IsListenServer()` — whether this node accepts
    /// inbound connections as a relay/listen server (as opposed to a pure
    /// client). The caller is expected to compute this itself (e.g. from
    /// `algo_config::Local::is_listen_server`), mirroring
    /// [`algo_p2p::derive_conn_limits`]'s own expectations.
    pub is_listen_server: bool,
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
/// `algo_p2p::P2pHost`'s swarm event loop, subscribed to every
/// go-compatible-convention propagation topic this crate defines
/// (`algo_p2p::pubsub::ALL_TOPICS` — TX, AV, PP, VB) so transactions and
/// agreement (proposal/vote/bundle) traffic can propagate over P2P.
///
/// Implements [`GossipNode`] directly (see the trait impl below) so it can
/// be handed to [`algo_network::local_tx_broadcast::LocalTxBroadcaster`]
/// and [`algo_network::AgreementNetworkBridge`] exactly like the WS-gossip
/// node is — both already only depend on `Arc<dyn GossipNode>`, so no
/// per-transport special-casing is needed in those two consumers. `crate`'s
/// `dual_gossip_node` module composes this with the WS node for `Hybrid`
/// mode, where both transports must carry the same traffic.
pub struct P2pTransport {
    peer_id: PeerId,
    /// Reused as this transport's `GossipNode::get_genesis_id()` — P2P
    /// gossipsub topics are keyed by protocol tag, not genesis ID, so no
    /// consumer of this transport as a `GossipNode` actually depends on
    /// this being genesis-ID-precise; it exists only for trait-completeness
    /// parity with `WebsocketNetwork`.
    network_id: String,
    listen_addrs: Arc<Mutex<Vec<Multiaddr>>>,
    connected_peers: Arc<Mutex<Vec<PeerId>>>,
    multiplexer: Arc<Multiplexer>,
    cmd_tx: mpsc::UnboundedSender<P2pCommand>,
    /// Established `/algorand-ws/2.2.0` stream peers — see this module's
    /// doc comment on why AV/PP/VB traffic needs this in addition to
    /// gossipsub.
    stream_peers: StreamPeers,
    /// Connection-identity dedup (issue #952): tracks, per connected
    /// `PeerId`, which single [`ConnectionId`] currently "owns" that
    /// identity — mirrors go's `identityTracker`/`p2pNetwork.go`'s
    /// `baseWsStreamHandler` (`n.identityTracker.setIdentity(wsp)`), whose
    /// dedup key there is the peer's raw public key
    /// (`p2pPeer.ExtractPublicKey()`, `netIdentPeerID`) — already
    /// equivalent to `PeerId` itself in this transport, since libp2p's
    /// Noise handshake cryptographically binds every established
    /// connection's `PeerId` to its authenticated public key (unlike the
    /// classic WS transport, which needs `algo_network::identity`'s
    /// separate 3-message challenge/response exchange to establish that
    /// binding over a plain, unauthenticated TCP+HTTP-upgrade connection —
    /// see [`P2pTransport::start`]'s swarm-loop comment on
    /// `ConnectionEstablished` for the full reasoning). A second
    /// established connection to a `PeerId` already claimed by a different
    /// `ConnectionId` is therefore a genuine redundant connection (e.g. both
    /// sides dialed each other at once), deduped the same way go's
    /// `baseWsStreamHandler` does: keep the first, close the second.
    #[cfg_attr(not(test), allow(dead_code))]
    identity_tracker: Arc<Mutex<IdentityTracker<PeerId, ConnectionId>>>,
    /// HTTP handlers registered via [`GossipNode::register_http_handler`],
    /// served over inbound `/algorand-http/1.0.0` streams (issue #1024) —
    /// the P2P-transport counterpart of [`algo_p2p::ALGORAND_HTTP_PROTOCOL`]
    /// go's `rpcs.LedgerService`/`rpcs.BlockService` register against via
    /// `HTTPServer.RegisterHTTPHandler` (`network/p2p/http.go`). Rebuilt
    /// (via [`Router::nest`]) on every `register_http_handler` call and
    /// snapshotted (a cheap `Router::clone` — internally `Arc`-backed) by
    /// the accept-loop each time a peer opens a new HTTP stream, so a
    /// handler registered after this transport starts is still picked up by
    /// the next inbound request.
    http_router: Arc<Mutex<Router>>,
    /// A [`libp2p_stream::Control`] handle kept around (in addition to the
    /// one consumed by the accept-loop above) so a caller can open an
    /// outbound `/algorand-http/1.0.0` stream to a peer — see
    /// [`P2pTransport::open_http_stream`]. Mirrors go's `p2pHTTPRoundTripper`
    /// opening a fresh stream per outbound HTTP request.
    ///
    /// No production caller exists yet — this transport only *serves*
    /// `/algorand-http/1.0.0` today (issue #1024's scope); the client side
    /// (e.g. a future `BlockServiceCustomFallbackEndpoints`-style P2P
    /// redirect-follow fetcher, noted as unblocked by this issue) is a
    /// deliberately separate follow-up. Exercised directly by this module's
    /// own tests in the meantime.
    #[allow(dead_code)]
    http_stream_control: libp2p_stream::Control,
    _task: tokio::task::JoinHandle<()>,
}

enum P2pCommand {
    Publish(&'static str, Vec<u8>),
}

impl P2pTransport {
    /// Build and start a P2P transport: creates the host, optionally
    /// listens, dials bootstrap peers, subscribes every propagation topic,
    /// and spawns the background swarm-driving task. Inbound gossipsub
    /// messages are dispatched to whatever handlers are registered on
    /// [`P2pTransport::multiplexer`] (via [`GossipNode::register_handlers`])
    /// — register handlers immediately after this returns, mirroring the
    /// WS-gossip node's own "register before traffic can arrive" ordering.
    pub async fn start(cfg: P2pTransportConfig) -> Result<Self, anyhow::Error> {
        let identity_cfg = IdentityConfig {
            private_key_path: cfg.private_key_path.clone(),
            data_dir: cfg.data_dir.clone(),
            persist_peer_id: cfg.persist_peer_id,
        };
        let host_cfg = P2pHostConfig {
            gossip_fanout: cfg.gossip_fanout,
            incoming_connections_limit: cfg.incoming_connections_limit,
            is_listen_server: cfg.is_listen_server,
            enable_dht_providers: cfg.enable_dht_providers,
        };
        let mut host = P2pHost::new(&identity_cfg, &cfg.network_id, &host_cfg)
            .map_err(|e| anyhow::anyhow!("failed to build P2P host: {e}"))?;
        let peer_id = host.peer_id();

        if let Some(addr) = &cfg.listen_multiaddr {
            host.listen(addr.clone())
                .map_err(|e| anyhow::anyhow!("failed to listen on {addr}: {e}"))?;
        }

        // `EnableDHTProviders`/`DHTMode` (issue #768): the DHT is only
        // seeded, bootstrapped, and mode-set when DHT-based peer
        // discovery/capabilities advertisement is enabled — go's
        // `EnableDHTProviders` gates the whole subsystem (`network/p2p/
        // capabilities.go`'s `CapabilitiesDiscovery`), not just its mode.
        // The gossip-mesh bootstrap dial below is unconditional either
        // way: it is plain P2P peer connectivity, not DHT routing.
        if cfg.enable_dht_providers {
            host.set_dht_mode(resolve_dht_mode(
                &cfg.dht_mode,
                cfg.listen_multiaddr.is_some(),
            ));
        }

        for addr in &cfg.bootstrap_peers {
            if cfg.enable_dht_providers {
                let (base, peer) = split_peer_id(addr);
                if let Some(peer) = peer {
                    host.add_bootstrap_peer(peer, base);
                }
            }
            if let Err(e) = host.dial(addr.clone()) {
                tracing::warn!(addr = %addr, error = %e, "failed to dial P2P bootstrap peer");
            }
        }
        if cfg.enable_dht_providers && !cfg.bootstrap_peers.is_empty() {
            host.bootstrap_dht();
        }

        for topic in algo_p2p::ALL_TOPICS {
            host.gossipsub_subscribe(topic)
                .map_err(|e| anyhow::anyhow!("failed to subscribe to {topic}: {e}"))?;
        }

        // `/algorand-ws/2.2.0` stream setup (issue #560): register an
        // acceptor for inbound streams now, before any peer can possibly
        // dial in. `stream_control` is cloned into the background task
        // below to open an outbound stream whenever *this* node dials out.
        let mut stream_control = host.stream_control();
        let mut incoming_ws_streams = stream_control
            .accept(ALGORAND_WS_PROTOCOL_V22)
            .map_err(|e| anyhow::anyhow!("failed to register algorand-ws stream acceptor: {e}"))?;

        // `/algorand-http/1.0.0` stream setup (issue #1024): register an
        // acceptor for inbound HTTP-over-libp2p-stream requests now, on the
        // same `Control` used above, before any peer can possibly dial in.
        // `http_stream_control` is a clone saved for outbound use (this
        // transport's `open_http_stream`, mirroring go's
        // `p2pHTTPRoundTripper`) — registering the acceptor on `stream_control`
        // itself (not a clone) first, exactly as the WS acceptor above does,
        // is what actually wires up the protocol handler on the shared swarm
        // behaviour.
        let mut incoming_http_streams =
            stream_control.accept(ALGORAND_HTTP_PROTOCOL).map_err(|e| {
                anyhow::anyhow!("failed to register algorand-http stream acceptor: {e}")
            })?;
        let http_stream_control = stream_control.clone();
        // Vote-compression advertisement (issue #925): always offer
        // stateless + stateful (table size 2048) vpack compression, exactly
        // as `algo_network::ws_network`'s classic WS-gossip transport does
        // (see `DEFAULT_VOTE_COMPRESSION_TABLE_SIZE`'s doc comment for the
        // go-source citation on why this is hardcoded-on rather than a
        // config knob). `our_features` is threaded into both the accept
        // and dial loops below so each side's handshake can compute the
        // intersection with whatever the peer actually advertised back.
        let our_features = advertise_vote_compression(true, DEFAULT_VOTE_COMPRESSION_TABLE_SIZE);
        let our_ws_headers = build_headers(
            &cfg.network_id,
            "",
            "algod-rust",
            &encode_peer_features(&our_features),
            ALGORAND_WS_SUPPORTED_VERSIONS,
        );

        let listen_addrs: Arc<Mutex<Vec<Multiaddr>>> = Arc::new(Mutex::new(Vec::new()));
        let connected_peers: Arc<Mutex<Vec<PeerId>>> = Arc::new(Mutex::new(Vec::new()));
        let multiplexer = Arc::new(Multiplexer::new());
        let stream_peers: StreamPeers = Arc::new(Mutex::new(StreamManager::new()));
        // Monotonically increasing id handed to every `StreamPeerHandle`
        // installed via `spawn_ws_peer` — see `StreamPeerHandle::generation`'s
        // doc comment for why a stale, already-replaced task needs this to
        // avoid evicting a newer stream on cleanup.
        let stream_generation: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
        let identity_tracker: Arc<Mutex<IdentityTracker<PeerId, ConnectionId>>> =
            Arc::new(Mutex::new(IdentityTracker::new()));
        let http_router: Arc<Mutex<Router>> = Arc::new(Mutex::new(Router::new()));
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<P2pCommand>();
        let local_peer_id = host.peer_id();

        // Accept-loop: every inbound `/algorand-ws/2.2.0` stream a peer
        // opens to us gets handshaken and, on success, joins `stream_peers`.
        // Go: `streamManager.streamHandler` brackets every accepted stream
        // (not just outbound dial attempts) with
        // `beginPeerAttempt`/`endPeerAttempt` — mirrored here by bumping the
        // in-flight counter before handing off to `handle_inbound_ws_stream`,
        // which itself ends the attempt on both the success path (inside
        // `spawn_ws_peer`, after the stream installs) and the failure path.
        {
            let mux = Arc::clone(&multiplexer);
            let sp = Arc::clone(&stream_peers);
            let gen_counter = Arc::clone(&stream_generation);
            let headers = our_ws_headers.clone();
            tokio::spawn(async move {
                while let Some((peer_id, stream)) = incoming_ws_streams.next().await {
                    sp.lock()
                        .expect("stream_peers mutex poisoned")
                        .begin_peer_attempt(peer_id);
                    tokio::spawn(handle_inbound_ws_stream(
                        peer_id,
                        stream,
                        headers.clone(),
                        our_features,
                        Arc::clone(&mux),
                        Arc::clone(&sp),
                        Arc::clone(&gen_counter),
                    ));
                }
            });
        }

        // Accept-loop: every inbound `/algorand-http/1.0.0` stream a peer
        // opens to us is served as a single HTTP/1.1 request/response
        // against whatever [`Router`] is currently registered (issue #1024)
        // — the P2P-transport equivalent of go's `HTTPServer`
        // (`network/p2p/http.go`) dispatching through its `gorilla/mux`
        // router. The router is snapshotted (a cheap, `Arc`-backed clone)
        // per accepted stream rather than once at startup, so a handler
        // registered via `register_http_handler` after this transport is
        // already running (the normal node-startup ordering — see
        // `GossipNode::register_http_handler`'s doc comment) is still
        // picked up by the next request.
        {
            let hr = Arc::clone(&http_router);
            tokio::spawn(async move {
                while let Some((peer_id, stream)) = incoming_http_streams.next().await {
                    let router = hr.lock().expect("http_router mutex poisoned").clone();
                    tokio::spawn(serve_p2p_http_stream(peer_id, stream, router));
                }
            });
        }

        let la = Arc::clone(&listen_addrs);
        let cp = Arc::clone(&connected_peers);
        let mux = Arc::clone(&multiplexer);
        let sp_for_task = Arc::clone(&stream_peers);
        let gen_counter_for_task = Arc::clone(&stream_generation);
        let identity_tracker_for_task = Arc::clone(&identity_tracker);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = host.next_event() => {
                        match event {
                            SwarmEvent::NewListenAddr { address, .. } => {
                                la.lock().expect("listen_addrs mutex poisoned").push(address);
                            }
                            SwarmEvent::ConnectionEstablished { peer_id, connection_id, .. } => {
                                // Connection-identity dedup (issue #952):
                                // go's `baseWsStreamHandler` runs
                                // `identityTracker.setIdentity(wsp)` keyed
                                // by the peer's own public key — already
                                // 1:1 with `PeerId` here (Noise
                                // cryptographically binds the two; see
                                // `identity_tracker`'s doc comment). A
                                // `false` result means a *different*,
                                // already-established `ConnectionId` for
                                // this same `PeerId` exists (e.g. both
                                // sides dialed each other at once) — close
                                // this redundant one immediately, mirroring
                                // go's `stream.Close()` on the loser, and
                                // skip opening a second `/algorand-ws`
                                // stream for it.
                                let is_new_identity = identity_tracker_for_task
                                    .lock()
                                    .expect("identity_tracker mutex poisoned")
                                    .set_identity(peer_id, connection_id);
                                if !is_new_identity {
                                    tracing::debug!(
                                        %peer_id, ?connection_id,
                                        "P2P: closing redundant connection — identity already claimed by another connection to this peer"
                                    );
                                    let _ = host.close_connection(connection_id);
                                    continue;
                                }

                                cp.lock().expect("connected_peers mutex poisoned").push(peer_id);

                                // Which side opens the `/algorand-ws/2.2.0`
                                // stream is decided by peer-ID order, not by
                                // which side physically dialed the TCP
                                // connection — go: `streamManager.Connected`'s
                                // `if localPeer > remotePeer { ignore }`
                                // ("ensure that only one of the peers
                                // initiates the stream"). A libp2p stream
                                // can be opened over an already-established
                                // connection regardless of which side
                                // originally dialed it, so the numerically
                                // lower `PeerId` always opens it — even when
                                // that side is the one that *accepted* the
                                // inbound TCP connection.
                                if should_initiate_stream(&local_peer_id, &peer_id) {
                                    // Go: `handleConnected`'s pre-flight
                                    // guard — skip re-opening a stream to a
                                    // peer we already have a live one with
                                    // (e.g. a second `ConnectionEstablished`
                                    // for a peer whose first connection's
                                    // stream is still up).
                                    let should_skip = sp_for_task
                                        .lock()
                                        .expect("stream_peers mutex poisoned")
                                        .should_skip_dial(&peer_id);
                                    if should_skip {
                                        tracing::debug!(%peer_id, "P2P: already have a live algorand-ws stream, skipping dial");
                                    } else {
                                        sp_for_task
                                            .lock()
                                            .expect("stream_peers mutex poisoned")
                                            .begin_peer_attempt(peer_id);
                                        let mut control = stream_control.clone();
                                        let mux = Arc::clone(&mux);
                                        let sp = Arc::clone(&sp_for_task);
                                        let gen_counter = Arc::clone(&gen_counter_for_task);
                                        let headers = our_ws_headers.clone();
                                        tokio::spawn(async move {
                                            match control.open_stream(peer_id, ALGORAND_WS_PROTOCOL_V22).await {
                                                Ok(stream) => {
                                                    handle_outbound_ws_stream(peer_id, stream, headers, our_features, mux, sp, gen_counter).await;
                                                }
                                                Err(e) => {
                                                    sp.lock()
                                                        .expect("stream_peers mutex poisoned")
                                                        .end_peer_attempt(peer_id);
                                                    tracing::debug!(
                                                        %peer_id, error = %e,
                                                        "failed to open P2P algorand-ws stream"
                                                    );
                                                }
                                            }
                                        });
                                    }
                                }
                            }
                            SwarmEvent::ConnectionClosed { peer_id, connection_id, .. } => {
                                identity_tracker_for_task
                                    .lock()
                                    .expect("identity_tracker mutex poisoned")
                                    .remove_identity(&peer_id, &connection_id);
                                cp.lock()
                                    .expect("connected_peers mutex poisoned")
                                    .retain(|p| *p != peer_id);
                                sp_for_task
                                    .lock()
                                    .expect("stream_peers mutex poisoned")
                                    .remove_stream(&peer_id);
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
                                // `TxTagHandler`/`AgreementNetworkBridge`'s
                                // handlers run before reporting a result;
                                // the pool-ingestion and agreement-service
                                // pipelines downstream still reject anything
                                // malformed. Mirrors go-algorand's own
                                // topic validators being a thin/fast check
                                // (real validation happens after dispatch).
                                host.report_message_validation_result(
                                    &message_id,
                                    &propagation_source,
                                    MessageValidationResult::Accept,
                                );
                                if let Some(tag) = topic_to_tag(message.topic.as_str()) {
                                    let msg = IncomingMessage::new(
                                        tag,
                                        message.data,
                                        propagation_source.to_string(),
                                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
                                    );
                                    let _ = mux.handle(msg).await;
                                }
                            }
                            _ => {}
                        }
                    }
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            Some(P2pCommand::Publish(topic, data)) => {
                                if let Err(e) = host.gossipsub_publish(topic, data) {
                                    tracing::debug!(topic, error = %e, "P2P publish failed");
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        Ok(Self {
            peer_id,
            network_id: cfg.network_id,
            listen_addrs,
            connected_peers,
            multiplexer,
            cmd_tx,
            stream_peers,
            identity_tracker,
            http_router,
            http_stream_control,
            _task: task,
        })
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

    /// Currently connected peer count. Exercised directly by this module's
    /// own tests; also reachable indirectly via `GossipNode::get_peers`.
    pub fn connected_peer_count(&self) -> usize {
        self.connected_peers
            .lock()
            .expect("connected_peers mutex poisoned")
            .len()
    }

    /// Number of peers with a currently-established `/algorand-ws/2.2.0`
    /// stream (issue #560) — exercised by this module's own tests and by
    /// the live go-algorand interop test
    /// (`bin/algod-rust/tests/p2p_go_algorand_interop.rs`) to observe that
    /// the handshake actually completed against a real peer, not just that
    /// the raw libp2p connection came up.
    pub fn stream_peer_count(&self) -> usize {
        self.stream_peers
            .lock()
            .expect("stream_peers mutex poisoned")
            .len()
    }

    /// Every currently-established `/algorand-ws/2.2.0` stream peer, as
    /// [`UnicastPeer`]s a [`algo_rest_client::GossipBlockSource`]-style
    /// catch-up fetcher can send `UniEnsBlockReq` requests to and await a
    /// correlated `TopicMsgResp` from (issue #591) — the P2P-transport
    /// equivalent of `WebsocketNetwork::get_unicast_peers()`. Empty until at
    /// least one peer's stream handshake completes.
    pub fn unicast_peers(&self) -> Vec<Arc<dyn UnicastPeer>> {
        self.stream_peers
            .lock()
            .expect("stream_peers mutex poisoned")
            .iter()
            .map(|(peer_id, handle)| {
                Arc::new(P2pUnicastPeer {
                    peer_id_str: peer_id.to_string(),
                    tx: handle.tx.clone(),
                    request_tracker: Arc::clone(&handle.request_tracker),
                    request_timeout: DEFAULT_REQUEST_TIMEOUT,
                }) as Arc<dyn UnicastPeer>
            })
            .collect()
    }

    /// The [`Multiplexer`] inbound gossipsub messages (for topics this
    /// transport subscribes to — TX/AV/PP/VB) are dispatched to. Callers
    /// register handlers here the same way they register on
    /// `WebsocketNetwork::multiplexer()`.
    pub fn multiplexer(&self) -> &Arc<Multiplexer> {
        &self.multiplexer
    }

    /// Open an outbound `/algorand-http/1.0.0` stream to `peer` (issue
    /// #1024) — the client-side counterpart of the HTTP-serving accept-loop
    /// [`P2pTransport::start`] spawns, for a caller that wants to speak the
    /// P2P-transport HTTP-over-libp2p-stream protocol directly: write a raw
    /// HTTP/1.1 request onto the returned stream and read a raw HTTP/1.1
    /// response back, exactly as go's `p2pHTTPRoundTripper`
    /// (`network/p2p/http.go`) does over its own per-request stream. Used
    /// today by this module's own tests; a future
    /// `BlockServiceCustomFallbackEndpoints`-style P2P redirect-follow
    /// client (noted as unblocked by issue #955/#1024) would use the same
    /// entry point.
    #[allow(dead_code)]
    pub async fn open_http_stream(&self, peer: PeerId) -> Result<P2pRawStream, anyhow::Error> {
        self.http_stream_control
            .clone()
            .open_stream(peer, ALGORAND_HTTP_PROTOCOL)
            .await
            .map_err(|e| anyhow::anyhow!("failed to open P2P HTTP stream to {peer}: {e}"))
    }

    /// Publish `data` on the gossipsub topic corresponding to `tag` and,
    /// for AV/PP/VB, also fan it out over every established
    /// `/algorand-ws/2.2.0` stream peer (see this module's doc comment on
    /// why both paths matter: a real go-algorand peer never gossips
    /// agreement traffic, only the stream carries it there).
    /// Fire-and-forget: the background task logs (rather than propagates)
    /// a publish failure, matching `GossipNode::broadcast`'s best-effort
    /// semantics for other transports. Returns an error only if `tag` has
    /// no defined P2P topic, or if the background task has already
    /// stopped.
    pub fn publish(&self, tag: Tag, data: Vec<u8>) -> Result<(), anyhow::Error> {
        let topic = tag_to_topic(tag)
            .ok_or_else(|| anyhow::anyhow!("no P2P gossipsub topic defined for tag {tag}"))?;

        if matches!(
            tag,
            Tag::AgreementVote | Tag::ProposalPayload | Tag::VoteBundle
        ) {
            self.stream_broadcast(tag, &data);
        }

        self.cmd_tx
            .send(P2pCommand::Publish(topic, data))
            .map_err(|_| anyhow::anyhow!("P2P transport task has stopped"))
    }

    /// Fan a `(tag, payload)` message out to every currently-established
    /// `/algorand-ws/2.2.0` stream peer. Best-effort: a peer whose writer
    /// task has already exited (connection dropped) simply drops the send.
    ///
    /// Framing and compression are applied per-peer, inside each peer's own
    /// writer task (see [`StreamPeerHandle::tx`]'s doc comment) — vote
    /// compression state is per-connection, so (unlike before issue #925) a
    /// single pre-framed buffer can no longer be computed once here and
    /// cloned out to every peer.
    fn stream_broadcast(&self, tag: Tag, data: &[u8]) {
        let peers = self
            .stream_peers
            .lock()
            .expect("stream_peers mutex poisoned");
        for (_, handle) in peers.iter() {
            let _ = handle.tx.send((tag, data.to_vec()));
        }
    }

    /// Whether stateless/stateful vpack vote compression is currently
    /// negotiated with `peer_id`'s `/algorand-ws/2.2.0` stream (issue
    /// #925), and the negotiated stateful table size (`0` if only the
    /// stateless tier, or neither, negotiated). `None` if no stream is
    /// currently established with that peer.
    ///
    /// Exposed for tests — proves negotiation actually happened independent
    /// of (and prior to) any functional round-trip assertion. `cfg(test)`-
    /// only: see [`StreamPeerHandle::negotiated_features`]'s doc comment.
    #[cfg(test)]
    pub fn stream_peer_vote_compression(&self, peer_id: PeerId) -> Option<(bool, u32)> {
        self.stream_peers
            .lock()
            .expect("stream_peers mutex poisoned")
            .get(&peer_id)
            .map(|h| {
                (
                    h.negotiated_features
                        .contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK),
                    stateful_table_size(h.negotiated_features),
                )
            })
    }

    /// Whether *this* transport is the side that opened (dialed) the
    /// currently-established `/algorand-ws/2.2.0` stream to `peer_id`, as
    /// opposed to having accepted an inbound one — see
    /// [`StreamPeerHandle::initiated_locally`]'s doc comment. `None` if no
    /// stream is currently established with that peer. `cfg(test)`-only:
    /// proves the live `should_initiate_stream` wiring (issue #952) actually
    /// governs which side opens the stream.
    #[cfg(test)]
    pub fn stream_initiated_locally(&self, peer_id: PeerId) -> Option<bool> {
        self.stream_peers
            .lock()
            .expect("stream_peers mutex poisoned")
            .get(&peer_id)
            .map(|h| h.initiated_locally)
    }

    /// Number of distinct peer identities currently claimed in this
    /// transport's [`IdentityTracker`] (issue #952) — exposed for tests to
    /// confirm the connection-acceptance-level dedup wiring actually runs,
    /// independent of whether a `/algorand-ws` stream also came up for that
    /// peer.
    #[cfg(test)]
    pub fn identity_count(&self) -> usize {
        self.identity_tracker
            .lock()
            .expect("identity_tracker mutex poisoned")
            .len()
    }
}

// ---------------------------------------------------------------------------
// GossipNode — lets P2pTransport be used directly by LocalTxBroadcaster and
// AgreementNetworkBridge, both of which only depend on `Arc<dyn GossipNode>`.
// ---------------------------------------------------------------------------

#[async_trait]
impl GossipNode for P2pTransport {
    fn address(&self) -> (String, bool) {
        (self.peer_id.to_string(), self.is_listening())
    }

    async fn broadcast(
        &self,
        tag: Tag,
        data: Vec<u8>,
        _wait: bool,
        _except: Option<Arc<dyn Peer>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.publish(tag, data)
            .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e.to_string()))
    }

    async fn relay(
        &self,
        tag: Tag,
        data: Vec<u8>,
        wait: bool,
        except: Option<Arc<dyn Peer>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Gossipsub has no per-publish "except this peer" concept — the
        // mesh already avoids echoing a message straight back to whichever
        // peer it arrived from. Any `except` the caller supplies (e.g.
        // `AgreementNetworkBridge::relay`'s sender-peer exclusion) can't be
        // honored at this layer; behave like `broadcast` otherwise.
        if except.is_some() {
            tracing::trace!(
                "P2P GossipNode::relay: 'except' peer cannot be honored over gossipsub"
            );
        }
        self.broadcast(tag, data, wait, None).await
    }

    fn disconnect(&self, _peer: Arc<dyn Peer>) {
        // No peer-scoring/ban mechanism wired up at this layer yet; not
        // required for this issue's traffic-routing scope.
    }

    fn disconnect_peers(&self) {}

    async fn request_connect_outgoing(&self, _replace: bool) {
        // P2P connectivity is maintained via DHT discovery and the
        // bootstrap-peer dialing done in `P2pTransport::start`; there is no
        // separate "reconnect outgoing" hook at this layer yet.
    }

    fn get_peers(&self, _options: &[PeerOption]) -> Vec<Arc<dyn Peer>> {
        // PeerOption filtering (connected-in vs connected-out vs
        // phonebook-relay) has no P2P-side equivalent yet — every
        // currently-connected peer is returned regardless of `_options`.
        self.connected_peers
            .lock()
            .expect("connected_peers mutex poisoned")
            .iter()
            .map(|p| {
                Arc::new(P2pPeerRef {
                    peer_id: p.to_string(),
                }) as Arc<dyn Peer>
            })
            .collect()
    }

    async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // The swarm event loop, listener, and dial setup already happened
        // in `P2pTransport::start` (the associated constructor above) —
        // this trait method exists only for `GossipNode` interface
        // completeness.
        Ok(())
    }

    async fn stop(&self) {}

    fn register_handlers(&self, dispatch: Vec<TaggedMessageHandler>) {
        self.multiplexer.register_handlers(dispatch);
    }

    fn clear_handlers(&self) {
        self.multiplexer.clear_handlers(&[]);
    }

    fn register_validator_handlers(&self, dispatch: Vec<TaggedMessageValidatorHandler>) {
        self.multiplexer.register_validator_handlers(dispatch);
    }

    fn clear_validator_handlers(&self) {
        self.multiplexer.clear_validator_handlers(&[]);
    }

    fn on_network_advance(&self) {
        // No WS-style mesh-cycling concept at this layer — libp2p
        // gossipsub manages its own mesh maintenance internally.
    }

    fn get_genesis_id(&self) -> &str {
        &self.network_id
    }

    fn register_http_handler(&self, path: &str, handler: Router) {
        // Mirrors `WebsocketNetwork::register_http_handler`
        // (`ws_network.rs`) / go's `HTTPServer::RegisterHTTPHandler`
        // (`network/p2p/http.go`): nest the newly registered router under
        // `path` onto whatever was previously registered, so a caller like
        // `relay.rs`/`participate.rs` registering both `BlockService` and
        // `CatchpointService` at `/` ends up with both merged, not the
        // second overwriting the first.
        let mut guard = self.http_router.lock().expect("http_router mutex poisoned");
        let existing = std::mem::replace(&mut *guard, Router::new());
        *guard = existing.nest(path, handler);
    }
}

/// Serve one inbound `/algorand-http/1.0.0` stream as a single HTTP/1.1
/// request/response dispatched into `router` (issue #1024) — the
/// libp2p-transport equivalent of go's `HTTPServer.RegisterHTTPHandler`
/// (`network/p2p/http.go`), which wraps a `libp2phttp.Host` around the same
/// registered `http.Handler` mux and lets `go-libp2p` translate the raw
/// HTTP/1.1 bytes on the wire. `CatchpointService`/`BlockService` need no
/// change to be served this way — they are already plain `axum::Router`s,
/// transport-agnostic by construction (see `catchpoint_service.rs`'s module
/// doc comment) — exactly the same `hyper::server::conn::http1` machinery
/// `algo_network::ws_network`'s classic-transport relay server already uses
/// to serve the identical `Router` over a raw TCP connection; here the "raw
/// connection" is a libp2p stream instead, adapted to `tokio`'s
/// `AsyncRead`/`AsyncWrite` via `tokio_util::compat`.
async fn serve_p2p_http_stream(peer_id: PeerId, stream: P2pRawStream, router: Router) {
    let io = TokioIo::new(stream.compat());
    let hyper_svc = TowerToHyperService::new(router);
    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, hyper_svc)
        .await
    {
        tracing::debug!(%peer_id, error = %e, "P2P HTTP stream connection error");
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

    /// Issue #949: `ResolvedP2p::enable_p2p`/`enable_p2p_hybrid_mode` must
    /// carry the same merged (CLI-wins-over-file) flags `mode` was actually
    /// derived from, since call sites feed these into `algo_config`'s
    /// canonical `is_listen_server`/`is_hybrid_server`/
    /// `validate_p2p_hybrid_config` derivations rather than re-deriving the
    /// booleans themselves.
    #[test]
    fn resolved_enable_flags_match_the_mode_they_produced() {
        let ws_only = P2pOptions::default().resolve();
        assert_eq!(ws_only.mode, NetworkMode::WsOnly);
        assert!(!ws_only.enable_p2p);
        assert!(!ws_only.enable_p2p_hybrid_mode);

        let p2p_only = P2pOptions {
            enable_p2p: true,
            ..Default::default()
        }
        .resolve();
        assert_eq!(p2p_only.mode, NetworkMode::P2pOnly);
        assert!(p2p_only.enable_p2p);
        assert!(!p2p_only.enable_p2p_hybrid_mode);

        let hybrid = P2pOptions {
            enable_p2p_hybrid_mode: true,
            file_p2p: Some(P2pConfig {
                enable_p2p: true,
                ..Default::default()
            }),
            ..Default::default()
        }
        .resolve();
        assert_eq!(hybrid.mode, NetworkMode::Hybrid);
        assert!(hybrid.enable_p2p);
        assert!(hybrid.enable_p2p_hybrid_mode);
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
        let transport = P2pTransport::start(P2pTransportConfig {
            network_id: "test-542".to_string(),
            listen_multiaddr: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
            bootstrap_peers: vec![],
            persist_peer_id: false,
            data_dir: None,
            private_key_path: None,
            enable_dht_providers: true,
            dht_mode: String::new(),
            gossip_fanout: 4,
            incoming_connections_limit: -1,
            is_listen_server: false,
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
        let transport = P2pTransport::start(P2pTransportConfig {
            network_id: "test-542".to_string(),
            listen_multiaddr: None,
            bootstrap_peers: vec![],
            persist_peer_id: false,
            data_dir: None,
            private_key_path: None,
            enable_dht_providers: true,
            dht_mode: String::new(),
            gossip_fanout: 4,
            incoming_connections_limit: -1,
            is_listen_server: false,
        })
        .await
        .expect("start p2p transport");

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!transport.is_listening());
    }

    /// Start two transports, dial `listener` from `dialer`, and wait until
    /// gossipsub has meshed both sides on every propagation topic. Returns
    /// once both report at least one connected peer, mirroring
    /// `algo_p2p::host`'s own tests: a freshly-subscribed peer is not
    /// immediately meshed, so callers publishing right after `dial()`
    /// reliably lose the message otherwise.
    async fn connected_pair() -> (P2pTransport, P2pTransport) {
        let listener = P2pTransport::start(P2pTransportConfig {
            network_id: "test-559".to_string(),
            listen_multiaddr: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
            bootstrap_peers: vec![],
            persist_peer_id: false,
            data_dir: None,
            private_key_path: None,
            enable_dht_providers: true,
            dht_mode: String::new(),
            gossip_fanout: 4,
            incoming_connections_limit: -1,
            is_listen_server: false,
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

        let dialer = P2pTransport::start(P2pTransportConfig {
            network_id: "test-559".to_string(),
            listen_multiaddr: None,
            bootstrap_peers: vec![dial_addr],
            persist_peer_id: false,
            data_dir: None,
            private_key_path: None,
            enable_dht_providers: true,
            dht_mode: String::new(),
            gossip_fanout: 4,
            incoming_connections_limit: -1,
            is_listen_server: false,
        })
        .await
        .expect("start dialer");

        let mesh_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while tokio::time::Instant::now() < mesh_deadline {
            if listener.connected_peer_count() > 0 && dialer.connected_peer_count() > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        (listener, dialer)
    }

    /// A `MessageHandler` that records every message it receives into an
    /// unbounded channel, so a test can `.recv()` what a `Multiplexer`
    /// dispatched to it.
    struct RecordingHandler {
        tx: mpsc::UnboundedSender<IncomingMessage>,
    }

    #[async_trait]
    impl algo_network::handler::MessageHandler for RecordingHandler {
        async fn handle(&self, msg: IncomingMessage) -> algo_network::OutgoingMessage {
            let _ = self.tx.send(msg);
            algo_network::OutgoingMessage {
                action: algo_network::ForwardingPolicy::Ignore,
                tag: Tag::Transaction,
                payload: Vec::new(),
                topics: None,
            }
        }
    }

    #[tokio::test]
    async fn two_transports_connect_and_propagate_a_transaction_over_p2p() {
        let (listener, dialer) = connected_pair().await;

        let (tx, mut rx_a) = mpsc::unbounded_channel();
        listener
            .multiplexer()
            .register_handlers(vec![TaggedMessageHandler {
                tag: Tag::Transaction,
                handler: Arc::new(RecordingHandler { tx }),
            }]);

        let payload = b"a signed txn's msgpack bytes".to_vec();
        dialer
            .publish(Tag::Transaction, payload.clone())
            .expect("publish");

        let received = tokio::time::timeout(std::time::Duration::from_secs(10), rx_a.recv())
            .await
            .expect("timed out waiting for the transaction to arrive over P2P")
            .expect("transport task closed its channel");
        assert_eq!(
            received.data, payload,
            "expected the listener to receive the dialer's exact tx payload via P2P gossipsub"
        );
        assert_eq!(received.tag, Tag::Transaction);
    }

    // -----------------------------------------------------------------------
    // P2pTransport as a GossipNode — TDD anchors for #559: outbound local
    // tx propagation and agreement (proposal/vote/bundle) round-trip over
    // P2P, exercised through the exact same `LocalTxBroadcaster` /
    // `AgreementNetworkBridge` consumers `participate.rs` wires up in
    // P2pOnly mode.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn local_tx_broadcaster_propagates_over_p2p_when_wired_to_a_p2p_gossip_node() {
        use algo_network::local_tx_broadcast::{LocalTxBroadcaster, PoolIngest};
        use algo_network::tx_syncer::SeenTxCache;

        struct AcceptingIngest;
        #[async_trait]
        impl PoolIngest for AcceptingIngest {
            async fn ingest(
                &self,
                _group: Vec<algo_types::SignedTransaction>,
            ) -> Result<(), String> {
                Ok(())
            }
        }

        let (listener, dialer) = connected_pair().await;
        let listener = Arc::new(listener);
        let dialer = Arc::new(dialer);

        let (tx, mut rx_a) = mpsc::unbounded_channel();
        listener
            .multiplexer()
            .register_handlers(vec![TaggedMessageHandler {
                tag: Tag::Transaction,
                handler: Arc::new(RecordingHandler { tx }),
            }]);

        let broadcaster = LocalTxBroadcaster::new(
            Arc::new(AcceptingIngest),
            dialer.clone() as Arc<dyn GossipNode>,
            Arc::new(SeenTxCache::new(16)),
        );

        let group = vec![algo_types::SignedTransaction::default()];
        broadcaster
            .submit_group(group)
            .await
            .expect("local submit should succeed and broadcast over the P2P gossip node");

        let received = tokio::time::timeout(std::time::Duration::from_secs(10), rx_a.recv())
            .await
            .expect("timed out waiting for the locally-submitted tx to arrive over P2P")
            .expect("transport task closed its channel");
        assert_eq!(received.tag, Tag::Transaction);
        assert!(
            !received.data.is_empty(),
            "expected the encoded transaction group's bytes to arrive over P2P"
        );
    }

    /// Issue #560: dialing another `P2pTransport` must, in addition to the
    /// gossipsub mesh forming, also bring up an `/algorand-ws/2.2.0` stream
    /// between the two peers — the transport go-algorand actually uses for
    /// AV/PP/VB traffic (see this module's doc comment). Both sides should
    /// see the other as a stream peer: exactly one side opens the stream
    /// (decided by peer-ID order — see
    /// `p2p_stream_open_side_follows_peer_id_order_not_dial_direction` below
    /// for the issue #952 regression guard that it's peer-ID order, not raw
    /// TCP dial direction), the other accepts it.
    #[tokio::test]
    async fn connecting_peers_establish_an_algorand_ws_stream_in_both_directions() {
        let (listener, dialer) = connected_pair().await;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while (listener.stream_peer_count() == 0 || dialer.stream_peer_count() == 0)
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        assert_eq!(
            listener.stream_peer_count(),
            1,
            "listener should have exactly one algorand-ws stream to the dialer"
        );
        assert_eq!(
            dialer.stream_peer_count(),
            1,
            "dialer should have exactly one algorand-ws stream to the listener"
        );

        // Issue #952: identity-based connection dedup (see
        // `P2pTransport::identity_tracker`'s doc comment) claims exactly one
        // identity per connected peer — proves that live wiring runs on
        // every established connection, not just ones that also end up
        // carrying an algorand-ws stream.
        assert_eq!(listener.identity_count(), 1);
        assert_eq!(dialer.identity_count(), 1);
    }

    /// Issue #952: which side opens the `/algorand-ws/2.2.0` stream is
    /// decided by [`algo_p2p::should_initiate_stream`]'s peer-ID ordering
    /// rule (mirroring go's `streamManager.Connected`'s `localPeer >
    /// remotePeer` check), *not* by which side physically dialed the
    /// underlying TCP connection. Before this issue's live wiring, this
    /// transport used `endpoint.is_dialer()` instead — always correct in
    /// the common case, but wrong whenever the physical dialer's `PeerId`
    /// happens to be numerically higher than the physical listener's.
    ///
    /// Deterministically forces that exact scenario: generates keypairs
    /// until the physical dialer's `PeerId` is higher than the physical
    /// listener's, then asserts the *listener* (despite only having
    /// accepted an inbound TCP connection) is the side that actually
    /// dialed the libp2p-stream substream, and the dialer only accepted
    /// one — the reverse of what dial direction alone would predict.
    #[tokio::test]
    async fn p2p_stream_open_side_follows_peer_id_order_not_dial_direction() {
        use libp2p::identity::Keypair;

        // Persisted-key identities (via `private_key_path`) so each side's
        // `PeerId` is known and controllable before any connection is made —
        // `IdentityConfig`/`get_or_create_keypair` already support loading a
        // pre-written protobuf-encoded key from an explicit path.
        fn write_keypair(dir: &std::path::Path, name: &str, keypair: &Keypair) -> PathBuf {
            let path = dir.join(name);
            std::fs::write(&path, keypair.to_protobuf_encoding().unwrap()).unwrap();
            path
        }

        let dir = std::env::temp_dir().join(format!(
            "algo-p2p-stream-order-test-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // Generate keypairs until the *physical listener's* PeerId is lower
        // than the *physical dialer's* — guaranteed to terminate (each draw
        // succeeds independently with probability ~1/2).
        let (listener_kp, dialer_kp) = loop {
            let a = Keypair::generate_ed25519();
            let b = Keypair::generate_ed25519();
            if a.public().to_peer_id() < b.public().to_peer_id() {
                break (a, b);
            }
        };
        let listener_key_path = write_keypair(&dir, "listener.key", &listener_kp);
        let dialer_key_path = write_keypair(&dir, "dialer.key", &dialer_kp);

        let listener = P2pTransport::start(P2pTransportConfig {
            network_id: "test-952-order".to_string(),
            listen_multiaddr: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
            bootstrap_peers: vec![],
            persist_peer_id: false,
            data_dir: None,
            private_key_path: Some(listener_key_path),
            enable_dht_providers: false,
            dht_mode: String::new(),
            gossip_fanout: 4,
            incoming_connections_limit: -1,
            is_listen_server: false,
        })
        .await
        .expect("start listener");
        assert_eq!(listener.peer_id(), listener_kp.public().to_peer_id());

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while listener.listen_addrs().is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let listen_addr = listener.listen_addrs().first().cloned().unwrap();
        let dial_addr = listen_addr.with(Protocol::P2p(listener.peer_id()));

        let dialer = P2pTransport::start(P2pTransportConfig {
            network_id: "test-952-order".to_string(),
            listen_multiaddr: None,
            bootstrap_peers: vec![dial_addr],
            persist_peer_id: false,
            data_dir: None,
            private_key_path: Some(dialer_key_path),
            enable_dht_providers: false,
            dht_mode: String::new(),
            gossip_fanout: 4,
            incoming_connections_limit: -1,
            is_listen_server: false,
        })
        .await
        .expect("start dialer");
        assert_eq!(dialer.peer_id(), dialer_kp.public().to_peer_id());
        assert!(
            listener.peer_id() < dialer.peer_id(),
            "test setup sanity check: listener must have the lower PeerId"
        );

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while (listener.stream_peer_count() == 0 || dialer.stream_peer_count() == 0)
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        assert_eq!(listener.stream_peer_count(), 1);
        assert_eq!(dialer.stream_peer_count(), 1);

        // The physical *listener* has the lower PeerId, so per
        // `should_initiate_stream` it must be the side that opened the
        // algorand-ws stream — the opposite of what `endpoint.is_dialer()`
        // (the pre-#952 logic) would have decided.
        assert_eq!(
            listener.stream_initiated_locally(dialer.peer_id()),
            Some(true),
            "the lower-PeerId side (the physical listener here) must have initiated the stream"
        );
        assert_eq!(
            dialer.stream_initiated_locally(listener.peer_id()),
            Some(false),
            "the higher-PeerId side (the physical dialer here) must have only accepted the stream"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // P2P catch-up block/cert fetch (issue #591) — TDD anchor.
    //
    // Before this issue, `P2pTransport::unicast_peers()` did not exist and
    // this stream's read loop silently dropped every `ForwardingPolicy::Respond`
    // handler result (see `spawn_ws_peer`'s doc comment), so a `P2pOnly`-mode
    // node that missed a live-agreement round had no way to fetch the
    // missing block+cert from a P2P peer — every catch-up attempt failed
    // with `NoPeersAvailable` forever (`participate.rs`'s
    // `GossipBlockFetcher` is hardcoded to `WebsocketNetwork`, which has no
    // peers in `P2pOnly` mode).
    // -----------------------------------------------------------------------

    /// A [`LedgerForBlockService`] serving one fixed block+cert pair for a
    /// single round, mirroring `block_service.rs`'s own `MockLedger` test
    /// double.
    struct FixedRoundLedger {
        round: u64,
        block_data: Vec<u8>,
        cert_data: Vec<u8>,
    }

    impl algo_network::block_service::LedgerForBlockService for FixedRoundLedger {
        fn encoded_block_cert(
            &self,
            round: u64,
        ) -> Result<(Vec<u8>, Vec<u8>), algo_network::block_service::BlockServiceError> {
            if round == self.round {
                Ok((self.block_data.clone(), self.cert_data.clone()))
            } else {
                Err(
                    algo_network::block_service::BlockServiceError::BlockNotAvailable {
                        round,
                        latest_round: Some(self.round),
                    },
                )
            }
        }

        fn latest_round(&self) -> u64 {
            self.round
        }
    }

    /// Serves `UniEnsBlockReq` requests from a [`BlockService`], mirroring
    /// `participate.rs`'s `ParticipateBlockRequestHandler`.
    struct BlockRequestHandler {
        block_service: Arc<algo_network::block_service::BlockService>,
    }

    #[async_trait]
    impl algo_network::handler::MessageHandler for BlockRequestHandler {
        async fn handle(&self, msg: IncomingMessage) -> algo_network::OutgoingMessage {
            let (response_topics, _guard) = self.block_service.handle_ws_block_request(&msg.data);
            algo_network::OutgoingMessage {
                action: ForwardingPolicy::Respond,
                tag: Tag::TopicMsgResp,
                payload: Vec::new(),
                topics: Some(response_topics),
            }
        }
    }

    /// TDD anchor for issue #591: without a P2P block-fetch protocol wired
    /// up, `dialer.unicast_peers()` doesn't exist / is always empty, so a
    /// `CatchupService::sync_cert`-style consumer has no way to fetch a
    /// missed block over the P2P transport. This pins the fix: once both
    /// sides' `/algorand-ws/2.2.0` streams are up, the dialer can send a
    /// `UniEnsBlockReq` to the listener over that stream (via
    /// `GossipBlockSource`, exactly as `participate.rs`'s `GossipBlockFetcher`
    /// does for the WS-gossip transport) and get back the exact block the
    /// listener's `BlockService` serves.
    #[tokio::test]
    async fn p2p_unicast_peer_fetches_a_block_via_uni_ens_block_req() {
        use algo_network::block_service::BlockService;
        use algo_types::{Block, Round};

        let (listener, dialer) = connected_pair().await;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while (listener.stream_peer_count() == 0 || dialer.stream_peer_count() == 0)
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(
            dialer.stream_peer_count(),
            1,
            "precondition: stream established"
        );

        // Build a minimal, canonically-encoded block for round 7 to serve.
        let block = Block {
            round: Round(7),
            current_protocol: "future".to_string(),
            ..Default::default()
        };
        let block_data = algo_codec::canonical_encode_block(&block);

        let ledger = Arc::new(FixedRoundLedger {
            round: 7,
            block_data,
            cert_data: Vec::new(),
        });
        let block_service = Arc::new(BlockService::new(ledger, "test-591".to_string(), 0));
        listener
            .multiplexer()
            .register_handlers(vec![TaggedMessageHandler {
                tag: Tag::UniEnsBlockReq,
                handler: Arc::new(BlockRequestHandler { block_service }),
            }]);

        let peers = dialer.unicast_peers();
        assert_eq!(
            peers.len(),
            1,
            "dialer should see exactly one P2P unicast peer (the listener)"
        );

        let source = algo_rest_client::GossipBlockSource::new(peers);
        let (response, _raw) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            source.get_block_with_raw_data(Round(7)),
        )
        .await
        .expect("fetch should not time out")
        .expect("fetch should succeed against a peer serving round 7");

        assert_eq!(
            response.block.round,
            Round(7),
            "fetched block should be exactly the round the listener served"
        );
    }

    // -----------------------------------------------------------------------
    // HTTP-over-P2P (issue #1024) — the P2P-transport counterpart of go's
    // `TestLedgerServiceP2P`: `CatchpointService::http_router()` (issue #955,
    // already transport-agnostic) registered on a P2P-only `GossipNode` and
    // fetched over a raw `/algorand-http/1.0.0` libp2p stream, exactly as
    // go's `p2pHTTPRoundTripper` fetches from `rpcs.LedgerService` registered
    // via `HTTPServer.RegisterHTTPHandler` (`network/p2p/http.go`).
    // -----------------------------------------------------------------------

    /// A fixed-round catchpoint tarball, mirroring `FixedRoundLedger` above
    /// but for [`algo_network::catchpoint_service::LedgerForCatchpointService`].
    struct FixedRoundCatchpoint {
        round: u64,
        gz_bytes: Vec<u8>,
    }

    impl algo_network::catchpoint_service::LedgerForCatchpointService for FixedRoundCatchpoint {
        fn catchpoint_file_bytes(
            &self,
            round: u64,
        ) -> Result<Vec<u8>, algo_network::catchpoint_service::CatchpointServiceError> {
            if round == self.round {
                Ok(self.gz_bytes.clone())
            } else {
                Err(algo_network::catchpoint_service::CatchpointServiceError::NotFound { round })
            }
        }
    }

    #[tokio::test]
    async fn p2p_client_fetches_a_p2p_registered_catchpoint_service_over_algorand_http() {
        use algo_network::catchpoint_service::CatchpointService;
        use libp2p::futures::AsyncWriteExt;
        use std::io::Write as _;

        let (listener, dialer) = connected_pair().await;

        // Gzip-compress a small fixed payload, matching what
        // `CatchpointService`'s ledger trait expects (raw catchpoint files
        // are gzip tarballs on disk).
        let plain = b"p2p catchpoint tarball bytes".to_vec();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&plain).expect("gzip write");
        let gz_bytes = encoder.finish().expect("gzip finish");

        let ledger = Arc::new(FixedRoundCatchpoint { round: 7, gz_bytes });
        let catchpoint_service = CatchpointService::new(ledger, "test-1024".to_string());

        // Register the transport-agnostic router onto the P2P `GossipNode`
        // exactly as `relay.rs`/`participate.rs` register it onto the
        // classic WS-gossip node.
        GossipNode::register_http_handler(&listener, "/", catchpoint_service.http_router());

        let listener_peer_id = listener.peer_id();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match dialer.open_http_stream(listener_peer_id).await {
                Ok(stream) => break stream,
                Err(e) if tokio::time::Instant::now() < deadline => {
                    tracing::debug!(error = %e, "retrying P2P HTTP stream open");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => panic!("failed to open P2P HTTP stream before deadline: {e}"),
            }
        };

        // Speak raw HTTP/1.1 directly onto the stream, matching go's
        // `p2pHTTPRoundTripper.RoundTrip` (`r.Write(s)` /
        // `http.ReadResponse(bufio.NewReader(s), r)`) — no additional
        // framing beyond what `hyper::server::conn::http1` on the listener
        // side already expects.
        let request =
            b"GET /v1/test-1024/ledger/7 HTTP/1.1\r\nHost: p2p\r\nConnection: close\r\n\r\n";
        stream.write_all(request).await.expect("write HTTP request");
        stream.flush().await.expect("flush HTTP request");

        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
            .await
            .expect("reading the HTTP response should not time out")
            .expect("read HTTP response");

        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.starts_with("HTTP/1.1 200"),
            "expected a 200 response from the P2P-registered CatchpointService, got: {response_str}"
        );
        assert!(
            response_str.ends_with(std::str::from_utf8(&plain).unwrap()),
            "expected the decompressed catchpoint bytes as the response body, got: {response_str}"
        );
    }

    #[tokio::test]
    async fn agreement_network_bridge_round_trips_votes_over_p2p() {
        use algo_agreement::traits::{AgreementNetwork, Tag as AgreementTag, AGREEMENT_VOTE_TAG};
        use algo_network::AgreementNetworkBridge;

        let (listener, dialer) = connected_pair().await;
        let listener: Arc<dyn GossipNode> = Arc::new(listener);
        let dialer: Arc<dyn GossipNode> = Arc::new(dialer);

        let rt_handle = tokio::runtime::Handle::current();
        let receiver_bridge =
            AgreementNetworkBridge::with_defaults(listener.clone(), rt_handle.clone());
        receiver_bridge.start();
        let sender_bridge = AgreementNetworkBridge::with_defaults(dialer.clone(), rt_handle);

        let vote_rx = receiver_bridge.messages(&AgreementTag(AGREEMENT_VOTE_TAG));

        let payload = b"a vote's msgpack bytes".to_vec();
        tokio::task::spawn_blocking({
            let payload = payload.clone();
            move || {
                sender_bridge
                    .broadcast(&AgreementTag(AGREEMENT_VOTE_TAG), &payload)
                    .expect("broadcast a vote over the P2P gossip node")
            }
        })
        .await
        .expect("broadcast task join");

        let received = tokio::task::spawn_blocking(move || {
            vote_rx.recv_timeout(std::time::Duration::from_secs(10))
        })
        .await
        .expect("recv task join")
        .expect("timed out waiting for the vote to round-trip over P2P");
        assert_eq!(received.data, payload);
    }

    #[tokio::test]
    async fn agreement_network_bridge_round_trips_proposal_payloads_over_p2p() {
        use algo_agreement::traits::{AgreementNetwork, Tag as AgreementTag, PROPOSAL_PAYLOAD_TAG};
        use algo_network::AgreementNetworkBridge;

        let (listener, dialer) = connected_pair().await;
        let listener: Arc<dyn GossipNode> = Arc::new(listener);
        let dialer: Arc<dyn GossipNode> = Arc::new(dialer);

        let rt_handle = tokio::runtime::Handle::current();
        let receiver_bridge =
            AgreementNetworkBridge::with_defaults(listener.clone(), rt_handle.clone());
        receiver_bridge.start();
        let sender_bridge = AgreementNetworkBridge::with_defaults(dialer.clone(), rt_handle);

        let proposal_rx = receiver_bridge.messages(&AgreementTag(PROPOSAL_PAYLOAD_TAG));

        let payload = b"a block proposal payload's msgpack bytes".to_vec();
        tokio::task::spawn_blocking({
            let payload = payload.clone();
            move || {
                sender_bridge
                    .broadcast(&AgreementTag(PROPOSAL_PAYLOAD_TAG), &payload)
                    .expect("broadcast a proposal payload over the P2P gossip node")
            }
        })
        .await
        .expect("broadcast task join");

        let received = tokio::task::spawn_blocking(move || {
            proposal_rx.recv_timeout(std::time::Duration::from_secs(10))
        })
        .await
        .expect("recv task join")
        .expect("timed out waiting for the proposal payload to round-trip over P2P");
        assert_eq!(received.data, payload);
    }

    #[test]
    fn tag_topic_mapping_covers_all_gossipsub_tags() {
        assert_eq!(tag_to_topic(Tag::Transaction), Some(algo_p2p::TX_TOPIC));
        assert_eq!(
            tag_to_topic(Tag::AgreementVote),
            Some(algo_p2p::AGREEMENT_VOTE_TOPIC)
        );
        assert_eq!(
            tag_to_topic(Tag::ProposalPayload),
            Some(algo_p2p::PROPOSAL_PAYLOAD_TOPIC)
        );
        assert_eq!(
            tag_to_topic(Tag::VoteBundle),
            Some(algo_p2p::VOTE_BUNDLE_TOPIC)
        );
        assert_eq!(tag_to_topic(Tag::UniEnsBlockReq), None);

        assert_eq!(topic_to_tag(algo_p2p::TX_TOPIC), Some(Tag::Transaction));
        assert_eq!(
            topic_to_tag(algo_p2p::AGREEMENT_VOTE_TOPIC),
            Some(Tag::AgreementVote)
        );
        assert_eq!(
            topic_to_tag(algo_p2p::PROPOSAL_PAYLOAD_TOPIC),
            Some(Tag::ProposalPayload)
        );
        assert_eq!(
            topic_to_tag(algo_p2p::VOTE_BUNDLE_TOPIC),
            Some(Tag::VoteBundle)
        );
        assert_eq!(topic_to_tag("not-a-real-topic"), None);
    }

    #[tokio::test]
    async fn publish_with_unmapped_tag_returns_error() {
        let transport = P2pTransport::start(P2pTransportConfig {
            network_id: "test-559".to_string(),
            listen_multiaddr: None,
            bootstrap_peers: vec![],
            persist_peer_id: false,
            data_dir: None,
            private_key_path: None,
            enable_dht_providers: true,
            dht_mode: String::new(),
            gossip_fanout: 4,
            incoming_connections_limit: -1,
            is_listen_server: false,
        })
        .await
        .expect("start transport");

        let err = transport
            .publish(Tag::UniEnsBlockReq, vec![1, 2, 3])
            .expect_err("UniEnsBlockReq has no P2P gossipsub topic");
        assert!(err.to_string().contains("no P2P gossipsub topic"));
    }

    // -----------------------------------------------------------------------
    // vpack vote-compression wiring (issue #925) — TDD anchors.
    //
    // go-algorand's P2P transport (`network/p2pNetwork.go`'s
    // `baseWsStreamHandler`) wraps every `/algorand-ws/2.2.0` libp2p stream
    // in a real `wsPeer{conn: &wsPeerConnP2P{...}, enableVoteCompression:
    // n.config.EnableVoteCompression, voteCompressionTableSize:
    // n.voteCompressionTableSize}` — the *identical* struct and
    // `wsPeerMsgCodec` compression machinery the classic WS-gossip
    // transport uses, not a separate implementation. These tests prove the
    // Rust side's equivalent wiring: (1) real `/algorand-ws/2.2.0` peers
    // negotiate vpack vote compression during the handshake, exactly as
    // `algo_network::connect`'s classic-transport negotiation does
    // (`remote_features.intersection(config.our_features)`), and (2) the
    // production write/read-loop code paths (`compress_outgoing_vote`/
    // `decompress_incoming_vote_core`, reused verbatim from
    // `algo_network::ws_peer` — see `DEFAULT_VOTE_COMPRESSION_TABLE_SIZE`'s
    // doc comment) actually apply that negotiated compression to the raw
    // bytes placed on the wire, not just that data eventually arrives
    // correctly (which could also happen if compression silently never
    // engaged, since `AgreementVote`-tag decompression tolerates a plain
    // uncompressed fallback — see `VpackError::LikelyUncompressed`).
    // -----------------------------------------------------------------------

    /// Builds a real, canonically msgpack-encoded `UnauthenticatedVote` for
    /// use as an outgoing `AgreementVoteTag` payload — mirrors
    /// `algo_network::ws_peer`'s own `sample_vote_msgpack` test helper
    /// (issue #817), reproduced here since `algo-network`'s test-only
    /// helpers aren't part of its public API surface.
    fn sample_vote_msgpack(round: u64) -> Vec<u8> {
        use algo_agreement::{
            Period, ProposalValue, RawVote, Step, UnauthenticatedCredential, UnauthenticatedVote,
        };
        use algo_consensus_crypto::OneTimeSignature;
        use algo_types::{Address, Digest, Round};

        let vote = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x11; 32]),
                round: Round(round),
                period: Period(0),
                step: Step(1),
                proposal: ProposalValue {
                    original_period: Period(0),
                    original_proposer: Address([0u8; 32]),
                    block_digest: Digest([0x22; 32]),
                    encoding_digest: Digest([0u8; 32]),
                },
            },
            cred: UnauthenticatedCredential::new([0x33; 80]),
            sig: OneTimeSignature {
                sig: [0x44; 64],
                pk: [0x55; 32],
                pk_sig_old: [0u8; 64],
                pk2: [0x66; 32],
                pk1_sig: [0x77; 64],
                pk2_sig: [0x88; 64],
            },
        };
        algo_agreement::codec::encode_vote(&vote)
    }

    /// TDD anchor for #925, part 1: two real `P2pTransport`s (each backed
    /// by a real `algo_p2p::P2pHost`) dial over a genuine loopback TCP+Noise
    /// libp2p connection and complete the real `/algorand-ws/2.2.0`
    /// handshake. Both sides advertise stateless + stateful (table size
    /// 2048) vpack vote compression unconditionally
    /// (`DEFAULT_VOTE_COMPRESSION_TABLE_SIZE`), so both directions of the
    /// resulting stream must negotiate the full stateful tier — proven
    /// directly via [`P2pTransport::stream_peer_vote_compression`], not
    /// inferred from data eventually decoding correctly.
    #[tokio::test]
    async fn real_p2p_peers_negotiate_stateful_vote_compression_over_loopback() {
        let (listener, dialer) = connected_pair().await;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while (listener.stream_peer_count() == 0 || dialer.stream_peer_count() == 0)
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let listener_view = listener
            .stream_peer_vote_compression(dialer.peer_id())
            .expect("listener should have an established stream to the dialer");
        let dialer_view = dialer
            .stream_peer_vote_compression(listener.peer_id())
            .expect("dialer should have an established stream to the listener");

        assert_eq!(
            listener_view,
            (true, 2048),
            "listener->dialer stream should negotiate stateless + stateful(2048) vpack"
        );
        assert_eq!(
            dialer_view,
            (true, 2048),
            "dialer->listener stream should negotiate stateless + stateful(2048) vpack"
        );
    }

    /// TDD anchor for #925, part 2: with real negotiation established (part
    /// 1), agreement votes broadcast over `P2pTransport::publish` actually
    /// round-trip correctly through the compressed `/algorand-ws/2.2.0`
    /// stream path for a sequence of distinct votes (stressing the stateful
    /// encoder/decoder's shared LRU reference table across multiple
    /// messages on the same connection, not just a single one).
    #[tokio::test]
    async fn agreement_votes_round_trip_correctly_over_compressed_p2p_stream() {
        use algo_agreement::traits::{AgreementNetwork, Tag as AgreementTag, AGREEMENT_VOTE_TAG};
        use algo_network::AgreementNetworkBridge;

        let (listener, dialer) = connected_pair().await;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while (listener.stream_peer_count() == 0 || dialer.stream_peer_count() == 0)
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(
            dialer.stream_peer_vote_compression(listener.peer_id()),
            Some((true, 2048)),
            "precondition: stateful vote compression negotiated"
        );

        let listener: Arc<dyn GossipNode> = Arc::new(listener);
        let dialer: Arc<dyn GossipNode> = Arc::new(dialer);

        let rt_handle = tokio::runtime::Handle::current();
        let receiver_bridge =
            AgreementNetworkBridge::with_defaults(listener.clone(), rt_handle.clone());
        receiver_bridge.start();
        let sender_bridge = Arc::new(AgreementNetworkBridge::with_defaults(
            dialer.clone(),
            rt_handle,
        ));

        let vote_rx = receiver_bridge.messages(&AgreementTag(AGREEMENT_VOTE_TAG));

        // Several distinct real votes on the same connection: the stateful
        // vpack encoder/decoder share an LRU reference table across
        // messages, so this exercises the table's cross-message state, not
        // just a single independent compress/decompress call.
        let votes: Vec<Vec<u8>> = (0..5).map(sample_vote_msgpack).collect();
        for vote in &votes {
            let vote = vote.clone();
            tokio::task::spawn_blocking({
                let sender_bridge = Arc::clone(&sender_bridge);
                move || {
                    sender_bridge
                        .broadcast(&AgreementTag(AGREEMENT_VOTE_TAG), &vote)
                        .expect("broadcast a vote over the compressed P2P stream")
                }
            })
            .await
            .expect("broadcast task join");
        }

        // `P2pTransport::publish` fans an AV-tagged message out over *both*
        // the compressed `/algorand-ws/2.2.0` stream and gossipsub (the
        // latter a harmless no-op against a real go-algorand peer, but a
        // real second delivery path between two algod-rust transports —
        // see this module's doc comment). So a given vote's *content* may
        // legitimately arrive twice; keep draining until every distinct
        // vote sent has been observed at least once (deduping by exact
        // byte content, which is itself part of what's being proven: each
        // delivery — via either path — decompresses back to the exact
        // original bytes), bounded by a generous receive-attempt ceiling
        // so a genuine wiring regression still fails fast rather than
        // hanging.
        let mut received: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let mut attempts = 0;
        while received.len() < votes.len() && attempts < votes.len() * 4 {
            attempts += 1;
            let msg = tokio::task::spawn_blocking({
                let vote_rx = vote_rx.clone();
                move || vote_rx.recv_timeout(std::time::Duration::from_secs(10))
            })
            .await
            .expect("recv task join")
            .expect("timed out waiting for a vote to round-trip over the compressed P2P stream");
            received.insert(msg.data);
        }

        let sent: std::collections::HashSet<Vec<u8>> = votes.iter().cloned().collect();
        assert_eq!(
            received, sent,
            "every vote should round-trip byte-for-byte through the compressed P2P stream"
        );
    }

    /// TDD anchor for #925, part 3: exercises the *exact* production
    /// compression functions `spawn_ws_peer`'s writer/reader loops call
    /// (`algo_network::ws_peer::{compress_outgoing_vote,
    /// decompress_incoming_vote_core}`) directly over a real, genuinely
    /// async duplex byte stream — the same shape a raw libp2p `Stream`
    /// exposes (`futures::AsyncRead`/`AsyncWrite`) — to prove *byte-for-byte
    /// on the wire* that stateful vpack compression is actually applied,
    /// not merely that end-to-end delivery happens to still work (which
    /// would also pass if compression were silently a no-op, since AV-tag
    /// decompression tolerates an uncompressed fallback).
    ///
    /// This is the P2P-transport counterpart of
    /// `algo_network::ws_peer`'s own `write_command_compresses_agreement_vote_stateful`
    /// (issue #817) — same assertions (wire tag becomes `VP`, decompressing
    /// the captured wire bytes recovers the exact original vote), adapted
    /// to the P2P raw-stream framing (`algo_p2p::wsproto::{read_frame,
    /// write_frame}`) instead of a WebSocket sink/stream, since the two
    /// transports share the compression core but not the outer transport
    /// framing.
    #[tokio::test]
    async fn p2p_stream_wire_bytes_are_vpack_compressed_for_agreement_votes() {
        use std::sync::atomic::AtomicBool;
        use tokio_util::compat::TokioAsyncReadCompatExt;

        let (client_half, server_half) = tokio::io::duplex(64 * 1024);
        let (client_read, mut client_write) = client_half.compat().split();
        let (mut server_read, _server_write) = server_half.compat().split();

        // Both sides negotiated stateful (table size 2048), matching what
        // `real_p2p_peers_negotiate_stateful_vote_compression_over_loopback`
        // proves happens for a real handshake.
        let negotiated = advertise_vote_compression(true, DEFAULT_VOTE_COMPRESSION_TABLE_SIZE);
        let vote_table_size = stateful_table_size(negotiated);
        assert_eq!(vote_table_size, 2048);
        let stateful_vote_enabled = Arc::new(AtomicBool::new(true));
        let mut stateful_encoder: Option<StatefulEncoder> = None;

        let raw_vote = sample_vote_msgpack(42);

        // Exactly what `spawn_ws_peer`'s writer loop does for an
        // `AgreementVote`-tag message once vpack compression is negotiated.
        let (frame, need_abort) = compress_outgoing_vote(
            &raw_vote,
            vote_table_size,
            &stateful_vote_enabled,
            &mut stateful_encoder,
            "test-peer",
        );
        assert!(
            !need_abort,
            "compression must not fail against a fresh encoder"
        );
        let frame = frame.expect("stateless vpack compression should succeed for a real vote");
        write_frame(&mut client_write, &frame)
            .await
            .expect("write compressed frame to the duplex stream");

        let body = read_frame(&mut server_read)
            .await
            .expect("read the frame back off the wire");
        let (tag, wire_payload) =
            algo_network::framing::decode_frame(&body).expect("decode tag+payload");

        // The wire tag must be VP (stateful), not AV — proof the stateful
        // tier actually engaged for this outgoing vote, not just the
        // stateless layer.
        assert_eq!(
            tag,
            Tag::VotePacked,
            "first vote on a stateful-negotiated connection should already be sent as VP"
        );
        assert_ne!(
            wire_payload, raw_vote,
            "the bytes on the wire must not be the plain uncompressed vote"
        );

        // Decompress exactly what a real peer's reader loop would, via the
        // same production core function `spawn_ws_peer`'s reader uses.
        let mut stateful_decoder: Option<StatefulDecoder> = None;
        let mut decode_tag = tag;
        let (decoded, need_abort) = decompress_incoming_vote_core(
            &mut decode_tag,
            wire_payload.to_vec(),
            negotiated,
            vote_table_size,
            &mut stateful_decoder,
            &Arc::new(AtomicBool::new(true)),
            "test-peer",
        );
        assert!(!need_abort);
        assert_eq!(
            decoded.expect("VP frame should decode to a payload"),
            raw_vote,
            "decompressing the exact wire bytes must recover the original vote"
        );
        // decompress_incoming_vote_core re-tags a decoded VP frame to AV
        // for downstream dispatch, mirroring go's wsPeerMsgCodec.decompress().
        assert_eq!(decode_tag, Tag::AgreementVote);

        drop(client_read);
    }
}
