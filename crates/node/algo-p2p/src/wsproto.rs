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

//! The `/algorand-ws/2.2.0` (and legacy `/algorand-ws/1.0.0`) libp2p stream
//! protocol: go-algorand's actual wire protocol for agreement (proposal/
//! vote/bundle) traffic in P2P mode.
//!
//! # Why this module exists
//!
//! Issue #540's investigation found that go-algorand v5.0.0-stable's own
//! `gossipSubTags` map wires gossipsub up for the `TX` tag **only** —
//! proposals, votes, and vote bundles are never published on gossipsub in
//! P2P mode. Instead (`../go-algorand/network/p2p/streams.go` +
//! `network/p2pNetwork.go`'s `wsStreamHandlerV1`/`wsStreamHandlerV22`), a
//! real go-algorand P2P node opens one raw bidirectional libp2p stream per
//! connected peer on the negotiated protocol ID (`AlgorandWsProtocolV22` =
//! `/algorand-ws/2.2.0`, falling back to `AlgorandWsProtocolV1` =
//! `/algorand-ws/1.0.0` pre-consensus-v41) and tunnels the **exact same**
//! tag-prefixed message framing the WS-gossip transport uses over a raw
//! WebSocket connection (`network/wsPeer.go`) — just with a different
//! transport-level wrapper (`network/p2pPeer.go`'s `wsPeerConnP2P`, a
//! `websocket.Conn`-shaped adapter around the libp2p `network.Stream`).
//!
//! `algo_network`'s existing `framing`/`handshake` modules already implement
//! this exact wire format (tag + msgpack payload; header-based handshake
//! carrying genesis ID / protocol version / peer features) for the WS
//! transport. This module re-derives the same framing and handshake content
//! for the raw-stream transport go actually uses, adding only what a raw
//! libp2p stream needs that a WebSocket connection provides for free:
//!
//! - **Message length delimiting.** A WebSocket already has message
//!   boundaries; a raw byte stream does not, so
//!   [`wsPeerConnP2P.WriteMessage`]/`NextReader`
//!   (`../go-algorand/network/p2pPeer.go`) prefix every frame with a 4-byte
//!   big-endian length — mirrored here by [`read_frame`]/[`write_frame`].
//! - **Handshake framing.** Instead of HTTP request/response headers, the
//!   handshake headers are exchanged as a single 2-byte-length-prefixed
//!   canonical-msgpack-encoded `map[string][]string`
//!   (`../go-algorand/network/p2pMetainfo.go`'s `peerMetaHeaders` type) —
//!   mirrored here by [`read_peer_meta_headers`]/[`write_peer_meta_headers`].
//!   The header *names* and *values* are otherwise identical to the WS
//!   handshake's, so this module converts to/from an `http::HeaderMap` at
//!   the boundary and reuses `algo_network::handshake`'s existing
//!   version/genesis validation rather than re-deriving it.
//!
//! Everything downstream of a successful handshake — the tag+payload frame
//! contents themselves — is unchanged from the WS wire format, which is why
//! this module only has to solve delimiting and handshake framing, not
//! reinvent message encoding.
//!
//! Reference: `../go-algorand/network/p2p/p2p.go` (protocol ID constants),
//! `network/p2pPeer.go` (`wsPeerConnP2P`), `network/p2pMetainfo.go`
//! (`peerMetaHeaders`, `readPeerMetaHeaders`, `writePeerMetaHeaders`),
//! `network/p2pNetwork.go` (`wsStreamHandlerV1`/`wsStreamHandlerV22`).

use std::collections::BTreeMap;
use std::io;

use futures_util::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::StreamProtocol;

/// go: `AlgorandWsProtocolV1 = "/algorand-ws/1.0.0"`. Retained pre-consensus-v41
/// for peers that haven't upgraded; this crate always prefers V22 for
/// outbound dials (see [`ALGORAND_WS_PROTOCOL_V22`]) and only accepts V1
/// inbound for completeness.
pub const ALGORAND_WS_PROTOCOL_V1: StreamProtocol = StreamProtocol::new("/algorand-ws/1.0.0");

/// go: `AlgorandWsProtocolV22 = "/algorand-ws/2.2.0"` — the protocol ID this
/// crate negotiates for agreement (proposal/vote/bundle) traffic, since
/// go-algorand's own gossipsub wiring only ever carries the `TX` tag (see
/// this module's doc comment).
pub const ALGORAND_WS_PROTOCOL_V22: StreamProtocol = StreamProtocol::new("/algorand-ws/2.2.0");

/// Maximum single-frame length this side will accept, mirroring go's
/// `MaxMessageLength` (`network/wsNetwork.go`) sanity bound against a
/// corrupt or malicious peer claiming an unbounded frame size. go's own
/// constant is `config.MaxTxGroupSize*proto.MaxTxnNoteBytes` in the worst
/// case; a flat generous ceiling well above any real Algorand message
/// (largest today: certificates / vote bundles) is used here instead of
/// threading consensus params through this transport-only crate.
pub const MAX_FRAME_LENGTH: u32 = 32 * 1024 * 1024;

/// Errors from the raw-stream framing/handshake layer.
#[derive(Debug, thiserror::Error)]
pub enum WsProtoError {
    #[error("I/O error on algorand-ws stream: {0}")]
    Io(#[from] io::Error),
    #[error("frame length {0} exceeds MAX_FRAME_LENGTH ({MAX_FRAME_LENGTH})")]
    FrameTooLarge(u32),
    #[error("peer meta headers exceed the 64KiB (u16) length limit")]
    HeadersTooLarge,
    #[error("failed to decode peer meta headers msgpack: {0}")]
    HeaderDecode(String),
    #[error("peer does not support any of our supported protocol versions")]
    NoVersionMatch,
}

// ---------------------------------------------------------------------------
// Frame delimiting — go: wsPeerConnP2P.NextReader / WriteMessage
// ---------------------------------------------------------------------------

/// Read one length-delimited frame (a raw tag+payload byte string, as
/// produced by `algo_network::framing::encode_frame`) from `stream`.
///
/// Go: `wsPeerConnP2P.NextReader` (`network/p2pPeer.go`) — a 4-byte
/// big-endian length prefix followed by exactly that many bytes.
pub async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, WsProtoError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LENGTH {
        return Err(WsProtoError::FrameTooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

/// Write one length-delimited frame to `stream`.
///
/// Go: `wsPeerConnP2P.WriteMessage` (`network/p2pPeer.go`).
pub async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    body: &[u8],
) -> Result<(), WsProtoError> {
    let len = u32::try_from(body.len()).map_err(|_| WsProtoError::FrameTooLarge(u32::MAX))?;
    if len > MAX_FRAME_LENGTH {
        return Err(WsProtoError::FrameTooLarge(len));
    }
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Handshake — go: network/p2pMetainfo.go's peerMetaHeaders
// ---------------------------------------------------------------------------

/// The subset of handshake header content this crate needs from a peer's
/// meta-headers exchange. Mirrors go's `peerMetaInfo`
/// (`network/p2pMetainfo.go`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerMeta {
    pub telemetry_id: String,
    pub instance_name: String,
    pub version: String,
    pub genesis_id: String,
    pub features: String,
}

/// Parameters this side announces during the handshake. Reuses
/// `algo_network::handshake::OutgoingHeaderParams`'s field set at the
/// call site rather than duplicating it here — this crate stays free of an
/// `algo-network` dependency (see [`encode_headers`]/[`decode_headers`]),
/// so callers pass the already-built header map in.
pub type PeerMetaHeaders = BTreeMap<String, Vec<String>>;

/// Encode a header map into go's `peerMetaHeaders` msgpack wire form: a
/// canonical-msgpack `map[string][]string`. `rmp_serde`'s default (non-named
/// struct) serializer already produces this shape for a `BTreeMap<String,
/// Vec<String>>`.
fn encode_headers(headers: &PeerMetaHeaders) -> Vec<u8> {
    rmp_serde::to_vec(headers).expect("BTreeMap<String, Vec<String>> is always serializable")
}

/// Decode go's `peerMetaHeaders` msgpack wire form back into a header map.
fn decode_headers(bytes: &[u8]) -> Result<PeerMetaHeaders, WsProtoError> {
    rmp_serde::from_slice(bytes).map_err(|e| WsProtoError::HeaderDecode(e.to_string()))
}

/// Write the 2-byte-length-prefixed msgpack peer-meta-headers message.
///
/// Go: `writePeerMetaHeaders` (`network/p2pMetainfo.go`).
pub async fn write_peer_meta_headers<S: AsyncWrite + Unpin>(
    stream: &mut S,
    headers: &PeerMetaHeaders,
) -> Result<(), WsProtoError> {
    let data = encode_headers(headers);
    let len = u16::try_from(data.len()).map_err(|_| WsProtoError::HeadersTooLarge)?;
    let mut msg = Vec::with_capacity(2 + data.len());
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(&data);
    stream.write_all(&msg).await?;
    stream.flush().await?;
    Ok(())
}

/// Read and decode the 2-byte-length-prefixed msgpack peer-meta-headers
/// message.
///
/// Go: `readPeerMetaHeaders` (`network/p2pMetainfo.go`).
pub async fn read_peer_meta_headers<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<PeerMetaHeaders, WsProtoError> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    decode_headers(&body)
}

/// Build the header map this side announces, using the same header *names*
/// `algo_network::handshake` defines for the WS transport (kept as string
/// literals here to avoid an `algo-p2p` -> `algo-network` dependency for
/// just five constants — see `handshake.rs`'s own
/// `X-Algorand-*` constants, asserted byte-identical by this module's own
/// tests).
pub fn build_headers(
    genesis_id: &str,
    telemetry_id: &str,
    instance_name: &str,
    peer_features: &str,
    supported_versions: &[&str],
) -> PeerMetaHeaders {
    let mut h = PeerMetaHeaders::new();
    h.insert(
        "X-Algorand-TelId".to_string(),
        vec![telemetry_id.to_string()],
    );
    h.insert(
        "X-Algorand-InstanceName".to_string(),
        vec![instance_name.to_string()],
    );
    h.insert(
        "X-Algorand-Genesis".to_string(),
        vec![genesis_id.to_string()],
    );
    h.insert(
        "X-Algorand-Peer-Features".to_string(),
        vec![peer_features.to_string()],
    );
    // Go's `checkProtocolVersionMatch` checks Accept-Version first, falling
    // back to the single Version header — send both, matching `setHeaders`.
    h.insert(
        "X-Algorand-Version".to_string(),
        vec![supported_versions
            .first()
            .copied()
            .unwrap_or("2.2")
            .to_string()],
    );
    h.insert(
        "X-Algorand-Accept-Version".to_string(),
        supported_versions.iter().map(|s| s.to_string()).collect(),
    );
    h
}

/// Extract [`PeerMeta`] from a decoded header map, matching against
/// `supported_versions` the same way go's `readPeerMetaHeaders` does
/// (Accept-Version first, falling back to Version).
pub fn extract_peer_meta(
    headers: &PeerMetaHeaders,
    supported_versions: &[&str],
) -> Result<PeerMeta, WsProtoError> {
    let get_first = |k: &str| -> String {
        headers
            .get(k)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default()
    };

    let version = headers
        .get("X-Algorand-Accept-Version")
        .into_iter()
        .flatten()
        .find(|v| supported_versions.contains(&v.as_str()))
        .cloned()
        .or_else(|| {
            let v = get_first("X-Algorand-Version");
            supported_versions.contains(&v.as_str()).then_some(v)
        })
        .ok_or(WsProtoError::NoVersionMatch)?;

    Ok(PeerMeta {
        telemetry_id: get_first("X-Algorand-TelId"),
        instance_name: get_first("X-Algorand-InstanceName"),
        genesis_id: get_first("X-Algorand-Genesis"),
        features: get_first("X-Algorand-Peer-Features"),
        version,
    })
}

/// Perform the outbound (dialer) side of the V22 handshake: write our
/// headers, then read and validate the peer's response.
///
/// Go: the `!incoming` branch of `wsStreamHandlerV22`
/// (`network/p2pNetwork.go`) — write first, then read the response.
pub async fn handshake_outbound<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    our_headers: &PeerMetaHeaders,
    supported_versions: &[&str],
) -> Result<PeerMeta, WsProtoError> {
    write_peer_meta_headers(stream, our_headers).await?;
    let response = read_peer_meta_headers(stream).await?;
    extract_peer_meta(&response, supported_versions)
}

/// Perform the inbound (listener) side of the V22 handshake: read the
/// peer's headers, validate, then write our response.
///
/// Go: the `incoming` branch of `wsStreamHandlerV22`.
pub async fn handshake_inbound<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    our_headers: &PeerMetaHeaders,
    supported_versions: &[&str],
) -> Result<PeerMeta, WsProtoError> {
    let request = read_peer_meta_headers(stream).await?;
    let meta = extract_peer_meta(&request, supported_versions)?;
    write_peer_meta_headers(stream, our_headers).await?;
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    // An in-memory duplex pipe stands in for a libp2p `Stream` (which also
    // just implements `futures::AsyncRead + AsyncWrite`) so these tests
    // exercise the exact framing/handshake logic without a live libp2p
    // connection. `tokio::io::duplex` + `tokio_util::compat` bridges
    // Tokio's AsyncRead/Write to the `futures`-crate traits this module's
    // functions are generic over (the same traits a real libp2p `Stream`
    // implements).
    fn duplex_pair() -> (
        tokio_util::compat::Compat<tokio::io::DuplexStream>,
        tokio_util::compat::Compat<tokio::io::DuplexStream>,
    ) {
        use tokio_util::compat::TokioAsyncReadCompatExt;
        let (a, b) = tokio::io::duplex(4096);
        (a.compat(), b.compat())
    }

    #[test]
    fn protocol_ids_match_go_exactly() {
        assert_eq!(ALGORAND_WS_PROTOCOL_V1.as_ref(), "/algorand-ws/1.0.0");
        assert_eq!(ALGORAND_WS_PROTOCOL_V22.as_ref(), "/algorand-ws/2.2.0");
    }

    #[tokio::test]
    async fn frame_round_trips_through_length_prefix() {
        let (mut a, mut b) = duplex_pair();
        let payload = b"\x00\x01hello world".to_vec();
        let writer = write_frame(&mut a, &payload);
        let reader = read_frame(&mut b);
        let (write_res, read_res) = tokio::join!(writer, reader);
        write_res.unwrap();
        assert_eq!(read_res.unwrap(), payload);
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_allocating() {
        let (mut a, mut b) = duplex_pair();
        // Hand-craft a frame claiming a length beyond MAX_FRAME_LENGTH.
        let bogus_len = (MAX_FRAME_LENGTH + 1).to_be_bytes();
        let writer = async move {
            AsyncWriteExt::write_all(&mut a, &bogus_len).await.unwrap();
            AsyncWriteExt::flush(&mut a).await.unwrap();
        };
        let reader = read_frame(&mut b);
        let (_, read_res) = tokio::join!(writer, reader);
        assert!(matches!(read_res, Err(WsProtoError::FrameTooLarge(_))));
    }

    #[tokio::test]
    async fn handshake_round_trips_and_matches_version() {
        let (mut a, mut b) = duplex_pair();
        let headers_a = build_headers("mynet-v1", "tel-a", "inst-a", "ppzstd", &["2.2"]);
        let headers_b = build_headers("mynet-v1", "tel-b", "inst-b", "ppzstd", &["2.2"]);

        let outbound = handshake_outbound(&mut a, &headers_a, &["2.2"]);
        let inbound = handshake_inbound(&mut b, &headers_b, &["2.2"]);
        let (out_res, in_res) = tokio::join!(outbound, inbound);

        let out_meta = out_res.expect("outbound handshake succeeds");
        let in_meta = in_res.expect("inbound handshake succeeds");

        // The dialer (a) sees the listener's (b) announced identity, and
        // vice versa — mirrors go's wsStreamHandlerV22 exchanging each
        // side's own headers, not echoing the peer's back.
        assert_eq!(out_meta.telemetry_id, "tel-b");
        assert_eq!(out_meta.genesis_id, "mynet-v1");
        assert_eq!(out_meta.version, "2.2");
        assert_eq!(in_meta.telemetry_id, "tel-a");
        assert_eq!(in_meta.genesis_id, "mynet-v1");
        assert_eq!(in_meta.version, "2.2");
    }

    #[tokio::test]
    async fn handshake_rejects_no_shared_version() {
        let (mut a, mut b) = duplex_pair();
        let headers_a = build_headers("mynet-v1", "", "", "", &["9.9"]);
        let headers_b = build_headers("mynet-v1", "", "", "", &["2.2"]);

        // The inbound (listener) side rejects with `NoVersionMatch` after
        // reading the request but *before* writing a response (mirrors
        // go's `wsStreamHandlerV22`, which resets the stream on a bad
        // version without replying) — so the outbound (dialer) side's
        // `read_peer_meta_headers` would block forever waiting for a
        // response that is never sent. Only assert on the inbound
        // rejection here; run outbound in a background task under a
        // timeout so the test can't hang if this regresses, rather than
        // `tokio::join!`-ing both (which requires both sides to complete).
        let outbound =
            tokio::spawn(async move { handshake_outbound(&mut a, &headers_a, &["2.2"]).await });
        let in_res = handshake_inbound(&mut b, &headers_b, &["2.2"]).await;
        assert!(matches!(in_res, Err(WsProtoError::NoVersionMatch)));

        // Dropping `b` (inbound is done with it) closes its half of the
        // duplex pipe, which unblocks outbound's pending read with an
        // EOF/error rather than hanging.
        drop(b);
        let out_res = tokio::time::timeout(std::time::Duration::from_secs(5), outbound)
            .await
            .expect("outbound must observe the closed stream, not hang")
            .expect("outbound task should not panic");
        assert!(
            out_res.is_err(),
            "outbound must fail once the peer closes without replying"
        );
    }

    // -------------------------------------------------------------------
    // go: `TestReadPeerMetaHeaders` (`network/p2pMetainfo_test.go:50`) —
    // per-`Read`-call error-injection / short-read cases. Go drives these
    // through a hand-rolled `MockStream` that returns exactly one chunk
    // (or an error) per `Read` call; this crate's `read_peer_meta_headers`
    // uses `AsyncReadExt::read_exact`, whose whole contract is looping over
    // however many partial reads (or a propagated error) the underlying
    // stream produces until the buffer is full — so these tests drive that
    // same contract through a real chunked/failing stream rather than
    // asserting it never mattered.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn read_peer_meta_headers_handles_length_split_across_multiple_reads() {
        // Mirrors go's "Verify short reads are handled: length arrives in
        // two reads" case.
        let (mut a, mut b) = duplex_pair();
        let headers = build_headers("mynet-v1", "tel", "inst", "feat", &["2.2"]);
        let data = encode_headers(&headers);
        let len = u16::try_from(data.len()).unwrap();
        let len_bytes = len.to_be_bytes();

        let writer = async move {
            // Write the 2-byte length prefix as two separate single-byte
            // writes, then the body in one write.
            AsyncWriteExt::write_all(&mut a, &len_bytes[..1])
                .await
                .unwrap();
            AsyncWriteExt::flush(&mut a).await.unwrap();
            AsyncWriteExt::write_all(&mut a, &len_bytes[1..])
                .await
                .unwrap();
            AsyncWriteExt::write_all(&mut a, &data).await.unwrap();
            AsyncWriteExt::flush(&mut a).await.unwrap();
        };
        let reader = read_peer_meta_headers(&mut b);
        let (_, read_res) = tokio::join!(writer, reader);
        let decoded = read_res.expect("split length reads must still be assembled correctly");
        assert_eq!(decoded, headers);
    }

    #[tokio::test]
    async fn read_peer_meta_headers_handles_body_split_across_multiple_reads() {
        // Mirrors go's "Verify short reads are handled: body arrives in
        // two reads" case.
        let (mut a, mut b) = duplex_pair();
        let headers = build_headers("mynet-v1", "tel", "inst", "feat", &["2.2"]);
        let data = encode_headers(&headers);
        let len = u16::try_from(data.len()).unwrap();
        let mid = data.len() / 2;

        let writer = async move {
            AsyncWriteExt::write_all(&mut a, &len.to_be_bytes())
                .await
                .unwrap();
            AsyncWriteExt::flush(&mut a).await.unwrap();
            AsyncWriteExt::write_all(&mut a, &data[..mid]).await.unwrap();
            AsyncWriteExt::flush(&mut a).await.unwrap();
            AsyncWriteExt::write_all(&mut a, &data[mid..]).await.unwrap();
            AsyncWriteExt::flush(&mut a).await.unwrap();
        };
        let reader = read_peer_meta_headers(&mut b);
        let (_, read_res) = tokio::join!(writer, reader);
        let decoded = read_res.expect("split body reads must still be assembled correctly");
        assert_eq!(decoded, headers);
    }

    #[tokio::test]
    async fn read_peer_meta_headers_surfaces_io_error_on_incomplete_length() {
        // Mirrors go's "Error case: incomplete length read then EOF" /
        // "Error case: error reading length" — the peer hangs up (or the
        // underlying transport errors) after less than 2 bytes arrive.
        let (a, mut b) = duplex_pair();
        let writer = async move {
            let mut a = a;
            AsyncWriteExt::write_all(&mut a, &[0x01]).await.unwrap();
            AsyncWriteExt::flush(&mut a).await.unwrap();
            drop(a); // closes the pipe, so the pending read_exact sees EOF
        };
        let reader = read_peer_meta_headers(&mut b);
        let (_, read_res) = tokio::join!(writer, reader);
        assert!(
            matches!(read_res, Err(WsProtoError::Io(_))),
            "a stream that closes mid-length-prefix must surface an I/O error, got: {read_res:?}"
        );
    }

    #[tokio::test]
    async fn read_peer_meta_headers_surfaces_io_error_on_incomplete_body() {
        // Mirrors go's "Error case: incomplete message read then EOF" /
        // "Error case: error reading message" — the length prefix arrives
        // intact but the peer hangs up partway through the body.
        let (a, mut b) = duplex_pair();
        let writer = async move {
            let mut a = a;
            AsyncWriteExt::write_all(&mut a, &100u16.to_be_bytes())
                .await
                .unwrap();
            AsyncWriteExt::write_all(&mut a, &[0u8; 10]).await.unwrap();
            AsyncWriteExt::flush(&mut a).await.unwrap();
            drop(a);
        };
        let reader = read_peer_meta_headers(&mut b);
        let (_, read_res) = tokio::join!(writer, reader);
        assert!(
            matches!(read_res, Err(WsProtoError::Io(_))),
            "a stream that closes mid-body must surface an I/O error, got: {read_res:?}"
        );
    }

    #[tokio::test]
    async fn read_peer_meta_headers_rejects_corrupt_msgpack() {
        // Mirrors go's "Error case: invalid messagepack (unmarshaling
        // error)" — a valid length prefix followed by bytes that aren't a
        // valid msgpack map.
        let (mut a, mut b) = duplex_pair();
        let corrupt = [0x99u8, 0x01, 0x02];
        let writer = async move {
            AsyncWriteExt::write_all(&mut a, &(corrupt.len() as u16).to_be_bytes())
                .await
                .unwrap();
            AsyncWriteExt::write_all(&mut a, &corrupt).await.unwrap();
            AsyncWriteExt::flush(&mut a).await.unwrap();
        };
        let reader = read_peer_meta_headers(&mut b);
        let (_, read_res) = tokio::join!(writer, reader);
        assert!(matches!(read_res, Err(WsProtoError::HeaderDecode(_))));
    }

    #[tokio::test]
    async fn write_peer_meta_headers_surfaces_io_error_when_peer_hung_up() {
        // Mirrors go's `TestWritePeerMetaHeaders` "Error case: write error"
        // — the peer end is gone before the write happens, so the write
        // must fail rather than silently succeed.
        let (mut a, b) = duplex_pair();
        drop(b);
        let headers = build_headers("mynet-v1", "tel", "inst", "feat", &["2.2"]);
        let result = write_peer_meta_headers(&mut a, &headers).await;
        assert!(
            matches!(result, Err(WsProtoError::Io(_))),
            "writing to a peer that already hung up must surface an I/O error, got: {result:?}"
        );
    }

    #[test]
    fn encode_headers_produces_canonical_msgpack_map_of_string_to_string_array() {
        // Mirrors go's msgp-generated encoding for `map[string][]string`:
        // a msgpack map whose values are msgpack arrays of strings — no
        // struct-specific framing (peerMetaHeaders is a plain map type, not
        // a `_struct`-tagged struct), so plain rmp_serde serialization of a
        // BTreeMap<String, Vec<String>> is wire-compatible.
        let mut headers = PeerMetaHeaders::new();
        headers.insert("X-Algorand-Genesis".to_string(), vec!["net-v1".to_string()]);
        let encoded = encode_headers(&headers);
        let decoded = decode_headers(&encoded).unwrap();
        assert_eq!(decoded, headers);
    }

    // -----------------------------------------------------------------------
    // Randomized roundtrip: go's `TestRandomizedEncodingpeerMetaHeaders` /
    // `TestRandomizedEncodingpeerMetaValues` (network/msgp_gen_test.go) run
    // `protocol.RunEncodingTest` 1000 times over `quick`-randomized instances
    // of `peerMetaHeaders` (`map[string]peerMetaValues`) and `peerMetaValues`
    // (`[]string`) respectively, asserting encode -> decode reproduces the
    // original value and re-encoding the decoded value reproduces the
    // original bytes. Since this crate uses plain `rmp_serde` msgpack
    // (`encode_headers`/`decode_headers`) rather than a hand-rolled
    // MarshalMsg/UnmarshalMsg pair, the analogous property is: for many
    // randomly generated `BTreeMap<String, Vec<String>>` / `Vec<String>`
    // instances (including empty maps/vecs, empty strings, and duplicate
    // values), encode -> decode -> re-encode is lossless and idempotent.
    fn random_string(rng: &mut impl rand::RngCore, max_len: usize) -> String {
        use rand::Rng;
        let len = rng.gen_range(0..=max_len);
        (0..len)
            .map(|_| {
                // Printable ASCII range, including a few header-hostile
                // characters (spaces, dashes) to catch escaping bugs.
                let c = rng.gen_range(0x20u8..=0x7Eu8);
                c as char
            })
            .collect()
    }

    #[test]
    fn randomized_roundtrip_peer_meta_headers() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0FFEE);
        for _ in 0..200 {
            let num_keys = rng.gen_range(0..=6);
            let mut headers = PeerMetaHeaders::new();
            for _ in 0..num_keys {
                let key = random_string(&mut rng, 24);
                let num_values = rng.gen_range(0..=4);
                let values: Vec<String> = (0..num_values)
                    .map(|_| random_string(&mut rng, 32))
                    .collect();
                headers.insert(key, values);
            }
            let encoded = encode_headers(&headers);
            let decoded = decode_headers(&encoded).expect("random headers must decode");
            assert_eq!(
                decoded, headers,
                "roundtrip must reproduce the original map"
            );
            // Re-encoding the decoded value must reproduce the same bytes
            // (mirrors go's re-encoding-consistency check).
            assert_eq!(
                encode_headers(&decoded),
                encoded,
                "re-encoding the decoded value must be byte-identical"
            );
        }
    }

    #[test]
    fn randomized_roundtrip_peer_meta_values() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xFACADE);
        for _ in 0..200 {
            let num_values = rng.gen_range(0..=8);
            let values: Vec<String> = (0..num_values)
                .map(|_| random_string(&mut rng, 40))
                .collect();
            let encoded = rmp_serde::to_vec(&values).expect("Vec<String> is always serializable");
            let decoded: Vec<String> =
                rmp_serde::from_slice(&encoded).expect("random values must decode");
            assert_eq!(decoded, values, "roundtrip must reproduce the original vec");
            let re_encoded =
                rmp_serde::to_vec(&decoded).expect("Vec<String> is always serializable");
            assert_eq!(
                re_encoded, encoded,
                "re-encoding the decoded value must be byte-identical"
            );
        }
    }
}
