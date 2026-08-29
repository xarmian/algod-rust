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

//! Comprehensive error taxonomy for WebSocket peer connectivity.
//!
//! Errors are split by layer so callers can decide which failures are
//! retryable vs fatal without matching on string messages.

use thiserror::Error;

// ---------------------------------------------------------------------------
// Connection-level errors
// ---------------------------------------------------------------------------

/// Errors that occur while establishing a WebSocket connection (DNS, TCP, TLS,
/// or the HTTP upgrade handshake).
#[derive(Debug, Error)]
pub enum WsConnectError {
    /// DNS resolution failed for the relay address.
    #[error("DNS resolution failed: {0}")]
    DnsFailure(String),

    /// TCP connection could not be established (timeout, refused, etc.).
    #[error("TCP connect failed: {0}")]
    TcpFailure(String),

    /// TLS handshake failed (certificate error, protocol mismatch, etc.).
    #[error("TLS handshake failed: {0}")]
    TlsFailure(String),

    /// The WebSocket upgrade was rejected by the remote peer.
    #[error("WebSocket upgrade failed: {0}")]
    UpgradeRejected(String),

    /// HTTP 412 Precondition Failed — genesis ID mismatch.
    #[error("genesis mismatch (HTTP 412)")]
    GenesisMismatch,

    /// HTTP 429 Too Many Requests — the relay is rate-limiting us.
    #[error("too many requests (HTTP 429), retry after {retry_after_secs:?}s")]
    TooManyRequests {
        /// The number of seconds to wait before retrying, parsed from the
        /// `Retry-After` header. `None` if the header was absent or invalid.
        retry_after_secs: Option<u64>,
    },

    /// HTTP 508 Loop Detected — we connected to ourselves.
    #[error("self-connection detected (HTTP 508)")]
    SelfLoop,

    /// The WebSocket upgrade failed with an unexpected HTTP status code.
    #[error("unexpected HTTP status {status}: {body}")]
    HttpStatus {
        /// The HTTP status code.
        status: u16,
        /// Truncated, ASCII-filtered response body.
        body: String,
    },

    /// The handshake did not complete within the allowed time.
    #[error("connection timed out")]
    Timeout,

    /// Algorand handshake error (protocol version, genesis, self-loop at header level).
    #[error("handshake failed: {0}")]
    Handshake(Box<HandshakeError>),

    /// Identity verification error during connection.
    #[error("identity verification failed: {0}")]
    Identity(#[from] IdentityError),

    /// Generic I/O error during connection setup.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Tungstenite-level error during connection.
    #[error("WebSocket error: {0}")]
    Tungstenite(#[from] tokio_tungstenite::tungstenite::Error),
}

// ---------------------------------------------------------------------------
// Handshake (protocol negotiation) errors
// ---------------------------------------------------------------------------

/// Errors during the Algorand-level handshake that happens *after* the
/// WebSocket connection is established.
#[derive(Debug, Error)]
pub enum HandshakeError {
    /// The peer advertised an incompatible protocol version.
    #[error("protocol version mismatch: local={local}, remote={remote}")]
    VersionMismatch { local: String, remote: String },

    /// The peer's genesis ID / genesis hash does not match ours.
    #[error("genesis mismatch: expected {expected}, got {actual}")]
    GenesisMismatch { expected: String, actual: String },

    /// We connected to ourselves (same node ID).
    #[error("self-connection detected")]
    SelfLoop,

    /// A required HTTP header was missing from the upgrade response.
    #[error("missing required header: {0}")]
    MissingHeader(String),

    /// The handshake did not complete within the allowed time.
    #[error("handshake timed out")]
    Timeout,
}

// ---------------------------------------------------------------------------
// Identity / challenge-response errors
// ---------------------------------------------------------------------------

/// Errors related to the identity-challenge protocol that peers use to prove
/// they control the private key corresponding to their advertised node ID.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// The peer's signature over the challenge bytes was invalid.
    #[error("invalid identity signature")]
    BadSignature,

    /// The identity challenge response header was missing or empty.
    ///
    /// This is non-fatal: the server simply did not participate in identity
    /// exchange (e.g. older relay software).
    #[error("identity challenge header missing")]
    HeaderMissing,

    /// The challenge bytes in the response did not match what we sent.
    #[error("identity challenge mismatch")]
    ChallengeMismatch,

    /// The public address in the challenge does not match any of our addresses.
    /// In Go, this is not an error -- the responder silently skips identity
    /// exchange. We model it as a distinct variant so callers can handle it
    /// without disconnecting.
    #[error("address not matched")]
    AddressNotMatched,

    /// The identity exchange did not complete within the allowed time.
    #[error("identity verification timed out")]
    Timeout,

    /// The peer's public key could not be decoded.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// The base64-encoded header value could not be decoded.
    #[error("base64 decode failed: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// The msgpack payload could not be decoded into the expected type.
    #[error("msgpack decode failed: {0}")]
    MsgpackDecode(#[from] rmp_serde::decode::Error),
}

// ---------------------------------------------------------------------------
// Runtime peer errors
// ---------------------------------------------------------------------------

/// Errors that occur on an already-established peer connection.
#[derive(Debug, Error)]
pub enum PeerError {
    /// The outbound send buffer is full — the remote side is not reading fast
    /// enough (or at all).
    #[error("send buffer full")]
    SendBufferFull,

    /// A read from the WebSocket returned an error.
    #[error("read error: {0}")]
    ReadError(String),

    /// A write to the WebSocket returned an error.
    #[error("write error: {0}")]
    WriteError(String),

    /// The peer did not send a keepalive/ping within the expected interval.
    #[error("keepalive timeout")]
    KeepaliveTimeout,

    /// The connection was closed by the remote peer.
    #[error("connection closed by remote")]
    ConnectionClosed,

    /// A unicast request timed out waiting for a response.
    #[error("request timed out")]
    RequestTimeout,

    /// The response channel was dropped (peer closed during request).
    #[error("response channel closed")]
    ResponseChannelClosed,

    /// No request tracker is configured on this peer.
    #[error("no request tracker configured")]
    NoRequestTracker,

    /// Tungstenite-level error on an active connection.
    #[error("WebSocket error: {0}")]
    Tungstenite(#[from] tokio_tungstenite::tungstenite::Error),
}

// ---------------------------------------------------------------------------
// Phonebook errors
// ---------------------------------------------------------------------------

/// Errors related to the peer phonebook.
#[derive(Debug, Error)]
pub enum PhonebookError {
    /// A DNS SRV lookup failed.
    #[error("SRV lookup failed for {service}.{protocol}.{name}: {reason}")]
    SrvLookupFailed {
        service: String,
        protocol: String,
        name: String,
        reason: String,
    },

    /// DNS bootstrap configuration is invalid.
    #[error("DNS bootstrap error: {0}")]
    DnsBootstrap(#[from] crate::dns_bootstrap::DnsBootstrapError),
}
