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

//! Abstraction over "an HTTP/1.1 request/response, carried over some duplex
//! byte stream" — the piece [`crate::CatchpointDownloader`] needs to speak
//! the same catchpoint-file HTTP protocol over a transport other than plain
//! TCP `reqwest` (issue #1127).
//!
//! ## Why this exists
//!
//! go-algorand's `TestLedgerFetcherP2P` (`catchup/ledgerFetcher_test.go`)
//! does not test a separate binary wire protocol for catchpoint download
//! over P2P. It proves that the *same* HTTP-shaped
//! `ledgerFetcher.headLedger`/`downloadLedger` code (built against go's
//! `network.HTTPPeer` interface) works correctly when the peer happens to be
//! a P2P-derived HTTP peer (an HTTP request/response carried over a libp2p
//! stream rather than a raw TCP connection) — go's P2P host exposes an
//! HTTP-compatible peer wrapper for exactly this reason
//! (`network/p2p/http.go`'s `p2pHTTPRoundTripper`).
//!
//! algod-rust already has the equivalent transport primitive:
//! `algo_p2p::httpproto`'s `/algorand-http/1.0.0` stream protocol, served
//! and dialed by `bin/algod-rust`'s `P2pTransport` (`open_http_stream`)
//! exactly the way go's `p2pHTTPRoundTripper` does — write a raw HTTP/1.1
//! request onto the stream, read a raw HTTP/1.1 response back. But
//! `crates/node/algo-p2p` and the concrete `P2pTransport` type both live
//! outside `algo-rest-client` (this crate cannot depend on `algo-p2p`'s
//! `libp2p`/`libp2p-stream` dependencies without pulling a large,
//! P2P-transport-specific dependency tree into every consumer of REST-only
//! catchpoint download — most of which never enable P2P at all), and
//! `bin/algod-rust` — the only crate that constructs a `P2pTransport` — is a
//! binary, not a library another crate can depend on.
//!
//! [`HttpPeerTransport`] is the seam that lets `CatchpointDownloader` stay
//! transport-agnostic (mirroring go's `network.HTTPPeer` interface) without
//! this crate depending on `algo-p2p`: `bin/algod-rust` implements this
//! trait once, wrapping `P2pTransport::open_http_stream` and adapting the
//! returned libp2p stream to `tokio`'s `AsyncRead`/`AsyncWrite` via
//! `tokio_util::compat` (exactly as `p2p_transport.rs`'s own HTTP-serving
//! accept loop already does for the server side), and hands a
//! `CatchpointDownloader` an `Arc<dyn HttpPeerTransport>` instead of a base
//! URL.

use std::collections::HashMap;

use algo_error::{AlgoError, Result};
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Marker trait for a duplex byte stream capable of carrying one raw
/// HTTP/1.1 request/response exchange — the trait-object-safe combination of
/// `AsyncRead` + `AsyncWrite` this module's helpers operate over.
pub trait AsyncDuplexStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncDuplexStream for T {}

/// A boxed [`AsyncDuplexStream`] — what [`HttpPeerTransport::open_stream`]
/// hands back. `tokio`'s blanket `AsyncRead`/`AsyncWrite` impls for
/// `Box<T>` (`T: ... + Unpin`) mean this can be read from / written to
/// directly, no `Pin` juggling required at call sites.
pub type BoxedDuplexStream = Box<dyn AsyncDuplexStream>;

/// Opens a duplex stream to a peer, capable of carrying one raw HTTP/1.1
/// request/response exchange — algod-rust's counterpart to go-algorand's
/// `network.HTTPPeer`/`p2pHTTPRoundTripper`, abstracted so
/// [`crate::CatchpointDownloader`] doesn't need to know whether the
/// underlying transport is a P2P libp2p stream, a Unix socket, or anything
/// else — only that a fresh stream can be opened per request, exactly like
/// go's `p2pHTTPRoundTripper.RoundTrip` opening one stream per request.
#[async_trait]
pub trait HttpPeerTransport: Send + Sync {
    /// Open a fresh duplex stream to `peer` (this transport's own peer
    /// identity format — e.g. a libp2p `PeerId`'s string form for the P2P
    /// implementation).
    async fn open_stream(&self, peer: &str) -> Result<BoxedDuplexStream>;
}

/// Build a raw `HEAD <path> HTTP/1.1` request, matching go's
/// `p2pHTTPRoundTripper` framing (a plain HTTP/1.1 request written directly
/// onto the stream, no additional envelope). `Connection: close` tells the
/// peer's HTTP server not to keep the (single-use, per-request) stream open
/// past this one response.
pub fn build_head_request(path: &str, host: &str) -> Vec<u8> {
    format!("HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").into_bytes()
}

/// Build a raw `GET <path> HTTP/1.1` request. `accept_gzip` mirrors
/// [`crate::CatchpointDownloader`]'s reqwest path's `Accept-Encoding: gzip`
/// header, requesting the still-compressed catchpoint tarball directly from
/// [`algo_network::catchpoint_service`]'s handler.
pub fn build_get_request(path: &str, host: &str, accept_gzip: bool) -> Vec<u8> {
    let mut s = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if accept_gzip {
        s.push_str("Accept-Encoding: gzip\r\n");
    }
    s.push_str("\r\n");
    s.into_bytes()
}

/// Write `request` to `stream` and flush it.
pub async fn write_request(stream: &mut BoxedDuplexStream, request: &[u8]) -> Result<()> {
    stream
        .write_all(request)
        .await
        .map_err(|e| stream_io_error("writing HTTP request", e))?;
    stream
        .flush()
        .await
        .map_err(|e| stream_io_error("flushing HTTP request", e))
}

/// The parsed head (status line + headers) of a raw HTTP/1.1 response, plus
/// any body bytes that were already read off the stream while scanning for
/// the header terminator (a single `stream.read()` call commonly reads past
/// the `\r\n\r\n` boundary into the start of the body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHttpResponseHead {
    /// HTTP status code (e.g. `200`, `404`).
    pub status: u16,
    /// Header names, lowercased, mapped to their (single) value. Good enough
    /// for the one header this module's callers need (`Content-Length`) —
    /// a request with the more permissive assumption of a single value per
    /// header name matches every response `algo_network::catchpoint_service`
    /// actually sends.
    pub headers: HashMap<String, String>,
    /// Body bytes already read past the header terminator.
    pub prefetched_body: Vec<u8>,
}

impl RawHttpResponseHead {
    /// The `Content-Length` header value, parsed as `u64`, if present and
    /// well-formed.
    pub fn content_length(&self) -> Option<u64> {
        self.headers.get("content-length")?.trim().parse().ok()
    }
}

/// Safety cap on how many header bytes this module will buffer while
/// scanning for the `\r\n\r\n` terminator, before giving up on a
/// malformed/hostile peer. Far larger than any real
/// `algo_network::catchpoint_service` response's headers.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Read and parse a raw HTTP/1.1 response's status line and headers off
/// `stream`, stopping at the `\r\n\r\n` header terminator. Mirrors go's
/// `http.ReadResponse(bufio.NewReader(s), r)` (`p2pHTTPRoundTripper.RoundTrip`),
/// just without pulling in a full HTTP client library for it — algod-rust's
/// P2P transport crates are deliberately kept free of one (see this module's
/// doc comment).
pub async fn read_http_response_head(
    stream: &mut BoxedDuplexStream,
) -> Result<RawHttpResponseHead> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];

    loop {
        if let Some(pos) = find_header_terminator(&buf) {
            let head = &buf[..pos];
            let body_start = pos + 4;
            let prefetched_body = buf[body_start..].to_vec();
            let (status, headers) = parse_head(head)?;
            return Ok(RawHttpResponseHead {
                status,
                headers,
                prefetched_body,
            });
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(AlgoError::RestClient {
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP response headers exceeded the size limit without a terminator",
                )),
                context: "reading HTTP response head over P2P stream".into(),
            });
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| stream_io_error("reading HTTP response head", e))?;
        if n == 0 {
            return Err(AlgoError::RestClient {
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before HTTP response headers were complete",
                )),
                context: "reading HTTP response head over P2P stream".into(),
            });
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find_header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_head(head: &[u8]) -> Result<(u16, HashMap<String, String>)> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");

    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| AlgoError::RestClient {
            source: Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("malformed HTTP status line: {status_line:?}"),
            )),
            context: "parsing HTTP response head over P2P stream".into(),
        })?;

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    Ok((status, headers))
}

fn stream_io_error(context: &str, e: std::io::Error) -> AlgoError {
    AlgoError::RestClient {
        source: Box::new(e),
        context: format!("{context} over P2P stream"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn build_head_request_shape() {
        let req = build_head_request("/v1/test-v1.0/ledger/7", "some-peer");
        assert_eq!(
            String::from_utf8(req).unwrap(),
            "HEAD /v1/test-v1.0/ledger/7 HTTP/1.1\r\nHost: some-peer\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn build_get_request_shape_with_gzip() {
        let req = build_get_request("/v1/test-v1.0/ledger/7", "some-peer", true);
        assert_eq!(
            String::from_utf8(req).unwrap(),
            "GET /v1/test-v1.0/ledger/7 HTTP/1.1\r\nHost: some-peer\r\nConnection: close\r\n\
             Accept-Encoding: gzip\r\n\r\n"
        );
    }

    #[test]
    fn build_get_request_shape_without_gzip() {
        let req = build_get_request("/v1/test-v1.0/ledger/7", "some-peer", false);
        assert_eq!(
            String::from_utf8(req).unwrap(),
            "GET /v1/test-v1.0/ledger/7 HTTP/1.1\r\nHost: some-peer\r\nConnection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn read_http_response_head_parses_status_and_headers() {
        let (client, mut server) = duplex(4096);
        tokio::spawn(async move {
            server
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-algorand-ledger-v2.1\r\n\
                      Content-Length: 5\r\n\r\nhello",
                )
                .await
                .unwrap();
        });

        let mut boxed: BoxedDuplexStream = Box::new(client);
        let head = read_http_response_head(&mut boxed).await.unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(head.content_length(), Some(5));
        assert_eq!(
            head.headers.get("content-type").unwrap(),
            "application/x-algorand-ledger-v2.1"
        );
        assert_eq!(head.prefetched_body, b"hello");
    }

    #[tokio::test]
    async fn read_http_response_head_reports_404() {
        let (client, mut server) = duplex(4096);
        tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let mut boxed: BoxedDuplexStream = Box::new(client);
        let head = read_http_response_head(&mut boxed).await.unwrap();
        assert_eq!(head.status, 404);
        assert_eq!(head.content_length(), Some(0));
    }

    #[tokio::test]
    async fn read_http_response_head_errors_on_early_close() {
        let (client, mut server) = duplex(4096);
        tokio::spawn(async move {
            server.write_all(b"HTTP/1.1 200 O").await.unwrap();
            // Drop without ever sending the header terminator.
        });

        let mut boxed: BoxedDuplexStream = Box::new(client);
        let result = read_http_response_head(&mut boxed).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn write_request_delivers_bytes_to_the_peer() {
        let (client, mut server) = duplex(4096);
        let mut boxed: BoxedDuplexStream = Box::new(client);

        let request = build_head_request("/v1/test/ledger/1", "peer");
        let request_clone = request.clone();
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; request_clone.len()];
            server.read_exact(&mut buf).await.unwrap();
            buf
        });

        write_request(&mut boxed, &request).await.unwrap();
        let received = reader.await.unwrap();
        assert_eq!(received, request);
    }
}
