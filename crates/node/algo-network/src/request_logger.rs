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

//! HTTP request-logging middleware for the relay's incoming connection log
//! (issue #1088, Phase 17 gap).
//!
//! Mirrors go-algorand's `network/requestLogger.go` `RequestLogger`
//! middleware, gated behind the same `EnableRequestLogger` config flag
//! (`enable_request_logger` here — see
//! [`crate::ws_network::WebsocketNetworkConfig::enable_request_logger`]).
//! Go's version wraps the `http.ResponseWriter` to capture the status code
//! and response body length and emits a `telemetryspec.HTTPRequestEvent`;
//! algod-rust has no equivalent structured-telemetry-event system (it uses
//! the `tracing` crate throughout), so this instead emits a `tracing::info!`
//! event carrying the same fields go's `telemetryspec.HTTPRequestDetails`
//! does.
//!
//! Unlike go's version, this middleware reads the response's
//! `Content-Length` header rather than wrapping/counting the body bytes
//! itself — the relay router this is layered onto also serves the gossip
//! WebSocket upgrade endpoint, whose successful (101 Switching Protocols)
//! response body is the raw hijacked connection; buffering or re-reading
//! that body to count bytes would break the upgrade. Reading the header
//! avoids touching the body at all.

use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::Response;
use std::net::SocketAddr;

use crate::handshake::{INSTANCE_NAME_HEADER, USER_AGENT_HEADER};

/// A single logged HTTP request/response, mirroring go's
/// `telemetryspec.HTTPRequestDetails`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestDetails {
    /// The client's address, with any port stripped (go: `Client`, built
    /// from `strings.Split(request.RemoteAddr, ":")[0]`).
    pub client: String,
    /// The peer's self-reported instance name, from the
    /// `X-Algorand-InstanceName` header (empty if absent).
    pub instance_name: String,
    /// `"<METHOD> <URI> <VERSION>"`, with the URI truncated to 64 bytes
    /// (go: `fmt.Sprintf("%s %s %s", request.Method, uri, request.Proto)`).
    pub request: String,
    /// The response status code.
    pub status_code: u16,
    /// The response body length in bytes, taken from the `Content-Length`
    /// response header (`0` if absent — see the module docs for why this
    /// isn't measured by counting bytes directly).
    pub body_length: u64,
    /// The client's `User-Agent` header value (empty if absent).
    pub user_agent: String,
}

/// go's `uri := request.RequestURI; if len(uri) > 64 { uri = uri[:64] }`.
const MAX_LOGGED_URI_LEN: usize = 64;

/// Raw inputs for [`build_request_details`], grouped into one struct so the
/// builder stays under clippy's argument-count limit (this is otherwise a
/// flat 1:1 mirror of go's `logRequest` locals).
#[derive(Debug, Clone, Copy)]
pub struct RawRequestDetails<'a> {
    pub client_addr: &'a str,
    pub method: &'a str,
    pub uri: &'a str,
    pub proto: &'a str,
    pub status_code: u16,
    pub body_length: u64,
    pub instance_name: &'a str,
    pub user_agent: &'a str,
}

/// Builds the structured request-completion record for one HTTP request,
/// mirroring go's `RequestLogger.logRequest`.
///
/// A plain function (rather than inline in the middleware) so the URI
/// truncation and client-address port-stripping can be unit-tested
/// directly, without needing to drive an axum request/response round trip.
pub fn build_request_details(raw: RawRequestDetails<'_>) -> HttpRequestDetails {
    // Go splits on ':' and keeps the first segment; a bracketed IPv6
    // literal like "[::1]:4160" would keep "[" as the client — go has the
    // same quirk (it doesn't special-case IPv6), so this stays 1:1.
    let client = raw
        .client_addr
        .split(':')
        .next()
        .unwrap_or(raw.client_addr)
        .to_string();

    let mut short_uri = raw.uri.to_string();
    if short_uri.len() > MAX_LOGGED_URI_LEN {
        short_uri.truncate(MAX_LOGGED_URI_LEN);
    }

    HttpRequestDetails {
        client,
        instance_name: raw.instance_name.to_string(),
        request: format!("{} {short_uri} {}", raw.method, raw.proto),
        status_code: raw.status_code,
        body_length: raw.body_length,
        user_agent: raw.user_agent.to_string(),
    }
}

/// Axum middleware wrapping [`build_request_details`] and logging the
/// result via `tracing::info!`. Only installed on the relay router when
/// `enable_request_logger` is set — see
/// [`crate::ws_network::WebsocketNetwork::build_relay_router`].
pub async fn request_logger_middleware(req: Request, next: Next) -> Response {
    let method = req.method().as_str().to_string();
    let uri = req.uri().to_string();
    let proto = format!("{:?}", req.version());

    let client_addr = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.to_string())
        .unwrap_or_default();
    let instance_name = header_str(&req, INSTANCE_NAME_HEADER);
    let user_agent = header_str(&req, USER_AGENT_HEADER);

    let response = next.run(req).await;

    let status_code = response.status().as_u16();
    let body_length = response
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    let details = build_request_details(RawRequestDetails {
        client_addr: &client_addr,
        method: &method,
        uri: &uri,
        proto: &proto,
        status_code,
        body_length,
        instance_name: &instance_name,
        user_agent: &user_agent,
    });

    tracing::info!(
        client = %details.client,
        instance_name = %details.instance_name,
        request = %details.request,
        status_code = details.status_code,
        body_length = details.body_length,
        user_agent = %details.user_agent,
        "http request"
    );

    response
}

fn header_str(req: &Request, name: &str) -> String {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only default so each test only spells out the fields it cares
    /// about, matching `RawRequestDetails`'s field-by-field mirror of go's
    /// `logRequest` locals without repeating every field in every test.
    impl Default for RawRequestDetails<'_> {
        fn default() -> Self {
            Self {
                client_addr: "127.0.0.1:1234",
                method: "GET",
                uri: "/status",
                proto: "HTTP/1.1",
                status_code: 200,
                body_length: 0,
                instance_name: "",
                user_agent: "",
            }
        }
    }

    #[test]
    fn strips_port_from_client_address() {
        let details = build_request_details(RawRequestDetails {
            client_addr: "203.0.113.7:54321",
            uri: "/v1/genesis/gossip",
            status_code: 101,
            ..Default::default()
        });
        assert_eq!(details.client, "203.0.113.7");
    }

    #[test]
    fn client_address_without_port_passes_through() {
        let details = build_request_details(RawRequestDetails {
            client_addr: "203.0.113.7",
            body_length: 12,
            ..Default::default()
        });
        assert_eq!(details.client, "203.0.113.7");
    }

    #[test]
    fn truncates_long_uri_to_64_bytes() {
        let long_path = format!("/{}", "a".repeat(100));
        assert!(long_path.len() > 64);
        let details = build_request_details(RawRequestDetails {
            uri: &long_path,
            ..Default::default()
        });
        let uri_field = details.request.split(' ').nth(1).unwrap();
        assert_eq!(uri_field.len(), 64);
        assert_eq!(uri_field, &long_path[..64]);
    }

    #[test]
    fn short_uri_is_not_truncated() {
        let details = build_request_details(RawRequestDetails {
            method: "POST",
            uri: "/v1/genesis/gossip",
            status_code: 101,
            ..Default::default()
        });
        assert_eq!(details.request, "POST /v1/genesis/gossip HTTP/1.1");
    }

    #[test]
    fn carries_instance_name_and_user_agent_through() {
        let details = build_request_details(RawRequestDetails {
            client_addr: "10.0.0.1:1",
            body_length: 42,
            instance_name: "relay-1",
            user_agent: "algod-rust/0.1.0",
            ..Default::default()
        });
        assert_eq!(details.instance_name, "relay-1");
        assert_eq!(details.user_agent, "algod-rust/0.1.0");
        assert_eq!(details.status_code, 200);
        assert_eq!(details.body_length, 42);
    }

    // Wiring smoke test: the middleware must pass an ordinary request
    // through unchanged (same status, same body) when layered onto a
    // router — mirroring the "does it forward correctly" half of go's
    // `TestRequestLogger` without needing algod-rust's non-existent
    // telemetry-event bus to observe the emitted log line.
    #[tokio::test]
    async fn middleware_passes_response_through_unchanged() {
        use axum::body::Body;
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(axum::middleware::from_fn(request_logger_middleware));

        let request = axum::http::Request::builder()
            .uri("/ping")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"pong");
    }
}
