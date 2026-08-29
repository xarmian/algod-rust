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

//! AGPL section 13 source-availability pointer (issue #742).
//!
//! go-algorand's `COPYING_FAQ` (item 3) explains the AGPLv3 section 13
//! obligation: anyone who modifies the AGPL-licensed node software and lets
//! users interact with it over a network must prominently offer the exact
//! corresponding source for download, and that offer cannot be removed.
//! `docs/LICENSING.md` (added in #731/PR #734) recorded this obligation but
//! noted no in-node mechanism yet satisfied it for network users (as opposed
//! to operators reading the README). This module is that mechanism for HTTP
//! clients: every response — success, error, unmatched route, CORS preflight
//! — carries an `X-Algod-Rust-Source` header pointing at the exact source
//! repository. `bin/algod-rust`'s startup log carries the equivalent pointer
//! for operators running the binary directly (see `algo-rest-api::server`).
//!
//! This is a header addition only: it must never touch any response *body*,
//! since `/versions` and other JSON bodies are byte-for-byte parity-tested
//! against go-algorand (see `bin/algod-rust/tests/live_go_parity.rs`).

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// The header name carrying the source-availability pointer.
pub const SOURCE_HEADER_NAME: &str = "x-algod-rust-source";

/// The exact source repository URL, matching the AGPL section 13 "exact
/// corresponding source" requirement.
pub const SOURCE_URL: &str = "https://github.com/xarmian/algod-rust";

/// Middleware that stamps `X-Algod-Rust-Source` on every response.
///
/// Registered as the outermost layer in `router::build_router` (added last,
/// so it wraps every other layer — including `cors_layer`'s short-circuited
/// `OPTIONS` preflight response and the unmatched-route fallback) so the
/// header is present unconditionally, matching the "cannot be removed"
/// obligation. Because it only appends a brand-new header name after
/// `next.run()` returns, it cannot disturb any existing header's value or
/// the relative order of headers set by inner layers.
pub async fn source_header_layer(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        HeaderName::from_static(SOURCE_HEADER_NAME),
        HeaderValue::from_static(SOURCE_URL),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn test_router() -> Router {
        Router::new()
            .route("/x", get(|| async { "hi" }))
            .layer(middleware::from_fn(source_header_layer))
    }

    #[tokio::test]
    async fn success_response_carries_source_header() {
        let resp = test_router()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/x")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.headers().get(SOURCE_HEADER_NAME).unwrap(), SOURCE_URL);
    }

    #[tokio::test]
    async fn header_present_even_when_wrapping_a_short_circuited_response() {
        // Simulates cors_layer's OPTIONS short-circuit: an inner layer that
        // never calls next() must still see the header added by this
        // (outer) middleware.
        async fn short_circuit(_req: Request, _next: Next) -> Response {
            axum::http::StatusCode::NO_CONTENT.into_response()
        }
        use axum::response::IntoResponse;

        let router = Router::new()
            .route("/y", get(|| async { "unreachable" }))
            .layer(middleware::from_fn(short_circuit))
            .layer(middleware::from_fn(source_header_layer));

        let resp = router
            .oneshot(
                axum::http::Request::builder()
                    .method("OPTIONS")
                    .uri("/y")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NO_CONTENT);
        assert_eq!(resp.headers().get(SOURCE_HEADER_NAME).unwrap(), SOURCE_URL);
    }
}
