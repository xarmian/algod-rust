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

//! HTTP server wrapper for the Algorand REST API.
//!
//! Provides `ApiServer` which binds to a TCP address and serves the API
//! router until shutdown is signaled. On startup, it writes `algod.net`
//! and reads or generates `algod.token` and `algod.admin.token` in the
//! data directory, matching go-algorand's behavior.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::auth;
use crate::node::NodeInterface;
use crate::router::{self, TokenConfig};

/// Write a token to a file with restrictive permissions (0o600 on Unix).
///
/// On Unix systems, the file is created with mode `0o600` (owner read/write
/// only) to prevent other users from reading the API token. On non-Unix
/// platforms, this falls back to `std::fs::write` with default permissions.
fn write_token_file(path: &Path, token: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(token.as_bytes())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, token)
    }
}

/// Emits the AGPL section 13 startup log banner, recording where the
/// corresponding source is available for operators running the binary
/// directly -- HTTP clients get the equivalent pointer via the
/// `X-Algod-Rust-Source` response header (see `crate::source_header`).
///
/// Factored out of [`ApiServer::serve`] as a standalone function so it can
/// be unit tested (see the `tests` module below) without needing a full
/// `NodeInterface` implementation and a bound listener.
fn log_source_banner() {
    tracing::info!(
        source = crate::source_header::SOURCE_URL,
        "algod-rust is free software licensed under the AGPLv3 -- corresponding source is available at the URL above"
    );
}

/// Name of the file containing the bound listen address.
const NET_FILE: &str = "algod.net";

/// Name of the file containing the public API token.
const TOKEN_FILE: &str = "algod.token";

/// Name of the file containing the admin API token.
const ADMIN_TOKEN_FILE: &str = "algod.admin.token";

/// Configuration for the API server.
#[derive(Debug, Clone)]
pub struct ApiServerConfig {
    /// The socket address to bind to (e.g. `127.0.0.1:8080`).
    pub listen_addr: SocketAddr,

    /// Path to the node's data directory where token files are stored.
    /// If `None`, token files are not read/written and random tokens are used.
    pub data_dir: Option<PathBuf>,

    /// Override for the public API token. If `None`, the token is read from
    /// `algod.token` in the data directory (or generated if it doesn't exist).
    pub api_token: Option<String>,

    /// Override for the admin API token. If `None`, the token is read from
    /// `algod.admin.token` in the data directory (or generated if it doesn't exist).
    pub admin_token: Option<String>,

    /// Turns off authentication for public (non-admin) API endpoints.
    /// Mirrors go-algorand's `config.Local.DisableAPIAuth` (issue #748).
    /// Callers should default this to `false` (auth enabled), matching
    /// go's default, when no `config.json` override is present.
    pub disable_api_auth: bool,

    /// Mirrors go-algorand's `config.Local.EnablePrivateNetworkAccessHeader`
    /// (issue #751). Callers should default this to `false`, matching go.
    pub enable_private_network_access_header: bool,

    /// `config.json`'s `RestReadTimeoutSeconds`/`RestWriteTimeoutSeconds`
    /// (issue #751), go: `version[4]:"15"`/`"120"`. Wired into a single
    /// `tower_http::timeout::TimeoutLayer` bounding total per-request time
    /// at `max(read, write)` seconds -- axum/hyper's server builder has no
    /// separate read/write-phase timeout the way go's `net/http.Server`
    /// does, so the two collapse into one approximation here. `0` (or
    /// both `0`) disables the layer entirely rather than producing a
    /// zero-duration timeout that would fail every request.
    pub rest_read_timeout_seconds: i64,
    /// See `rest_read_timeout_seconds`.
    pub rest_write_timeout_seconds: i64,

    /// `config.json`'s `RestConnectionsSoftLimit` (issue #751), go:
    /// `version[20]:"1024"`. Wired as a `tower::limit::ConcurrencyLimitLayer`
    /// bound on in-flight requests. `0` disables the layer (unbounded).
    pub rest_connections_soft_limit: u64,
    /// `config.json`'s `RestConnectionsHardLimit` (issue #751), go:
    /// `version[20]:"2048"`. Wired into `ApiServer::serve`'s accept loop:
    /// once concurrently-open connections reach this count, newly accepted
    /// sockets are closed immediately rather than handed to the router,
    /// mirroring go's `limitlistener.RejectingLimitListener`. `0` disables
    /// the check (unbounded).
    pub rest_connections_hard_limit: u64,
}

/// The REST API HTTP server.
///
/// Wraps an axum server with the full Algorand REST API router.
pub struct ApiServer {
    config: ApiServerConfig,
}

impl ApiServer {
    /// Create a new API server with the given configuration.
    pub fn new(config: ApiServerConfig) -> Self {
        Self { config }
    }

    /// Resolve the public API token.
    ///
    /// Priority: config override > file on disk > generate new token.
    fn resolve_token(
        data_dir: Option<&Path>,
        override_token: Option<&str>,
        filename: &str,
    ) -> std::io::Result<String> {
        // 1. Use override if provided
        if let Some(token) = override_token {
            return Ok(token.to_string());
        }

        // 2. Try to read from file
        if let Some(dir) = data_dir {
            let path = dir.join(filename);
            match std::fs::read_to_string(&path) {
                Ok(contents) => {
                    let token = contents.trim().to_string();
                    if !token.is_empty() {
                        tracing::info!(file = %path.display(), "loaded API token from file");
                        return Ok(token);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // File doesn't exist, will generate below
                }
                Err(e) => {
                    tracing::warn!(
                        file = %path.display(),
                        err = %e,
                        "failed to read token file, generating new token"
                    );
                }
            }

            // 3. Generate new token and write to file
            let token = auth::generate_token();
            if let Err(e) = write_token_file(&path, &token) {
                tracing::warn!(
                    file = %path.display(),
                    err = %e,
                    "failed to write generated token file"
                );
            } else {
                tracing::info!(file = %path.display(), "generated new API token file");
            }
            return Ok(token);
        }

        // No data dir and no override -- generate an ephemeral token
        Ok(auth::generate_token())
    }

    /// Write the `algod.net` file containing the bound address.
    fn write_net_file(data_dir: &Path, addr: SocketAddr) {
        let path = data_dir.join(NET_FILE);
        if let Err(e) = std::fs::write(&path, addr.to_string()) {
            tracing::warn!(
                file = %path.display(),
                err = %e,
                "failed to write algod.net file"
            );
        } else {
            tracing::info!(file = %path.display(), addr = %addr, "wrote algod.net");
        }
    }

    /// Start serving HTTP requests.
    ///
    /// This method:
    /// 1. Resolves API tokens (from config, files, or generates new ones)
    /// 2. Builds the router with authentication middleware
    /// 3. Binds to the configured address
    /// 4. Writes `algod.net` to the data directory (if configured)
    /// 5. Spawns the server task and returns immediately
    ///
    /// Returns the actual bound address (useful when binding to port 0)
    /// and a `JoinHandle` that completes when the server shuts down.
    /// Callers can await the handle to detect server failures or wait
    /// for graceful shutdown to finish.
    pub async fn serve<N: NodeInterface>(
        &self,
        node: Arc<N>,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(SocketAddr, JoinHandle<()>), std::io::Error> {
        // Resolve tokens
        let api_token = Self::resolve_token(
            self.config.data_dir.as_deref(),
            self.config.api_token.as_deref(),
            TOKEN_FILE,
        )?;
        let admin_token = Self::resolve_token(
            self.config.data_dir.as_deref(),
            self.config.admin_token.as_deref(),
            ADMIN_TOKEN_FILE,
        )?;

        let tokens = TokenConfig {
            api_token,
            admin_token,
            enable_experimental_api: node.enable_experimental_api(),
            disable_api_auth: self.config.disable_api_auth,
            enable_private_network_access_header: self.config.enable_private_network_access_header,
        };

        let mut router = router::build_router(node, tokens);

        // `RestConnectionsHardLimit` (issue #751): once concurrently
        // in-flight requests reach this count, further requests are
        // rejected immediately with 503 rather than admitted at all —
        // approximating go's `limitlistener.RejectingLimitListener`
        // (a raw-connection-count reject) at the request layer, since
        // `axum::serve` in this axum version takes a concrete
        // `tokio::net::TcpListener` with no hook to customize accept-time
        // admission. `0` disables the check (unbounded), matching
        // `Local::default()` never producing `0` for this field in
        // practice but keeping the knob well-defined for a hand-edited
        // `config.json`.
        if self.config.rest_connections_hard_limit > 0 {
            let limit = self.config.rest_connections_hard_limit;
            let in_flight = Arc::new(AtomicU64::new(0));
            router = router.layer(axum::middleware::from_fn(move |request, next| {
                let in_flight = in_flight.clone();
                async move { connection_hard_limit_guard(limit, in_flight, request, next).await }
            }));
        }

        // `RestConnectionsSoftLimit` (issue #751): backpressures (queues,
        // rather than rejects) admission once in-flight requests reach
        // this count, matching go's soft-limit admission-queue semantics.
        if self.config.rest_connections_soft_limit > 0 {
            router = router.layer(ConcurrencyLimitLayer::new(
                self.config.rest_connections_soft_limit as usize,
            ));
        }

        // `RestReadTimeoutSeconds`/`RestWriteTimeoutSeconds` (issue #751):
        // collapsed into a single overall per-request timeout (see
        // `ApiServerConfig`'s doc comment for why axum/hyper's server
        // builder can't split read/write phases the way go's
        // `net/http.Server` does). `0` for both disables the layer.
        let timeout_secs = self
            .config
            .rest_read_timeout_seconds
            .max(self.config.rest_write_timeout_seconds);
        if timeout_secs > 0 {
            router = router.layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                Duration::from_secs(timeout_secs as u64),
            ));
        }

        let listener = bind_listener(self.config.listen_addr).await?;
        let local_addr = listener.local_addr()?;

        // Write algod.net file
        if let Some(ref data_dir) = self.config.data_dir {
            Self::write_net_file(data_dir, local_addr);
        }

        tracing::info!(addr = %local_addr, "REST API server listening");
        log_source_banner();

        let handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router)
                .with_graceful_shutdown(shutdown)
                .await
            {
                tracing::error!(err = %e, "REST API server failed");
            }
        });

        Ok((local_addr, handle))
    }
}

/// Bind the REST API listener, applying go-algorand's port-0-falls-back-
/// to-8080 special case (issue #953).
///
/// Mirrors `daemon/algod/server.go`'s `makeListener`
/// (`../go-algorand/daemon/algod/server.go:294-307`): when the configured
/// address's port is `0` ("pick any free port"), first *prefer* port 8080
/// on the same host, and only fall back to the OS-assigned ephemeral port
/// (the original `addr`, unchanged) if 8080 is already taken. A
/// non-zero configured port is bound directly with no special-casing,
/// exactly as before this issue.
///
/// go's version string-matches only the literal `"127.0.0.1:0"`/`":0"`
/// addresses; this is generalized to "any address whose port is 0" since
/// `SocketAddr` doesn't retain the original string form and every real
/// caller already only ever passes one of those two forms (or an explicit
/// non-zero port) for `EndpointAddress`. This is a strict superset of go's
/// behavior and produces identical results for both forms go recognizes.
async fn bind_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    if addr.port() == 0 {
        let preferred = SocketAddr::new(addr.ip(), 8080);
        if let Ok(listener) = TcpListener::bind(preferred).await {
            return Ok(listener);
        }
        // 8080 unavailable (or a bind error unrelated to the port) — fall
        // back to the original, port-0 address, matching go's fallthrough
        // to `net.Listen("tcp", addr)`.
    }
    TcpListener::bind(addr).await
}

/// The `RestConnectionsHardLimit` admission check (issue #751), factored
/// out of `serve`'s middleware closure so it's a plain testable `async fn`.
///
/// Approximates go's `limitlistener.RejectingLimitListener` (a raw
/// TCP-accept-time hard cap) at the HTTP-request layer: once `in_flight`
/// reaches `limit`, a newly arriving request is rejected with `503`
/// *without* incrementing the counter or invoking the inner service at
/// all, mirroring "closing requests with no response" rather than queuing
/// them (that queuing behavior belongs to `RestConnectionsSoftLimit`'s
/// `ConcurrencyLimitLayer` instead). The counter is decremented once the
/// inner service's response (or panic-unwind) has been produced, via an
/// RAII guard, so a slow request's slot is held for its entire duration.
/// The increment-then-check is optimistic (not compare-and-swap), so
/// concurrently racing requests right at the boundary can over-admit by a
/// small amount — an acceptable approximation for an operational ceiling,
/// not a hard invariant.
async fn connection_hard_limit_guard(
    limit: u64,
    in_flight: Arc<AtomicU64>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if in_flight.fetch_add(1, Ordering::Relaxed) >= limit {
        in_flight.fetch_sub(1, Ordering::Relaxed);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many concurrent REST requests",
        )
            .into_response();
    }
    struct DecrementGuard(Arc<AtomicU64>);
    impl Drop for DecrementGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::Relaxed);
        }
    }
    let _guard = DecrementGuard(in_flight);
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    /// A `MakeWriter` that appends every write into a shared in-memory
    /// buffer, so a test can assert on the exact rendered log line without
    /// depending on this repo's real (JSON/env-filter) tracing setup.
    #[derive(Clone, Default)]
    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    impl io::Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for BufferWriter {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Verifies the AGPL section 13 startup banner ([`log_source_banner`])
    /// actually emits a log line naming the exact source repository URL --
    /// the "Startup log banner verified" acceptance criterion from issue
    /// #742.
    #[test]
    fn startup_banner_logs_the_exact_source_url() {
        let buffer = BufferWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, log_source_banner);

        let logged = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(
            logged.contains(crate::source_header::SOURCE_URL),
            "startup banner must log the exact source repository URL, got: {logged:?}"
        );
        assert!(
            logged.contains("AGPLv3"),
            "startup banner should mention the AGPLv3 license, got: {logged:?}"
        );
    }

    // --- `RestConnectionsHardLimit` (issue #751) ------------------------

    /// Below the limit: the guard admits the request and runs the inner
    /// service, and releases its slot afterward (checked by running three
    /// requests back-to-back against a limit of 1 — each one must be
    /// admitted once the prior one's slot has been released).
    #[tokio::test]
    async fn hard_limit_guard_admits_below_limit_and_releases_slot() {
        use axum::body::Body;
        use axum::extract::Request;
        use axum::middleware::Next;
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let in_flight = Arc::new(AtomicU64::new(0));
        let limit = 1u64;
        let router = Router::new().route("/x", get(|| async { "hi" })).layer(
            axum::middleware::from_fn(move |req: Request, next: Next| {
                let in_flight = in_flight.clone();
                async move { connection_hard_limit_guard(limit, in_flight, req, next).await }
            }),
        );

        for _ in 0..3 {
            let resp = router
                .clone()
                .oneshot(Request::builder().uri("/x").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "each sequential request must be admitted once the prior one's slot is released"
            );
        }
    }

    /// A request that arrives while `limit` slots are already held
    /// (simulated directly via the shared counter, since driving true
    /// concurrency deterministically through a oneshot service is racy)
    /// is rejected with 503 and does not reach the inner handler.
    #[tokio::test]
    async fn hard_limit_guard_rejects_with_503_at_limit() {
        use axum::body::{to_bytes, Body};
        use axum::extract::Request;
        use axum::middleware::Next;
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let limit = 2u64;
        let in_flight = Arc::new(AtomicU64::new(limit)); // already at the limit
        let router = Router::new()
            .route(
                "/x",
                get(|| async {
                    panic!("handler must not run once the hard limit is reached");
                    #[allow(unreachable_code)]
                    ""
                }),
            )
            .layer(axum::middleware::from_fn(
                move |req: Request, next: Next| {
                    let in_flight = in_flight.clone();
                    async move { connection_hard_limit_guard(limit, in_flight, req, next).await }
                },
            ));

        let resp = router
            .oneshot(Request::builder().uri("/x").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert!(!body.is_empty());
    }

    // --- `RestConnectionsSoftLimit` (issue #751) -------------------------

    /// Port of go's `TestConnectionLimiterBasic`
    /// (`daemon/algod/api/server/lib/middlewares/connectionLimiter_test.go`):
    /// go's soft limit (`MakeConnectionLimiter`) *queues* excess requests
    /// behind a semaphore rather than rejecting them, unlike the hard
    /// limit's immediate 503. algod-rust wires this as a bare
    /// `tower::limit::ConcurrencyLimitLayer` (see `ApiServerConfig`'s
    /// `rest_connections_soft_limit` doc comment) rather than a
    /// hand-rolled guard, so this test exercises that layer directly:
    /// three concurrent requests against a limit of 1 must all eventually
    /// succeed (never 503/429), and at most one may run inside the
    /// handler at any instant -- proving admission is serialized
    /// (queued), not merely rate-tracked.
    ///
    /// Exercises `tower::limit::ConcurrencyLimitLayer` (the exact type
    /// `serve()` wires up for `rest_connections_soft_limit`) directly
    /// atop a plain `tower::service_fn`, rather than through
    /// `axum::Router` — `Router`'s own `Service::poll_ready` always
    /// returns `Ready` unconditionally (axum defers all inner-layer
    /// backpressure into the future returned by `call`), which makes a
    /// Router-mediated version of this test unable to distinguish "queued
    /// behind the semaphore" from "ran immediately"; testing the layer
    /// directly avoids that axum-specific readiness quirk entirely.
    #[tokio::test]
    async fn soft_limit_layer_queues_rather_than_rejects_at_capacity() {
        use std::convert::Infallible;
        use std::sync::atomic::AtomicUsize;
        use tower::{Service, ServiceBuilder, ServiceExt};

        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));
        let in_flight_svc = in_flight.clone();
        let max_observed_svc = max_observed.clone();

        let svc = ServiceBuilder::new()
            .layer(ConcurrencyLimitLayer::new(1))
            .service(tower::service_fn(move |_req: ()| {
                let in_flight = in_flight_svc.clone();
                let max_observed = max_observed_svc.clone();
                async move {
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    max_observed.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    Ok::<_, Infallible>(())
                }
            }));

        let mut handles = Vec::new();
        for _ in 0..3 {
            let mut svc = svc.clone();
            handles.push(tokio::spawn(async move {
                svc.ready().await.unwrap().call(()).await.unwrap();
            }));
        }

        for handle in handles {
            tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .expect("queued request must not hang forever")
                .expect("task must not panic");
        }
        assert_eq!(
            max_observed.load(Ordering::SeqCst),
            1,
            "at most one request should run inside the service at a time under a soft limit of 1"
        );
    }

    // ── bind_listener port-0-fallback (issue #953) ─────────────────────

    /// TDD anchor for issue #953, mirroring go-algorand's
    /// `TestFirstListenerSetupGetsPort8080WhenPassedPortZero`
    /// (`daemon/algod/server_test.go`): binding with port `0` must prefer
    /// port 8080 over an OS-assigned ephemeral port when 8080 is free.
    ///
    /// Skipped if port 8080 is already occupied on the test machine, same
    /// caveat go's own test carries.
    #[tokio::test]
    async fn bind_listener_prefers_port_8080_when_passed_port_zero() {
        let host = std::net::Ipv4Addr::LOCALHOST;
        let probe_addr = SocketAddr::from((host, 8080));
        // Skip if 8080 is already in use on this machine (matches go's own
        // test skip condition).
        match TcpListener::bind(probe_addr).await {
            Ok(probe) => drop(probe),
            Err(_) => {
                eprintln!("SKIPPED: port 8080 is already in use on this machine");
                return;
            }
        }

        let requested = SocketAddr::from((host, 0));
        let listener = bind_listener(requested)
            .await
            .expect("bind_listener must succeed");
        assert_eq!(
            listener.local_addr().unwrap(),
            probe_addr,
            "port 0 must fall back to port 8080 when it's free"
        );
    }

    /// TDD anchor for issue #953, mirroring go-algorand's
    /// `TestSecondListenerSetupGetsAnotherPortWhen8080IsBusy`: once 8080 is
    /// already bound, a second port-0 bind must fall back to a different
    /// (OS-assigned) port rather than failing.
    #[tokio::test]
    async fn bind_listener_falls_back_when_8080_is_busy() {
        let host = std::net::Ipv4Addr::LOCALHOST;
        let requested = SocketAddr::from((host, 0));

        let first = bind_listener(requested)
            .await
            .expect("first bind_listener must succeed");
        // Whichever address the first listener landed on (8080, if free —
        // otherwise this test still holds, since a second port-0 bind must
        // never collide with the first).
        let second = bind_listener(requested)
            .await
            .expect("second bind_listener must succeed despite the first one holding a port");
        assert_ne!(
            first.local_addr().unwrap(),
            second.local_addr().unwrap(),
            "two concurrent port-0 binds must never land on the same address"
        );
    }

    /// TDD anchor for issue #953, mirroring go-algorand's
    /// `TestFirstListenerSetupGetsPassedPortWhenPassedPortNonZero`: an
    /// explicit non-zero port is bound directly, with no 8080 special-casing.
    #[tokio::test]
    async fn bind_listener_uses_explicit_nonzero_port_directly() {
        let host = std::net::Ipv4Addr::LOCALHOST;
        // Bind to port 0 first to reserve *some* free ephemeral port, then
        // release it and immediately request that exact port explicitly —
        // avoids hardcoding a port number that might collide with another
        // process on the CI runner.
        let probe = TcpListener::bind(SocketAddr::from((host, 0)))
            .await
            .unwrap();
        let explicit_addr = probe.local_addr().unwrap();
        drop(probe);

        let listener = bind_listener(explicit_addr)
            .await
            .expect("bind_listener must succeed for an explicit non-zero port");
        assert_eq!(listener.local_addr().unwrap(), explicit_addr);
    }
}
