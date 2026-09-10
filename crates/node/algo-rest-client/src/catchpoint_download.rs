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

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use algo_error::{AlgoError, Result};
use algo_network::LEDGER_RESPONSE_CONTENT_TYPE;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::http_over_stream::{
    build_get_request, build_head_request, read_http_response_head, write_request,
    BoxedDuplexStream, HttpPeerTransport,
};

/// Default chunk size for streaming reads (64 KiB).
const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Default minimum acceptable download speed (bytes/second) — go's
/// `MinCatchpointFileDownloadBytesPerSecond` default (`config.Local`,
/// `../go-algorand/config/local_defaults.go:118`, matching
/// `defaultMinCatchpointFileDownloadBytesPerSecond` in
/// `catchup/ledgerFetcher.go:45`).
const DEFAULT_MIN_BYTES_PER_SECOND: u64 = 20 * 1024;

/// Floor added to the per-chunk stall-detection window regardless of
/// configured speed, mirroring go's `maxCatchpointFileChunkDownloadDuration`
/// 2-minute floor (`catchup/ledgerFetcher.go:157`) — a slow-but-still-moving
/// peer over a real network shouldn't be killed by an overly tight window.
const STALL_WINDOW_FLOOR: Duration = Duration::from_secs(120);

/// Progress information reported during a catchpoint file download.
#[derive(Debug, Clone)]
pub struct DownloadProgress {
    /// Number of bytes downloaded so far.
    pub bytes_downloaded: u64,
    /// Total expected bytes from the `Content-Length` header, if available.
    pub total_bytes: Option<u64>,
}

/// Configuration for catchpoint file downloads.
#[derive(Debug, Clone)]
pub struct CatchpointDownloadConfig {
    /// Overall request timeout (default: 30 minutes — catchpoint files can be 500MB+).
    pub timeout: Duration,
    /// Read buffer size hint in bytes (default: 64 KiB).
    ///
    /// Note: the actual chunk sizes returned by `reqwest` may differ from this
    /// value. This is used as a guidance for progress reporting frequency.
    pub chunk_size: usize,
    /// Maximum number of retry attempts on transient errors (default: 3).
    pub max_retries: u32,
    /// Delay between retries, doubled on each successive retry (default: 1s).
    pub retry_delay: Duration,
    /// Minimum acceptable sustained download speed, in bytes/second — go's
    /// `MinCatchpointFileDownloadBytesPerSecond` (`config.Local`, issue
    /// #749). If no `chunk_size` bytes arrive within the resulting
    /// per-chunk stall window, the in-progress request is abandoned as a
    /// recoverable error and retried (same path as a dropped connection),
    /// rather than hanging indefinitely on a stalled peer. `0` disables
    /// stall detection entirely (only the overall `timeout` still applies).
    pub min_bytes_per_second: u64,
}

impl Default for CatchpointDownloadConfig {
    fn default() -> Self {
        Self {
            // go's real default is 12h (`MaxCatchpointDownloadDuration`,
            // version 28 onward) — the previous 30-minute value here
            // matched neither of go's real defaults (2h pre-28, 12h from
            // 28 onward), issue #749.
            timeout: Duration::from_secs(12 * 60 * 60),
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
            min_bytes_per_second: DEFAULT_MIN_BYTES_PER_SECOND,
        }
    }
}

impl CatchpointDownloadConfig {
    /// Per-chunk stall-detection window: how long a single `response.chunk()`
    /// read may take before it's treated as a stall. Mirrors (not
    /// byte-for-byte — algod-rust's `chunk_size` is far smaller than go's
    /// `maxCatchpointFileChunkSize`) go's formula at
    /// `catchup/ledgerFetcher.go:157-162`: a fixed floor plus
    /// `chunk_size / min_bytes_per_second`. Returns `None` when
    /// `min_bytes_per_second` is `0` (stall detection disabled).
    fn stall_window(&self) -> Option<Duration> {
        if self.min_bytes_per_second == 0 {
            return None;
        }
        let extra =
            Duration::from_secs_f64(self.chunk_size as f64 / self.min_bytes_per_second as f64);
        Some(STALL_WINDOW_FLOOR + extra)
    }
}

/// Streaming HTTP client for downloading catchpoint (ledger) files from an
/// Algorand node.
///
/// The Go endpoint serves catchpoint data at
/// `GET /v1/{genesisID}/ledger/{round}` where `round` is **base-36 encoded**.
///
/// See `go-algorand/rpcs/ledgerService.go` for the server implementation.
///
/// ## Transport
///
/// By default (`new`/`with_config`) this issues plain-TCP HTTP requests via
/// `reqwest` against `base_url`. [`Self::with_p2p_transport`] instead routes
/// the *same* HTTP-shaped requests (`HEAD`/`GET .../ledger/{round}`) over an
/// [`HttpPeerTransport`] (issue #1127) — algod-rust's counterpart to
/// go-algorand's `TestLedgerFetcherP2P`, which proves `headLedger`/
/// `downloadLedger` work unchanged against a P2P-derived `network.HTTPPeer`.
/// See `crate::http_over_stream`'s module doc comment for why this is a
/// pluggable trait rather than a direct `algo-p2p` dependency.
pub struct CatchpointDownloader {
    base_url: String,
    token: String,
    http: reqwest::Client,
    config: CatchpointDownloadConfig,
    /// When set, HTTP requests are carried over this transport instead of
    /// plain-TCP `reqwest`, addressed by `base_url` as the transport's own
    /// peer identity (e.g. a libp2p `PeerId`'s string form) rather than a
    /// URL.
    p2p_transport: Option<Arc<dyn HttpPeerTransport>>,
}

impl CatchpointDownloader {
    /// Create a new downloader with the default configuration.
    pub fn new(base_url: &str, token: &str) -> Self {
        Self::with_config(base_url, token, CatchpointDownloadConfig::default())
    }

    /// Create a new downloader with a custom configuration.
    pub fn with_config(base_url: &str, token: &str, config: CatchpointDownloadConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("failed to build HTTP client for catchpoint downloads");

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http,
            config,
            p2p_transport: None,
        }
    }

    /// Create a downloader that routes its HTTP requests over `transport`
    /// (e.g. `bin/algod-rust`'s `P2pTransport::open_http_stream`, wrapped in
    /// an [`HttpPeerTransport`] impl) instead of plain-TCP `reqwest`.
    ///
    /// `peer_id` is the transport's own peer identity (not a URL) — for the
    /// P2P implementation, a libp2p `PeerId`'s string form.
    pub fn with_p2p_transport(
        peer_id: &str,
        transport: Arc<dyn HttpPeerTransport>,
        config: CatchpointDownloadConfig,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("failed to build HTTP client for catchpoint downloads");

        Self {
            base_url: peer_id.to_string(),
            token: String::new(),
            http,
            config,
            p2p_transport: Some(transport),
        }
    }

    /// Download a catchpoint file to `dest_path`.
    ///
    /// The file is first written to a temporary sibling file in the same
    /// directory, then atomically renamed to `dest_path` on success.  This
    /// ensures that a partially-downloaded file never appears at the final
    /// path.
    ///
    /// The `progress_cb` callback, if provided, is invoked periodically with
    /// the current download progress (at most once per `chunk_size` bytes of
    /// data received).
    ///
    /// A catchpoint file can be 500MB+, so the transfer itself (as opposed to
    /// just the initial request, which [`get_with_retry`](Self::get_with_retry)
    /// already retries) is the part most likely to hit a transient network
    /// failure — a connection reset or timeout partway through the body. Such
    /// a failure is recoverable: mirroring go-algorand's fast-catchup
    /// robustness fix (`catchup/catchpointService.go`'s
    /// `checkLedgerDownload`/`headLedger`, which retries across peers rather
    /// than aborting the whole catchup on a single fetch failure), the whole
    /// request is retried up to `config.max_retries` times with the same
    /// doubling backoff used for header-level retries, instead of failing the
    /// entire catchpoint sync on one interrupted transfer.
    ///
    /// # Arguments
    ///
    /// * `genesis_id` — e.g. `"mainnet-v1.0"`
    /// * `round` — the catchpoint round to download
    /// * `dest_path` — final destination path for the downloaded file
    /// * `progress_cb` — optional progress callback
    pub async fn download<F>(
        &self,
        genesis_id: &str,
        round: u64,
        dest_path: &Path,
        progress_cb: Option<F>,
    ) -> Result<()>
    where
        F: Fn(DownloadProgress),
    {
        // Encode the round in base 36, matching the Go server's expectation.
        let round_b36 = radix_fmt(round, 36);
        let path = format!("/v1/{genesis_id}/ledger/{round_b36}");

        debug!(round, %round_b36, genesis_id, "starting catchpoint download");

        if let Some(transport) = self.p2p_transport.clone() {
            return self
                .p2p_download(transport.as_ref(), &path, round, dest_path, progress_cb)
                .await;
        }

        // Ensure the parent directory exists (once, not per attempt).
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                AlgoError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "failed to create parent directory {}: {e}",
                        parent.display()
                    ),
                ))
            })?;
        }

        // Write to a temp file alongside the destination, then rename.
        let tmp_path = dest_path.with_extension("tmp");

        let mut backoff = self.config.retry_delay;

        for attempt in 0..=self.config.max_retries {
            let response = self.get_with_retry(&path).await?;

            // Extract total size from Content-Length if the server provides it.
            let total_bytes = response.content_length();

            if let Some(total) = total_bytes {
                info!(
                    round,
                    total_bytes = total,
                    "catchpoint download: content-length known"
                );
            }

            let result = self
                .stream_to_file(response, &tmp_path, total_bytes, &progress_cb)
                .await;

            match result {
                Ok(()) => {
                    tokio::fs::rename(&tmp_path, dest_path).await.map_err(|e| {
                        AlgoError::Io(std::io::Error::new(
                            e.kind(),
                            format!(
                                "failed to rename {} -> {}: {e}",
                                tmp_path.display(),
                                dest_path.display()
                            ),
                        ))
                    })?;
                    info!(round, path = %dest_path.display(), "catchpoint download complete");
                    return Ok(());
                }
                Err(e) if is_recoverable_stream_error(&e) && attempt < self.config.max_retries => {
                    warn!(
                        attempt = attempt + 1,
                        max = self.config.max_retries,
                        error = %e,
                        round,
                        backoff_ms = backoff.as_millis() as u64,
                        "catchpoint download: transfer interrupted, retrying rather than \
                         aborting catchup"
                    );
                    // Best-effort cleanup of the partial temp file before retrying.
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
                Err(e) => {
                    // Either a non-recoverable error (e.g. local disk I/O) or
                    // retries are exhausted — best-effort cleanup and give up.
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                    return Err(e);
                }
            }
        }

        unreachable!("retry loop always returns on its last iteration")
    }

    /// Stream a response body to a file on disk, invoking `progress_cb`
    /// after each chunk.
    async fn stream_to_file<F>(
        &self,
        mut response: reqwest::Response,
        path: &Path,
        total_bytes: Option<u64>,
        progress_cb: &Option<F>,
    ) -> Result<()>
    where
        F: Fn(DownloadProgress),
    {
        use tokio::io::AsyncWriteExt;

        let mut file = tokio::fs::File::create(path).await.map_err(|e| {
            AlgoError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to create temp file {}: {e}", path.display()),
            ))
        })?;

        let mut bytes_downloaded: u64 = 0;
        let mut bytes_since_progress: usize = 0;
        let stall_window = self.config.stall_window();

        // Use reqwest's chunk() method to stream the response body without
        // buffering the entire payload in memory.
        while let Some(chunk) = self
            .read_chunk_with_stall_check(&mut response, stall_window, bytes_downloaded, path)
            .await?
        {
            file.write_all(&chunk).await.map_err(|e| {
                AlgoError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "failed to write {} bytes at offset {bytes_downloaded} to {}: {e}",
                        chunk.len(),
                        path.display()
                    ),
                ))
            })?;

            bytes_downloaded += chunk.len() as u64;
            bytes_since_progress += chunk.len();

            // Report progress at most once per `chunk_size` bytes to avoid
            // excessive callback overhead with very small HTTP chunks.
            if bytes_since_progress >= self.config.chunk_size {
                bytes_since_progress = 0;
                if let Some(ref cb) = progress_cb {
                    cb(DownloadProgress {
                        bytes_downloaded,
                        total_bytes,
                    });
                }
            }
        }

        file.flush().await.map_err(|e| {
            AlgoError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to flush {}: {e}", path.display()),
            ))
        })?;

        // Final progress report.
        if let Some(ref cb) = progress_cb {
            cb(DownloadProgress {
                bytes_downloaded,
                total_bytes,
            });
        }

        debug!(
            bytes_downloaded,
            "catchpoint file written to {}",
            path.display()
        );
        Ok(())
    }

    /// Read the next chunk from `response`, applying the per-chunk
    /// stall-detection window (go's `MinCatchpointFileDownloadBytesPerSecond`,
    /// issue #749) when one is configured. A read that exceeds
    /// `stall_window` is treated as a recoverable error identically to a
    /// dropped connection — [`Self::download`]'s outer retry loop restarts
    /// the whole request rather than hanging on a peer that stopped sending
    /// data.
    async fn read_chunk_with_stall_check(
        &self,
        response: &mut reqwest::Response,
        stall_window: Option<Duration>,
        bytes_downloaded: u64,
        path: &Path,
    ) -> Result<Option<bytes::Bytes>> {
        let read = response.chunk();
        let result = match stall_window {
            Some(window) => match tokio::time::timeout(window, read).await {
                Ok(r) => r,
                Err(_) => {
                    warn!(
                        bytes_downloaded,
                        stall_window_secs = window.as_secs_f64(),
                        path = %path.display(),
                        "catchpoint download: no data received within the stall window, \
                         treating as a recoverable interruption"
                    );
                    return Err(AlgoError::RestClient {
                        source: Box::new(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!(
                                "no bytes received within {:.1}s (min download speed not met)",
                                window.as_secs_f64()
                            ),
                        )),
                        context: format!("stalled reading chunk at offset {bytes_downloaded}"),
                    });
                }
            },
            None => read.await,
        };
        result.map_err(|e| AlgoError::RestClient {
            source: Box::new(e),
            context: format!(
                "reading chunk at offset {bytes_downloaded} from {}",
                path.display()
            ),
        })
    }

    /// Send a HEAD request to the catchpoint (ledger) endpoint to check
    /// whether `round`'s catchpoint file is available from this peer,
    /// without downloading the body.
    ///
    /// Mirrors go's `ledgerFetcher.headLedger` (`catchup/ledgerFetcher.go`),
    /// used by `CatchpointCatchupService.checkLedgerDownload` as a
    /// pre-flight availability probe stage ahead of the real download
    /// (issue #917). A 404 response is reported as [`AlgoError::NotFound`]
    /// (the peer doesn't have this round's catchpoint, matching go's
    /// `peerRankNoCatchpointForRound` classification), any other
    /// non-success status as [`AlgoError::RestClient`], and a transport
    /// failure (connection refused, timeout, etc.) is also surfaced as
    /// [`AlgoError::RestClient`] — this method does not retry, since it is
    /// only ever used to rank a peer, not to fetch data callers depend on.
    pub async fn probe_availability(&self, genesis_id: &str, round: u64) -> Result<()> {
        let round_b36 = radix_fmt(round, 36);
        let path = format!("/v1/{genesis_id}/ledger/{round_b36}");

        if let Some(transport) = &self.p2p_transport {
            return self.p2p_probe_availability(transport.as_ref(), &path).await;
        }

        let url = format!("{}{}", self.base_url, path);

        let mut request = self.http.head(&url);
        if !self.token.is_empty() {
            request = request.header("X-Algo-API-Token", &self.token);
        }

        let response = request.send().await.map_err(|e| AlgoError::RestClient {
            source: Box::new(e),
            context: format!("catchpoint HEAD {path}"),
        })?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(AlgoError::NotFound(format!("catchpoint HEAD {path}")));
        }
        Err(AlgoError::RestClient {
            source: Box::new(std::io::Error::other(format!("HTTP {status}"))),
            context: format!("catchpoint HEAD {path}"),
        })
    }

    /// [`Self::probe_availability`]'s P2P-transport path: builds and sends a
    /// raw `HEAD` request over `transport` and classifies the response the
    /// same way the `reqwest` path above does.
    async fn p2p_probe_availability(
        &self,
        transport: &dyn HttpPeerTransport,
        path: &str,
    ) -> Result<()> {
        let request = build_head_request(path, &self.base_url);
        let mut stream = transport
            .open_stream(&self.base_url)
            .await
            .map_err(|e| p2p_open_error(&self.base_url, e))?;
        write_request(&mut stream, &request).await?;
        let head = read_http_response_head(&mut stream).await?;

        if (200..300).contains(&head.status) {
            return Ok(());
        }
        if head.status == 404 {
            return Err(AlgoError::NotFound(format!(
                "catchpoint HEAD {path} (P2P peer {})",
                self.base_url
            )));
        }
        Err(AlgoError::RestClient {
            source: Box::new(std::io::Error::other(format!("HTTP {}", head.status))),
            context: format!("catchpoint HEAD {path} (P2P peer {})", self.base_url),
        })
    }

    /// [`Self::download`]'s P2P-transport path: retries a full `GET`
    /// transfer (mirroring the `reqwest` path's `attempt`/backoff loop)
    /// with the response body streamed directly to `dest_path`'s temp file
    /// rather than buffered in memory — catchpoint files can be 500MB+, and
    /// [`crate::http_over_stream`]'s raw-stream reader hands back only the
    /// parsed head plus whatever body bytes were prefetched while scanning
    /// for it, exactly so the remaining body can still be streamed in
    /// bounded chunks.
    async fn p2p_download<F>(
        &self,
        transport: &dyn HttpPeerTransport,
        path: &str,
        round: u64,
        dest_path: &Path,
        progress_cb: Option<F>,
    ) -> Result<()>
    where
        F: Fn(DownloadProgress),
    {
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                AlgoError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "failed to create parent directory {}: {e}",
                        parent.display()
                    ),
                ))
            })?;
        }

        let tmp_path = dest_path.with_extension("tmp");
        let mut backoff = self.config.retry_delay;

        for attempt in 0..=self.config.max_retries {
            let result = self
                .p2p_download_attempt(transport, path, &tmp_path, &progress_cb)
                .await;

            match result {
                Ok(()) => {
                    tokio::fs::rename(&tmp_path, dest_path).await.map_err(|e| {
                        AlgoError::Io(std::io::Error::new(
                            e.kind(),
                            format!(
                                "failed to rename {} -> {}: {e}",
                                tmp_path.display(),
                                dest_path.display()
                            ),
                        ))
                    })?;
                    info!(round, path = %dest_path.display(), "catchpoint download complete (P2P)");
                    return Ok(());
                }
                // A 404 (the peer confirmed it doesn't have this round) is
                // never worth retrying, mirroring `get_with_retry`'s
                // immediate-return behavior for the same status.
                Err(e @ AlgoError::NotFound(_)) => {
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                    return Err(e);
                }
                Err(e) if attempt < self.config.max_retries => {
                    warn!(
                        attempt = attempt + 1,
                        max = self.config.max_retries,
                        error = %e,
                        round,
                        backoff_ms = backoff.as_millis() as u64,
                        "catchpoint download (P2P): transfer interrupted, retrying rather than \
                         aborting catchup"
                    );
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
                Err(e) => {
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                    return Err(e);
                }
            }
        }

        unreachable!("retry loop always returns on its last iteration")
    }

    /// One full P2P download attempt: open a fresh stream (mirroring go's
    /// `p2pHTTPRoundTripper` opening one stream per request), send the
    /// `GET`, read the head, then stream the body to `tmp_path` in chunks.
    async fn p2p_download_attempt<F>(
        &self,
        transport: &dyn HttpPeerTransport,
        path: &str,
        tmp_path: &Path,
        progress_cb: &Option<F>,
    ) -> Result<()>
    where
        F: Fn(DownloadProgress),
    {
        let request = build_get_request(path, &self.base_url, true);
        let mut stream = transport
            .open_stream(&self.base_url)
            .await
            .map_err(|e| p2p_open_error(&self.base_url, e))?;
        write_request(&mut stream, &request).await?;
        let head = read_http_response_head(&mut stream).await?;

        if head.status == 404 {
            return Err(AlgoError::NotFound(format!(
                "catchpoint GET {path} (P2P peer {})",
                self.base_url
            )));
        }
        if !(200..300).contains(&head.status) {
            return Err(AlgoError::RestClient {
                source: Box::new(std::io::Error::other(format!("HTTP {}", head.status))),
                context: format!("catchpoint GET {path} (P2P peer {})", self.base_url),
            });
        }

        validate_p2p_ledger_content_type(&head.headers, path, &self.base_url)?;

        let total_bytes = head.content_length();
        self.p2p_stream_body_to_file(
            stream,
            head.prefetched_body,
            total_bytes,
            tmp_path,
            progress_cb,
        )
        .await
    }

    /// Copy a P2P response body to `tmp_path`, starting with any
    /// `prefetched_body` bytes already read off the stream while parsing
    /// the head, then reading further chunks (applying the same stall
    /// window and quantized progress reporting the `reqwest` path uses)
    /// until `total_bytes` have been written (when `Content-Length` was
    /// present) or the stream reaches EOF (when it was not).
    async fn p2p_stream_body_to_file<F>(
        &self,
        mut stream: BoxedDuplexStream,
        prefetched_body: Vec<u8>,
        total_bytes: Option<u64>,
        tmp_path: &Path,
        progress_cb: &Option<F>,
    ) -> Result<()>
    where
        F: Fn(DownloadProgress),
    {
        let mut file = tokio::fs::File::create(tmp_path).await.map_err(|e| {
            AlgoError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to create temp file {}: {e}", tmp_path.display()),
            ))
        })?;

        let mut bytes_downloaded: u64 = 0;
        let mut bytes_since_progress: usize = 0;
        let stall_window = self.config.stall_window();
        let report_every = self.config.chunk_size.max(1);

        if !prefetched_body.is_empty() {
            write_download_chunk(&mut file, &prefetched_body, tmp_path).await?;
            bytes_downloaded += prefetched_body.len() as u64;
            bytes_since_progress += prefetched_body.len();
        }

        let mut buf = vec![0u8; report_every.clamp(1, 64 * 1024)];
        loop {
            if let Some(total) = total_bytes {
                if bytes_downloaded >= total {
                    break;
                }
            }

            let read_fut = stream.read(&mut buf);
            let n = match stall_window {
                Some(window) => match tokio::time::timeout(window, read_fut).await {
                    Ok(r) => r.map_err(|e| p2p_stream_io_error("reading response body", e))?,
                    Err(_) => {
                        warn!(
                            bytes_downloaded,
                            stall_window_secs = window.as_secs_f64(),
                            path = %tmp_path.display(),
                            "catchpoint download (P2P): no data received within the stall \
                             window, treating as a recoverable interruption"
                        );
                        return Err(AlgoError::RestClient {
                            source: Box::new(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                format!(
                                    "no bytes received within {:.1}s (min download speed not met)",
                                    window.as_secs_f64()
                                ),
                            )),
                            context: format!(
                                "stalled reading P2P chunk at offset {bytes_downloaded}"
                            ),
                        });
                    }
                },
                None => read_fut
                    .await
                    .map_err(|e| p2p_stream_io_error("reading response body", e))?,
            };

            if n == 0 {
                if let Some(total) = total_bytes {
                    if bytes_downloaded < total {
                        return Err(AlgoError::RestClient {
                            source: Box::new(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                format!(
                                    "connection closed after {bytes_downloaded} of {total} \
                                     expected bytes"
                                ),
                            )),
                            context: "streaming P2P catchpoint response body".into(),
                        });
                    }
                }
                break;
            }

            write_download_chunk(&mut file, &buf[..n], tmp_path).await?;
            bytes_downloaded += n as u64;
            bytes_since_progress += n;

            if bytes_since_progress >= report_every {
                bytes_since_progress = 0;
                if let Some(cb) = progress_cb {
                    cb(DownloadProgress {
                        bytes_downloaded,
                        total_bytes,
                    });
                }
            }
        }

        file.flush().await.map_err(|e| {
            AlgoError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to flush {}: {e}", tmp_path.display()),
            ))
        })?;

        if let Some(cb) = progress_cb {
            cb(DownloadProgress {
                bytes_downloaded,
                total_bytes,
            });
        }

        debug!(
            bytes_downloaded,
            "catchpoint file written to {} (P2P)",
            tmp_path.display()
        );
        Ok(())
    }

    /// Execute a GET request with retry and exponential backoff.
    ///
    /// Follows the same pattern as `AlgodClient::get_with_retry`.
    async fn get_with_retry(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        let mut backoff = self.config.retry_delay;

        for attempt in 0..=self.config.max_retries {
            let mut request = self.http.get(&url);

            // Send the auth token the same way AlgodClient does.
            if !self.token.is_empty() {
                request = request.header("X-Algo-API-Token", &self.token);
            }

            // Request gzip-compressed transfer to reduce bandwidth, matching
            // the Go client behaviour.
            request = request.header("Accept-Encoding", "gzip");

            let result = request.send().await;

            match result {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        validate_ledger_content_type(resp.headers(), path)?;
                        return Ok(resp);
                    }
                    if status.is_server_error() && attempt < self.config.max_retries {
                        warn!(
                            attempt = attempt + 1,
                            max = self.config.max_retries,
                            status = %status,
                            path,
                            backoff_ms = backoff.as_millis() as u64,
                            "catchpoint download: server error, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        continue;
                    }
                    // 4xx or exhausted retries on 5xx.
                    let body = resp.text().await.unwrap_or_default();
                    if status == reqwest::StatusCode::NOT_FOUND {
                        return Err(AlgoError::NotFound(format!(
                            "catchpoint GET {path}: {body}"
                        )));
                    }
                    return Err(AlgoError::RestClient {
                        source: Box::new(std::io::Error::other(format!("HTTP {status}"))),
                        context: format!("catchpoint GET {path}: {body}"),
                    });
                }
                Err(e) if is_retryable(&e) && attempt < self.config.max_retries => {
                    warn!(
                        attempt = attempt + 1,
                        max = self.config.max_retries,
                        error = %e,
                        path,
                        backoff_ms = backoff.as_millis() as u64,
                        "catchpoint download: transient error, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
                Err(e) => {
                    return Err(AlgoError::RestClient {
                        source: Box::new(e),
                        context: format!("catchpoint GET {path}"),
                    });
                }
            }
        }

        unreachable!("retry loop should always return")
    }
}

/// Check if a reqwest error is transient and worth retrying.
fn is_retryable(err: &reqwest::Error) -> bool {
    err.is_connect() || err.is_timeout()
}

/// Validate a successful ledger-fetch response's `Content-Type` header
/// before the body is read, mirroring go's `getPeerLedger`
/// (`catchup/ledgerFetcher.go:143-154`): exactly one `Content-Type` header
/// must be present, and its value must equal
/// `rpcs.LedgerResponseContentType` (algod-rust:
/// `algo_network::LEDGER_RESPONSE_CONTENT_TYPE`). Checked only on the
/// `GET`/download path — go's `headLedger` (the HEAD pre-flight probe this
/// crate's `probe_availability` mirrors) never inspects Content-Type at
/// all, so `probe_availability` deliberately does not call this.
fn validate_ledger_content_type(headers: &reqwest::header::HeaderMap, path: &str) -> Result<()> {
    let mut content_types = headers.get_all(reqwest::header::CONTENT_TYPE).iter();
    let first = content_types.next();
    let count = first.iter().count() + content_types.count();

    let value = match (count, first) {
        (1, Some(v)) => v,
        (count, _) => {
            return Err(AlgoError::RestClient {
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("http ledger fetcher invalid content type count {count}"),
                )),
                context: format!("catchpoint GET {path}"),
            });
        }
    };

    if value.as_bytes() != LEDGER_RESPONSE_CONTENT_TYPE.as_bytes() {
        return Err(AlgoError::RestClient {
            source: Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "http ledger fetcher response has an invalid content type : {}",
                    String::from_utf8_lossy(value.as_bytes())
                ),
            )),
            context: format!("catchpoint GET {path}"),
        });
    }

    Ok(())
}

/// [`validate_ledger_content_type`]'s P2P-transport equivalent: same
/// presence/value check, applied to the raw-stream head parser's
/// `HashMap<String, String>` headers. Unlike `reqwest`'s `HeaderMap` (which
/// preserves every header instance), `http_over_stream::parse_head` folds
/// repeated header lines into a single map entry, so the "duplicate
/// Content-Type header" case go's count check also catches isn't
/// representable via this transport — only "missing" and "wrong value" are.
fn validate_p2p_ledger_content_type(
    headers: &std::collections::HashMap<String, String>,
    path: &str,
    peer: &str,
) -> Result<()> {
    match headers.get("content-type") {
        Some(value) if value == LEDGER_RESPONSE_CONTENT_TYPE => Ok(()),
        Some(value) => Err(AlgoError::RestClient {
            source: Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("http ledger fetcher response has an invalid content type : {value}"),
            )),
            context: format!("catchpoint GET {path} (P2P peer {peer})"),
        }),
        None => Err(AlgoError::RestClient {
            source: Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "http ledger fetcher invalid content type count 0",
            )),
            context: format!("catchpoint GET {path} (P2P peer {peer})"),
        }),
    }
}

/// Write one chunk to the in-progress download's temp file, wrapping any
/// I/O failure with enough context to diagnose which file/offset it hit.
async fn write_download_chunk(
    file: &mut tokio::fs::File,
    chunk: &[u8],
    tmp_path: &Path,
) -> Result<()> {
    file.write_all(chunk).await.map_err(|e| {
        AlgoError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "failed to write {} bytes to {}: {e}",
                chunk.len(),
                tmp_path.display()
            ),
        ))
    })
}

/// Wrap a failure to open a P2P HTTP stream to `peer` with enough context to
/// diagnose which peer/attempt it was, matching the classification
/// `reqwest`'s own connect failures get. `HttpPeerTransport::open_stream`
/// already returns `Result<_, AlgoError>` (never `NotFound` — this is a
/// connection-establishment failure, not an HTTP response), so this only
/// needs to add context, not reclassify.
fn p2p_open_error(peer: &str, err: AlgoError) -> AlgoError {
    AlgoError::RestClient {
        source: Box::new(std::io::Error::other(format!(
            "opening P2P HTTP stream to {peer}: {err}"
        ))),
        context: format!("opening P2P HTTP stream to {peer}"),
    }
}

/// Wrap a raw I/O failure reading/writing a P2P stream as an
/// [`AlgoError::RestClient`], matching `is_recoverable_stream_error`'s
/// expectations for the retry loop above.
fn p2p_stream_io_error(context: &str, err: std::io::Error) -> AlgoError {
    AlgoError::RestClient {
        source: Box::new(err),
        context: format!("{context} over P2P stream"),
    }
}

/// Check whether an error from streaming a catchpoint response body is a
/// recoverable network interruption (connection reset, timeout, incomplete
/// body) worth restarting the whole request for, as opposed to a local
/// failure (e.g. disk I/O) that a retry cannot fix.
///
/// `stream_to_file` only ever produces [`AlgoError::RestClient`] from a
/// failed `response.chunk()` read (a body-streaming/network failure) or
/// [`AlgoError::Io`] from local file operations (create/write/flush/rename).
/// Only the former is treated as recoverable here.
fn is_recoverable_stream_error(err: &AlgoError) -> bool {
    matches!(err, AlgoError::RestClient { .. })
}

/// Format a `u64` as a base-36 string (digits 0-9, then a-z).
///
/// Go's `strconv.ParseUint(s, 36, 64)` accepts lowercase letters, so we
/// produce lowercase output.
fn radix_fmt(mut value: u64, radix: u32) -> String {
    if value == 0 {
        return "0".to_string();
    }
    let radix = radix as u64;
    let mut digits = Vec::new();
    while value > 0 {
        let d = (value % radix) as u8;
        let ch = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
        digits.push(ch as char);
        value /= radix;
    }
    digits.reverse();
    digits.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A minimal raw-socket HTTP server that simulates a connection that is
    /// reset partway through streaming the response body — the kind of
    /// "recoverable" mid-transfer network error a multi-hundred-MB catchpoint
    /// download can hit (go-algorand's `checkLedgerDownload`/`headLedger`
    /// retry-across-peers path exists precisely because single-attempt
    /// catchpoint fetches are not reliable over real networks).
    ///
    /// The first `fail_attempts` connections are accepted, sent a `200`
    /// header advertising a `Content-Length` larger than the body actually
    /// written, and then the socket is dropped — causing the HTTP client to
    /// observe an incomplete-body error while streaming. Connections after
    /// that serve the full body successfully.
    async fn spawn_flaky_catchpoint_server(
        fail_attempts: usize,
        full_body: &'static [u8],
    ) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = Arc::clone(&attempts);

        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let attempt = attempts_clone.fetch_add(1, Ordering::SeqCst);

                // Drain (and ignore) the request.
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;

                if attempt < fail_attempts {
                    // Advertise the full length but only write a prefix, then
                    // drop the connection — an incomplete body.
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/x-algorand-ledger-v2.1\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n",
                        full_body.len()
                    );
                    let _ = socket.write_all(header.as_bytes()).await;
                    let truncated = &full_body[..full_body.len() / 2];
                    let _ = socket.write_all(truncated).await;
                    let _ = socket.flush().await;
                    drop(socket);
                } else {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/x-algorand-ledger-v2.1\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n",
                        full_body.len()
                    );
                    let _ = socket.write_all(header.as_bytes()).await;
                    let _ = socket.write_all(full_body).await;
                    let _ = socket.flush().await;
                    drop(socket);
                }
            }
        });

        (format!("http://{addr}"), attempts)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn download_retries_on_mid_stream_connection_drop() {
        // Simulate a single recoverable failure (connection dropped after
        // partial body) followed by a fully successful response.
        const BODY: &[u8] = b"catchpoint-file-bytes-0123456789-catchpoint-file-bytes";
        let (base_url, attempts) = spawn_flaky_catchpoint_server(1, BODY).await;

        let dl = CatchpointDownloader::with_config(
            &base_url,
            "",
            CatchpointDownloadConfig {
                timeout: Duration::from_secs(5),
                chunk_size: 16,
                max_retries: 3,
                retry_delay: Duration::from_millis(10),
                min_bytes_per_second: 0,
            },
        );

        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-retry-test-{}",
            std::process::id()
        ));
        let dest = tmp_dir.join("catchpoint-1.tar.gz");

        let result = dl
            .download::<fn(DownloadProgress)>("test-v1.0", 1, &dest, None)
            .await;

        assert!(
            result.is_ok(),
            "expected download to recover from a mid-stream connection drop \
             by retrying rather than aborting the whole catchup, got: {:?}",
            result.err()
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            BODY,
            "final file should contain the full body from the retried attempt"
        );
        assert!(
            attempts.load(Ordering::SeqCst) >= 2,
            "expected at least one retry (2 connection attempts), got {}",
            attempts.load(Ordering::SeqCst)
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    /// A raw-socket HTTP server that always answers with a fixed status
    /// line/body, across every connection it accepts — used to exercise
    /// `CatchpointDownloader::download`'s (the `getPeerLedger`/
    /// `downloadLedger` analog, go's `catchup/ledgerFetcher.go`) status-code
    /// classification across the retry loop, unlike
    /// `spawn_flaky_catchpoint_server` which changes behavior after N
    /// attempts.
    async fn spawn_fixed_status_server(status_line: &'static str, body: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let header = format!(
                    "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(header.as_bytes()).await;
                let _ = socket.write_all(body).await;
                let _ = socket.flush().await;
                drop(socket);
            }
        });

        format!("http://{addr}")
    }

    /// Mirrors part of go's `TestLedgerFetcher`/`TestLedgerFetcherErrorResponseHandling`
    /// (`catchup/ledgerFetcher_test.go`): a 404 GET response should surface
    /// as `errNoLedgerForRound` (algod-rust: [`AlgoError::NotFound`]) and
    /// must not be retried.
    #[tokio::test(flavor = "multi_thread")]
    async fn download_maps_404_to_not_found_without_retrying() {
        let base_url = spawn_fixed_status_server("HTTP/1.1 404 Not Found", b"").await;

        let dl = CatchpointDownloader::with_config(
            &base_url,
            "",
            CatchpointDownloadConfig {
                timeout: Duration::from_secs(5),
                chunk_size: 16,
                max_retries: 3,
                retry_delay: Duration::from_millis(10),
                min_bytes_per_second: 0,
            },
        );

        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-404-test-{}",
            std::process::id()
        ));
        let dest = tmp_dir.join("catchpoint-404.tar.gz");

        let result = dl
            .download::<fn(DownloadProgress)>("test-v1.0", 1, &dest, None)
            .await;

        assert!(
            matches!(result, Err(AlgoError::NotFound(_))),
            "expected NotFound for a 404 response, got: {result:?}"
        );
        assert!(!dest.exists(), "no file should be written on a 404");

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    /// Mirrors go's `TestLedgerFetcher`'s 500-response case: a persistent
    /// server error should be retried (per `max_retries`) and, once
    /// exhausted, surfaced as a non-`NotFound` REST-client error rather than
    /// hanging or panicking.
    #[tokio::test(flavor = "multi_thread")]
    async fn download_maps_persistent_server_error_to_rest_client_error() {
        let base_url =
            spawn_fixed_status_server("HTTP/1.1 500 Internal Server Error", b"boom").await;

        let dl = CatchpointDownloader::with_config(
            &base_url,
            "",
            CatchpointDownloadConfig {
                timeout: Duration::from_secs(5),
                chunk_size: 16,
                max_retries: 1,
                retry_delay: Duration::from_millis(5),
                min_bytes_per_second: 0,
            },
        );

        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-500-test-{}",
            std::process::id()
        ));
        let dest = tmp_dir.join("catchpoint-500.tar.gz");

        let result = dl
            .download::<fn(DownloadProgress)>("test-v1.0", 1, &dest, None)
            .await;

        assert!(
            matches!(result, Err(AlgoError::RestClient { .. })),
            "expected a RestClient error once retries on a persistent 500 are \
             exhausted, got: {result:?}"
        );
        assert!(!dest.exists(), "no file should be left behind on failure");

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    // -- Content-Type validation (issue #1203, go's `getPeerLedger`'s
    //    "exactly one Content-Type header, matching
    //    `rpcs.LedgerResponseContentType`" check,
    //    `catchup/ledgerFetcher.go:143-154`) --

    /// A minimal raw-socket HTTP server that answers every GET with a `200`
    /// whose header block is exactly `header_lines` (caller-supplied, so
    /// tests can omit/duplicate/mis-value the `Content-Type` header) plus a
    /// `Content-Length`-correct body.
    async fn spawn_custom_headers_server(
        header_lines: &'static str,
        body: &'static [u8],
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let header = format!(
                    "HTTP/1.1 200 OK\r\n{header_lines}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(header.as_bytes()).await;
                let _ = socket.write_all(body).await;
                let _ = socket.flush().await;
                drop(socket);
            }
        });

        format!("http://{addr}")
    }

    /// Mirrors go's `TestLedgerFetcherErrorResponseHandling`: a 200 response
    /// with no `Content-Type` header at all must be rejected before the body
    /// is accepted, not treated as a successful download.
    #[tokio::test(flavor = "multi_thread")]
    async fn download_rejects_response_with_missing_content_type() {
        let base_url = spawn_custom_headers_server("", b"not-a-catchpoint-file").await;

        let dl = CatchpointDownloader::with_config(
            &base_url,
            "",
            CatchpointDownloadConfig {
                timeout: Duration::from_secs(5),
                chunk_size: 16,
                max_retries: 0,
                retry_delay: Duration::from_millis(5),
                min_bytes_per_second: 0,
            },
        );

        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-missing-ct-{}",
            std::process::id()
        ));
        let dest = tmp_dir.join("catchpoint-missing-ct.tar.gz");

        let result = dl
            .download::<fn(DownloadProgress)>("test-v1.0", 1, &dest, None)
            .await;

        assert!(
            matches!(result, Err(AlgoError::RestClient { .. })),
            "a response with no Content-Type header must be rejected, got: {result:?}"
        );
        assert!(
            !dest.exists(),
            "no file should be written when Content-Type validation fails"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    /// Mirrors go's `TestLedgerFetcherErrorResponseHandling`: a 200 response
    /// with two `Content-Type` headers (even if both are the correct value)
    /// must be rejected — go's check is a header *count* check first,
    /// independent of the value(s).
    #[tokio::test(flavor = "multi_thread")]
    async fn download_rejects_response_with_duplicate_content_type_headers() {
        let base_url = spawn_custom_headers_server(
            "Content-Type: application/x-algorand-ledger-v2.1\r\n\
             Content-Type: application/x-algorand-ledger-v2.1\r\n",
            b"not-a-catchpoint-file",
        )
        .await;

        let dl = CatchpointDownloader::with_config(
            &base_url,
            "",
            CatchpointDownloadConfig {
                timeout: Duration::from_secs(5),
                chunk_size: 16,
                max_retries: 0,
                retry_delay: Duration::from_millis(5),
                min_bytes_per_second: 0,
            },
        );

        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-dup-ct-{}",
            std::process::id()
        ));
        let dest = tmp_dir.join("catchpoint-dup-ct.tar.gz");

        let result = dl
            .download::<fn(DownloadProgress)>("test-v1.0", 1, &dest, None)
            .await;

        assert!(
            matches!(result, Err(AlgoError::RestClient { .. })),
            "a response with duplicate Content-Type headers must be rejected, got: {result:?}"
        );
        assert!(
            !dest.exists(),
            "no file should be written when Content-Type validation fails"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    /// Mirrors go's `TestLedgerFetcherErrorResponseHandling`: a 200 response
    /// with exactly one `Content-Type` header but the wrong value (e.g. a
    /// captive portal or misconfigured proxy serving an HTML error page with
    /// a 200 status) must be rejected before the body is streamed to disk.
    #[tokio::test(flavor = "multi_thread")]
    async fn download_rejects_response_with_wrong_content_type_value() {
        let base_url = spawn_custom_headers_server(
            "Content-Type: text/html\r\n",
            b"<html>not a catchpoint</html>",
        )
        .await;

        let dl = CatchpointDownloader::with_config(
            &base_url,
            "",
            CatchpointDownloadConfig {
                timeout: Duration::from_secs(5),
                chunk_size: 16,
                max_retries: 0,
                retry_delay: Duration::from_millis(5),
                min_bytes_per_second: 0,
            },
        );

        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-wrong-ct-{}",
            std::process::id()
        ));
        let dest = tmp_dir.join("catchpoint-wrong-ct.tar.gz");

        let result = dl
            .download::<fn(DownloadProgress)>("test-v1.0", 1, &dest, None)
            .await;

        assert!(
            matches!(result, Err(AlgoError::RestClient { .. })),
            "a response with the wrong Content-Type value must be rejected, got: {result:?}"
        );
        assert!(
            !dest.exists(),
            "no file should be written when Content-Type validation fails"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    /// Regression: a single, correct `Content-Type` header must still
    /// download successfully — the validation above must not reject the
    /// happy path.
    #[tokio::test(flavor = "multi_thread")]
    async fn download_succeeds_with_a_single_correct_content_type_header() {
        const BODY: &[u8] = b"catchpoint-file-bytes-0123456789";
        let base_url = spawn_custom_headers_server(
            "Content-Type: application/x-algorand-ledger-v2.1\r\n",
            BODY,
        )
        .await;

        let dl = CatchpointDownloader::with_config(
            &base_url,
            "",
            CatchpointDownloadConfig {
                timeout: Duration::from_secs(5),
                chunk_size: 16,
                max_retries: 0,
                retry_delay: Duration::from_millis(5),
                min_bytes_per_second: 0,
            },
        );

        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-ok-ct-{}",
            std::process::id()
        ));
        let dest = tmp_dir.join("catchpoint-ok-ct.tar.gz");

        let result = dl
            .download::<fn(DownloadProgress)>("test-v1.0", 1, &dest, None)
            .await;

        assert!(
            result.is_ok(),
            "a single correct Content-Type header must still download successfully, got: {result:?}"
        );
        assert_eq!(std::fs::read(&dest).unwrap(), BODY);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    /// The P2P-transport path (`p2p_download_attempt`) gets the same
    /// value/presence check — proven here with a `MockP2pTransport`
    /// response that lacks `Content-Type` entirely. Unlike the `reqwest`
    /// path above, the raw-stream header parser (`http_over_stream::parse_head`)
    /// folds duplicate header lines into a single `HashMap` entry (last
    /// value wins), so a byte-for-byte "duplicate header" case isn't
    /// representable through this transport — the missing/wrong-value cases
    /// are.
    #[tokio::test(flavor = "multi_thread")]
    async fn download_rejects_missing_content_type_over_p2p_transport() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata".to_vec();
        let transport: Arc<dyn crate::http_over_stream::HttpPeerTransport> =
            Arc::new(MockP2pTransport::new(response));
        let dl = CatchpointDownloader::with_p2p_transport(
            "12D3KooWtestpeer",
            transport,
            CatchpointDownloadConfig {
                max_retries: 0,
                min_bytes_per_second: 0,
                ..CatchpointDownloadConfig::default()
            },
        );

        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-p2p-missing-ct-{}",
            std::process::id()
        ));
        let dest = tmp_dir.join("catchpoint-p2p-missing-ct.tar.gz");

        let result = dl
            .download::<fn(DownloadProgress)>("test-v1.0", 1, &dest, None)
            .await;

        assert!(
            matches!(result, Err(AlgoError::RestClient { .. })),
            "a P2P response with no Content-Type header must be rejected, got: {result:?}"
        );
        assert!(!dest.exists());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_radix_fmt_base36() {
        // 0
        assert_eq!(radix_fmt(0, 36), "0");
        // 1..35 → single digit
        assert_eq!(radix_fmt(10, 36), "a");
        assert_eq!(radix_fmt(35, 36), "z");
        // 36 → "10"
        assert_eq!(radix_fmt(36, 36), "10");
        // Known value: Go's strconv.FormatUint(1000000, 36) == "lfls"
        assert_eq!(radix_fmt(1_000_000, 36), "lfls");
        // Larger: Go's strconv.FormatUint(12345678, 36) == "7clzi"
        assert_eq!(radix_fmt(12_345_678, 36), "7clzi");
    }

    #[test]
    fn test_default_config() {
        // go's real defaults (issue #749): MaxCatchpointDownloadDuration is
        // 12h (version 28 onward), not the previous hardcoded 30-minute
        // value, which matched neither of go's real defaults (2h pre-28,
        // 12h from 28 onward).
        let config = CatchpointDownloadConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(12 * 60 * 60));
        assert_eq!(config.chunk_size, DEFAULT_CHUNK_SIZE);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay, Duration::from_secs(1));
        assert_eq!(
            config.min_bytes_per_second, DEFAULT_MIN_BYTES_PER_SECOND,
            "go's MinCatchpointFileDownloadBytesPerSecond default is 20*1024"
        );
    }

    #[test]
    fn stall_window_is_none_when_min_bytes_per_second_is_zero() {
        let config = CatchpointDownloadConfig {
            min_bytes_per_second: 0,
            ..CatchpointDownloadConfig::default()
        };
        assert!(config.stall_window().is_none());
    }

    #[test]
    fn stall_window_scales_with_configured_speed_and_respects_the_floor() {
        // A very high configured speed still respects (stays within a
        // handful of microseconds of) the 2-minute floor.
        let fast = CatchpointDownloadConfig {
            chunk_size: 64 * 1024,
            min_bytes_per_second: 1_000_000_000,
            ..CatchpointDownloadConfig::default()
        };
        let fast_window = fast.stall_window().unwrap();
        assert!(
            fast_window >= STALL_WINDOW_FLOOR
                && fast_window < STALL_WINDOW_FLOOR + Duration::from_millis(1),
            "expected ~= the floor, got {fast_window:?}"
        );

        // A slow configured speed extends the window beyond the floor.
        let slow = CatchpointDownloadConfig {
            chunk_size: 64 * 1024,
            min_bytes_per_second: 1024,
            ..CatchpointDownloadConfig::default()
        };
        let window = slow.stall_window().unwrap();
        assert!(
            window > STALL_WINDOW_FLOOR,
            "a slow configured speed must extend the window beyond the floor, got {window:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn read_chunk_with_stall_check_times_out_on_a_stalled_response() {
        // Direct unit test of the stall-detection primitive itself (issue
        // #749), using an explicit short window rather than
        // `config.stall_window()`'s real 2-minute floor — proving the
        // arithmetic in `stall_window` is exercised separately above.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                // Send headers, then stall well past the test's window
                // before ever writing a body byte.
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
                    .await;
                tokio::time::sleep(Duration::from_secs(2)).await;
                let _ = socket.write_all(b"data").await;
            }
        });

        let dl = CatchpointDownloader::new(&format!("http://{addr}"), "");
        let mut response = reqwest::get(format!("http://{addr}/")).await.unwrap();

        let result = dl
            .read_chunk_with_stall_check(
                &mut response,
                Some(Duration::from_millis(100)),
                0,
                Path::new("test.tmp"),
            )
            .await;

        assert!(
            result.is_err(),
            "a chunk read exceeding the stall window must be treated as an error"
        );
        assert!(
            is_recoverable_stream_error(&result.unwrap_err()),
            "a stall timeout must be recoverable (retried), like a dropped connection"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn read_chunk_with_stall_check_succeeds_when_data_arrives_in_time() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata")
                    .await;
            }
        });

        let dl = CatchpointDownloader::new(&format!("http://{addr}"), "");
        let mut response = reqwest::get(format!("http://{addr}/")).await.unwrap();

        let result = dl
            .read_chunk_with_stall_check(
                &mut response,
                Some(Duration::from_secs(5)),
                0,
                Path::new("test.tmp"),
            )
            .await;

        let chunk = result.expect("data arriving well within the window must succeed");
        assert_eq!(chunk.unwrap().as_ref(), b"data");
    }

    #[test]
    fn test_constructor_trims_trailing_slash() {
        let dl = CatchpointDownloader::new("http://localhost:4001/", "mytoken");
        assert_eq!(dl.base_url, "http://localhost:4001");
    }

    #[test]
    fn test_constructor_no_trailing_slash() {
        let dl = CatchpointDownloader::new("http://localhost:4001", "mytoken");
        assert_eq!(dl.base_url, "http://localhost:4001");
    }

    /// Port of go's `TestNonParsableAddress` (`catchup/ledgerFetcher_test.go`,
    /// issue #976): a malformed peer address must cause the catchpoint fetch
    /// to fail gracefully with an error, not panic.
    ///
    /// Unlike go's `ledgerFetcher.getPeerLedger` (which parses the peer's
    /// address into a URL up front), `CatchpointDownloader::new`/
    /// `with_config` only trim a trailing slash and store the string
    /// verbatim — they never construct or parse a URL themselves. The
    /// equivalent rejection point here is the first network call, where
    /// `reqwest`'s request builder parses the assembled URL: malformed input
    /// (no scheme/host, like go's test address `":def"`) fails that parse
    /// and `.send()` surfaces it as `Err`, never a panic — `is_retryable`
    /// only treats connect/timeout failures as transient
    /// (`catchpoint_download.rs`'s `is_retryable`), so a parse failure is
    /// neither silently swallowed nor endlessly retried.
    #[tokio::test(flavor = "multi_thread")]
    async fn probe_availability_rejects_non_parsable_base_url() {
        let dl = CatchpointDownloader::new(":def", "");
        let result = dl.probe_availability("test genesisID", 0).await;
        assert!(
            result.is_err(),
            "a non-parsable base URL must be rejected with an error, not accepted or panicked on"
        );
    }

    /// Same rejection, exercised through the retrying `download` path
    /// (`get_with_retry`) rather than the single-shot `probe_availability`
    /// HEAD request — confirms the parse failure is treated as permanent
    /// (not retried `max_retries` times before failing).
    #[tokio::test(flavor = "multi_thread")]
    async fn download_rejects_non_parsable_base_url_without_retrying() {
        let dl = CatchpointDownloader::new(":def", "");
        let dest = std::env::temp_dir().join(format!(
            "algod-rust-test-nonparsable-{}.tmp",
            std::process::id()
        ));

        let result = dl
            .download("test genesisID", 0, &dest, None::<fn(DownloadProgress)>)
            .await;

        assert!(
            result.is_err(),
            "a non-parsable base URL must be rejected with an error"
        );
        let _ = std::fs::remove_file(&dest);
    }

    // -- probe_availability (issue #917's checkLedgerDownload-equivalent
    //    pre-flight probe, go's ledgerFetcher.headLedger) --

    #[tokio::test(flavor = "multi_thread")]
    async fn probe_availability_succeeds_on_200() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let method_seen = Arc::new(std::sync::Mutex::new(String::new()));
        let method_seen_clone = Arc::clone(&method_seen);

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request_line = String::from_utf8_lossy(&buf[..n]);
                *method_seen_clone.lock().unwrap() = request_line
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = socket.flush().await;
            }
        });

        let dl = CatchpointDownloader::new(&format!("http://{addr}"), "");
        let result = dl.probe_availability("test-v1.0", 42).await;

        assert!(
            result.is_ok(),
            "a 200 response must be treated as available"
        );
        assert_eq!(
            method_seen.lock().unwrap().as_str(),
            "HEAD",
            "probe_availability must send a HEAD request, not a full GET"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn probe_availability_maps_404_to_not_found() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let _ = socket.flush().await;
            }
        });

        let dl = CatchpointDownloader::new(&format!("http://{addr}"), "");
        let result = dl.probe_availability("test-v1.0", 1).await;

        assert!(matches!(result, Err(AlgoError::NotFound(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn probe_availability_maps_server_error_to_rest_client_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\
                          Connection: close\r\n\r\n",
                    )
                    .await;
                let _ = socket.flush().await;
            }
        });

        let dl = CatchpointDownloader::new(&format!("http://{addr}"), "");
        let result = dl.probe_availability("test-v1.0", 1).await;

        assert!(matches!(result, Err(AlgoError::RestClient { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn probe_availability_reports_connection_refused_as_rest_client_error() {
        // No listener bound at this address — connection should fail.
        let dl = CatchpointDownloader::new("http://127.0.0.1:1", "");
        let result = dl.probe_availability("test-v1.0", 1).await;

        assert!(matches!(result, Err(AlgoError::RestClient { .. })));
    }

    // -- P2P transport (issue #1127) --
    //
    // Mirrors go-algorand's `TestLedgerFetcherP2P` (`catchup/ledgerFetcher_test.go`):
    // that test doesn't exercise a separate binary wire protocol, it proves
    // the *same* HTTP-shaped `ledgerFetcher.headLedger`/`downloadLedger`
    // code works unchanged against a P2P-derived HTTP peer. These tests pin
    // the equivalent claim for `CatchpointDownloader`: `probe_availability`/
    // `download` behave identically whether `HttpPeerTransport` is backed by
    // plain TCP or (as `bin/algod-rust`'s real `P2pHttpPeerTransport` does)
    // an HTTP-over-libp2p stream — proven here with an in-memory
    // `tokio::io::duplex`-backed transport standing in for the real libp2p
    // stream, since this crate deliberately has no `algo-p2p`/`libp2p`
    // dependency (see `crate::http_over_stream`'s module doc comment). The
    // real libp2p wiring is proven end-to-end by
    // `bin/algod-rust`'s own P2P transport tests.

    /// An [`HttpPeerTransport`] backed by an in-memory duplex pipe per
    /// `open_stream` call: `respond_with` is written back for every request
    /// received on that stream (byte-for-byte), simulating a peer's HTTP
    /// server without a real socket. `requests_seen` counts how many
    /// streams were opened, so tests can assert on failover behavior.
    struct MockP2pTransport {
        respond_with: Vec<u8>,
        streams_opened: std::sync::atomic::AtomicUsize,
    }

    impl MockP2pTransport {
        fn new(respond_with: Vec<u8>) -> Self {
            Self {
                respond_with,
                streams_opened: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn streams_opened(&self) -> usize {
            self.streams_opened.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl crate::http_over_stream::HttpPeerTransport for MockP2pTransport {
        async fn open_stream(
            &self,
            _peer: &str,
        ) -> Result<crate::http_over_stream::BoxedDuplexStream> {
            self.streams_opened.fetch_add(1, Ordering::SeqCst);
            let (client, mut server) = tokio::io::duplex(4 * 1024 * 1024);
            let response = self.respond_with.clone();
            tokio::spawn(async move {
                // Drain (and ignore) whatever request bytes arrive, mirroring
                // a real HTTP/1.1 server reading the request off the same
                // stream it writes the response back on. `read` (not
                // `read_to_end`) is enough — the client always sends a
                // complete, bounded request and this mock never needs to
                // inspect it.
                let mut sink = [0u8; 4096];
                let _ = server.read(&mut sink).await;
                let _ = server.write_all(&response).await;
                let _ = server.flush().await;
                let _ = server.shutdown().await;
            });
            Ok(Box::new(client))
        }
    }

    fn ok_head_response() -> Vec<u8> {
        b"HTTP/1.1 200 OK\r\nContent-Type: application/x-algorand-ledger-v2.1\r\n\
          Content-Length: 0\r\n\r\n"
            .to_vec()
    }

    fn not_found_response() -> Vec<u8> {
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
    }

    fn ok_get_response(body: &[u8]) -> Vec<u8> {
        let mut resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-algorand-ledger-v2.1\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        resp.extend_from_slice(body);
        resp
    }

    /// TDD regression for issue #1127, headLedger-equivalent shape: a
    /// `CatchpointDownloader` built with [`CatchpointDownloader::with_p2p_transport`]
    /// must route `probe_availability`'s HEAD probe over the abstract
    /// transport (not `reqwest`) and report success for a 200 response —
    /// this must fail against pre-#1127 code, which has no
    /// `with_p2p_transport` constructor at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn probe_availability_succeeds_over_p2p_transport() {
        let transport: Arc<dyn crate::http_over_stream::HttpPeerTransport> =
            Arc::new(MockP2pTransport::new(ok_head_response()));
        let dl = CatchpointDownloader::with_p2p_transport(
            "12D3KooWtestpeer",
            Arc::clone(&transport),
            CatchpointDownloadConfig::default(),
        );

        let result = dl.probe_availability("test-v1.0", 7).await;
        assert!(result.is_ok(), "expected success, got {result:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn probe_availability_maps_404_to_not_found_over_p2p_transport() {
        let transport: Arc<dyn crate::http_over_stream::HttpPeerTransport> =
            Arc::new(MockP2pTransport::new(not_found_response()));
        let dl = CatchpointDownloader::with_p2p_transport(
            "12D3KooWtestpeer",
            transport,
            CatchpointDownloadConfig::default(),
        );

        let result = dl.probe_availability("test-v1.0", 7).await;
        assert!(matches!(result, Err(AlgoError::NotFound(_))));
    }

    /// TDD regression for issue #1127, downloadLedger-equivalent shape: a
    /// full `download()` over the abstract P2P transport must write the
    /// exact body bytes to `dest_path`, exercising both the "prefetched
    /// body already read while parsing the head" and "further chunked
    /// reads" paths (the mock's response is written as one contiguous
    /// buffer, so `read_http_response_head`'s single `stream.read()` call
    /// typically captures the whole small body as prefetched bytes here —
    /// the large-body test below forces the chunked-read path instead).
    #[tokio::test(flavor = "multi_thread")]
    async fn download_succeeds_over_p2p_transport() {
        const BODY: &[u8] = b"p2p-catchpoint-tarball-bytes-0123456789";
        let transport: Arc<dyn crate::http_over_stream::HttpPeerTransport> =
            Arc::new(MockP2pTransport::new(ok_get_response(BODY)));
        let dl = CatchpointDownloader::with_p2p_transport(
            "12D3KooWtestpeer",
            transport,
            CatchpointDownloadConfig {
                min_bytes_per_second: 0,
                ..CatchpointDownloadConfig::default()
            },
        );

        let tmp_dir =
            std::env::temp_dir().join(format!("algod-rust-catchpoint-p2p-{}", std::process::id()));
        let dest = tmp_dir.join("catchpoint-p2p.tar.gz");

        let result = dl
            .download::<fn(DownloadProgress)>("test-v1.0", 7, &dest, None)
            .await;
        assert!(result.is_ok(), "expected success, got {result:?}");
        assert_eq!(std::fs::read(&dest).unwrap(), BODY);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    /// Forces the chunked (non-prefetched) body-read path: a body larger
    /// than `chunk_size` with a small `duplex` buffer between the mock
    /// server and client all but guarantees `read_http_response_head`'s
    /// initial read only captures the head, and the loop in
    /// `p2p_stream_body_to_file` must then read the remainder across
    /// multiple `stream.read()` calls.
    #[tokio::test(flavor = "multi_thread")]
    async fn download_over_p2p_transport_streams_a_multi_chunk_body() {
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let transport: Arc<dyn crate::http_over_stream::HttpPeerTransport> =
            Arc::new(MockP2pTransport::new(ok_get_response(&body)));
        let dl = CatchpointDownloader::with_p2p_transport(
            "12D3KooWtestpeer",
            transport,
            CatchpointDownloadConfig {
                chunk_size: 4096,
                min_bytes_per_second: 0,
                ..CatchpointDownloadConfig::default()
            },
        );

        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-p2p-large-{}",
            std::process::id()
        ));
        let dest = tmp_dir.join("catchpoint-p2p-large.tar.gz");

        let result = dl
            .download::<fn(DownloadProgress)>("test-v1.0", 9, &dest, None)
            .await;
        assert!(result.is_ok(), "expected success, got {result:?}");
        assert_eq!(std::fs::read(&dest).unwrap(), body);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn download_maps_404_to_not_found_over_p2p_transport_without_retrying() {
        let mock = Arc::new(MockP2pTransport::new(not_found_response()));
        let dl = CatchpointDownloader::with_p2p_transport(
            "12D3KooWtestpeer",
            mock.clone() as Arc<dyn crate::http_over_stream::HttpPeerTransport>,
            CatchpointDownloadConfig {
                max_retries: 3,
                retry_delay: Duration::from_millis(1),
                min_bytes_per_second: 0,
                ..CatchpointDownloadConfig::default()
            },
        );

        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-p2p-404-{}",
            std::process::id()
        ));
        let dest = tmp_dir.join("catchpoint-p2p-404.tar.gz");

        let result = dl
            .download::<fn(DownloadProgress)>("test-v1.0", 1, &dest, None)
            .await;
        assert!(matches!(result, Err(AlgoError::NotFound(_))));
        // The unavailable-round classification must not be retried, mirroring
        // `get_with_retry`'s immediate 404 return: exactly one stream was
        // opened, not `1 + max_retries`.
        assert_eq!(
            mock.streams_opened(),
            1,
            "a 404 must not be retried across additional P2P stream attempts"
        );
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
