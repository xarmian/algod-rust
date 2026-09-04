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
use std::time::Duration;

use algo_error::{AlgoError, Result};
use tracing::{debug, info, warn};

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
pub struct CatchpointDownloader {
    base_url: String,
    token: String,
    http: reqwest::Client,
    config: CatchpointDownloadConfig,
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
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        full_body.len()
                    );
                    let _ = socket.write_all(header.as_bytes()).await;
                    let truncated = &full_body[..full_body.len() / 2];
                    let _ = socket.write_all(truncated).await;
                    let _ = socket.flush().await;
                    drop(socket);
                } else {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
}
