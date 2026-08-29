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
}

impl Default for CatchpointDownloadConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30 * 60),
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
        }
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

        // Use reqwest's chunk() method to stream the response body without
        // buffering the entire payload in memory.
        while let Some(chunk) = response.chunk().await.map_err(|e| AlgoError::RestClient {
            source: Box::new(e),
            context: format!(
                "reading chunk at offset {bytes_downloaded} from {}",
                path.display()
            ),
        })? {
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
        let config = CatchpointDownloadConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30 * 60));
        assert_eq!(config.chunk_size, DEFAULT_CHUNK_SIZE);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay, Duration::from_secs(1));
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
}
