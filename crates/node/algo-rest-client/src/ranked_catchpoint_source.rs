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

//! Peer-ranked catchpoint file source (issue #901).
//!
//! Mirrors go-algorand's `catchup/catchpointService.go`:
//! `CatchpointCatchupService.blocksDownloadPeerSelector`, built by
//! `initDownloadPeerSelector()` -> `makeCatchpointPeerSelector(net)`, and
//! used both by `checkLedgerDownload`'s pre-flight availability probe and
//! by the staged catchpoint-file download itself to pick which peer to try
//! next and to rank it on success/failure
//! (`peerRankDownloadFailed`/`peerRankNoCatchpointForRound`).
//!
//! Unlike go's two-stage flow (a separate `checkLedgerDownload` HEAD-probe
//! stage ahead of the real download), this module ranks peers directly
//! around the download attempt: a candidate that fails is deprioritized in
//! favor of a better-ranked one on the next retry, without a distinct
//! up-front probe stage. Go's fuller staged pipeline
//! (`processStageLatestBlockDownload` et al.) is explicitly optional per
//! issue #901 and is not ported here.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use algo_error::{AlgoError, Result};

use algo_network::peer_ranker::{
    make_catchpoint_peer_selector, ClassBasedPeerSelector, PeerClassKind, PeerSelector,
    PeersRetriever, PEER_RANK_DOWNLOAD_FAILED, PEER_RANK_NO_CATCHPOINT_FOR_ROUND,
};

use crate::{CatchpointDownloadConfig, CatchpointDownloader, DownloadProgress};

/// Presents a fixed list of candidate base URLs to the peer ranker, all
/// under the `PhonebookRelays` class — [`make_catchpoint_peer_selector`]'s
/// preferred (tolerance-3) class, matching go's real catchpoint peer
/// selector topology. algod-rust has no relay/archival distinction for
/// catchpoint candidate peers at this layer, so the fallback
/// `PhonebookArchivalNodes` class (tolerance 10) always reports empty.
struct StaticUrlRetriever {
    urls: Vec<String>,
}

impl PeersRetriever for StaticUrlRetriever {
    fn get_peers(&self, class: PeerClassKind) -> Vec<String> {
        if class == PeerClassKind::PhonebookRelays {
            self.urls.clone()
        } else {
            Vec::new()
        }
    }
}

/// A catchpoint-file source that ranks multiple candidate algod peers by
/// historical download performance, so a peer that fails or is slow is
/// deprioritized in favor of a better-ranked one on the next attempt.
pub struct RankedCatchpointSource {
    downloaders: HashMap<String, CatchpointDownloader>,
    selector: StdMutex<ClassBasedPeerSelector>,
}

impl RankedCatchpointSource {
    /// Build a ranked source from candidate `(base_url, token)` pairs,
    /// each given its own [`CatchpointDownloader`] sharing `config`.
    ///
    /// Peer identity for ranking purposes is the base URL.
    pub fn new(peers: &[(String, String)], config: CatchpointDownloadConfig) -> Self {
        let mut downloaders = HashMap::with_capacity(peers.len());
        let mut urls = Vec::with_capacity(peers.len());
        for (url, token) in peers {
            downloaders.insert(
                url.clone(),
                CatchpointDownloader::with_config(url, token, config.clone()),
            );
            urls.push(url.clone());
        }
        let retriever: Arc<dyn PeersRetriever> = Arc::new(StaticUrlRetriever { urls });
        Self {
            downloaders,
            selector: StdMutex::new(make_catchpoint_peer_selector(retriever)),
        }
    }

    /// Number of candidate peers configured.
    pub fn peer_count(&self) -> usize {
        self.downloaders.len()
    }

    /// Download the catchpoint file, trying candidate peers in ranked
    /// order until one succeeds or every candidate has been tried once.
    ///
    /// Mirrors go's `peerSelector.getNextPeer()` /
    /// `peerSelector.rankPeer()` call sites around a catchpoint fetch: a
    /// successful download is ranked by observed duration
    /// (`peerDownloadDurationToRank`); a failed one is ranked
    /// `peerRankNoCatchpointForRound` when the peer reported the catchpoint
    /// as unavailable (HTTP 404, matching `checkLedgerDownload`'s
    /// unavailable-catchpoint case) or `peerRankDownloadFailed` for any
    /// other transfer failure.
    pub async fn download(
        &self,
        genesis_id: &str,
        round: u64,
        dest_path: &Path,
        progress_cb: Option<&(dyn Fn(DownloadProgress) + Send + Sync)>,
    ) -> Result<()> {
        if self.downloaders.is_empty() {
            return Err(AlgoError::Network {
                message: "no catchpoint peers available for ranked download".into(),
            });
        }

        // Ranked selection offers no guarantee that each attempt lands on a
        // distinct peer (a failing peer's rank may not yet have separated
        // from a reliable one's, e.g. two peers tied in the same rank
        // bucket and tie-broken at random) — capping attempts at the peer
        // count risks exhausting the retry budget on the same bad peer
        // repeatedly while a good one sits untried. Retry a fixed multiple
        // of the peer count instead, mirroring go's `checkLedgerDownload`
        // loop bound (`CatchupLedgerDownloadRetryAttempts`), which is
        // likewise a fixed retry budget independent of peer count.
        const RETRY_ATTEMPTS_PER_PEER: usize = 5;
        let attempts = self
            .downloaders
            .len()
            .saturating_mul(RETRY_ATTEMPTS_PER_PEER);
        let mut last_err = None;

        for _ in 0..attempts {
            let psp = {
                let mut selector = self
                    .selector
                    .lock()
                    .expect("catchpoint peer selector lock poisoned");
                selector.get_next_peer()
            };
            let psp = match psp {
                Ok(p) => p,
                Err(_) => break,
            };
            let downloader = match self.downloaders.get(&psp.peer_id) {
                Some(d) => d,
                None => continue,
            };

            let started = Instant::now();
            match downloader
                .download(genesis_id, round, dest_path, progress_cb)
                .await
            {
                Ok(()) => {
                    let elapsed = started.elapsed();
                    let mut selector = self
                        .selector
                        .lock()
                        .expect("catchpoint peer selector lock poisoned");
                    let rank = selector.peer_download_duration_to_rank(&psp, elapsed);
                    selector.rank_peer(&psp, rank);
                    return Ok(());
                }
                Err(e) => {
                    let failure_rank = if matches!(e, AlgoError::NotFound(_)) {
                        PEER_RANK_NO_CATCHPOINT_FOR_ROUND
                    } else {
                        PEER_RANK_DOWNLOAD_FAILED
                    };
                    let mut selector = self
                        .selector
                        .lock()
                        .expect("catchpoint peer selector lock poisoned");
                    selector.rank_peer(&psp, failure_rank);
                    drop(selector);
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| AlgoError::Network {
            message: format!("all {attempts} catchpoint peers failed for round {round}"),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A minimal raw-socket HTTP server that always resets the connection
    /// (simulating a consistently unreachable/unreliable catchpoint peer),
    /// counting how many connection attempts it received.
    async fn spawn_always_failing_server() -> (String, Arc<AtomicUsize>) {
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
                attempts_clone.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                // Drop without responding: the client sees a connection error.
                drop(socket);
            }
        });

        (format!("http://{addr}"), attempts)
    }

    /// A minimal raw-socket HTTP server that always serves `body`
    /// successfully, counting how many requests it received.
    async fn spawn_always_succeeding_server(body: &'static [u8]) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let requests_clone = Arc::clone(&requests);

        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                requests_clone.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(header.as_bytes()).await;
                let _ = socket.write_all(body).await;
                let _ = socket.flush().await;
                drop(socket);
            }
        });

        (format!("http://{addr}"), requests)
    }

    fn fast_retry_config() -> CatchpointDownloadConfig {
        CatchpointDownloadConfig {
            timeout: std::time::Duration::from_secs(5),
            chunk_size: 16,
            max_retries: 0,
            retry_delay: std::time::Duration::from_millis(1),
            min_bytes_per_second: 0,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn no_peers_returns_error() {
        let src = RankedCatchpointSource::new(&[], CatchpointDownloadConfig::default());
        let tmp = std::env::temp_dir().join(format!(
            "algod-rust-ranked-catchpoint-noop-{}",
            std::process::id()
        ));
        let result = src.download("test-v1.0", 1, &tmp, None).await;
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ranked_source_prefers_the_reliable_peer_after_the_unreliable_one_fails() {
        // TDD regression for issue #901: catchpoint source selection must
        // route through the peer_ranker rather than a single fixed source,
        // and must feed download outcomes back into it, so a peer that
        // fails is deprioritized in favor of a reliable one on subsequent
        // rounds.
        const BODY: &[u8] = b"catchpoint-file-bytes-0123456789";
        let (bad_url, bad_attempts) = spawn_always_failing_server().await;
        let (good_url, good_requests) = spawn_always_succeeding_server(BODY).await;

        let src = RankedCatchpointSource::new(
            &[(bad_url, String::new()), (good_url, String::new())],
            fast_retry_config(),
        );
        assert_eq!(src.peer_count(), 2);

        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-ranked-catchpoint-test-{}",
            std::process::id()
        ));

        const ROUNDS: u64 = 8;
        for round in 1..=ROUNDS {
            let dest = tmp_dir.join(format!("catchpoint-{round}.tar.gz"));
            let result = src.download("test-v1.0", round, &dest, None).await;
            assert!(
                result.is_ok(),
                "round {round} should have succeeded via the reliable peer, got {:?}",
                result.err()
            );
        }

        // The bad peer may unavoidably be tried once while both start
        // tied, but must be consistently deprioritized afterward.
        assert!(
            bad_attempts.load(Ordering::SeqCst) <= 2,
            "unreliable catchpoint peer should be deprioritized after failing, but was \
             retried {} times",
            bad_attempts.load(Ordering::SeqCst)
        );
        assert!(
            good_requests.load(Ordering::SeqCst) >= ROUNDS as usize - 2,
            "reliable catchpoint peer should serve almost every round, got {} of {ROUNDS}",
            good_requests.load(Ordering::SeqCst)
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    // -- TestCatchpointServicePeerRank-equivalent: ranking must not panic
    //    when there is exactly one (already-local-equivalent) source and
    //    it fails, mirroring go's assertion that ranking a peer never
    //    crashes the catchpoint service even in a degenerate case. --

    #[tokio::test(flavor = "multi_thread")]
    async fn single_peer_failure_is_ranked_without_panicking() {
        let (bad_url, bad_attempts) = spawn_always_failing_server().await;
        let src = RankedCatchpointSource::new(&[(bad_url, String::new())], fast_retry_config());

        let tmp = std::env::temp_dir().join(format!(
            "algod-rust-ranked-catchpoint-single-{}",
            std::process::id()
        ));
        let result = src.download("test-v1.0", 1, &tmp, None).await;
        assert!(result.is_err());
        // Retries the single (always-failing) peer up to the fixed
        // per-peer attempt budget rather than giving up after one try.
        assert!(bad_attempts.load(Ordering::SeqCst) >= 1);
    }
}
