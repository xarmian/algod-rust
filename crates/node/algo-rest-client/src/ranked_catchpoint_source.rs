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

//! Peer-ranked catchpoint file source (issue #901; staged pre-flight probe
//! added by issue #917).
//!
//! Mirrors go-algorand's `catchup/catchpointService.go`:
//! `CatchpointCatchupService.blocksDownloadPeerSelector`, built by
//! `initDownloadPeerSelector()` -> `makeCatchpointPeerSelector(net)`, and
//! used both by `checkLedgerDownload`'s pre-flight availability probe and
//! by the staged catchpoint-file download itself to pick which peer to try
//! next and to rank it on success/failure
//! (`peerRankDownloadFailed`/`peerRankNoCatchpointForRound`).
//!
//! [`RankedCatchpointSource::download`] runs go's two-stage flow: a
//! `check_ledger_download` pre-flight stage (mirroring
//! `checkLedgerDownload`/`headLedger` — a HEAD probe across ranked
//! candidates that ranks an unavailable-catchpoint peer
//! `PEER_RANK_NO_CATCHPOINT_FOR_ROUND` without ever starting a real
//! transfer) followed by the real download stage, both sharing the same
//! peer-selector state so a probe failure carries forward into download
//! peer selection exactly as go's `CatchpointCatchupService.Start()` ->
//! `run()` sequencing does.
//!
//! Go's fuller staged pipeline beyond this — the persisted,
//! resumable-across-restarts `CatchpointCatchupState` machine
//! (`processStageLedgerDownload`/`processStageLatestBlockDownload`/
//! `processStageBlocksDownload`/`processStageSwitch`, which also covers
//! downloading the post-catchpoint block lookback window needed for state
//! proof/lease verification) has no equivalent here: algod-rust's
//! `SyncOrchestrator` (`crates/core/algo-ledger/src/sync/state_machine.rs`,
//! `SyncState`) already owns that block-lookback phase as part of its own
//! phase state machine, so porting go's version would duplicate rather
//! than replace it. This remains documented, deliberately out-of-scope
//! follow-up (see issue #917's PR).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use algo_error::{AlgoError, Result};

use algo_network::peer_ranker::{
    make_catchpoint_peer_selector, ClassBasedPeerSelector, PeerClassKind, PeerSelector,
    PeersRetriever, PEER_RANK_DOWNLOAD_FAILED, PEER_RANK_NO_CATCHPOINT_FOR_ROUND,
};

use crate::http_over_stream::HttpPeerTransport;
use crate::{CatchpointDownloadConfig, CatchpointDownloader, DownloadProgress};

/// Presents the live list of candidate peer identities (HTTP base URLs
/// and/or, since issue #1127, P2P peer IDs added via
/// [`RankedCatchpointSource::push_p2p_peer`]) to the peer ranker, all under
/// the `PhonebookRelays` class — [`make_catchpoint_peer_selector`]'s
/// preferred (tolerance-3) class, matching go's real catchpoint peer
/// selector topology. algod-rust has no relay/archival distinction for
/// catchpoint candidate peers at this layer, so the fallback
/// `PhonebookArchivalNodes` class (tolerance 10) always reports empty.
///
/// A live `Mutex<Vec<String>>` (rather than the fixed `Vec` this held
/// before #1127) so [`RankedCatchpointSource::push_p2p_peer`] can extend the
/// candidate pool after construction — mirroring
/// `crate::gossip_block_source::GossipPeersRetriever`'s identical live-list
/// pattern for block-fetch peers.
struct StaticUrlRetriever {
    urls: StdMutex<Vec<String>>,
}

impl PeersRetriever for StaticUrlRetriever {
    fn get_peers(&self, class: PeerClassKind) -> Vec<String> {
        if class == PeerClassKind::PhonebookRelays {
            self.urls
                .lock()
                .expect("peer url list lock poisoned")
                .clone()
        } else {
            Vec::new()
        }
    }
}

/// A catchpoint-file source that ranks multiple candidate algod peers by
/// historical download performance, so a peer that fails or is slow is
/// deprioritized in favor of a better-ranked one on the next attempt.
pub struct RankedCatchpointSource {
    downloaders: StdMutex<HashMap<String, Arc<CatchpointDownloader>>>,
    retriever: Arc<StaticUrlRetriever>,
    config: CatchpointDownloadConfig,
    selector: StdMutex<ClassBasedPeerSelector>,
    ledger_download_retry_attempts: usize,
}

impl RankedCatchpointSource {
    /// go's `config.Local.CatchupLedgerDownloadRetryAttempts` default (50,
    /// `config/local_defaults.go`) — the fallback [`Self::new`] applies
    /// until a caller overrides it via
    /// [`Self::with_ledger_download_retry_attempts`] (issue #1289).
    pub const DEFAULT_LEDGER_DOWNLOAD_RETRY_ATTEMPTS: usize = 50;

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
                Arc::new(CatchpointDownloader::with_config(
                    url,
                    token,
                    config.clone(),
                )),
            );
            urls.push(url.clone());
        }
        let retriever = Arc::new(StaticUrlRetriever {
            urls: StdMutex::new(urls),
        });
        Self {
            downloaders: StdMutex::new(downloaders),
            selector: StdMutex::new(make_catchpoint_peer_selector(
                Arc::clone(&retriever) as Arc<dyn PeersRetriever>
            )),
            retriever,
            config,
            ledger_download_retry_attempts: Self::DEFAULT_LEDGER_DOWNLOAD_RETRY_ATTEMPTS,
        }
    }

    /// Override the pre-flight probe retry budget [`Self::check_ledger_download`]
    /// uses — go's `config.Local.CatchupLedgerDownloadRetryAttempts` (issue
    /// #1289). Callers with a loaded `config.json` should pass
    /// `node_config.catchup_ledger_download_retry_attempts` here rather than
    /// relying on [`Self::DEFAULT_LEDGER_DOWNLOAD_RETRY_ATTEMPTS`], the same
    /// way [`CatchpointDownloadConfig`] itself is meant to be built from
    /// config rather than left at its own defaults.
    pub fn with_ledger_download_retry_attempts(mut self, attempts: usize) -> Self {
        self.ledger_download_retry_attempts = attempts;
        self
    }

    /// Add a P2P-backed candidate catchpoint peer (issue #1127): its
    /// [`CatchpointDownloader`] routes HTTP requests over `transport`
    /// (e.g. `bin/algod-rust`'s `P2pTransport::open_http_stream`) instead of
    /// plain-TCP `reqwest`, keyed by `peer_id` (the transport's own peer
    /// identity, e.g. a libp2p `PeerId`'s string form) rather than a URL.
    ///
    /// The new peer joins the same `PhonebookRelays`-class candidate pool
    /// [`Self::new`]'s HTTP peers already occupy and is ranked by the same
    /// [`ClassBasedPeerSelector`] machinery — a P2P-sourced peer that fails
    /// or is slow is deprioritized exactly the way an HTTP-sourced one
    /// already is (this method's whole point: extending, not duplicating,
    /// #901's existing ranking wiring).
    pub fn push_p2p_peer(&self, peer_id: String, transport: Arc<dyn HttpPeerTransport>) {
        let downloader = Arc::new(CatchpointDownloader::with_p2p_transport(
            &peer_id,
            transport,
            self.config.clone(),
        ));
        self.downloaders
            .lock()
            .expect("downloaders map lock poisoned")
            .insert(peer_id.clone(), downloader);
        self.retriever
            .urls
            .lock()
            .expect("peer url list lock poisoned")
            .push(peer_id);
    }

    /// Number of candidate peers configured.
    pub fn peer_count(&self) -> usize {
        self.downloaders
            .lock()
            .expect("downloaders map lock poisoned")
            .len()
    }

    /// Pre-flight availability probe stage: mirrors go's
    /// `CatchpointCatchupService.checkLedgerDownload` (`catchup/catchpointService.go`),
    /// run once ahead of the real transfer in [`Self::download`].
    ///
    /// Sends a HEAD request (via [`CatchpointDownloader::probe_availability`],
    /// go's `ledgerFetcher.headLedger`) to ranked candidate peers, one at a
    /// time, until one reports the catchpoint available (`Ok(())`, without
    /// ranking that peer here — matching go, which leaves ranking the
    /// success to the real download stage that follows) or the attempt
    /// budget is exhausted (`Err`, matching go's `checkLedgerDownload`
    /// returning an error that aborts the catchup before it starts). A
    /// peer that doesn't have the catchpoint (HTTP 404 ->
    /// [`AlgoError::NotFound`]) is ranked `PEER_RANK_NO_CATCHPOINT_FOR_ROUND`;
    /// any other probe failure is ranked `PEER_RANK_DOWNLOAD_FAILED` — both
    /// mirroring `checkLedgerDownload`'s `peerRankNoCatchpointForRound`
    /// classification (go ranks every `headLedger` failure this way,
    /// without go's finer 404-vs-other distinction; this module keeps that
    /// distinction, already used by the download stage below, for
    /// consistency).
    async fn check_ledger_download(&self, genesis_id: &str, round: u64) -> Result<()> {
        // Configurable budget (issue #1289), matching go's `for i := 0; i <
        // cs.config.CatchupLedgerDownloadRetryAttempts; i++` exactly — go
        // never scales this down for a small candidate-peer count, and
        // neither must this: `get_next_peer()` breaks ties between
        // equally-ranked peers at random (`PeerRanker::get_next_peer`), and
        // a single probe failure's post-failure rank can land in the same
        // bucket as another peer's post-success rank (both are bounded into
        // the same `[lower_bound..upper_bound]` class range by
        // `HistoricStats::push`), so two peers can still draw as a tie
        // *after* one of them has already failed once. A budget capped at
        // `downloaders.len()` gives zero slack for that unlucky redraw and
        // can exhaust itself on the same already-known-bad peer while a
        // working peer sits untried in the very same tied pool (see issue
        // #928).
        let attempts = self.ledger_download_retry_attempts;
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
            let downloader = {
                let guard = self
                    .downloaders
                    .lock()
                    .expect("downloaders map lock poisoned");
                guard.get(&psp.peer_id).cloned()
            };
            let downloader = match downloader {
                Some(d) => d,
                None => continue,
            };

            match downloader.probe_availability(genesis_id, round).await {
                Ok(()) => return Ok(()),
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
            message: format!(
                "check_ledger_download(): catchpoint round {round} unavailable from any of \
                 {attempts} probed peers"
            ),
        }))
    }

    /// Download the catchpoint file, trying candidate peers in ranked
    /// order until one succeeds or every candidate has been tried once.
    ///
    /// Runs [`Self::check_ledger_download`]'s pre-flight probe stage first
    /// (mirroring go's `CatchpointCatchupService.Start()` calling
    /// `checkLedgerDownload` before the real staged pipeline runs); a
    /// probe failure aborts here without ever attempting a real transfer,
    /// exactly as go's `Start()` does when `checkLedgerDownload` errors.
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
        if self
            .downloaders
            .lock()
            .expect("downloaders map lock poisoned")
            .is_empty()
        {
            return Err(AlgoError::Network {
                message: "no catchpoint peers available for ranked download".into(),
            });
        }

        self.check_ledger_download(genesis_id, round).await?;

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
            .lock()
            .expect("downloaders map lock poisoned")
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
            let downloader = {
                let guard = self
                    .downloaders
                    .lock()
                    .expect("downloaders map lock poisoned");
                guard.get(&psp.peer_id).cloned()
            };
            let downloader = match downloader {
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
                    "HTTP/1.1 200 OK\r\nContent-Type: application/x-algorand-ledger-v2.1\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
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
        // With the pre-flight check_ledger_download probe stage (issue
        // #917), a single always-failing peer is ranked and rejected during
        // the probe itself, so `download()` returns without ever reaching
        // the real-transfer retry loop below it — the connection is still
        // attempted (and still ranked, without panicking) at least once.
        assert!(bad_attempts.load(Ordering::SeqCst) >= 1);
    }

    // -- check_ledger_download pre-flight probe stage (issue #917) --

    /// A minimal raw-socket HTTP server that always responds `404 Not
    /// Found` (simulating a peer that doesn't retain this round's
    /// catchpoint), counting how many requests it received.
    async fn spawn_always_404_server() -> (String, Arc<AtomicUsize>) {
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
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let _ = socket.flush().await;
                drop(socket);
            }
        });

        (format!("http://{addr}"), requests)
    }

    /// TDD regression for issue #917: `check_ledger_download` must probe
    /// (HEAD, not a real transfer) and rank a 404-for-this-round peer
    /// `PEER_RANK_NO_CATCHPOINT_FOR_ROUND` — mirroring go's
    /// `checkLedgerDownload`/`headLedger` — *before* `download()` ever
    /// attempts a real transfer against that peer. With a reliable second
    /// peer available, the 404 peer should be probed at most once (the
    /// unavoidable first tie-broken draw) and never actually downloaded
    /// from.
    #[tokio::test(flavor = "multi_thread")]
    async fn check_ledger_download_probe_deprioritizes_a_404_peer_before_any_real_download() {
        const BODY: &[u8] = b"catchpoint-file-bytes-0123456789";
        let (missing_url, missing_requests) = spawn_always_404_server().await;
        let (good_url, good_requests) = spawn_always_succeeding_server(BODY).await;

        let src = RankedCatchpointSource::new(
            &[(missing_url, String::new()), (good_url, String::new())],
            fast_retry_config(),
        );

        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-ranked-catchpoint-404-{}",
            std::process::id()
        ));

        const ROUNDS: u64 = 6;
        for round in 1..=ROUNDS {
            let dest = tmp_dir.join(format!("catchpoint-{round}.tar.gz"));
            let result = src.download("test-v1.0", round, &dest, None).await;
            assert!(
                result.is_ok(),
                "round {round} should have succeeded via the peer that has the catchpoint, \
                 got {:?}",
                result.err()
            );
        }

        // The 404 peer may unavoidably be probed once while both peers
        // start tied, but must be consistently deprioritized afterward —
        // and, crucially, every one of its hits is a cheap HEAD probe, not
        // a real GET transfer (the always-404 server responds identically
        // to both, so this bound alone proves the probe stage is catching
        // it early rather than falling through to the download stage).
        assert!(
            missing_requests.load(Ordering::SeqCst) <= 2,
            "a peer reporting the catchpoint unavailable should be deprioritized after the \
             first probe, but was hit {} times",
            missing_requests.load(Ordering::SeqCst)
        );
        assert!(
            good_requests.load(Ordering::SeqCst) >= ROUNDS as usize - 2,
            "the peer with the catchpoint should serve almost every round, got {} of {ROUNDS}",
            good_requests.load(Ordering::SeqCst)
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    /// TDD regression for issue #928: a probe-stage retry budget capped at
    /// `downloaders.len()` (rather than go's fixed
    /// `CatchupLedgerDownloadRetryAttempts`, 50) has essentially zero slack
    /// for `get_next_peer`'s random tie-breaking, and this repo's
    /// `HistoricStats::push` maps *both* a single probe failure's new rank
    /// and a fast real-download success's new rank into the same
    /// `[lower_bound..upper_bound]` bucket for a class — so two peers can
    /// still draw as a tie *after* one of them has already failed once.
    ///
    /// This reproduces the exact sequence observed causing the flake before
    /// the fix: round 1's `download()` moves the reliable peer's rank from
    /// its pristine initial rank into the post-success bucket, then round
    /// 2's `check_ledger_download` probe can draw the already-known-bad
    /// peer twice in a row (a peer-count-sized budget of 2 gives no slack
    /// for that), returning `NotFound` and failing the round even though
    /// the reliable peer was available in the very same tied pool the whole
    /// time. Run many independent trials (fresh source/servers each time,
    /// so no state leaks between them) to make this a deterministic pin
    /// rather than a coin flip: the peer-count-capped budget failed this
    /// scenario about 1 in 8 trials locally, so 100 trials essentially
    /// never pass by chance, while the fixed 50-attempt budget makes
    /// failure astronomically unlikely even under repeated unlucky ties.
    #[tokio::test(flavor = "multi_thread")]
    async fn check_ledger_download_retry_budget_is_not_capped_by_peer_count() {
        const BODY: &[u8] = b"catchpoint-file-bytes-0123456789";
        const TRIALS: usize = 100;

        for trial in 0..TRIALS {
            let (missing_url, _missing_requests) = spawn_always_404_server().await;
            let (good_url, _good_requests) = spawn_always_succeeding_server(BODY).await;

            let src = RankedCatchpointSource::new(
                &[(missing_url, String::new()), (good_url, String::new())],
                fast_retry_config(),
            );

            let tmp_dir = std::env::temp_dir().join(format!(
                "algod-rust-ranked-catchpoint-budget-{}-{trial}",
                std::process::id()
            ));
            let dest = tmp_dir.join("catchpoint-1.tar.gz");

            // Round 1: a full download, elevating the reliable peer's rank
            // out of its pristine initial rank into the post-success
            // bucket, exactly as in the original flake's setup.
            let round1 = src.download("test-v1.0", 1, &dest, None).await;
            assert!(
                round1.is_ok(),
                "trial {trial}: round 1 download should have succeeded via the peer that has \
                 the catchpoint, got {:?}",
                round1.err()
            );

            // Round 2: the probe stage alone, where the original flake
            // manifested — the reliable peer's rank may now tie with the
            // 404 peer's post-first-failure rank, so this must survive
            // more than one unlucky redraw of the known-bad peer.
            let round2 = src.check_ledger_download("test-v1.0", 2).await;
            assert!(
                round2.is_ok(),
                "trial {trial}: round 2 probe should have succeeded via the peer that has the \
                 catchpoint even under an unlucky peer-selector tie, got {:?}",
                round2.err()
            );

            let _ = std::fs::remove_dir_all(&tmp_dir);
        }
    }

    /// Direct unit test of `check_ledger_download`'s failure path (all
    /// candidates report the catchpoint unavailable): it must return an
    /// error without panicking, and — mirroring go's `checkLedgerDownload`
    /// returning an error that aborts `CatchpointCatchupService.Start()`
    /// before the staged pipeline ever runs — `download()` must propagate
    /// that failure without attempting a real transfer.
    #[tokio::test(flavor = "multi_thread")]
    async fn check_ledger_download_fails_when_every_peer_lacks_the_catchpoint() {
        let (missing_url, missing_requests) = spawn_always_404_server().await;
        let src = RankedCatchpointSource::new(&[(missing_url, String::new())], fast_retry_config());

        let probe_result = src.check_ledger_download("test-v1.0", 1).await;
        assert!(
            probe_result.is_err(),
            "check_ledger_download should fail when the only candidate lacks the catchpoint"
        );
        assert!(missing_requests.load(Ordering::SeqCst) >= 1);

        let tmp = std::env::temp_dir().join(format!(
            "algod-rust-ranked-catchpoint-404-only-{}",
            std::process::id()
        ));
        let download_result = src.download("test-v1.0", 1, &tmp, None).await;
        assert!(
            download_result.is_err(),
            "download() must propagate a check_ledger_download failure rather than falling \
             through to a real transfer attempt"
        );
    }

    /// Issue #1289: `check_ledger_download`'s probe-retry budget must
    /// actually be configurable — go's real `Config.CatchupLedgerDownloadRetryAttempts`
    /// bounds `checkLedgerDownload`'s loop, and algod-rust's default-config
    /// callers should be able to override the equivalent budget here rather
    /// than being stuck on the hardcoded go-default-matching fallback. With
    /// a single, permanently-404 candidate peer, `PeerSelector::get_next_peer`
    /// always returns that one peer (no tie/redraw ambiguity to worry
    /// about), so the number of HTTP requests observed is an exact proxy
    /// for the number of probe attempts actually made.
    #[tokio::test(flavor = "multi_thread")]
    async fn check_ledger_download_retry_budget_is_configurable() {
        let (missing_url, missing_requests) = spawn_always_404_server().await;
        let src = RankedCatchpointSource::new(&[(missing_url, String::new())], fast_retry_config())
            .with_ledger_download_retry_attempts(3);

        let probe_result = src.check_ledger_download("test-v1.0", 1).await;
        assert!(
            probe_result.is_err(),
            "check_ledger_download should fail once the configured budget is exhausted"
        );
        assert_eq!(
            missing_requests.load(Ordering::SeqCst),
            3,
            "check_ledger_download must make exactly the configured number of probe attempts, \
             not the hardcoded 50-attempt go-default fallback"
        );
    }

    /// `RankedCatchpointSource::new` without any
    /// `with_ledger_download_retry_attempts` override still uses
    /// [`RankedCatchpointSource::DEFAULT_LEDGER_DOWNLOAD_RETRY_ATTEMPTS`]
    /// (go's `CatchupLedgerDownloadRetryAttempts` default, 50) as the probe
    /// budget passed into the loop — asserted directly on the constant
    /// (rather than by driving a real 404 server to 50 requests, which a
    /// single-candidate-peer `ClassBasedPeerSelector` can exhaust
    /// `get_next_peer()` well before reaching, independent of this budget;
    /// see `check_ledger_download_retry_budget_is_configurable` above for
    /// the end-to-end proof that a *smaller* configured budget is honored).
    #[test]
    fn default_ledger_download_retry_attempts_matches_go_default() {
        assert_eq!(
            RankedCatchpointSource::DEFAULT_LEDGER_DOWNLOAD_RETRY_ATTEMPTS,
            50
        );
    }

    // -- push_p2p_peer (issue #1127) --

    /// A minimal [`crate::http_over_stream::HttpPeerTransport`] mock, mirroring
    /// `catchpoint_download.rs`'s own `MockP2pTransport` test double — kept
    /// as a separate, smaller copy here rather than shared `pub(crate)` test
    /// scaffolding, since each module's mock only needs to prove its own
    /// module's wiring (this one only ever needs a single canned response
    /// per source).
    struct MockP2pTransport {
        respond_with: Vec<u8>,
        streams_opened: AtomicUsize,
    }

    impl MockP2pTransport {
        fn new(respond_with: Vec<u8>) -> Self {
            Self {
                respond_with,
                streams_opened: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::http_over_stream::HttpPeerTransport for MockP2pTransport {
        async fn open_stream(
            &self,
            _peer: &str,
        ) -> algo_error::Result<crate::http_over_stream::BoxedDuplexStream> {
            self.streams_opened.fetch_add(1, Ordering::SeqCst);
            let (client, mut server) = tokio::io::duplex(64 * 1024);
            let response = self.respond_with.clone();
            tokio::spawn(async move {
                let mut sink = [0u8; 4096];
                let _ = server.read(&mut sink).await;
                let _ = server.write_all(&response).await;
                let _ = server.flush().await;
                let _ = server.shutdown().await;
            });
            Ok(Box::new(client))
        }
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

    fn not_found_response() -> Vec<u8> {
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
    }

    /// TDD regression for issue #1127's second acceptance criterion:
    /// `RankedCatchpointSource`'s peer ranking must observe a P2P-sourced
    /// peer added via `push_p2p_peer` the same way it already does for
    /// HTTP-sourced peers (constructed via `new`) — a P2P peer that always
    /// fails must be deprioritized in favor of a reliable HTTP peer already
    /// in the pool, using the exact same `ClassBasedPeerSelector` machinery
    /// (not a separate, P2P-specific ranking path).
    ///
    /// Mirrors go-algorand's `TestLedgerFetcherP2P` shape at the
    /// `RankedCatchpointSource` level: a mixed pool of HTTP and P2P-derived
    /// peers must both be usable as catchpoint download candidates.
    #[tokio::test(flavor = "multi_thread")]
    async fn push_p2p_peer_joins_the_same_ranked_pool_as_http_peers() {
        const BODY: &[u8] = b"catchpoint-file-bytes-0123456789";
        let (good_url, good_requests) = spawn_always_succeeding_server(BODY).await;

        let src = RankedCatchpointSource::new(&[(good_url, String::new())], fast_retry_config());
        assert_eq!(src.peer_count(), 1);

        let bad_p2p = Arc::new(MockP2pTransport::new(not_found_response()));
        src.push_p2p_peer(
            "12D3KooWbadp2ppeer".to_string(),
            bad_p2p.clone() as Arc<dyn crate::http_over_stream::HttpPeerTransport>,
        );
        assert_eq!(
            src.peer_count(),
            2,
            "push_p2p_peer must add to the same candidate pool new() populated"
        );

        const ROUNDS: u64 = 8;
        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-ranked-catchpoint-p2p-mixed-{}",
            std::process::id()
        ));
        for round in 1..=ROUNDS {
            let dest = tmp_dir.join(format!("catchpoint-{round}.tar.gz"));
            let result = src.download("test-v1.0", round, &dest, None).await;
            assert!(
                result.is_ok(),
                "round {round} should have succeeded via the reliable HTTP peer even with a \
                 failing P2P peer in the same pool, got {:?}",
                result.err()
            );
        }

        assert!(
            bad_p2p.streams_opened.load(Ordering::SeqCst) <= 2,
            "the always-404 P2P peer should be deprioritized after failing, but had {} \
             streams opened",
            bad_p2p.streams_opened.load(Ordering::SeqCst)
        );
        assert!(
            good_requests.load(Ordering::SeqCst) >= ROUNDS as usize - 2,
            "the reliable HTTP peer should serve almost every round, got {} of {ROUNDS}",
            good_requests.load(Ordering::SeqCst)
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    /// The mirror image of the test above: a P2P peer that actually has the
    /// catchpoint must be usable as the sole successful source, proving
    /// `push_p2p_peer`'s downloader really does route through the abstract
    /// transport end-to-end (probe + full download), not just get counted
    /// in `peer_count()`.
    #[tokio::test(flavor = "multi_thread")]
    async fn push_p2p_peer_alone_can_serve_a_full_download() {
        const BODY: &[u8] = b"p2p-only-catchpoint-file-bytes";
        let src = RankedCatchpointSource::new(&[], fast_retry_config());

        let good_p2p = Arc::new(MockP2pTransport::new(ok_get_response(BODY)));
        src.push_p2p_peer(
            "12D3KooWgoodp2ppeer".to_string(),
            good_p2p as Arc<dyn crate::http_over_stream::HttpPeerTransport>,
        );

        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-ranked-catchpoint-p2p-only-{}",
            std::process::id()
        ));
        let dest = tmp_dir.join("catchpoint.tar.gz");

        let result = src.download("test-v1.0", 1, &dest, None).await;
        assert!(result.is_ok(), "expected success, got {:?}", result.err());
        assert_eq!(std::fs::read(&dest).unwrap(), BODY);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
